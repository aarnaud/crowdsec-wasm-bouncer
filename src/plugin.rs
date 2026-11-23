use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use crate::config::Config;
use crate::http::CrowdSecHttpContext;
use crate::network::*;

#[derive(Deserialize)]
struct DecisionsResponse {
    #[serde(default)]
    new: Option<Vec<Decision>>,
    #[serde(default)]
    deleted: Option<Vec<Decision>>,
}

#[derive(Deserialize)]
struct Decision {
    #[serde(rename = "type")]
    decision_type: String,
    scope: String,
    value: String,
    scenario: String,
    // Every decision carries its own lifetime ("3h59m57s", negative once elapsed).
    // Honouring it is what keeps a missed `deleted` notification from banning an
    // address permanently.
    #[serde(default)]
    duration: String,
}

/// Hard cap on the LAPI decisions-stream response body read per sync tick.
/// Bounds memory against a slow/compromised/misrouted LAPI claiming a huge
/// body_size; deployments with larger blocklists can raise the configured cap.
const MAX_LAPI_RESPONSE_BODY_SIZE: usize = 32 * 1024 * 1024;

/// Cap on stored Range decisions per address family. Each one is scanned on every
/// request, so this bounds both shared-data memory and the per-request match cost.
const MAX_RANGE_DECISIONS: usize = 4096;

/// Shared-data flag marking the full `startup=true` pull as done.
///
/// It lives in shared data rather than a struct field because every worker thread runs
/// its own WASM VM with its own copy of those fields: a per-instance flag means each VM
/// independently believes it is the first and pulls the entire decision set, so an
/// 8-worker proxy does eight full syncs on every start. Only set once the sync actually
/// succeeds, so a failed pull is retried instead of leaving the bouncer empty.
const STARTUP_DONE_KEY: &str = "crowdsec_startup_done";

// Exact-IP keys are otherwise not enumerable through the Proxy-Wasm ABI. Keeping
// an index lets a recovery snapshot remove bans whose deletion delta was lost.
const IP_INDEX_KEY: &str = "crowdsec_ip_index_v1";

/// Applied when a decision's duration is missing or unparseable. Dropping the decision
/// would fail open, and treating it as permanent is the bug this replaces, so bound it.
const DEFAULT_DECISION_TTL_MS: i64 = 3_600_000;

/// Parse a Go duration into milliseconds, as sent in a decision's `duration` field
/// ("3h59m57s", "29m57s", "1m30.5s", or negative like "-52m11s" once elapsed).
fn parse_go_duration_ms(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    let (negative, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if body.is_empty() {
        return None;
    }
    if body == "0" {
        return Some(0);
    }

    let bytes = body.as_bytes();
    let mut total_ms = 0f64;
    let mut i = 0;
    while i < bytes.len() {
        let number_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if i == number_start {
            return None;
        }
        let amount: f64 = body[number_start..i].parse().ok()?;

        let unit_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' {
            i += 1;
        }
        total_ms += match &body[unit_start..i] {
            "ns" => amount / 1_000_000.0,
            "us" | "\u{b5}s" | "\u{3bc}s" => amount / 1_000.0,
            "ms" => amount,
            "s" => amount * 1_000.0,
            "m" => amount * 60_000.0,
            "h" => amount * 3_600_000.0,
            _ => return None,
        };
    }

    let total = total_ms as i64;
    Some(if negative { -total } else { total })
}

/// How long a held sync lock may go unreleased before another worker steals it.
/// The lock is released in on_http_call_response, so it only outlives its holder when
/// that callback never arrives (VM recycled, worker torn down mid-flight). Without a
/// steal path the lock would persist in shared data forever and decision syncing would
/// stop permanently: bans go stale and `deleted` entries are never removed. Twice the
/// 60s LAPI dispatch timeout, so a genuinely in-flight sync is never interrupted.
const SYNC_LOCK_STALE_MS: u64 = 120_000;

/// Read the epoch-millis timestamp out of a sync lock value. Returns None for anything
/// that is not one (including the old fixed `b"locked"` value), which is treated as
/// stale so an upgrade cannot inherit a permanently wedged lock.
fn parse_lock_timestamp(data: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = data.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

pub struct CrowdSecPlugin {
    config: Option<Config>,
    /// Whether the sync currently in flight from this VM is the startup pull
    pending_startup: bool,
    context_id: u32,
    network: bool,
    registry: Registry,
    generation: u64,
    pending_token: Option<u32>,
    pending_since: u64,
}

impl CrowdSecPlugin {
    pub fn new(context_id: u32) -> Self {
        Self {
            config: None,
            pending_startup: false,
            context_id,
            network: false,
            registry: Rc::new(RefCell::new(HashMap::new())),
            generation: 0,
            pending_token: None,
            pending_since: 0,
        }
    }

    fn sync_decisions(&mut self) {
        let config = match &self.config {
            Some(c) => c.clone(),
            None => return,
        };

        if !config.crowdsec.lapi.enabled {
            return;
        }

        let now = now_millis(self);
        if self.pending_token.is_some() {
            if now.saturating_sub(self.pending_since) < 60_000 {
                return;
            }
            self.finish_sync(false);
        }
        let frequency = self.config.as_ref().unwrap().crowdsec.lapi.sync_freq as u64 * 1000;
        if !self.sync_due(now, frequency) {
            return;
        }

        // Use SharedData CAS to prevent multiple threads syncing simultaneously
        let sync_lock_key = "crowdsec_sync_lock";

        // Try to acquire lock atomically
        let (lock_data, cas) = self.get_shared_data(sync_lock_key);
        let now = self
            .get_current_time()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Some(data) = lock_data {
            if !data.is_empty() {
                match parse_lock_timestamp(&data) {
                    Some(held_since) if now.saturating_sub(held_since) < SYNC_LOCK_STALE_MS => {
                        log::debug!("Sync already in progress, skipping");
                        return;
                    }
                    Some(held_since) => log::warn!(
                        "Sync lock held for {}ms with no release, stealing it",
                        now.saturating_sub(held_since)
                    ),
                    None => log::warn!("Sync lock value is not a timestamp, stealing it"),
                }
            }
        }

        // Try to set lock with CAS - only one thread will succeed. The CAS also settles
        // the race when several workers spot the same stale lock at once.
        if self
            .set_shared_data(sync_lock_key, Some(&now.to_be_bytes()), cas)
            .is_err()
        {
            log::debug!("Failed to acquire sync lock, another thread won");
            return;
        }

        if !self.sync_due(now, frequency) {
            let _ = self.set_shared_data(sync_lock_key, None, None);
            return;
        }
        let _ = self.set_shared_data(
            "crowdsec_last_sync_attempt_v1",
            Some(&now.to_be_bytes()),
            None,
        );
        self.pending_since = now;

        // Decided here, under the lock, from shared state rather than a per-VM field, so
        // only one worker's VM performs the full pull
        let (startup_flag, _) = self.get_shared_data(STARTUP_DONE_KEY);
        let startup = !matches!(startup_flag, Some(ref v) if !v.is_empty());
        self.pending_startup = startup;

        log::info!("Lock acquired, starting sync (startup={})", startup);

        let path = if startup {
            "/v1/decisions/stream?startup=true"
        } else {
            "/v1/decisions/stream"
        };

        let headers = vec![
            (":method", "GET"),
            (":path", path),
            (":authority", ""),
            ("X-Api-Key", &config.crowdsec.lapi.key),
            (
                "user-agent",
                concat!("crowdsec-wasm-bouncer/v", env!("CARGO_PKG_VERSION")),
            ),
        ];

        match self.dispatch_http_call(
            &config.crowdsec.lapi.cluster,
            headers,
            None,
            vec![],
            Duration::from_secs(60),
        ) {
            Ok(token) => self.pending_token = Some(token),
            Err(e) => {
                log::error!("failed to dispatch LAPI call: {:?}", e);
                self.finish_sync(false);
            }
        }
    }

    fn sync_due(&self, now: u64, frequency: u64) -> bool {
        let (last, _) = self.get_shared_data("crowdsec_last_sync_attempt_v1");
        last.as_deref()
            .and_then(parse_lock_timestamp)
            .is_none_or(|last| now.saturating_sub(last) >= frequency)
    }

    fn finish_sync(&mut self, success: bool) {
        // A late callback must not release another worker's stolen lease
        let (lease, _) = self.get_shared_data("crowdsec_sync_lock");
        if lease.as_deref().and_then(parse_lock_timestamp) == Some(self.pending_since) {
            // A failed incremental response may already have advanced LAPI's stream.
            // Recover with a full snapshot so missed additions cannot be lost forever.
            if !success {
                let _ = self.set_shared_data(STARTUP_DONE_KEY, None, None);
            }
            let _ = self.set_shared_data(HEALTH_KEY, Some(&[u8::from(success)]), None);
            if success {
                let (value, cas) = self.get_shared_data(GENERATION_KEY);
                let next = value
                    .as_deref()
                    .and_then(parse_lock_timestamp)
                    .unwrap_or(0)
                    .wrapping_add(1);
                if self
                    .set_shared_data(GENERATION_KEY, Some(&next.to_be_bytes()), cas)
                    .is_err()
                {
                    let _ = self.set_shared_data(HEALTH_KEY, Some(&[0]), None);
                }
            }
            let _ = self.set_shared_data("crowdsec_sync_lock", None, None);
        }
        self.pending_token = None;
    }

    fn recheck_connections(&mut self) {
        if !self
            .config
            .as_ref()
            .is_some_and(|config| config.crowdsec.lapi.enabled)
        {
            return;
        }
        let (value, _) = self.get_shared_data(GENERATION_KEY);
        let generation = value.as_deref().and_then(parse_lock_timestamp).unwrap_or(0);
        if generation == self.generation {
            return;
        }
        self.generation = generation;
        // Closing can destroy contexts; never keep the registry borrowed across a host call
        let contexts: Vec<_> = self
            .registry
            .borrow()
            .iter()
            .map(|(&id, entry)| (id, entry.clone()))
            .collect();
        for (id, entry) in contexts {
            if cached_ban(self, &entry.ip).is_none() {
                continue;
            }
            if proxy_wasm::hostcalls::set_effective_context(id).is_ok() {
                log::warn!(
                    "Closing newly banned {:?} context {} from {}",
                    entry.kind,
                    id,
                    entry.ip
                );
                let result = match entry.kind {
                    ContextKind::Network => proxy_wasm::hostcalls::close_downstream(),
                    ContextKind::Http => proxy_wasm::hostcalls::reset_http_request(),
                };
                if let Err(error) = result {
                    log::error!("failed to close banned context {}: {:?}", id, error);
                }
            }
            let _ = proxy_wasm::hostcalls::set_effective_context(self.context_id);
            self.registry.borrow_mut().remove(&id);
        }
    }

    /// Apply additions and removals to a packed range blob in shared data.
    ///
    /// Records are fixed-width, so add/remove is a byte-slice comparison with no parsing.
    /// Identity is the CIDR part only, not the whole record: the same range re-sent with
    /// a refreshed lifetime must replace the existing entry rather than accumulate beside
    /// it. Expired records are dropped while the blob is being rewritten anyway - this
    /// runs under the sync lock, so it is the one place with a single writer.
    fn update_range_blob(
        &self,
        key: &str,
        record_size: usize,
        add: &[Vec<u8>],
        remove: &[Vec<u8>],
        now: u64,
        reset: bool,
    ) -> Result<(), ()> {
        if !reset && add.is_empty() && remove.is_empty() {
            return Ok(());
        }
        fn cidr_of(record: &[u8]) -> Option<&[u8]> {
            split_expiry(record).map(|(_, cidr)| cidr)
        }

        let (existing, cas) = self.get_shared_data(key);
        let existing = if reset {
            Vec::new()
        } else {
            existing.unwrap_or_default()
        };
        let mut records: Vec<&[u8]> = existing.chunks_exact(record_size).collect();

        let before = records.len();
        records.retain(|record| match split_expiry(record) {
            Some((expires_at, cidr)) => {
                expires_at > now && !remove.iter().any(|d| d.as_slice() == cidr)
            }
            None => false,
        });
        let dropped = before - records.len();

        for record in add {
            let cidr = match cidr_of(record) {
                Some(c) => c,
                None => continue,
            };
            if let Some(pos) = records.iter().position(|e| cidr_of(e) == Some(cidr)) {
                // Same range, refreshed lifetime
                records[pos] = record.as_slice();
                continue;
            }
            if records.len() >= MAX_RANGE_DECISIONS {
                log::error!(
                    "Range decision cap ({}) reached for {}, dropping further ranges",
                    MAX_RANGE_DECISIONS,
                    key
                );
                return Err(());
            }
            records.push(record.as_slice());
        }

        let count = records.len();
        let blob: Vec<u8> = records.concat();
        if self.set_shared_data(key, Some(&blob), cas).is_err() {
            log::error!("Failed to update range blob {} (CAS conflict)", key);
            Err(())
        } else {
            log::info!(
                "Range blob {} now holds {} entries ({} expired or removed)",
                key,
                count,
                dropped
            );
            Ok(())
        }
    }
}

impl CrowdSecPlugin {
    fn apply_sync_response(&mut self, num_headers: usize, body_size: usize) -> bool {
        if num_headers == 0 {
            log::error!("LAPI call failed without response headers; keeping cached decisions");
            return false;
        }
        let status = self
            .get_http_call_response_header(":status")
            .unwrap_or_else(|| "503".to_string())
            .parse::<u32>()
            .unwrap_or(503);

        if status != 200 {
            log::error!(
                "LAPI decision endpoint returned unexpected status: {}",
                status
            );
            return false;
        }

        let max_body = self
            .config
            .as_ref()
            .map(|c| (c.crowdsec.lapi.max_body_size_kb as usize).saturating_mul(1024))
            .unwrap_or(MAX_LAPI_RESPONSE_BODY_SIZE);
        if body_size > max_body {
            // The startup flag is only set on success, so this is retried on the next
            // tick rather than leaving the bouncer permanently without decisions
            log::error!(
                "LAPI decisions response body too large ({} bytes, max {}); no decisions \
                 applied; keeping cached decisions and applying lapi.fail_open. Raise \
                 lapi.max_body_size_kb if the VM has headroom, or reduce the blocklist",
                body_size,
                max_body
            );
            return false;
        }

        let body = if body_size > 0 {
            self.get_http_call_response_body(0, body_size)
        } else {
            None
        };

        let body = match body {
            Some(b) => b,
            None => {
                log::error!("failed to get LAPI decisions response body");
                return false;
            }
        };

        let resp: DecisionsResponse = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                log::error!("failed to parse LAPI decisions response: {:?}", e);
                return false;
            }
        };

        let new = resp.new.unwrap_or_default();
        let deleted = resp.deleted.unwrap_or_default();
        let index_needed = self.pending_startup
            || new
                .iter()
                .chain(&deleted)
                .any(|d| d.scope.eq_ignore_ascii_case("ip"));
        let old_ips: BTreeSet<String> = if index_needed {
            let (data, _) = self.get_shared_data(IP_INDEX_KEY);
            data.map(|data| {
                String::from_utf8_lossy(&data)
                    .lines()
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let mut current_ips = if self.pending_startup {
            BTreeSet::new()
        } else {
            old_ips.clone()
        };

        let now = self
            .get_current_time()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut v4_add = Vec::new();
        let mut v6_add = Vec::new();
        let mut v4_remove = Vec::new();
        let mut v6_remove = Vec::new();
        let mut applied = 0;

        // Apply removals first so a replacement ban for the same IP wins this batch.
        for d in &deleted {
            match d.scope.to_lowercase().as_str() {
                "ip" => {
                    let ip = match normalize_ip(&d.value) {
                        Some(ip) => ip,
                        None => {
                            log::warn!("Skipping invalid decision IP {}", d.value);
                            continue;
                        }
                    };
                    let key = format!("{}{}", IP_DECISION_PREFIX, ip);
                    current_ips.remove(&ip);
                    if self.set_shared_data(&key, None, None).is_err() {
                        log::error!("failed to remove LAPI decision");
                        return false;
                    }
                }
                "range" => match encode_range(&d.value) {
                    Some((true, cidr)) => v6_remove.push(cidr),
                    Some((false, cidr)) => v4_remove.push(cidr),
                    None => {}
                },
                _ => {}
            }
        }

        for d in &new {
            // Only "ban" is enforceable here. A captcha decision has no challenge flow on
            // this path and any other type is unknown, so storing them would turn them
            // into silent hard blocks.
            if !d.decision_type.eq_ignore_ascii_case("ban") {
                log::info!(
                    "Ignoring unsupported decision type {} for {}",
                    d.decision_type,
                    d.value
                );
                continue;
            }

            let ttl_ms = match parse_go_duration_ms(&d.duration) {
                Some(ms) if ms <= 0 => {
                    log::debug!("Decision for {} has already elapsed, skipping", d.value);
                    continue;
                }
                Some(ms) => ms,
                None => {
                    log::warn!(
                        "Decision for {} has an unparseable duration {:?}, applying default TTL",
                        d.value,
                        d.duration
                    );
                    DEFAULT_DECISION_TTL_MS
                }
            };
            let expires_at = now.saturating_add(ttl_ms as u64);

            match d.scope.to_lowercase().as_str() {
                "ip" => {
                    let ip = match normalize_ip(&d.value) {
                        Some(ip) => ip,
                        None => {
                            log::warn!("Skipping invalid decision IP {}", d.value);
                            continue;
                        }
                    };
                    let key = format!("{}{}", IP_DECISION_PREFIX, ip);
                    let reason = format!("{}_{}", d.decision_type, d.scenario);
                    let value = with_expiry(expires_at, reason.as_bytes());
                    if self.set_shared_data(&key, Some(&value), None).is_err() {
                        log::error!("failed to store LAPI decision");
                        return false;
                    }
                    current_ips.insert(ip);
                    applied += 1;
                }
                "range" => match encode_range(&d.value) {
                    Some((is_v6, cidr)) => {
                        let record = with_expiry(expires_at, &cidr);
                        if is_v6 {
                            v6_add.push(record);
                        } else {
                            v4_add.push(record);
                        }
                        applied += 1;
                    }
                    None => log::warn!("Skipping unparseable range decision: {}", d.value),
                },
                other => log::info!(
                    "Ignoring decision with unsupported scope {} for {}",
                    other,
                    d.value
                ),
            }
        }

        if self
            .update_range_blob(
                RANGES_V4_KEY,
                RANGE_V4_RECORD,
                &v4_add,
                &v4_remove,
                now,
                self.pending_startup,
            )
            .is_err()
            || self
                .update_range_blob(
                    RANGES_V6_KEY,
                    RANGE_V6_RECORD,
                    &v6_add,
                    &v6_remove,
                    now,
                    self.pending_startup,
                )
                .is_err()
        {
            return false;
        }

        if self.pending_startup {
            for ip in old_ips.difference(&current_ips) {
                if self
                    .set_shared_data(&format!("{}{}", IP_DECISION_PREFIX, ip), None, None)
                    .is_err()
                {
                    return false;
                }
            }
        }
        if index_needed {
            let index = current_ips.into_iter().collect::<Vec<_>>().join("\n");
            if self
                .set_shared_data(IP_INDEX_KEY, Some(index.as_bytes()), None)
                .is_err()
            {
                return false;
            }
        }

        if self.pending_startup {
            if self
                .set_shared_data(STARTUP_DONE_KEY, Some(&[1u8][..]), None)
                .is_err()
            {
                return false;
            }
            self.pending_startup = false;
            log::info!("Startup decision pull complete; other workers will sync incrementally");
        }

        log::info!(
            "Synced decisions: +{} new ({} applied), -{} deleted",
            new.len(),
            applied,
            deleted.len()
        );
        true
    }
}

impl Context for CrowdSecPlugin {
    fn on_http_call_response(&mut self, token: u32, headers: usize, body: usize, _trailers: usize) {
        if self.pending_token != Some(token) {
            return;
        }
        let (lease, _) = self.get_shared_data("crowdsec_sync_lock");
        if lease.as_deref().and_then(parse_lock_timestamp) != Some(self.pending_since) {
            self.pending_token = None;
            return;
        }
        let success = self.apply_sync_response(headers, body);
        self.finish_sync(success);
        self.recheck_connections();
    }
}

impl RootContext for CrowdSecPlugin {
    fn on_configure(&mut self, _configuration_size: usize) -> bool {
        self.network = self
            .get_property(vec!["plugin_root_id"])
            .is_some_and(|id| id == NETWORK_ROOT_ID.as_bytes());
        match self.get_plugin_configuration() {
            Some(config_bytes) => {
                match serde_json::from_slice::<Config>(&config_bytes) {
                    Ok(mut config) => {
                        // Fall back to environment variables for empty keys
                        if config.crowdsec.lapi.key.is_empty() {
                            if let Ok(key) = std::env::var("CROWDSEC_LAPI_KEY") {
                                config.crowdsec.lapi.key = key;
                            }
                        }
                        if config.crowdsec.appsec.key.is_empty() {
                            if let Ok(key) = std::env::var("CROWDSEC_APPSEC_KEY") {
                                config.crowdsec.appsec.key = key;
                            }
                        }

                        // Drop unusable trusted_ips entries rather than carrying them
                        // into the trust check: an empty or unparseable entry can match
                        // an odd source address and hand X-Forwarded-For control to an
                        // untrusted peer. Dropping one only means XFF stops being
                        // honoured for that proxy, which fails closed.
                        config.crowdsec.trusted_ips.retain(|entry| {
                            let valid = encode_range(entry).is_some();
                            if !valid {
                                log::error!("Ignoring invalid trusted_ips entry: {:?}", entry);
                            }
                            valid
                        });

                        // Refuse to load on a configuration that cannot work. Left to run,
                        // an enabled feature with no cluster or key fails every dispatch,
                        // which means either a total outage (fail_open: false) or a
                        // silently disabled WAF (fail_open: true) - both discovered in
                        // production rather than at deploy time.
                        if config.crowdsec.lapi.enabled {
                            if config.crowdsec.lapi.cluster.is_empty() {
                                log::error!("lapi.enabled is true but lapi.cluster is empty");
                                return false;
                            }
                            if config.crowdsec.lapi.key.is_empty() {
                                log::error!(
                                    "lapi.enabled is true but no API key was given in config or CROWDSEC_LAPI_KEY"
                                );
                                return false;
                            }
                            if config.crowdsec.lapi.sync_freq == 0 {
                                // set_tick_period(0) disables the tick outright, so the
                                // plugin would load, log success and never sync a decision
                                log::error!("lapi.sync_freq must be greater than 0");
                                return false;
                            }
                        }
                        if !self.network && config.crowdsec.appsec.enabled {
                            if config.crowdsec.appsec.cluster.is_empty() {
                                log::error!("appsec.enabled is true but appsec.cluster is empty");
                                return false;
                            }
                            if config.crowdsec.appsec.key.is_empty() {
                                log::error!(
                                    "appsec.enabled is true but no API key was given in config or CROWDSEC_APPSEC_KEY"
                                );
                                return false;
                            }
                            if config.crowdsec.appsec.forward_body
                                && config.crowdsec.appsec.max_body_size_kb == 0
                            {
                                // Would dispatch immediately with an empty body, i.e.
                                // forward_body silently does nothing
                                log::error!(
                                    "appsec.forward_body is true but appsec.max_body_size_kb is 0"
                                );
                                return false;
                            }
                        }

                        log::warn!(
                            "CrowdSec Plugin loading:\n\
                            \tNetwork filter: {}\n\
                            \tLAPI cluster: {}\n\
                            \tLAPI enabled: {}\n\
                            \tLAPI FailOpen: {}\n\
                            \tLAPI sync_freq: {}\n\
                            \tAppSec cluster: {}\n\
                            \tAppsec enabled: {}\n\
                            \tAppsec FailOpen: {}\n\
                            \tAppsec ForwardBody: {}\n\
                            \tAppsec MaxBodySizeKB: {}\n\
                            \tTrustedIPs: {}\n",
                            self.network,
                            config.crowdsec.lapi.cluster,
                            config.crowdsec.lapi.enabled,
                            config.crowdsec.lapi.fail_open,
                            config.crowdsec.lapi.sync_freq,
                            config.crowdsec.appsec.cluster,
                            !self.network && config.crowdsec.appsec.enabled,
                            config.crowdsec.appsec.fail_open,
                            config.crowdsec.appsec.forward_body,
                            config.crowdsec.appsec.max_body_size_kb,
                            config.crowdsec.trusted_ips.join(", "),
                        );

                        // Schedule periodic sync
                        self.set_tick_period(Duration::from_secs(1));

                        self.config = Some(config);
                        true
                    }
                    Err(e) => {
                        log::error!("failed to parse config: {:?}", e);
                        false
                    }
                }
            }
            None => {
                log::error!("failed to get config");
                false
            }
        }
    }

    fn on_tick(&mut self) {
        self.recheck_connections();
        self.sync_decisions();
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CrowdSecHttpContext::new(
            self.config.as_ref()?.clone(),
            context_id,
            self.registry.clone(),
        )))
    }

    fn create_stream_context(&self, context_id: u32) -> Option<Box<dyn StreamContext>> {
        Some(Box::new(CrowdSecNetworkContext::new(
            self.config.as_ref()?.crowdsec.lapi.clone(),
            context_id,
            self.registry.clone(),
        )))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(if self.network {
            ContextType::StreamContext
        } else {
            ContextType::HttpContext
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_context_selects_http_or_network_without_a_mode_field() {
        let mut root = CrowdSecPlugin::new(1);
        assert_eq!(root.get_type(), Some(ContextType::HttpContext));
        root.network = true;
        assert_eq!(root.get_type(), Some(ContextType::StreamContext));
    }

    #[test]
    fn test_parse_go_duration_typical_lapi_values() {
        assert_eq!(parse_go_duration_ms("3h59m57s"), Some(14_397_000));
        assert_eq!(parse_go_duration_ms("29m57s"), Some(1_797_000));
        assert_eq!(parse_go_duration_ms("4h"), Some(14_400_000));
        assert_eq!(parse_go_duration_ms("30m"), Some(1_800_000));
        assert_eq!(parse_go_duration_ms("90s"), Some(90_000));
    }

    #[test]
    fn test_parse_go_duration_negative_means_elapsed() {
        // LAPI reports already-expired decisions with a negative duration
        assert_eq!(parse_go_duration_ms("-52m11s"), Some(-3_131_000));
        assert!(parse_go_duration_ms("-1s").unwrap() < 0);
    }

    #[test]
    fn test_parse_go_duration_fractional_and_small_units() {
        assert_eq!(parse_go_duration_ms("1m30.5s"), Some(90_500));
        assert_eq!(parse_go_duration_ms("1.5s"), Some(1_500));
        assert_eq!(parse_go_duration_ms("250ms"), Some(250));
        assert_eq!(parse_go_duration_ms("3h59m58.123456789s"), Some(14_398_123));
        assert_eq!(parse_go_duration_ms("500us"), Some(0));
        assert_eq!(parse_go_duration_ms("500\u{b5}s"), Some(0));
        assert_eq!(parse_go_duration_ms("1000000ns"), Some(1));
    }

    #[test]
    fn test_parse_go_duration_zero() {
        assert_eq!(parse_go_duration_ms("0"), Some(0));
        assert_eq!(parse_go_duration_ms("0s"), Some(0));
    }

    #[test]
    fn test_parse_go_duration_rejects_garbage() {
        // Unparseable durations fall back to a bounded default rather than being
        // treated as permanent, so they must be reported as None not silently zero
        assert!(parse_go_duration_ms("").is_none());
        assert!(parse_go_duration_ms("forever").is_none());
        assert!(parse_go_duration_ms("12").is_none());
        assert!(parse_go_duration_ms("3d").is_none());
        assert!(parse_go_duration_ms("h").is_none());
    }
}
