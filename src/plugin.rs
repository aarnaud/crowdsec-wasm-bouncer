use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use crate::config::Config;
use crate::http::CrowdSecHttpContext;
use crate::http::{encode_range, RANGES_V4_KEY, RANGES_V6_KEY, RANGE_V4_RECORD, RANGE_V6_RECORD};

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
}

/// Hard cap on the LAPI decisions-stream response body read per sync tick.
/// Bounds memory against a slow/compromised/misrouted LAPI claiming a huge
/// body_size, while staying well above realistic blocklist sizes.
const MAX_LAPI_RESPONSE_BODY_SIZE: usize = 32 * 1024 * 1024;

/// Cap on stored Range decisions per address family. Each one is scanned on every
/// request, so this bounds both shared-data memory and the per-request match cost.
const MAX_RANGE_DECISIONS: usize = 4096;

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
    first_sync: bool,
}

impl CrowdSecPlugin {
    pub fn new() -> Self {
        Self {
            config: None,
            first_sync: true,
        }
    }

    fn sync_decisions(&mut self, startup: bool) {
        let config = match &self.config {
            Some(c) => c,
            None => return,
        };

        if !config.crowdsec.lapi.enabled {
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
            ("user-agent", "crowdsec-wasm-bouncer"),
        ];

        match self.dispatch_http_call(
            &config.crowdsec.lapi.cluster,
            headers,
            None,
            vec![],
            Duration::from_secs(60),
        ) {
            Ok(_) => {}
            Err(e) => {
                log::error!("failed to dispatch LAPI call: {:?}", e);
                // Release lock on error
                let _ = self.set_shared_data(sync_lock_key, None, None);
            }
        }
    }

    /// Apply additions and removals to a packed range blob in shared data. Records are
    /// fixed-width, so add/remove is a byte-slice comparison with no parsing.
    fn update_range_blob(
        &self,
        key: &str,
        record_size: usize,
        add: &[Vec<u8>],
        remove: &[Vec<u8>],
    ) {
        if add.is_empty() && remove.is_empty() {
            return;
        }
        let (existing, cas) = self.get_shared_data(key);
        let existing = existing.unwrap_or_default();
        let mut records: Vec<&[u8]> = existing.chunks_exact(record_size).collect();
        records.retain(|r| !remove.iter().any(|d| d.as_slice() == *r));
        for r in add {
            if records.contains(&r.as_slice()) {
                continue;
            }
            if records.len() >= MAX_RANGE_DECISIONS {
                log::error!(
                    "Range decision cap ({}) reached for {}, dropping further ranges",
                    MAX_RANGE_DECISIONS,
                    key
                );
                break;
            }
            records.push(r.as_slice());
        }
        let blob: Vec<u8> = records.concat();
        let count = blob.len() / record_size;
        if self.set_shared_data(key, Some(&blob), cas).is_err() {
            log::error!("Failed to update range blob {} (CAS conflict)", key);
        } else {
            log::info!("Range blob {} now holds {} entries", key, count);
        }
    }
}

impl Context for CrowdSecPlugin {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        // Always release the sync lock when done
        let release_result = self.set_shared_data("crowdsec_sync_lock", None, None);
        if release_result.is_ok() {
            log::info!("Released sync lock");
        } else {
            log::error!("Failed to release sync lock: {:?}", release_result);
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
            return;
        }

        if body_size > MAX_LAPI_RESPONSE_BODY_SIZE {
            log::error!(
                "LAPI decisions response body too large ({} bytes, max {}), skipping sync",
                body_size,
                MAX_LAPI_RESPONSE_BODY_SIZE
            );
            return;
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
                return;
            }
        };

        let resp: DecisionsResponse = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                log::error!("failed to parse LAPI decisions response: {:?}", e);
                return;
            }
        };

        let new = resp.new.unwrap_or_default();
        let deleted = resp.deleted.unwrap_or_default();

        let mut v4_add = Vec::new();
        let mut v6_add = Vec::new();
        let mut v4_remove = Vec::new();
        let mut v6_remove = Vec::new();
        let mut applied = 0;

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
            match d.scope.to_lowercase().as_str() {
                "ip" => {
                    let key = format!("ip:{}", d.value);
                    let value = format!("{}_{}", d.decision_type, d.scenario);
                    let _ = self.set_shared_data(&key, Some(value.as_bytes()), None);
                    applied += 1;
                }
                "range" => match encode_range(&d.value) {
                    Some((true, record)) => {
                        v6_add.push(record);
                        applied += 1;
                    }
                    Some((false, record)) => {
                        v4_add.push(record);
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

        // Removals apply regardless of type: whatever the decision was, it is over.
        for d in &deleted {
            match d.scope.to_lowercase().as_str() {
                "ip" => {
                    let key = format!("ip:{}", d.value);
                    let _ = self.set_shared_data(&key, None, None);
                }
                "range" => match encode_range(&d.value) {
                    Some((true, record)) => v6_remove.push(record),
                    Some((false, record)) => v4_remove.push(record),
                    None => {}
                },
                _ => {}
            }
        }

        self.update_range_blob(RANGES_V4_KEY, RANGE_V4_RECORD, &v4_add, &v4_remove);
        self.update_range_blob(RANGES_V6_KEY, RANGE_V6_RECORD, &v6_add, &v6_remove);

        log::info!(
            "Synced decisions: +{} new ({} applied), -{} deleted",
            new.len(),
            applied,
            deleted.len()
        );
    }
}

impl RootContext for CrowdSecPlugin {
    fn on_configure(&mut self, _configuration_size: usize) -> bool {
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
                        if config.crowdsec.appsec.enabled {
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
                            \tLAPI cluster: {}\n\
                            \tLAPI enabled: {}\n\
                            \tLAPI sync_freq: {}\n\
                            \tAppSec cluster: {}\n\
                            \tAppsec enabled: {}\n\
                            \tAppsec FailOpen: {}\n\
                            \tAppsec ForwardBody: {}\n\
                            \tAppsec MaxBodySizeKB: {}\n\
                            \tTrustedIPs: {}\n",
                            config.crowdsec.lapi.cluster,
                            config.crowdsec.lapi.enabled,
                            config.crowdsec.lapi.sync_freq,
                            config.crowdsec.appsec.cluster,
                            config.crowdsec.appsec.enabled,
                            config.crowdsec.appsec.fail_open,
                            config.crowdsec.appsec.forward_body,
                            config.crowdsec.appsec.max_body_size_kb,
                            config.crowdsec.trusted_ips.join(", "),
                        );

                        // Schedule periodic sync
                        let sync_millis = (config.crowdsec.lapi.sync_freq as u64) * 1000;
                        self.set_tick_period(Duration::from_millis(sync_millis));

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
        // Use first_sync flag to trigger startup=true on first tick
        self.sync_decisions(self.first_sync);
        self.first_sync = false;
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CrowdSecHttpContext::new(
            self.config.as_ref()?.clone(),
        )))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}
