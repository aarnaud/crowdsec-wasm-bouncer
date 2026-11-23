use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::UNIX_EPOCH;

use crate::config::LAPIConfig;

pub(crate) const NETWORK_ROOT_ID: &str = "crowdsec-network";
pub(crate) const HEALTH_KEY: &str = "crowdsec_sync_healthy_v1";
pub(crate) const GENERATION_KEY: &str = "crowdsec_sync_generation_v1";

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ContextKind {
    Http,
    Network,
}

#[derive(Clone)]
pub(crate) struct TrackedContext {
    pub ip: String,
    pub kind: ContextKind,
}

pub(crate) type Registry = Rc<RefCell<HashMap<u32, TrackedContext>>>;

#[derive(Debug, PartialEq)]
pub(crate) enum Admission {
    Allow,
    Banned,
    Unavailable,
}

pub(crate) fn normalize_ip(address: &str) -> Option<String> {
    strip_port(address)
        .parse::<IpAddr>()
        .ok()
        .map(|ip| match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
            IpAddr::V4(v4) => v4.to_string(),
        })
}

pub(crate) fn now_millis<C: Context + ?Sized>(context: &C) -> u64 {
    context
        .get_current_time()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn cached_ban<C: Context + ?Sized>(context: &C, ip: &str) -> Option<String> {
    let now = now_millis(context);
    let (data, _) = context.get_shared_data(&format!("{}{}", IP_DECISION_PREFIX, ip));
    if let Some(data) = data {
        if let Some((until, reason)) = split_expiry(&data) {
            if until > now {
                return Some(String::from_utf8_lossy(reason).into_owned());
            }
        }
    }
    if let Some(ip) = parse_ipv4(ip) {
        let (data, _) = context.get_shared_data(RANGES_V4_KEY);
        return data.and_then(|blob| match_v4_range(ip, &blob, now));
    }
    if let Some(ip) = parse_ipv6(ip) {
        let (data, _) = context.get_shared_data(RANGES_V6_KEY);
        return data.and_then(|blob| match_v6_range(ip, &blob, now));
    }
    None
}

pub(crate) fn admission(
    config: &LAPIConfig,
    valid_ip: bool,
    healthy: bool,
    banned: bool,
) -> Admission {
    if !config.enabled {
        Admission::Allow
    } else if banned {
        Admission::Banned
    } else if (!valid_ip || !healthy) && !config.fail_open {
        Admission::Unavailable
    } else {
        Admission::Allow
    }
}

pub(crate) fn lapi_admission<C: Context + ?Sized>(
    context: &C,
    config: &LAPIConfig,
    ip: &str,
) -> Admission {
    if !config.enabled {
        return Admission::Allow;
    }
    let (health, _) = context.get_shared_data(HEALTH_KEY);
    admission(
        config,
        normalize_ip(ip).is_some(),
        health.as_deref() == Some(&[1]),
        cached_ban(context, ip).is_some(),
    )
}

pub struct CrowdSecNetworkContext {
    config: LAPIConfig,
    context_id: u32,
    registry: Registry,
    ip: String,
}

impl CrowdSecNetworkContext {
    pub(crate) fn new(config: LAPIConfig, context_id: u32, registry: Registry) -> Self {
        Self {
            config,
            context_id,
            registry,
            ip: String::new(),
        }
    }

    fn close(&self) -> Action {
        log::warn!("Closing LAPI-denied connection from {}", self.ip);
        self.close_downstream();
        Action::Pause
    }

    fn check_existing(&self) -> Action {
        if self.config.enabled && cached_ban(self, &self.ip).is_some() {
            self.close()
        } else {
            Action::Continue
        }
    }
}

impl Context for CrowdSecNetworkContext {}

impl StreamContext for CrowdSecNetworkContext {
    fn on_new_connection(&mut self) -> Action {
        self.ip = self
            .get_property(vec!["source", "address"])
            .and_then(|value| String::from_utf8(value).ok())
            .and_then(|address| normalize_ip(&address))
            .unwrap_or_default();
        match lapi_admission(self, &self.config, &self.ip) {
            Admission::Allow => {
                if self.config.enabled {
                    self.registry.borrow_mut().insert(
                        self.context_id,
                        TrackedContext {
                            ip: self.ip.clone(),
                            kind: ContextKind::Network,
                        },
                    );
                }
                Action::Continue
            }
            Admission::Banned | Admission::Unavailable => self.close(),
        }
    }

    fn on_downstream_data(&mut self, _size: usize, _end: bool) -> Action {
        self.check_existing()
    }

    fn on_upstream_data(&mut self, _size: usize, _end: bool) -> Action {
        self.check_existing()
    }
}

impl Drop for CrowdSecNetworkContext {
    fn drop(&mut self) {
        self.registry.borrow_mut().remove(&self.context_id);
    }
}

/// Shared-data keys holding the packed CIDR blobs synced from LAPI `Range` decisions.
/// Records are fixed-width and big-endian: an expiry, then a (base, mask) pair. Fixed
/// widths keep the per-request match a tight masking loop with no string parsing on the
/// hot path.
///
/// The `_v2` suffix is deliberate. Shared data outlives any single WASM VM and every
/// worker thread runs its own instance, so during a rolling update a new-format reader
/// can meet an old-format blob. Reading 8-byte records as 16-byte ones would silently
/// block the wrong addresses; a new key means stale blobs are ignored and rebuilt.
pub(crate) const RANGES_V4_KEY: &str = "crowdsec_ranges_v4_2";
pub(crate) const RANGES_V6_KEY: &str = "crowdsec_ranges_v6_2";

/// Key prefix for exact-IP decisions. Versioned for the same reason as the range keys:
/// the stored value gained an expiry prefix.
pub(crate) const IP_DECISION_PREFIX: &str = "ip2:";

/// Every stored decision starts with its expiry as big-endian epoch millis
pub(crate) const EXPIRY_LEN: usize = 8;

pub(crate) const RANGE_V4_CIDR_LEN: usize = 8;
pub(crate) const RANGE_V6_CIDR_LEN: usize = 32;
pub(crate) const RANGE_V4_RECORD: usize = EXPIRY_LEN + RANGE_V4_CIDR_LEN;
pub(crate) const RANGE_V6_RECORD: usize = EXPIRY_LEN + RANGE_V6_CIDR_LEN;

/// Split a stored decision into its expiry and payload.
///
/// Decisions carry their own lifetime, and honouring it is what stops a missed `deleted`
/// notification from banning an address forever: the entry simply stops matching when
/// the ban would have ended anyway.
pub(crate) fn split_expiry(value: &[u8]) -> Option<(u64, &[u8])> {
    if value.len() < EXPIRY_LEN {
        return None;
    }
    let (head, rest) = value.split_at(EXPIRY_LEN);
    let bytes: [u8; EXPIRY_LEN] = head.try_into().ok()?;
    Some((u64::from_be_bytes(bytes), rest))
}

/// Prefix a payload with its expiry for storage.
pub(crate) fn with_expiry(expires_at: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(EXPIRY_LEN + payload.len());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Strip the port suffix from an address that may be "ip:port" or "[ipv6]:port".
pub(crate) fn strip_port(addr: &str) -> String {
    if addr.starts_with('[') {
        // Bracketed IPv6: "[::1]:8080" → "::1"
        if let Some(close) = addr.find(']') {
            return addr[1..close].to_string();
        }
    } else if addr.matches(':').count() == 1 {
        // IPv4:port — exactly one colon means it is a port separator
        if let Some(idx) = addr.rfind(':') {
            return addr[..idx].to_string();
        }
    }
    // Bare IPv6 (multiple colons, no brackets) or plain IP: leave unchanged
    addr.to_string()
}

/// Parse a dotted-decimal IPv4 address into a u32.
pub(crate) fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a = parts[0].parse::<u8>().ok()? as u32;
    let b = parts[1].parse::<u8>().ok()? as u32;
    let c = parts[2].parse::<u8>().ok()? as u32;
    let d = parts[3].parse::<u8>().ok()? as u32;
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

/// Parse an IPv6 address into a u128, handling "::" compression and an embedded IPv4
/// tail ("::ffff:192.0.2.1"). Needed so trusted_ips and Range decisions work on IPv6
/// rather than degrading to an exact string comparison.
pub(crate) fn parse_ipv6(s: &str) -> Option<u128> {
    if s.is_empty() || !s.contains(':') {
        return None;
    }

    fn groups(part: &str) -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        for g in part.split(':') {
            if g.is_empty() {
                return None;
            }
            if g.contains('.') {
                let v4 = parse_ipv4(g)?;
                out.push((v4 >> 16) as u16);
                out.push((v4 & 0xffff) as u16);
                continue;
            }
            if g.len() > 4 {
                return None;
            }
            out.push(u16::from_str_radix(g, 16).ok()?);
        }
        Some(out)
    }

    let pack = |g: &[u16]| g.iter().fold(0u128, |acc, &v| (acc << 16) | v as u128);

    match s.find("::") {
        Some(i) => {
            let tail_str = &s[i + 2..];
            if tail_str.contains("::") {
                return None;
            }
            let head = groups(&s[..i])?;
            let tail = groups(tail_str)?;
            // "::" must stand in for at least one zero group
            if head.len() + tail.len() > 7 {
                return None;
            }
            let mut all = head;
            all.resize(8 - tail.len(), 0);
            all.extend(tail);
            Some(pack(&all))
        }
        None => {
            let all = groups(s)?;
            if all.len() != 8 {
                return None;
            }
            Some(pack(&all))
        }
    }
}

pub(crate) fn is_valid_ip(s: &str) -> bool {
    parse_ipv4(s).is_some() || parse_ipv6(s).is_some()
}

/// Return true if `ip` falls within `cidr`. Supports IPv4 and IPv6 CIDR notation, and a
/// bare address as an implicit /32 or /128.
pub(crate) fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    if ip.is_empty() || cidr.is_empty() {
        return false;
    }
    let (base, prefix_len) = match cidr.find('/') {
        Some(slash) => match cidr[slash + 1..].parse::<u32>() {
            Ok(n) => (&cidr[..slash], Some(n)),
            Err(_) => return false,
        },
        None => (cidr, None),
    };

    if let (Some(ip_v4), Some(base_v4)) = (parse_ipv4(ip), parse_ipv4(base)) {
        let prefix = prefix_len.unwrap_or(32);
        if prefix > 32 {
            return false;
        }
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        return (ip_v4 & mask) == (base_v4 & mask);
    }

    if let (Some(ip_v6), Some(base_v6)) = (parse_ipv6(ip), parse_ipv6(base)) {
        let prefix = prefix_len.unwrap_or(128);
        if prefix > 128 {
            return false;
        }
        let mask = if prefix == 0 {
            0u128
        } else {
            !0u128 << (128 - prefix)
        };
        return (ip_v6 & mask) == (base_v6 & mask);
    }

    // Mixed families, or an address neither side can parse: only an exact literal match
    prefix_len.is_none() && ip == base
}

pub(crate) fn is_trusted_ip(ip: &str, trusted: &[String]) -> bool {
    trusted
        .iter()
        .any(|entry| !entry.is_empty() && ip_in_cidr(ip, entry))
}

/// Resolve the real client IP.
///
/// X-Forwarded-For is walked right-to-left, skipping hops that are themselves trusted
/// proxies, and the first untrusted hop wins. The leftmost entry must never be taken:
/// it is whatever the client sent, so a client behind a trusted proxy could otherwise
/// set it to any value and walk straight past both the LAPI blocklist and AppSec's
/// IP-scoped rules.
///
/// Returns None when the source address is missing or unparseable — the caller must then
/// apply the fail-open/fail-closed policy rather than continuing with an empty identity.
pub(crate) fn resolve_client_ip(
    source_ip: &str,
    xff: Option<&str>,
    trusted: &[String],
) -> Option<String> {
    if !is_valid_ip(source_ip) {
        return None;
    }
    if trusted.is_empty() || !is_trusted_ip(source_ip, trusted) {
        return Some(source_ip.to_string());
    }
    // No XFF from a trusted proxy just means it did not add one: that is the direct
    // peer, not an unresolvable address
    let xff = match xff {
        Some(v) => v,
        None => return Some(source_ip.to_string()),
    };
    for entry in xff.rsplit(',') {
        let candidate = strip_port(entry.trim());
        // A malformed hop means the chain can no longer be reasoned about; everything
        // further left is unverifiable, so stop here
        if !is_valid_ip(&candidate) {
            break;
        }
        if !is_trusted_ip(&candidate, trusted) {
            return Some(candidate);
        }
    }
    Some(source_ip.to_string())
}

/// Pack a CIDR into the fixed-width key used inside the shared-data range blobs.
/// Returns (is_ipv6, key) with the base pre-masked so matching is a single AND.
/// The caller prepends the expiry to form a full record.
pub(crate) fn encode_range(cidr: &str) -> Option<(bool, Vec<u8>)> {
    let (base, prefix) = match cidr.find('/') {
        Some(slash) => (&cidr[..slash], Some(cidr[slash + 1..].parse::<u32>().ok()?)),
        None => (cidr, None),
    };

    if let Some(addr) = parse_ipv4(base) {
        let prefix = prefix.unwrap_or(32);
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        let mut record = Vec::with_capacity(RANGE_V4_CIDR_LEN);
        record.extend_from_slice(&(addr & mask).to_be_bytes());
        record.extend_from_slice(&mask.to_be_bytes());
        return Some((false, record));
    }

    if let Some(addr) = parse_ipv6(base) {
        let prefix = prefix.unwrap_or(128);
        if prefix > 128 {
            return None;
        }
        let mask = if prefix == 0 {
            0u128
        } else {
            !0u128 << (128 - prefix)
        };
        let mut record = Vec::with_capacity(RANGE_V6_CIDR_LEN);
        record.extend_from_slice(&(addr & mask).to_be_bytes());
        record.extend_from_slice(&mask.to_be_bytes());
        return Some((true, record));
    }

    None
}

pub(crate) fn format_v4(addr: u32) -> String {
    let o = addr.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

pub(crate) fn format_v6(addr: u128) -> String {
    (0..8)
        .map(|i| format!("{:x}", (addr >> (112 - i * 16)) as u16))
        .collect::<Vec<_>>()
        .join(":")
}

/// Scan a packed range blob for a CIDR containing `ip`, returning it in CIDR notation
/// for the block log.
pub(crate) fn match_v4_range(ip: u32, blob: &[u8], now: u64) -> Option<String> {
    for record in blob.as_chunks::<RANGE_V4_RECORD>().0 {
        let (expires_at, cidr) = match split_expiry(record) {
            Some(parts) => parts,
            None => continue,
        };
        if expires_at <= now {
            continue;
        }
        let base = u32::from_be_bytes([cidr[0], cidr[1], cidr[2], cidr[3]]);
        let mask = u32::from_be_bytes([cidr[4], cidr[5], cidr[6], cidr[7]]);
        if (ip & mask) == base {
            return Some(format!("{}/{}", format_v4(base), mask.leading_ones()));
        }
    }
    None
}

pub(crate) fn match_v6_range(ip: u128, blob: &[u8], now: u64) -> Option<String> {
    for record in blob.as_chunks::<RANGE_V6_RECORD>().0 {
        let (expires_at, cidr) = match split_expiry(record) {
            Some(parts) => parts,
            None => continue,
        };
        if expires_at <= now {
            continue;
        }
        let mut base_bytes = [0u8; 16];
        let mut mask_bytes = [0u8; 16];
        base_bytes.copy_from_slice(&cidr[..16]);
        mask_bytes.copy_from_slice(&cidr[16..]);
        let base = u128::from_be_bytes(base_bytes);
        let mask = u128::from_be_bytes(mask_bytes);
        if (ip & mask) == base {
            return Some(format!("{}/{}", format_v6(base), mask.leading_ones()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    struct Cache(HashMap<String, Vec<u8>>);

    impl Context for Cache {
        fn get_current_time(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1000)
        }

        fn get_shared_data(&self, key: &str) -> (Option<Vec<u8>>, Option<u32>) {
            (self.0.get(key).cloned(), None)
        }
    }

    fn config(enabled: bool, fail_open: bool) -> LAPIConfig {
        serde_json::from_value(serde_json::json!({
            "cluster": "lapi", "enabled": enabled, "fail_open": fail_open,
        }))
        .unwrap()
    }

    #[test]
    fn fail_policy_matrix_and_disabled_feature() {
        for enabled in [false, true] {
            for fail_open in [false, true] {
                for healthy in [false, true] {
                    for valid in [false, true] {
                        for banned in [false, true] {
                            let expected = if !enabled {
                                Admission::Allow
                            } else if banned {
                                Admission::Banned
                            } else if (!valid || !healthy) && !fail_open {
                                Admission::Unavailable
                            } else {
                                Admission::Allow
                            };
                            assert_eq!(
                                admission(&config(enabled, fail_open), valid, healthy, banned),
                                expected
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn normalize_connection_addresses_and_mapped_ipv6() {
        for (address, expected) in [
            ("192.0.2.8:1234", "192.0.2.8"),
            ("[2001:0db8::8]:1234", "2001:db8::8"),
            ("2001:db8:0:0:0:0:0:8", "2001:db8::8"),
            ("[::ffff:192.0.2.8]:443", "192.0.2.8"),
        ] {
            assert_eq!(normalize_ip(address).as_deref(), Some(expected));
        }
        for address in ["", "garbage", "/tmp/socket", "999.1.1.1"] {
            assert_eq!(normalize_ip(address), None);
        }
    }

    #[test]
    fn cached_bans_survive_failed_sync_but_honor_expiration() {
        let mut cache = Cache(HashMap::from([
            (HEALTH_KEY.to_string(), vec![0]),
            (
                format!("{}192.0.2.8", IP_DECISION_PREFIX),
                with_expiry(2000, b"ban"),
            ),
            (
                format!("{}192.0.2.9", IP_DECISION_PREFIX),
                with_expiry(999, b"old"),
            ),
        ]));
        for fail_open in [false, true] {
            assert_eq!(
                lapi_admission(&cache, &config(true, fail_open), "192.0.2.8"),
                Admission::Banned
            );
        }
        assert_eq!(
            lapi_admission(&cache, &config(true, false), "192.0.2.9"),
            Admission::Unavailable
        );
        assert_eq!(
            lapi_admission(&cache, &config(true, true), "192.0.2.9"),
            Admission::Allow
        );
        cache.0.insert(HEALTH_KEY.to_string(), vec![1]);
        assert_eq!(
            lapi_admission(&cache, &config(true, false), "192.0.2.9"),
            Admission::Allow
        );
    }

    #[test]
    fn shared_lookup_matches_both_cidr_families() {
        let mut cache = Cache(HashMap::new());
        for (cidr, key, matching, other) in [
            ("192.0.2.0/24", RANGES_V4_KEY, "192.0.2.8", "198.51.100.8"),
            ("2001:db8::/32", RANGES_V6_KEY, "2001:db8::8", "2001:db9::8"),
        ] {
            let (_, value) = encode_range(cidr).unwrap();
            cache.0.insert(key.to_string(), with_expiry(2000, &value));
            assert!(cached_ban(&cache, matching).is_some());
            assert!(cached_ban(&cache, other).is_none());
            cache.0.insert(key.to_string(), with_expiry(999, &value));
            assert!(cached_ban(&cache, matching).is_none());
        }
    }

    #[test]
    fn destroyed_network_context_leaves_no_registry_entry() {
        let registry = Rc::new(RefCell::new(HashMap::new()));
        registry.borrow_mut().insert(
            42,
            TrackedContext {
                ip: "192.0.2.8".into(),
                kind: ContextKind::Network,
            },
        );
        drop(CrowdSecNetworkContext::new(
            config(true, false),
            42,
            registry.clone(),
        ));
        assert!(registry.borrow().is_empty());
    }
}
