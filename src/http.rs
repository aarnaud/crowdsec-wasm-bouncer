use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

use crate::config::Config;

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

/// Return true if `ip` falls within `cidr`.
/// Supports IPv4 CIDR notation and exact IPv6 matching.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    if let Some(slash) = cidr.find('/') {
        let base = &cidr[..slash];
        let prefix_len: u32 = match cidr[slash + 1..].parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        match (parse_ipv4(ip), parse_ipv4(base)) {
            (Some(ip_u32), Some(base_u32)) => {
                let mask = if prefix_len == 0 {
                    0u32
                } else if prefix_len >= 32 {
                    !0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                (ip_u32 & mask) == (base_u32 & mask)
            }
            // IPv6 CIDR: not supported, fall back to exact match of base
            _ => ip == base,
        }
    } else {
        ip == cidr
    }
}

fn is_trusted_ip(ip: &str, trusted: &[String]) -> bool {
    trusted.iter().any(|entry| ip_in_cidr(ip, entry))
}

/// Whether a request body's declared Content-Type is one AppSec can meaningfully
/// inspect as text. Binary/compressed content types are skipped entirely (headers-only
/// AppSec check) rather than forwarded, since raw binary noise scores as highly
/// anomalous under signature-based WAF rules and can trigger false-positive bans on
/// legitimate uploads.
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

/// Whether on_http_request_body should dispatch the buffered body to AppSec now:
/// only once per request, when enough data has accumulated or the stream ended,
/// and never while a call is already in flight.
fn should_dispatch_appsec(
    pending: bool,
    body_len: usize,
    max_size: usize,
    end_of_stream: bool,
) -> bool {
    !pending && (body_len >= max_size || end_of_stream)
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

/// Add 'wasm-unsafe-eval' to a CSP's script-src (or default-src, if no script-src is
/// present) directive. CrowdSec's shipped bot-detection challenge page ships a CSP
/// whose script-src lacks it, which Firefox enforces strictly for
/// WebAssembly.instantiate (used by the challenge's PoW module) while Chromium is
/// more lenient - breaking the challenge only in Firefox. No config-level override
/// exists upstream yet, so patch the header here before relaying it to the client.
fn patch_csp_for_wasm(value: &str) -> String {
    let directives: Vec<&str> = value
        .split(';')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();
    let target = if directives
        .iter()
        .any(|d| d.split_whitespace().next() == Some("script-src"))
    {
        "script-src"
    } else if directives
        .iter()
        .any(|d| d.split_whitespace().next() == Some("default-src"))
    {
        "default-src"
    } else {
        return value.to_string();
    };
    directives
        .into_iter()
        .map(|d| {
            if d.split_whitespace().next() == Some(target) && !d.contains("unsafe-eval") {
                format!("{d} 'wasm-unsafe-eval'")
            } else {
                d.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Flatten a challenge envelope's user_headers and user_cookies into (name, value) pairs
/// for send_http_response. Each user_headers value list becomes one header per entry;
/// each user_cookies entry becomes one set-cookie header.
fn build_challenge_headers(envelope: &ChallengeEnvelope) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for (name, values) in &envelope.user_headers {
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
    cookie: String,
    content_type: String,
    body_data: Vec<u8>,
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
            cookie: String::new(),
            content_type: String::new(),
            body_data: Vec::new(),
            appsec_pending: false,
            appsec_done: false,
            response_paused: false,
        }
    }

    fn send_appsec_event(&mut self) {
        let body_len = self.body_data.len().to_string();
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
        if !self.content_type.is_empty() && !self.body_data.is_empty() {
            headers.push(("Content-Type", self.content_type.as_str()));
        }
        // Forward the client's cookies untouched so AppSec can recognise a
        // previously-solved bot-detection challenge (__crowdsec_challenge cookie).
        if !self.cookie.is_empty() {
            headers.push(("Cookie", self.cookie.as_str()));
        }

        log::info!(
            "Sending AppSec event to cluster: {}, body length: {}",
            self.config.crowdsec.appsec.cluster,
            self.body_data.len()
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
        (self.config.crowdsec.appsec.max_body_size_kb as usize) * 1024
    }

    fn max_response_body_size(&self) -> usize {
        (self.config.crowdsec.appsec.max_response_body_size_kb as usize) * 1024
    }

    fn request_has_body(&self) -> bool {
        self.config.crowdsec.appsec.forward_body
            && matches!(self.method.as_str(), "POST" | "PUT" | "PATCH")
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
                    challenge.http_status as u32,
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

        // Only honour X-Forwarded-For when the direct peer is a configured trusted proxy,
        // preventing clients from spoofing their IP via that header.
        let trusted = !self.config.crowdsec.trusted_ips.is_empty()
            && is_trusted_ip(&source_ip, &self.config.crowdsec.trusted_ips);

        self.ip = if trusted {
            // Use the leftmost (original client) IP from XFF, falling back to source_ip.
            self.get_http_request_header("x-forwarded-for")
                .and_then(|xff| xff.split(',').next().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| source_ip.clone())
        } else {
            source_ip
        };

        self.path = self.get_http_request_header(":path").unwrap_or_default();
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.user_agent = self
            .get_http_request_header("user-agent")
            .unwrap_or_default();
        self.host = self
            .get_http_request_header(":authority")
            .unwrap_or_default();
        self.cookie = self.get_http_request_header("cookie").unwrap_or_default();

        log::info!("Request: {} {} from {}", self.method, self.path, self.ip);

        // Check IP blocking
        if self.config.crowdsec.lapi.enabled {
            let key = format!("ip:{}", self.ip);
            let (decision_data, _) = self.get_shared_data(&key);
            if let Some(decision) = decision_data {
                if !decision.is_empty() {
                    log::warn!(
                        "Blocking IP {}: {}",
                        self.ip,
                        String::from_utf8_lossy(&decision)
                    );
                    self.send_http_response(
                        403,
                        vec![("content-type", "text/plain")],
                        Some(b"Access Denied"),
                    );
                    return Action::Pause;
                }
            }
        }

        if !self.config.crowdsec.appsec.enabled {
            return Action::Continue;
        }

        if self.request_has_body() {
            self.content_type = self
                .get_http_request_header("content-type")
                .unwrap_or_default();

            if !body_is_inspectable(&self.content_type) {
                // Binary/compressed body: skip forwarding it to AppSec entirely
                // (headers-only check) and let it stream straight through.
                log::info!(
                    "Body not inspectable ({}), headers-only AppSec check",
                    self.content_type
                );
                self.send_appsec_event();
                return if self.config.crowdsec.appsec.async_mode {
                    Action::Continue
                } else {
                    Action::Pause
                };
            }

            if !end_of_stream {
                log::info!("Request has inspectable body, waiting for body data");
                return Action::Continue;
            }
            // Body arrived with headers (end_of_stream=true): read it now
            let max_size = self.max_body_size();
            if let Some(body) = self.get_http_request_body(0, max_size) {
                log::info!("Read {} bytes of body at headers", body.len());
                self.body_data = body;
            }
        }

        // No body or inspectable body already read: dispatch AppSec
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

        // Non-inspectable body: AppSec was already dispatched headers-only in
        // on_http_request_headers; let the body stream through untouched.
        if self.request_has_body() && !body_is_inspectable(&self.content_type) {
            return Action::Continue;
        }

        // prevent 413 when buffer is bigger that 512k
        if self.appsec_pending && body_size > 512 * 1024 {
            return Action::Continue;
        }

        // Accumulate body up to max_body_size_kb
        let max_size = self.max_body_size();
        if body_size > 0 && self.body_data.len() < max_size {
            let offset = self.body_data.len();
            let read_size = body_size.saturating_sub(offset).min(max_size - offset);
            if read_size > 0 {
                if let Some(chunk) = self.get_http_request_body(offset, read_size) {
                    self.body_data.extend_from_slice(&chunk);
                    log::debug!("Buffered {} bytes of body", self.body_data.len());
                }
            }
        }

        // Dispatch AppSec once we have enough data or stream ends — but only once
        // per request: skip while a call is already in flight, otherwise every
        // later chunk that still satisfies this condition re-dispatches, causing
        // overlapping AppSec calls that each independently resume/respond.
        if should_dispatch_appsec(
            self.appsec_pending,
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
    fn test_is_trusted_ip_empty_list() {
        assert!(!is_trusted_ip("1.2.3.4", &[]));
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
    fn test_should_dispatch_appsec_at_size_threshold() {
        assert!(should_dispatch_appsec(false, 100, 100, false));
    }

    #[test]
    fn test_should_dispatch_appsec_below_threshold_mid_stream() {
        assert!(!should_dispatch_appsec(false, 50, 100, false));
    }

    #[test]
    fn test_should_dispatch_appsec_end_of_stream_triggers() {
        assert!(should_dispatch_appsec(false, 10, 100, true));
    }

    #[test]
    fn test_should_dispatch_appsec_skipped_while_pending() {
        // Regression: a call already in flight must not be re-dispatched even
        // though the buffer is full (this was the duplicate-dispatch bug).
        assert!(!should_dispatch_appsec(true, 100, 100, false));
    }

    #[test]
    fn test_should_dispatch_appsec_skipped_while_pending_at_end_of_stream() {
        assert!(!should_dispatch_appsec(true, 100, 100, true));
    }

    #[test]
    fn test_is_trusted_ip_matches() {
        let trusted = vec!["10.0.0.0/8".to_string(), "192.168.1.100".to_string()];
        assert!(is_trusted_ip("10.5.6.7", &trusted));
        assert!(is_trusted_ip("192.168.1.100", &trusted));
        assert!(!is_trusted_ip("172.16.0.1", &trusted));
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
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self'"
        );
    }

    #[test]
    fn test_patch_csp_for_wasm_falls_back_to_default_src() {
        let csp = "default-src 'self'; style-src 'self'";
        let patched = patch_csp_for_wasm(csp);
        assert_eq!(
            patched,
            "default-src 'self' 'wasm-unsafe-eval'; style-src 'self'"
        );
    }

    #[test]
    fn test_patch_csp_for_wasm_noop_when_already_allowed() {
        let csp = "script-src 'self' 'unsafe-eval'";
        assert_eq!(patch_csp_for_wasm(csp), csp);

        let csp_wasm = "script-src 'self' 'wasm-unsafe-eval'";
        assert_eq!(patch_csp_for_wasm(csp_wasm), csp_wasm);
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
            "script-src-elem 'self'; default-src 'self' 'wasm-unsafe-eval'"
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
                "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'".to_string()
            )]
        );
    }
}
