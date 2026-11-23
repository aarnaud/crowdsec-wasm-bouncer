use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

use crate::config::Config;

use crate::network::*;

/// Cap on the client headers relayed to AppSec, bounding VM memory per in-flight request
const MAX_FORWARDED_HEADER_BYTES: usize = 8 * 1024;

/// Bytes of body needed before the binary/text sniff is worth running
const SNIFF_PREFIX: usize = 512;

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

/// Whether this request is an HTTP protocol-upgrade handshake (WebSocket being the
/// common case). RFC 7230 requires both signals: Connection listing the "upgrade"
/// token, and a non-empty Upgrade header naming the target protocol. A genuine
/// handshake carries no body of its own - real protocol frames (WebSocket included)
/// only start flowing after the server's 101 response - so there is nothing here for a
/// body-based WAF check to inspect. Envoy keeps this request's stream open (no
/// end_of_stream) in anticipation of the tunnel; without this check that reads as an
/// ordinary large/streaming body, and the subsequent tunnelled bytes (audio, control
/// frames, indefinitely, for the life of the connection) get buffered and shipped to
/// AppSec as if they were more of the GET's body.
fn is_protocol_upgrade(connection: &str, upgrade: &str) -> bool {
    if upgrade.trim().is_empty() {
        return false;
    }
    connection
        .split(',')
        .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
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
///
/// A missing Content-Type is deliberately *not* treated as inspectable: should_forward_body
/// ORs this with the byte sniff, so returning true here would skip that sniff entirely
/// for every content-type-less body. Plenty of raw-upload clients (S3/MinIO multipart
/// UploadPart in particular) send binary object bytes with no Content-Type header at
/// all - falling through to the byte sniff is what actually catches those.
fn body_is_inspectable(content_type: &str) -> bool {
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

/// Does this body actually look like binary? Three signals, any of which is
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
///
/// Inspects the whole slice handed to it, not a fixed-size prefix: a short ASCII/hex
/// preamble (e.g. the chunk-size/signature framing an S3-style "aws-chunked" upload
/// puts ahead of each block of raw object bytes) dilutes a small fixed sample below
/// the thresholds even though the bulk of the buffered body is genuinely binary. The
/// caller already bounds the buffer size via max_body_size_kb, so scanning all of it
/// costs nothing extra.
fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.contains(&0) {
        return true;
    }
    let len = bytes.len();
    let control = bytes
        .iter()
        .filter(|b| **b < 0x09 || (**b > 0x0d && **b < 0x20) || **b == 0x7f)
        .count();
    let non_ascii = bytes.iter().filter(|b| **b >= 0x80).count();
    control * 100 > len * 30 || (non_ascii * 100 > len * 40 && control * 100 > len * 5)
}

/// True when Content-Encoding declares a transformation this filter cannot undo.
///
/// There is no decompression codec available in this WASM filter, so for an encoded
/// body the bytes on the wire are not the literal request content. Trusting the
/// declared Content-Type for such a body, the way body_is_inspectable does, would
/// have AppSec parse compressed/ciphertext noise as if it were real JSON/form data -
/// exactly how a gzip or "aws-chunked" streaming upload turns into bogus WAF matches.
fn is_undecodable_encoding(content_encoding: &str) -> bool {
    let enc = content_encoding.trim();
    !enc.is_empty() && !enc.eq_ignore_ascii_case("identity")
}

/// Whether the buffered body should go to AppSec.
///
/// An undecodable Content-Encoding rules a body out unconditionally, since neither
/// the declared Content-Type nor the byte sniff below can be trusted against bytes
/// this filter cannot decompress. Otherwise, the declared Content-Type only gets to
/// *exclude* a body, and only when the bytes agree with it. Content-Type is
/// attacker-controlled, so trusting it alone turns "skip binary uploads" into a
/// one-header WAF bypass: a JSON injection payload sent as `application/octet-stream`
/// would never be inspected, while plenty of backends parse the body regardless of
/// what it claims to be.
fn should_forward_body(content_type: &str, content_encoding: &str, prefix: &[u8]) -> bool {
    if is_undecodable_encoding(content_encoding) {
        return false;
    }
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
    context_id: u32,
    registry: Registry,
    ip: String,
    path: String,
    method: String,
    host: String,
    user_agent: String,
    content_type: String,
    content_encoding: String,
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
    pub(crate) fn new(config: Config, context_id: u32, registry: Registry) -> Self {
        Self {
            config,
            context_id,
            registry,
            ip: String::new(),
            path: String::new(),
            method: String::new(),
            host: String::new(),
            user_agent: String::new(),
            content_type: String::new(),
            content_encoding: String::new(),
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

    fn appsec_request_headers(&self) -> Vec<(&str, &str)> {
        let authority = if self.config.crowdsec.appsec.host.is_empty() {
            self.host.as_str()
        } else {
            self.config.crowdsec.appsec.host.as_str()
        };
        vec![
            (":method", "POST"),
            (":path", "/"),
            (":authority", authority),
            ("X-Crowdsec-Appsec-Ip", self.ip.as_str()),
            ("X-Crowdsec-Appsec-Uri", self.path.as_str()),
            ("X-Crowdsec-Appsec-Host", self.host.as_str()),
            ("X-Crowdsec-Appsec-Verb", self.method.as_str()),
            ("X-Crowdsec-Appsec-User-Agent", self.user_agent.as_str()),
            (
                "X-Crowdsec-Appsec-Api-Key",
                self.config.crowdsec.appsec.key.as_str(),
            ),
        ]
    }

    fn send_appsec_event(&mut self) {
        let body_len = self.body_data.len().to_string();
        let relayed_ct = self.relayed_content_type();
        let mut headers = self.appsec_request_headers();
        headers.push(("Content-Length", body_len.as_str()));
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
        if !should_forward_body(&self.content_type, &self.content_encoding, &self.body_data) {
            log::info!(
                "Body not forwarded (content-type: {}, content-encoding: {}), headers-only AppSec check",
                self.content_type, self.content_encoding
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
}

impl Drop for CrowdSecHttpContext {
    fn drop(&mut self) {
        self.registry.borrow_mut().remove(&self.context_id);
    }
}

impl Context for CrowdSecHttpContext {
    fn on_http_call_response(
        &mut self,
        token_id: u32,
        num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        log::info!(
            "AppSec response received - token_id: {}, body_size: {}",
            token_id,
            body_size
        );
        self.appsec_pending = false;

        let status = if num_headers == 0 {
            503
        } else {
            self.get_http_call_response_header(":status")
                .unwrap_or_else(|| "503".to_string())
                .parse::<u32>()
                .unwrap_or(503)
        };

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
                if (!self.config.crowdsec.lapi.enabled || self.config.crowdsec.lapi.fail_open)
                    && (!self.config.crowdsec.appsec.enabled
                        || self.config.crowdsec.appsec.fail_open)
                {
                    return Action::Continue;
                }
                self.send_http_response(
                    if self.config.crowdsec.lapi.enabled && !self.config.crowdsec.lapi.fail_open {
                        503
                    } else {
                        403
                    },
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

        self.ip = normalize_ip(&self.ip).unwrap_or_default();
        match lapi_admission(self, &self.config.crowdsec.lapi, &self.ip) {
            Admission::Allow => {}
            Admission::Banned => {
                self.send_http_response(
                    403,
                    vec![("content-type", "text/plain")],
                    Some(b"LAPI Access Denied"),
                );
                return Action::Pause;
            }
            Admission::Unavailable => {
                self.send_http_response(
                    503,
                    vec![("content-type", "text/plain")],
                    Some(b"LAPI unavailable"),
                );
                return Action::Pause;
            }
        }
        if self.config.crowdsec.lapi.enabled {
            self.registry.borrow_mut().insert(
                self.context_id,
                TrackedContext {
                    ip: self.ip.clone(),
                    kind: ContextKind::Http,
                },
            );
        }

        if !self.config.crowdsec.appsec.enabled {
            return Action::Continue;
        }

        self.client_headers = collect_client_headers(self.get_http_request_headers());
        self.content_type = self
            .get_http_request_header("content-type")
            .unwrap_or_default();
        self.content_encoding = self
            .get_http_request_header("content-encoding")
            .unwrap_or_default();

        let content_length = self
            .get_http_request_header("content-length")
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let connection_header = self
            .get_http_request_header("connection")
            .unwrap_or_default();
        let upgrade_header = self.get_http_request_header("upgrade").unwrap_or_default();
        if is_protocol_upgrade(&connection_header, &upgrade_header) {
            log::info!(
                "Protocol upgrade request (Upgrade: {}), skipping AppSec body inspection",
                upgrade_header
            );
            self.has_body = false;
        } else {
            self.has_body = !end_of_stream || content_length > 0;
        }

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
    fn test_appsec_destination_host_preserves_original_host() {
        let config: Config = serde_json::from_slice(
            br#"{"crowdsec":{"lapi":{"cluster":"lapi"},"appsec":{"key":"test-key"}}}"#,
        )
        .unwrap();
        let mut context = CrowdSecHttpContext::new(config, 1, Default::default());
        for original_host in ["", "site.example.com:8080"] {
            context.host = original_host.to_string();
            for host in ["", "appsec.example.com", "appsec.example.com:8443"] {
                context.config.crowdsec.appsec.host = host.to_string();
                let headers = context.appsec_request_headers();
                assert!(headers.contains(&(
                    ":authority",
                    if host.is_empty() { original_host } else { host }
                )));
                assert!(headers.contains(&("X-Crowdsec-Appsec-Host", original_host)));
                assert!(headers.contains(&("X-Crowdsec-Appsec-Api-Key", "test-key")));
            }
        }
    }

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
    fn test_is_protocol_upgrade_detects_websocket_handshake() {
        assert!(is_protocol_upgrade("Upgrade", "websocket"));
        // Connection is a comma-separated token list, not just "Upgrade" alone
        assert!(is_protocol_upgrade("keep-alive, Upgrade", "websocket"));
        // Case-insensitive on both the token and the header value
        assert!(is_protocol_upgrade("UPGRADE", "WebSocket"));
    }

    #[test]
    fn test_is_protocol_upgrade_requires_both_signals() {
        // Connection without the "upgrade" token: an ordinary keep-alive request
        assert!(!is_protocol_upgrade("keep-alive", "websocket"));
        // Upgrade token present but no protocol named to upgrade to
        assert!(!is_protocol_upgrade("Upgrade", ""));
        assert!(!is_protocol_upgrade("", ""));
    }

    #[test]
    fn test_body_is_inspectable_empty_content_type_defers_to_byte_sniff() {
        // No Content-Type must not short-circuit should_forward_body's OR past the
        // byte sniff - plenty of raw-upload clients (S3/MinIO UploadPart) send binary
        // object bytes with no Content-Type header at all.
        assert!(!body_is_inspectable(""));
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
        assert!(should_forward_body("application/json", "", br#"{"a":1}"#));
    }

    #[test]
    fn test_should_forward_body_skips_genuine_binary() {
        assert!(!should_forward_body(
            "application/octet-stream",
            "",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        ));
        assert!(!should_forward_body("image/png", "", &[0u8; 128]));
    }

    #[test]
    fn test_should_forward_body_inspects_mislabelled_text_payload() {
        // The WAF bypass this closes: declare a binary content type, send a text
        // injection payload, and the body used to skip inspection entirely.
        assert!(should_forward_body(
            "application/octet-stream",
            "",
            br#"{"q":"1' UNION SELECT password FROM users--"}"#
        ));
        assert!(should_forward_body(
            "image/png",
            "",
            b"<script>alert(document.cookie)</script>"
        ));
    }

    #[test]
    fn test_should_forward_body_empty_body_is_not_binary() {
        assert!(should_forward_body("application/octet-stream", "", b""));
    }

    #[test]
    fn test_should_forward_body_no_content_type_still_checked_for_binary() {
        // Reproduces alert 16009: an S3/MinIO UploadPart PUT with no Content-Type
        // header at all, carrying raw binary object bytes. body_is_inspectable("")
        // must not wave this through unconditionally - the byte sniff has to run.
        assert!(!should_forward_body("", "", &[0u8; 128]));
        // A genuinely textual body with no declared type is still forwarded.
        assert!(should_forward_body("", "", br#"{"a":1}"#));
    }

    #[test]
    fn test_should_forward_body_skips_undecodable_encoding() {
        // A declared-text body under an encoding we cannot decompress must never be
        // forwarded, even though Content-Type alone would call it inspectable - the
        // bytes on the wire are not the literal JSON/form content they claim to be.
        assert!(!should_forward_body(
            "application/json",
            "gzip",
            br#"{"a":1}"#
        ));
        assert!(!should_forward_body(
            "application/json",
            "aws-chunked",
            br#"{"a":1}"#
        ));
        // "identity" and no header at all are pass-through, not an encoding
        assert!(should_forward_body(
            "application/json",
            "identity",
            br#"{"a":1}"#
        ));
        assert!(should_forward_body("application/json", "", br#"{"a":1}"#));
    }

    #[test]
    fn test_looks_binary_detects_binary_after_text_preamble() {
        // Reproduces the alert-15999 false negative: an S3/MinIO "aws-chunked"
        // streaming upload prefixes each block of raw object bytes with an ASCII
        // chunk-size/signature line. A sniff limited to a small fixed prefix sees
        // mostly that text and misses the binary payload that follows it.
        let preamble =
            b"2000;chunk-signature=1234567890abcdef1234567890abcdef1234567890ab\r\n".repeat(5);
        let mut body = preamble.to_vec();
        let entropy: Vec<u8> = (0..8192u32)
            .map(|i| {
                let v = (i.wrapping_mul(2654435761) >> 13) as u8;
                if v == 0 {
                    1
                } else {
                    v
                }
            })
            .collect();
        body.extend_from_slice(&entropy);
        assert!(looks_binary(&body));
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
