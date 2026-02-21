use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::Duration;

use crate::config::Config;

pub struct CrowdSecHttpContext {
    config: Config,
    ip: String,
    path: String,
    method: String,
    host: String,
    user_agent: String,
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
            content_type: String::new(),
            body_data: Vec::new(),
            appsec_pending: false,
            appsec_done: false,
            response_paused: false,
        }
    }

    fn send_appsec_event(&mut self) {
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
        ];
        if !self.content_type.is_empty() && !self.body_data.is_empty() {
            headers.push(("Content-Type", self.content_type.as_str()));
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
                if self.config.crowdsec.appsec.fail_open {
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

    fn request_has_body(&self) -> bool {
        self.config.crowdsec.appsec.forward_body
            && matches!(self.method.as_str(), "POST" | "PUT" | "PATCH")
    }

    /// Only forward body to AppSec for content types it can meaningfully inspect.
    /// Binary/compressed bodies produce false positives (null bytes, CR/LF, etc.).
    fn body_is_inspectable(&self) -> bool {
        if self.content_type.is_empty() {
            return true;
        }
        let ct = self.content_type.to_lowercase();
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

        if status == 503 {
            log::error!("AppSec API unavailable");
            if self.config.crowdsec.appsec.fail_open {
                self.allow_and_resume();
                return;
            }
            log::warn!("fail_open disabled, denying request");
        }

        if status == 200 {
            log::info!("AppSec allows request, resuming");
            self.allow_and_resume();
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
    }
}

impl HttpContext for CrowdSecHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        self.ip = self
            .get_http_request_header("x-forwarded-for")
            .or_else(|| {
                self.get_property(vec!["source", "address"])
                    .and_then(|bytes| String::from_utf8(bytes).ok())
            })
            .unwrap_or_default();

        // source.address may return IP:port — strip the port robustly.
        // Bracketed IPv6: "[::1]:8080" → strip brackets and ":port"
        // IPv4 with port: "1.2.3.4:8080" → strip ":port" (exactly one colon)
        // Bare IPv6: "::1" or "2001:db8::1" → multiple colons, no brackets, leave as-is
        if self.ip.starts_with('[') {
            // Bracketed IPv6: find the closing ']', discard everything after it
            if let Some(close) = self.ip.find(']') {
                self.ip = self.ip[1..close].to_string();
            }
        } else if self.ip.matches(':').count() == 1 {
            // IPv4:port — single colon means it must be a port separator
        if let Some(idx) = self.ip.rfind(':') {
                self.ip = self.ip[..idx].to_string();
            }
        }
        // Bare IPv6 (multiple colons, no brackets): leave unchanged

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

            if self.body_is_inspectable() {
                if !end_of_stream {
                    // Inspectable body: continue to let body callbacks fire
                    log::info!(
                        "Request has inspectable body, continuing headers (body will be held)"
                    );
                    return Action::Continue;
                }
                // Small inspectable body arrived with headers, read it now
                let max_size = self.max_body_size();
                if let Some(body) = self.get_http_request_body(0, max_size) {
                    log::info!(
                        "Read {} bytes of body at headers (end_of_stream=true)",
                        body.len()
                    );
                    self.body_data = body;
                }
            } else {
                // Non-inspectable body (binary/compressed): headers-only check,
                // pause here, on_http_request_body returns Continue to let body
                // stream. AppSec responds fast and resume_http_request releases all.
                log::info!(
                    "Body not inspectable ({}), headers-only AppSec check",
                    self.content_type
                );
                self.send_appsec_event();
                return Action::Pause;
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

        // Non-inspectable body: AppSec was dispatched with headers only,
        // let the body stream through while waiting for the response
        if !self.body_is_inspectable() {
            return Action::Continue;
        }

        // Waiting on AppSec response, keep holding body
        if self.appsec_pending {
            return Action::Pause;
        }

        // Accumulate body up to max_body_size_kb
        let max_size = self.max_body_size();
        if body_size > 0 && self.body_data.len() < max_size {
            let read_size = body_size.min(max_size);
            if let Some(body) = self.get_http_request_body(0, read_size) {
                self.body_data = body;
                log::debug!("Buffered {} bytes of body", self.body_data.len());
            }
        }

        // Dispatch AppSec once we have enough data or stream ends
        if self.body_data.len() >= max_size || end_of_stream {
            log::info!(
                "Dispatching AppSec: {} bytes, end_of_stream={}",
                self.body_data.len(),
                end_of_stream
            );
            self.send_appsec_event();
        }

        Action::Pause
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if self.appsec_pending {
            log::info!("AppSec pending, pausing response");
            self.response_paused = true;
            return Action::Pause;
        }
        Action::Continue
    }
}
