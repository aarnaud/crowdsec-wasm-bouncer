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
            ("X-Crowdsec-Appsec-Api-Key", self.config.crowdsec.appsec.key.as_str()),
        ];
        if !self.content_type.is_empty() {
            headers.push(("Content-Type", self.content_type.as_str()));
        }

        log::info!("Sending AppSec event to cluster: {}, body length: {}",
                  self.config.crowdsec.appsec.cluster, self.body_data.len());

        match self.dispatch_http_call(
            &self.config.crowdsec.appsec.cluster,
            headers,
            Some(&self.body_data),
            vec![],
            Duration::from_millis(2000),
        ) {
            Ok(call_id) => {
                self.appsec_pending = true;
                log::info!("AppSec call dispatched successfully with call_id: {}", call_id);
            }
            Err(e) => {
                log::error!("Failed to dispatch AppSec call: {:?}", e);
                self.appsec_pending = false;
                if self.config.crowdsec.appsec.fail_open {
                    self.appsec_done = true;
                    self.resume_http_request();
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
        log::info!("AppSec response received - token_id: {}, body_size: {}", token_id, body_size);
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
                self.appsec_done = true;
                self.resume_http_request();
                return;
            }
            log::warn!("fail_open disabled, denying request");
        }

        if status == 200 {
            log::info!("AppSec allows request, resuming");
            self.appsec_done = true;
            self.resume_http_request();
        } else {
            log::warn!("AppSec blocking request from {} (status: {})", self.ip, status);
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

        // source.address returns IP:port, strip the port
        if let Some(idx) = self.ip.rfind(':') {
            if self.ip[..idx].contains('.') || self.ip[..idx].contains(']') {
                self.ip = self.ip[..idx].to_string();
            }
        }
        // Strip brackets from IPv6
        self.ip = self.ip.trim_matches(|c| c == '[' || c == ']').to_string();

        self.path = self.get_http_request_header(":path").unwrap_or_default();
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.user_agent = self.get_http_request_header("user-agent").unwrap_or_default();
        self.host = self.get_http_request_header(":authority").unwrap_or_default();

        log::info!("Request: {} {} from {}", self.method, self.path, self.ip);

        // Check IP blocking
        if self.config.crowdsec.lapi.enabled {
            let key = format!("ip:{}", self.ip);
            let (decision_data, _) = self.get_shared_data(&key);
            if let Some(decision) = decision_data {
                if !decision.is_empty() {
                    log::warn!("Blocking IP {}: {}", self.ip, String::from_utf8_lossy(&decision));
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

        // Body methods: Continue to let headers through to router so body
        // callbacks fire. Body will be held in on_http_request_body.
        // Headers reaching the backend is harmless — the backend can't
        // process a POST/PUT/PATCH without body data.
        // If AppSec blocks, send_http_response(403) resets the upstream.
        // on_http_response_headers pauses any early backend response.
        if self.request_has_body() && !end_of_stream {
            self.content_type = self.get_http_request_header("content-type").unwrap_or_default();
            log::info!("Request has body, continuing headers (body will be held)");
            return Action::Continue;
        }

        // Body method with end_of_stream=true: small body arrived with headers.
        // on_http_request_body won't be called, so read body here.
        if self.request_has_body() {
            self.content_type = self.get_http_request_header("content-type").unwrap_or_default();
            let max_size = (self.config.crowdsec.appsec.max_body_size_kb as usize) * 1024;
            if let Some(body) = self.get_http_request_body(0, max_size) {
                log::info!("Read {} bytes of body at headers (end_of_stream=true)", body.len());
                self.body_data = body;
            }
        }

        // No body, or body read above: dispatch AppSec now and pause
        self.send_appsec_event();
        if self.config.crowdsec.appsec.async_mode {
            Action::Continue
        } else {
            Action::Pause
        }
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        log::info!("on_http_request_body: body_size={}, end_of_stream={}", body_size, end_of_stream);

        if !self.config.crowdsec.appsec.enabled {
            return Action::Continue;
        }

        // AppSec already approved, let remaining body flow
        if self.appsec_done {
            return Action::Continue;
        }

        // Waiting on AppSec response, keep holding body
        if self.appsec_pending {
            return Action::Pause;
        }

        // Accumulate body up to max_body_size_kb
        let max_size = (self.config.crowdsec.appsec.max_body_size_kb as usize) * 1024;
        if body_size > 0 && self.body_data.len() < max_size {
            let read_size = body_size.min(max_size);
            if let Some(body) = self.get_http_request_body(0, read_size) {
                self.body_data = body;
                log::info!("Buffered {} bytes of body", self.body_data.len());
            }
        }

        // Dispatch AppSec once we have enough data or stream ends
        if self.body_data.len() >= max_size || end_of_stream {
            log::info!("Dispatching AppSec: {} bytes, end_of_stream={}", self.body_data.len(), end_of_stream);
            self.send_appsec_event();
        }

        // Hold body until AppSec decides
        Action::Pause
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // If AppSec check is still in-flight, hold the response.
        // This handles the case where the backend responds to headers alone
        // before AppSec has made a decision.
        if self.appsec_pending {
            log::info!("AppSec pending, pausing response");
            return Action::Pause;
        }
        Action::Continue
    }
}
