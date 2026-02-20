use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::Duration;

use crate::config::Config;
use crate::http::CrowdSecHttpContext;
use crate::DecisionsResponse;

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
        if let Some(data) = lock_data {
            if !data.is_empty() {
                log::debug!("Sync already in progress, skipping");
                return;
            }
        }

        // Try to set lock with CAS - only one thread will succeed
        if self
            .set_shared_data(sync_lock_key, Some(&b"locked"[..]), cas)
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

        if status == 503 {
            log::error!("failed to call lapi decision endpoint");
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

        // Update shared data
        for d in &new {
            let key = format!("{}:{}", d.scope.to_lowercase(), d.value);
            let value = format!("{}_{}", d.decision_type, d.scenario);
            let _ = self.set_shared_data(&key, Some(value.as_bytes()), None);
        }

        for d in &deleted {
            let key = format!("{}:{}", d.scope.to_lowercase(), d.value);
            let _ = self.set_shared_data(&key, None, None);
        }

        log::info!(
            "Synced decisions: +{} new, -{} deleted",
            new.len(),
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
                        log::warn!(
                            "CrowdSec Plugin loading:\n\
                            \tLAPI cluster: {}\n\
                            \tLAPI enabled: {}\n\
                            \tLAPI sync_freq: {}\n\
                            \tAppSec cluster: {}\n\
                            \tAppsec enabled: {}\n\
                            \tAppsec FailOpen: {}\n\
                            \tAppsec ForwardBody: {}\n\
                            \tAppsec MaxBodySizeKB: {}\n",
                            config.crowdsec.lapi.cluster,
                            config.crowdsec.lapi.enabled,
                            config.crowdsec.lapi.sync_freq,
                            config.crowdsec.appsec.cluster,
                            config.crowdsec.appsec.enabled,
                            config.crowdsec.appsec.fail_open,
                            config.crowdsec.appsec.forward_body,
                            config.crowdsec.appsec.max_body_size_kb,
                        );

                        // Schedule periodic sync
                        let sync_millis = config.crowdsec.lapi.sync_freq * 1000;
                        self.set_tick_period(Duration::from_millis(sync_millis as u64));

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
