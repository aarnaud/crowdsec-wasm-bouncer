use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub crowdsec: CrowdSecConfig,
}

impl Config {
    pub fn apply_environment(&mut self, mut get_var: impl FnMut(&str) -> Option<String>) {
        for (value, name) in [
            (&mut self.crowdsec.lapi.key, "CROWDSEC_LAPI_KEY"),
            (&mut self.crowdsec.appsec.key, "CROWDSEC_APPSEC_KEY"),
            (&mut self.crowdsec.lapi.host, "CROWDSEC_LAPI_HOST"),
            (&mut self.crowdsec.appsec.host, "CROWDSEC_APPSEC_HOST"),
        ] {
            if value.is_empty() {
                if let Some(fallback) = get_var(name) {
                    *value = fallback;
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CrowdSecConfig {
    pub lapi: LAPIConfig,
    pub appsec: AppSecConfig,
    // IPs/CIDRs (IPv4 or IPv6 exact) of trusted reverse proxies.
    // When the connecting address matches, the leftmost IP in X-Forwarded-For is used
    // as the real client IP. Leave empty to always use the direct connection address.
    #[serde(default)]
    pub trusted_ips: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LAPIConfig {
    pub cluster: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub key: String,
    #[serde(default = "default_sync_freq")]
    pub sync_freq: u32, // seconds, default 10
    #[serde(default = "default_true")]
    pub enabled: bool,
    // Cap on the decisions-stream body read per sync. Bounds VM memory against a huge
    // blocklist: the raw body and the parsed decisions are both live at once, so peak
    // usage is roughly twice this. Raising it needs headroom in the WASM VM.
    #[serde(default = "default_max_lapi_body_size_kb")]
    pub max_body_size_kb: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AppSecConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub async_mode: bool,
    #[serde(default)]
    pub cluster: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub fail_open: bool,
    #[serde(default)]
    pub forward_body: bool,
    #[serde(default = "default_max_body_size_kb")]
    pub max_body_size_kb: u32,
    // Cap on the AppSec 403-response body (challenge/ban envelope) read per call.
    // Bot-detection challenge pages embed a PoW/fingerprint script and can run to
    // several hundred KiB; too low a value falls back to a classic flat block.
    #[serde(default = "default_max_response_body_size_kb")]
    pub max_response_body_size_kb: u32,
}

fn default_sync_freq() -> u32 {
    10
}

fn default_true() -> bool {
    true
}

fn default_max_body_size_kb() -> u32 {
    8
}

fn default_max_lapi_body_size_kb() -> u32 {
    32 * 1024
}

fn default_max_response_body_size_kb() -> u32 {
    1024
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn config() -> Config {
        serde_json::from_slice(br#"{"crowdsec":{"lapi":{"cluster":"lapi"},"appsec":{}}}"#).unwrap()
    }

    #[test]
    fn test_host_deserialization() {
        let defaults = config();
        assert!(defaults.crowdsec.lapi.host.is_empty());
        assert!(defaults.crowdsec.appsec.host.is_empty());

        for host in ["", "crowdsec.example.com", "crowdsec.example.com:8443"] {
            let json = serde_json::json!({
                "crowdsec": {
                    "lapi": {"cluster": "lapi", "host": host},
                    "appsec": {"host": host}
                }
            });
            let config: Config =
                serde_json::from_slice(&serde_json::to_vec(&json).unwrap()).unwrap();
            assert_eq!(config.crowdsec.lapi.host, host);
            assert_eq!(config.crowdsec.appsec.host, host);
        }
    }

    #[test]
    fn test_environment_fallbacks() {
        let mut config = config();
        config.apply_environment(|name| {
            Some(
                match name {
                    "CROWDSEC_LAPI_HOST" => "lapi.example.com:8443",
                    "CROWDSEC_APPSEC_HOST" => "appsec.example.com",
                    "CROWDSEC_LAPI_KEY" => "lapi-key",
                    "CROWDSEC_APPSEC_KEY" => "appsec-key",
                    _ => panic!("unexpected environment variable: {name}"),
                }
                .to_string(),
            )
        });
        assert_eq!(config.crowdsec.lapi.host, "lapi.example.com:8443");
        assert_eq!(config.crowdsec.appsec.host, "appsec.example.com");
        assert_eq!(config.crowdsec.lapi.key, "lapi-key");
        assert_eq!(config.crowdsec.appsec.key, "appsec-key");

        config.apply_environment(|name| panic!("explicit config must win over {name}"));
        assert_eq!(config.crowdsec.lapi.host, "lapi.example.com:8443");
        assert_eq!(config.crowdsec.appsec.host, "appsec.example.com");
    }

    #[test]
    fn test_host_environment_fallbacks_are_independent() {
        for name in ["CROWDSEC_LAPI_HOST", "CROWDSEC_APPSEC_HOST"] {
            let mut config = config();
            config.apply_environment(|key| (key == name).then(|| "proxy.example.com".to_string()));
            assert_eq!(
                config.crowdsec.lapi.host,
                if name == "CROWDSEC_LAPI_HOST" {
                    "proxy.example.com"
                } else {
                    ""
                }
            );
            assert_eq!(
                config.crowdsec.appsec.host,
                if name == "CROWDSEC_APPSEC_HOST" {
                    "proxy.example.com"
                } else {
                    ""
                }
            );
        }
    }

    #[test]
    fn test_missing_or_empty_environment_preserves_host_defaults() {
        let mut config = config();
        config.apply_environment(|_| None);
        assert!(config.crowdsec.lapi.host.is_empty());
        assert!(config.crowdsec.appsec.host.is_empty());
        config.apply_environment(|_| Some(String::new()));
        assert!(config.crowdsec.lapi.host.is_empty());
        assert!(config.crowdsec.appsec.host.is_empty());
    }
}
