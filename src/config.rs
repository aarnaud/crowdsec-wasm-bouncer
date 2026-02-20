use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub crowdsec: CrowdSecConfig,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CrowdSecConfig {
    pub lapi: LAPIConfig,
    pub appsec: AppSecConfig,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LAPIConfig {
    pub cluster: String,
    #[serde(default)]
    pub key: String,
    #[serde(default = "default_sync_freq")]
    pub sync_freq: u32, // seconds, default 10
    #[serde(default = "default_true")]
    pub enabled: bool,
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
    pub key: String,
    #[serde(default)]
    pub fail_open: bool,
    #[serde(default)]
    pub forward_body: bool,
    #[serde(default = "default_max_body_size_kb")]
    pub max_body_size_kb: u32, // Default: 100KB
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
