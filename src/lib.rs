use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};

mod config;
mod plugin;
mod http;

use plugin::CrowdSecPlugin;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(CrowdSecPlugin::new())
    });
}}

#[derive(Serialize, Deserialize)]
pub struct DecisionsResponse {
    #[serde(default)]
    pub new: Option<Vec<Decision>>,
    #[serde(default)]
    pub deleted: Option<Vec<Decision>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Decision {
    pub id: i64,
    pub origin: String,
    #[serde(rename = "type")]
    pub decision_type: String,
    pub scope: String,
    pub value: String,
    pub duration: String,
    pub scenario: String,
}
