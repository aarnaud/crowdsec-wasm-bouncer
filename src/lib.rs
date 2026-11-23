use proxy_wasm::traits::*;
use proxy_wasm::types::*;

mod config;
mod http;
mod network;
mod plugin;

use plugin::CrowdSecPlugin;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|context_id| -> Box<dyn RootContext> {
        Box::new(CrowdSecPlugin::new(context_id))
    });
}}
