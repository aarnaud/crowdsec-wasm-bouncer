use proxy_wasm::traits::*;
use proxy_wasm::types::*;

mod config;
mod http;
mod plugin;

use plugin::CrowdSecPlugin;

extern "C" fn initialize_plugin() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(CrowdSecPlugin::new()) });
}

// WASI's reactor entry point calls constructors before the first Proxy-WASM callback
#[cfg(target_os = "wasi")]
#[used]
#[link_section = ".init_array"]
static INITIALIZE_PLUGIN: extern "C" fn() = initialize_plugin;

#[cfg(not(target_os = "wasi"))]
proxy_wasm::main! {{ initialize_plugin(); }}
