# AGENTS.md — crowdsec-wasm-bouncer

## Project Overview

Rust Proxy-WASM filter for Envoy that integrates with CrowdSec for IP blocking and
web application firewall (WAF) via AppSec. Compiled to `wasm32-wasip1`. Uses the
`proxy-wasm` SDK (callback-based async model, not Rust async/await).

Source layout (4 files in `src/`):
- `lib.rs` — crate root, module declarations, proxy-wasm entry point
- `config.rs` — serde config structs and default functions
- `plugin.rs` — `RootContext` impl: LAPI decision sync on tick timer
- `http.rs` — `HttpContext` impl: per-request IP check + AppSec dispatch

## Build / Lint / Test Commands

```bash
# Install the WASM target (one-time setup)
make install-deps          # rustup target add wasm32-wasip1

# Build the WASM module (release, optimised for size)
make build                 # cargo build --target wasm32-wasip1 --release

# Run unit tests
make test                  # cargo test

# Run a single test by name
cargo test <test_name>     # e.g. cargo test test_config_defaults

# Run tests matching a pattern with output
cargo test <pattern> -- --nocapture

# Check formatting (no auto-fix)
make fmt                   # cargo fmt --check

# Auto-fix formatting
cargo fmt

# Lint with clippy (warnings are errors)
make clippy                # cargo clippy -- -D warnings

# Integration tests (requires Docker)
make integration-test      # builds WASM, starts docker-compose, runs tests/run_tests.sh
make docker-down # tears down containers

# Docker
make docker-build          # builds image crowdsec-wasm-bouncer:latest
make extract-wasm          # copies plugin.wasm out of the Docker image

# Clean
make clean                 # cargo clean
```

## Dependencies

| Crate        | Version | Purpose                                  |
|-------------|---------|------------------------------------------|
| proxy-wasm  | 0.2     | Proxy-WASM ABI for Envoy/Istio filters   |
| serde       | 1.0     | Serialization (with `derive` feature)     |
| serde_json  | 1.0     | JSON parsing                              |
| log         | 0.4     | Logging facade (proxy-wasm provides sink) |

No `anyhow`, `thiserror`, `tokio`, or `tracing` — keep it that way. The proxy-wasm
runtime provides the async model and logging sink.

## Code Style Guidelines

### Formatting

Standard `rustfmt` defaults (no `rustfmt.toml`). Run `cargo fmt` before committing.
Clippy with `-D warnings` — all warnings must be fixed, not suppressed.

### Import Ordering

Three groups separated by blank lines:

```rust
// 1. proxy-wasm glob imports (always first, always glob)
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// 2. External crates — specific imports, no globs
use serde::Deserialize;
use std::time::Duration;

// 3. Local crate imports
use crate::config::Config;
use crate::http::CrowdSecHttpContext;
```

- proxy-wasm traits/types always use `*` glob imports.
- All other crates use specific imports (not glob).
- Do NOT merge imports with `use proxy_wasm::{traits::*, types::*};` — keep separate lines.
- `mod` declarations in `lib.rs` go between groups 1 and 3.

### Naming Conventions

| Item            | Convention       | Examples                                    |
|----------------|-----------------|---------------------------------------------|
| Structs/Enums  | `CamelCase`      | `CrowdSecPlugin`, `CrowdSecHttpContext`     |
| Acronyms       | Keep uppercase   | `LAPIConfig`, `AppSecConfig`                |
| Functions      | `snake_case`     | `sync_decisions`, `send_appsec_event`       |
| Fields/Vars    | `snake_case`     | `sync_freq`, `body_data`, `fail_open`       |
| Modules        | `snake_case`     | `config`, `plugin`, `http`                  |
| Constants      | `SCREAMING_SNAKE`| (none yet, follow this if adding)           |

### Type Annotations

- Rely on type inference. Only annotate when the compiler needs help:
  - `let resp: DecisionsResponse = match serde_json::from_slice(&body) { ... };`
  - `.parse::<u32>()`
  - `serde_json::from_slice::<Config>(&bytes)`

### Error Handling

The proxy-wasm trait methods have fixed signatures (`-> Action`, `-> bool`, `-> ()`).
The `?` operator is never used. Follow these patterns:

```rust
// Pattern 1: match + log + early return (primary pattern)
let config = match &self.config {
    Some(c) => c,
    None => return,
};

// Pattern 2: match + log::error! + return on Err
let resp: Type = match fallible_call() {
    Ok(r) => r,
    Err(e) => {
        log::error!("failed to do thing: {:?}", e);
        return;
    }
};

// Pattern 3: Discard Result explicitly
let _ = self.set_shared_data(&key, Some(value.as_bytes()), None);

// Pattern 4: unwrap_or_default / unwrap_or_else for optional values
let path = self.get_http_request_header(":path").unwrap_or_default();
```

### Logging

Use the `log` crate (`log::error!`, `log::warn!`, `log::info!`, `log::debug!`).

| Level   | Use for                                  | Message casing |
|---------|------------------------------------------|----------------|
| `error` | Parse/dispatch failures                  | lowercase      |
| `warn`  | Blocked requests, config dumps at start  | Uppercase      |
| `info`  | Normal operations (sync, request info)   | Uppercase      |
| `debug` | Lock contention, skipped operations      | Uppercase      |

Use `{:?}` (Debug) for error values. Use `{}` (Display) for strings/numbers.

### Serde / Serialization

- Derive `Serialize, Deserialize, Clone` on config structs.
- Derive only `Deserialize` on internal response structs.
- Use `#[serde(default)]` or `#[serde(default = "fn_name")]` liberally for optional fields.
- Use `#[serde(rename = "...")]` when JSON keys conflict with Rust keywords.
- Default value functions are private module-level fns: `fn default_sync_freq() -> u32 { 10 }`.
- Deserialize from bytes with `serde_json::from_slice`, not `from_str`.

### Visibility

- Modules are private (`mod config;` not `pub mod config;`).
- Mark structs/constructors `pub` only when used cross-module.
- Keep helper functions private by default.

### Comments

- Use `//` inline comments sparingly — explain *why*, not *what*.
- Comments go on the line above the code, not trailing (except short field annotations).
- Doc comments (`///`) only for non-obvious public API surfaces.
- Sentence case (capitalize first word), no trailing period.

### Async Model

This is proxy-wasm callback-based, NOT Rust async/await:
- Dispatch outbound calls with `self.dispatch_http_call(...)`.
- Handle responses in `on_http_call_response(...)` callback.
- Pause requests with `Action::Pause`, resume with `self.resume_http_request()`.
- Track state manually via struct fields (`appsec_pending`, `appsec_done`, etc.).
- Shared data with CAS (compare-and-swap) for cross-thread coordination.

### Struct Conventions

- All struct fields use owned types (`String`, `Vec<u8>`, `bool`, `u32`).
- No references or lifetime annotations — keep it that way for WASM compat.
- Use `#[derive(...)]` on the line directly above `struct`.

### Module Organization

Keep the flat 4-file structure. One module per proxy-wasm context type.
If adding new functionality, prefer extending existing modules over adding new ones
unless the concern is clearly distinct.
