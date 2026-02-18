.PHONY: build clean install-deps

# Default target
build: crowdsec_wasm_bouncer.wasm

# Install required Rust targets and tools
install-deps:
	rustup target add wasm32-wasip1

# Build the WASM module
crowdsec_wasm_bouncer.wasm: Cargo.toml src/lib.rs src/config.rs src/plugin.rs src/http.rs
	cargo build --target wasm32-wasip1 --release

# Clean build artifacts
clean:
	cargo clean
# Run tests
test:
	cargo test

# Check code formatting
fmt:
	cargo fmt --check

# Run clippy linting
clippy:
	cargo clippy -- -D warnings

docker-build:
	docker build -t crowdsec-wasm-bouncer:latest .

extract-wasm:
	docker create --name wasm-extract crowdsec-wasm-bouncer:latest
	docker cp wasm-extract:/plugin.wasm ./plugin.wasm
	docker rm wasm-extract

# Integration tests
integration-test: crowdsec_wasm_bouncer.wasm
	cd tests && docker compose up -d --wait --force-recreate
	@sleep 5
	cd tests && bash run_tests.sh; ret=$$?; docker compose logs envoy crowdsec > test-output.log 2>&1; exit $$ret

integration-test-down:
	cd tests && docker compose down -v
