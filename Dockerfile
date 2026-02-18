# Stage 1: Build the Rust WASM plugin
FROM rust:1.93-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

# Install wasm32-wasip1 target
RUN rustup target add wasm32-wasip1

# Copy Cargo files
COPY Cargo.toml ./

# Copy source code
COPY src/ ./src/

# Build WASM plugin
RUN cargo build --target wasm32-wasip1 --release

# Stage 2: Create minimal image with only the WASM file
FROM scratch

COPY --from=builder /build/target/wasm32-wasip1/release/crowdsec_wasm_bouncer.wasm /plugin.wasm
