# Stage 1: Build the WASM plugin
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go plugin.go http.go ./

# Build WASM with same flags as Makefile
RUN GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm main.go plugin.go http.go

# Stage 2: Create minimal image with only the WASM file
FROM scratch

COPY --from=builder /build/plugin.wasm /plugin.wasm
