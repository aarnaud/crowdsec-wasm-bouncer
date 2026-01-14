# CrowdSec WASM Bouncer

Proxy-WASM filter for CrowdSec integration with LAPI stream and AppSec support.

## Features

- **LAPI Stream**: Periodic decision sync every 30s (configurable)
- **Per-context bouncer ID**: Each WASM context gets unique bouncer ID
- **Shared memory**: Decisions stored in proxy shared data (accessible across workers)
- **AppSec**: Async event reporting (non-blocking)
- **IP blocking**: Checks decisions on each request

## Build

**Requirements:** TinyGo (for WASM without threading support)

```bash
# Install TinyGo
wget https://github.com/tinygo-org/tinygo/releases/download/v0.33.0/tinygo_0.33.0_amd64.deb
sudo dpkg -i tinygo_0.33.0_amd64.deb

# Build
make build
```

## Configuration

Edit `config.json` or inline in `envoy.yaml`:

```json
{
  "crowdsec": {
    "lapi": {
      "url": "localhost:8080",
      "key": "your-lapi-key",
      "sync_freq": 30
    },
    "appsec": {
      "enabled": true,
      "url": "localhost:7422",
      "key": "your-appsec-key"
    }
  }
}
```

## Deploy

### Envoy

```bash
envoy -c envoy.yaml
```

### Istio

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: crowdsec-bouncer
spec:
  selector:
    matchLabels:
      app: myapp
  url: file:///path/to/main.wasm
  pluginConfig:
    crowdsec:
      lapi:
        url: "crowdsec-lapi:8080"
        key: "your-key"
        sync_freq: 30
      appsec:
        enabled: true
        url: "crowdsec-appsec:7422"
        key: "your-appsec-key"
```

## Architecture

- **Plugin context**: Syncs decisions periodically via DispatchHttpCall
- **HTTP context**: Checks IP against shared data on each request
- **AppSec**: Async dispatch (won't block request flow)
- **Thread-safe**: Uses proxy shared data with CAS operations
