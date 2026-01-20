# CrowdSec WASM Bouncer

Proxy-WASM filter for CrowdSec integration with LAPI stream and AppSec support.

## Features

- **LAPI Stream**: Periodic decision sync every 10s (configurable)
- **Shared memory**: Decisions stored in proxy shared data (accessible across workers)
- **AppSec**: Async event reporting (non-blocking or blocking) (configurable)
- **IP blocking**: Checks decisions on each request

## Build

**Requirements:** Go 1.24 (for WASM)

# Build
make build
```

## Configuration

Edit `config.json` or inline in `envoy.yaml`:

```json
{
  "crowdsec": {
    "lapi": {
      "cluster": "crowdsec_lapi",
      "key": "your-lapi-key",
      "sync_freq": 30
    },
    "appsec": {
      "enabled": true,
      "async_mode": false,
      "cluster": "crowdsec_appsec",
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
        cluster: "crowdsec_lapi"
        key: "your-key"
        sync_freq: 30
      appsec:
        enabled: true
        async_mode: false
        cluster: "crowdsec_appsec"
        key: "your-appsec-key"
```

## Architecture

- **Plugin context**: Syncs decisions periodically via DispatchHttpCall
- **HTTP context**: Checks IP against shared data on each request
- **AppSec**: Async dispatch (won't block request flow) or sync (will block request flow)
- **Thread-safe**: Uses proxy shared data with CAS operations
