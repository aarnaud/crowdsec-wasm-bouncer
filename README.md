# CrowdSec WASM Bouncer

Proxy-WASM filter for CrowdSec integration with LAPI stream and AppSec support.

## Features

- **LAPI Stream**: Periodic decision sync every 10s (configurable)
- **Shared memory**: Decisions stored in proxy shared data (accessible across workers)
- **AppSec**: Async event reporting (non-blocking or blocking) (configurable)
- **IP blocking**: Checks decisions on each request

## Project Structure

- `lib.rs` - Main entry point and exports
- `config.rs` - Configuration structures
- `plugin.rs` - Plugin context and LAPI synchronization logic
- `http.rs` - HTTP request handling and AppSec integration
- `Cargo.toml` - Rust dependencies and build configuration

## Build

```
make build
# or
make docker-build
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
      "key": "your-appsec-key",
      "fail_open": false
    }
  }
}
```

## Deploy

### Envoy Gateway

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: gateway-config
spec:
  filterOrder:
    - name: envoy.filters.http.wasm
      before: envoy.filters.http.ext_authz
    - name: envoy.filters.http.wasm
      before: envoy.filters.http.basic_auth
  bootstrap:
    type: Merge
    value: |
      static_resources:
        clusters:
          - name: crowdsec_lapi
            type: STRICT_DNS
            connect_timeout: 30s             
            load_assignment:
              cluster_name: crowdsec_lapi
              endpoints:
                - lb_endpoints:
                    - endpoint:
                        address:
                          socket_address:
                            address: crowdsec-service.security.svc.cluster.local.
                            port_value: 8080
          - name: crowdsec_appsec
            type: STRICT_DNS
            connect_timeout: 10s             
            load_assignment:
              cluster_name: crowdsec_appsec
              endpoints:
                - lb_endpoints:
                    - endpoint:
                        address:
                          socket_address:
                            address: crowdsec-appsec-service.security.svc.cluster.local.
                            port_value: 7422
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: crowdsec-wasm-bouncer
spec:
  targetSelectors:
    - group: gateway.networking.k8s.io
      kind: Gateway
  wasm:
    - name: wasm-filter
      code:
        type: Image
        image:
          url: ghcr.io/aarnaud/crowdsec-wasm-bouncer:vx.x.x
      failOpen: true
      config:
        crowdsec:
          lapi:
            cluster: crowdsec_lapi
            key: ""your-key"
            sync_freq: 60
          appsec:
            enabled: true
            async_mode: false
            cluster: crowdsec_appsec
            key: "your-appsec-key"
            fail_open: false
            forward_body: true
            max_body_size_kb: 100
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
        fail_open: false
```

## Architecture

- **Plugin context**: Syncs decisions periodically via DispatchHttpCall
- **HTTP context**: Checks IP against shared data on each request
- **AppSec**: Async dispatch (won't block request flow) or sync (will block request flow)
- **Thread-safe**: Uses proxy shared data with CAS operations
