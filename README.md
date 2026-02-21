# CrowdSec WASM Bouncer

Proxy-WASM filter for CrowdSec integration with LAPI stream and AppSec support.

## Features

- **LAPI Stream**: Periodic decision sync every 10s (configurable)
- **Shared memory**: Decisions stored in proxy shared data (accessible across workers)
- **AppSec**: Async/Sync event reporting (non-blocking or blocking) (configurable)
- **IP blocking**: Checks decisions on each request (configurable)

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
        "enabled": true,
        "cluster": "crowdsec_lapi",
        "sync_freq": 10
      },
      "appsec": {
        "enabled": true,
        "async_mode": false,
        "cluster": "crowdsec_appsec",
        "forward_body": true,
        "max_body_size_kb": 8
      }
    }
}
```

## Deploy

### Envoy 

Exemple here [envoy.yaml](tests/envoy.yaml)

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
                            address: crowdsec-service.crowdsec.svc.cluster.local.
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
                            address: crowdsec-appsec-service.crowdsec.svc.cluster.local.
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
      failOpen: false
      env:
        hostKeys:
          - CROWDSEC_LAPI_KEY
          - CROWDSEC_APPSEC_KEY
      config:
        crowdsec:
          lapi:
            enabled: true
            cluster: crowdsec_lapi
            #key: "YOUR_KEY_IF_NOT_IN_ENV"
            sync_freq: 10
          appsec:
            enabled: true
            cluster: crowdsec_appsec
            #key: "YOUR_KEY_IF_NOT_IN_ENV"
            async_mode: false
            fail_open: false
            forward_body: true
            max_body_size_kb: 8
```

### Istio

```yaml
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: crowdsec-lapi
spec:
  hosts:
    - crowdsec-lapi.internal
  ports:
    - number: 8080
      name: http
      protocol: HTTP
  resolution: DNS
  location: MESH_INTERNAL
  endpoints:
    - address: crowdsec-service.crowdsec.svc.cluster.local
      ports:
        http: 8080
---
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: crowdsec-appsec
spec:
  hosts:
    - crowdsec-appsec.internal
  ports:
    - number: 7422
      name: http
      protocol: HTTP
  resolution: DNS
  location: MESH_INTERNAL
  endpoints:
    - address: crowdsec-appsec-service.crowdsec.svc.cluster.local
      ports:
        http: 7422
---
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: crowdsec
spec:
  targetRefs:
    - kind: Gateway
      group: gateway.networking.k8s.io
      name: yourgateway
  url: oci://ghcr.io/aarnaud/crowdsec-wasm-bouncer:vx.x.x
  imagePullPolicy: IfNotPresent
  phase: AUTHN
  pluginConfig:
    crowdsec:
      lapi:
        enabled: false
        cluster: "inbound-vip|8080|http|crowdsec-lapi.internal"
        #key: "YOUR_KEY_IF_NOT_IN_ENV"
        sync_freq: 10
      appsec:
        enabled: true
        cluster: "inbound-vip|7422|http|crowdsec-appsec.internal"
        #key: "YOUR_KEY_IF_NOT_IN_ENV"
        async_mode: false
        fail_open: false
        forward_body: true
        max_body_size_kb: 8
```

## Architecture

- **Plugin context**: Syncs decisions periodically via DispatchHttpCall
- **HTTP context**: Checks IP against shared data on each request
- **AppSec**: Async dispatch (won't block request flow) or sync (will block request flow)
- **Thread-safe**: Uses proxy shared data with CAS operations
