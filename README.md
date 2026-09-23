# CrowdSec WASM Bouncer

Proxy-WASM filter for CrowdSec integration with LAPI stream and AppSec support.

## Features

- **LAPI Stream**: Periodic decision sync every 10s (configurable)
- **Shared memory**: Decisions stored in proxy shared data (accessible across workers)
- **AppSec**: Async/Sync event reporting (non-blocking or blocking) (configurable)
- **IP blocking**: Checks decisions on each request (configurable)

## Security Model and Limitations

Read this before relying on the filter as a preventive control.

### Request bodies are inspected, but a block stops the response — not the request

For a request whose body is streamed (essentially every HTTP/1.1 chunked and HTTP/2
request body), the filter forwards headers and body chunks upstream while the AppSec
call is in flight, and blocks by suppressing the **response**. The origin has therefore
already received and processed the request by the time a 403 is returned.

This is deliberate. Proxy-WASM exposes no backpressure to the downstream connection, so
pausing a request mid-upload just accumulates data in Envoy's connection buffer until it
exceeds `per_connection_buffer_limit_bytes` and the client gets a 413.

**Do not assume a 403 means the origin never saw the request.** Requests with side
effects (writes, uploads, anything non-idempotent) still reach the backend. Requests
whose body arrives with the headers, and all header-only checks, are blocked before the
request is forwarded.

### Body inspection is capped

Only the first `max_body_size_kb` of a body is sent to AppSec — a deliberate DoS control,
since every in-flight request holds its buffer in the WASM VM's linear memory. Content
past the cap is not inspected. Budget for `max_body_size_kb x peak concurrency` of VM
memory when raising it.

Bodies whose bytes look genuinely binary (NUL bytes or a high proportion of control
characters) are not forwarded, to avoid false-positive bans on legitimate uploads. The
declared `Content-Type` is only a hint: a text payload sent as `application/octet-stream`
is still inspected, because that header is attacker-controlled.

### Client IP resolution

By default the direct connection address is used. `trusted_ips` (IPv4/IPv6 addresses or
CIDRs) lists reverse proxies permitted to supply `X-Forwarded-For`. When the direct peer
matches, the header is walked **right to left**, skipping hops that are themselves in
`trusted_ips`, and the first untrusted hop is taken as the client.

The leftmost entry is never used: it is whatever the client sent, so trusting it would
let any client behind a trusted proxy pick its own IP and bypass both the LAPI blocklist
and AppSec's IP-scoped rules. Set `trusted_ips` to your proxies only, never `0.0.0.0/0`.

If the source address cannot be resolved at all, the request is failed according to
`appsec.fail_open` rather than continuing with an empty identity.

### What reaches AppSec

The client's request headers are relayed alongside the `X-Crowdsec-Appsec-*` metadata, so
rules matching on `Referer`, `Origin`, `Cookie` or custom headers work. Client-supplied
`X-Crowdsec-Appsec-*` headers are stripped before relaying — otherwise a client could
override the API key, IP, URI or verb the WAF evaluates. Framing and hop-by-hop headers
are dropped. The relayed set is capped at 8 KiB.

### Decisions

`Ip` and `Range` scoped `ban` decisions are enforced. Other scopes (`Country`, `AS`) and
other decision types (including `captcha`) are synced-but-ignored rather than treated as
hard blocks, and are logged when seen. Range decisions are capped at 4096 per address
family.

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
      },
      "trusted_ips": []
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
          # Reverse proxies allowed to supply X-Forwarded-For. Your proxies only.
          trusted_ips: []
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
      # Reverse proxies allowed to supply X-Forwarded-For. Your proxies only.
      trusted_ips: []
```

## Architecture

- **Plugin context**: Syncs decisions periodically via DispatchHttpCall
- **HTTP context**: Checks IP against shared data on each request
- **AppSec**: Async dispatch (won't block request flow) or sync (will block request flow)
- **Thread-safe**: Uses proxy shared data with CAS operations
