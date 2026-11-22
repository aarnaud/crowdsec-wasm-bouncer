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

### Challenge responses

When AppSec returns a bot-detection challenge, its status code is clamped to the 100-599
range and its headers are restricted to an allowlist (content-type, CSP, cache-control,
set-cookie and similar). AppSec is a semi-trusted network peer and `send_http_response`
relays whatever it is handed, so arbitrary header names and out-of-range statuses are not
passed through to the client.

The challenge page's CSP is patched to add `'unsafe-eval'`, which CrowdSec's shipped
challenge script needs and its own CSP omits. When the policy has no `script-src`, a
`script-src` is derived from `default-src` rather than adding `'unsafe-eval'` to
`default-src` itself, so directives that inherit from it (images, styles, connect,
frames) are not widened along with scripts.

### Configuration is validated at load

The filter refuses to load rather than starting in a state that cannot work: an enabled
feature with no cluster or no API key, `lapi.sync_freq: 0` (which disables the sync tick
outright), or `forward_body: true` with `max_body_size_kb: 0`. Left to run, these fail
every dispatch, which means either a total outage under `fail_open: false` or a silently
disabled WAF under `fail_open: true` — both discovered in production instead of at deploy
time. Check the proxy log on startup if the filter does not come up.

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

Requires Rust 1.100 or newer. `rust-toolchain.toml` selects stable Rust with the
`wasm32-wasip1` target, rustfmt, and Clippy. The Docker builder uses Rust 1.100.

The WASI runtime provides `_initialize`; filter registration runs through a WASI
constructor. This avoids the duplicate `_initialize` symbol produced by combining
Rust 1.100's reactor startup with `proxy_wasm::main!`.

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
        "host": "",
        "sync_freq": 10
      },
      "appsec": {
        "enabled": true,
        "async_mode": false,
        "cluster": "crowdsec_appsec",
        "host": "",
        "forward_body": true,
        "max_body_size_kb": 8
      },
      "trusted_ips": []
    }
}
```

### Outbound hosts and environment variables

Set `crowdsec.lapi.host` and `crowdsec.appsec.host` when a reverse proxy requires a
particular HTTP Host header (`:authority`). Use a hostname, optionally with a port,
such as `lapi.example.com` or `appsec.example.com:8443`, without a URL scheme or path.
The Envoy cluster still determines the destination address and port.

| JSON field | Environment fallback | Default when both are unset or empty |
|------------|----------------------|--------------------------------------|
| `crowdsec.lapi.host` | `CROWDSEC_LAPI_HOST` | Empty authority |
| `crowdsec.appsec.host` | `CROWDSEC_APPSEC_HOST` | Original client request's authority |

A nonempty JSON value takes precedence over the environment variable, matching the
existing `key` fields and their `CROWDSEC_LAPI_KEY` / `CROWDSEC_APPSEC_KEY` fallbacks.
Environment variables are read when the filter configuration loads and must be exposed
to the WASM VM; setting them only on the Envoy process is insufficient. For example:

```yaml
# Under the WASM filter's vm_config
environment_variables:
  host_env_keys:
    - CROWDSEC_LAPI_KEY
    - CROWDSEC_APPSEC_KEY
    - CROWDSEC_LAPI_HOST
    - CROWDSEC_APPSEC_HOST
```

The AppSec host setting changes the destination authority only.
`X-Crowdsec-Appsec-Host` continues to contain the original client request's host so
AppSec evaluates the correct site.

For an HTTPS reverse proxy, also configure TLS on the corresponding Envoy cluster.
The HTTP host fields do not configure TLS SNI. For example, a cluster connecting to
`lapi.example.com` on port 443 can use:

```yaml
# Under the crowdsec_lapi cluster
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
    sni: lapi.example.com
    common_tls_context:
      validation_context:
        trusted_ca:
          filename: /etc/ssl/certs/ca-certificates.crt
        match_typed_subject_alt_names:
          - san_type: DNS
            matcher:
              exact: lapi.example.com
```

Set `crowdsec.lapi.host` (or `CROWDSEC_LAPI_HOST`) to `lapi.example.com` for HTTP
routing, and use the CA bundle path available in your Envoy container. Configure the
AppSec cluster similarly when it uses HTTPS. See Envoy's
[upstream TLS configuration](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto).

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
          - CROWDSEC_LAPI_HOST
          - CROWDSEC_APPSEC_HOST
      config:
        crowdsec:
          lapi:
            enabled: true
            cluster: crowdsec_lapi
            #key: "YOUR_KEY_IF_NOT_IN_ENV"
            #host: "lapi.example.com" # Or CROWDSEC_LAPI_HOST
            sync_freq: 10
          appsec:
            enabled: true
            cluster: crowdsec_appsec
            #key: "YOUR_KEY_IF_NOT_IN_ENV"
            #host: "appsec.example.com" # Or CROWDSEC_APPSEC_HOST
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
