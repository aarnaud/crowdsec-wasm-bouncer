# LAPI enforcement on connections and HTTP requests

The same `plugin.wasm` supports `envoy.filters.network.wasm` and
`envoy.filters.http.wasm`. Attach the network filter before each HTTP connection
manager or TCP proxy. Keep the HTTP filter to run AppSec and to check HTTP clients
identified through trusted proxies, including gRPC and HTTP/3.

There is no `crowdsec.mode` setting. Envoy's `root_id: crowdsec-network` selects
connection callbacks. Other root IDs retain the existing HTTP callbacks. Use
the **same VM identity and bytecode** for network and HTTP attachments using the
same LAPI bouncer key, with different root IDs. This shares the cache, health state,
and sync lease across roots and workers. Separate caches using one bouncer key can
consume each other's incremental updates. Use identical LAPI cluster/key/sync
settings and VM environment variables across these attachments. Separate VM/cache
domains require separate registered bouncer keys.

Network filtering checks source IPs for TCP, TLS passthrough, and terminated TLS,
without decoding application data. TLS passthrough does not require the private
key. Native UDP and QUIC connection filtering are not implemented. HTTP/3 requests
continue through the HTTP filter. This is proxy-level enforcement, not packet or
SYN filtering before Envoy accepts a connection.

## Configuration

Network filter fragment (cluster `crowdsec_lapi` must exist):

```yaml
- name: envoy.filters.network.wasm
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.wasm.v3.Wasm
    config:
      name: crowdsec-network
      root_id: crowdsec-network
      vm_config:
        vm_id: crowdsec
        runtime: envoy.wasm.runtime.v8
        code:
          local:
            filename: /etc/envoy/plugin.wasm
        environment_variables:
          host_env_keys:
            - CROWDSEC_LAPI_KEY
            - CROWDSEC_APPSEC_KEY
      configuration:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: |
          {
            "crowdsec": {
              "lapi": {
                "enabled": true,
                "fail_open": false,
                "cluster": "crowdsec_lapi",
                "sync_freq": 10,
                "max_body_size_kb": 65536
              }
            }
          }
```

Set the HTTP attachment's `vm_id` to `crowdsec` as well; its root ID can stay
`crowdsec`. `appsec` can be omitted on the network attachment. If present, its settings are
ignored there, including its enable flag and credentials. The HTTP attachment
continues to honor `appsec.enabled`, independently of `lapi.enabled`.

`lapi.fail_open` defaults to `false`. This is a change from the previous implicit
allow-until-synchronized behavior. Set it explicitly to `true` where availability
must take precedence during a LAPI outage:

| State | `fail_open: false` | `fail_open: true` |
| --- | --- | --- |
| LAPI disabled | Allow | Allow |
| Valid cached ban, including during outages | Deny | Deny |
| Successful sync, no matching ban | Allow | Allow |
| No initial cache, failed sync, or unavailable client identity | Deny new traffic | Allow new traffic |

HTTP bans return 403; unavailable fail-closed LAPI checks return 503. Network denies
close the connection. AppSec's failure policy cannot override a LAPI denial.
Synchronization remains asynchronous in either case; requests do not call LAPI.
A failed sync preserves cached bans and requires a full snapshot on recovery,
including after a failed incremental response that LAPI may have already consumed.
The snapshot also removes decisions absent from LAPI, so a missed deletion does
not leave an address blocked until its previous TTL expires.

Existing connections are rechecked after decision updates, including idle TCP
connections. The root checks other workers' published updates on a one-second
timer. New bans reset matching HTTP/gRPC streams, without disconnecting unrelated
clients on a shared trusted-proxy connection. A sync failure alone does not tear
down established traffic. Expired decisions cease matching according to their TTL.

Envoy's async response buffer is independent of `max_body_size_kb`. For a 64 MiB
buffer, append this layer to the bootstrap `layered_runtime.layers` array:

```yaml
- name: crowdsec-response-buffer
  static_layer:
    http.async_response_buffer_limit: 67108864
```

This branch starts from upstream and intentionally does not add the fork's outbound
Host-header feature or Rust toolchain changes. Preserve those separately when
integrating into a build that talks to a hostname-routed remote LAPI.

## Envoy Gateway

An `EnvoyExtensionPolicy` installs the HTTP filter. Install the network filter
through an additional `EnvoyPatchPolicy` on TCP Listener resources; match its VM
identity to the HTTP filter's generated VM ID (inspect xDS). Do not attach
it to the QUIC listener. Apply this policy after existing patches which assume
the HTTP connection manager is the first network filter (for example, priority
1000 after default-priority policies).

For each actual Listener resource name, insert before every TCP proxy or HTTP
connection manager, including default filter chains:

```yaml
operation:
  op: add
  jsonPath: "$..filters[?(@.name == 'envoy.filters.network.tcp_proxy' || @.name == 'envoy.filters.network.http_connection_manager')]"
  value:
    # The complete network filter configuration above
    name: envoy.filters.network.wasm
    typed_config: {}
```

Replace the abbreviated `value` with the complete filter fragment. xDS Listener
names differ across Envoy Gateway naming schemes; inspect the generated xDS,
rather than assuming a Gateway listener's name is the xDS resource name.

After rendering, check all TCP filter chains from the Envoy admin config dump:

```bash
python3 tools/check_network_coverage.py < config_dump.json
```

Envoy Gateway's built-in readiness and metrics listeners are excluded from the
external traffic check. The checker rejects unprotected added listeners, missing default chains, disabled
network LAPI, filters inserted after their terminal proxy, and combined HTTP/network
attachments that reuse a bouncer key with different VM configurations. Run it whenever
listeners or Envoy Gateway versions change.

## Tests

```bash
cargo test --locked
cargo clippy --all-targets -- -D warnings
make build
python3 -m pip install h2
make network-integration-test
python3 -m unittest discover -s tests -p 'test_*.py'
```

The network integration suite runs a local Envoy container with two workers and
isolated fake LAPI, AppSec, HTTP/gRPC, and TCP/TLS backends. It needs Docker or
Podman and OpenSSL; it never connects to a real LAPI. Set `CONTAINER_ENGINE` or
`ENVOY_IMAGE` to select the runtime or test another supported Envoy release.
