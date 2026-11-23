#!/usr/bin/env python3
"""Reject an Envoy config_dump with unprotected TCP proxy/HTTP filter chains.

Usage: python3 tools/check_network_coverage.py < config_dump.json
Accepts either /config_dump JSON or a standalone bootstrap. UDP/QUIC is excluded.
"""

import json
import sys

TERMINAL = {"envoy.filters.network.tcp_proxy", "envoy.filters.network.http_connection_manager"}


def listeners(value):
    if isinstance(value, list):
        for item in value:
            yield from listeners(item)
    elif isinstance(value, dict):
        if "address" in value and ("filter_chains" in value or "default_filter_chain" in value):
            yield value
        else:
            for item in value.values():
                yield from listeners(item)


def wasm_config(filter_config):
    typed = filter_config.get("typed_config", {})
    if "type_url" in typed:
        typed = typed.get("value", {})
    return typed.get("config", {})


def lapi_config(plugin):
    raw = plugin.get("configuration", {}).get("value", {})
    try:
        settings = json.loads(raw) if isinstance(raw, str) else raw
        return settings.get("crowdsec", {}).get("lapi", {})
    except (ValueError, TypeError, AttributeError):
        return {}


def uncovered(config):
    failures = []
    checked = 0
    for listener in listeners(config):
        socket = listener.get("address", {}).get("socket_address", {})
        name = listener.get("name", "")
        if ((name.startswith("envoy-gateway-proxy-stats-") and socket.get("port_value") == 19001)
                or (name.startswith("envoy-gateway-proxy-ready-") and socket.get("port_value") == 19003)):
            # Gateway's own metrics/readiness endpoints are not routed client traffic.
            continue
        if socket.get("protocol", "TCP") == "UDP" or "udp_listener_config" in listener:
            continue
        chains = list(listener.get("filter_chains", []))
        if "default_filter_chain" in listener:
            chains.append(listener["default_filter_chain"])
        for index, chain in enumerate(chains):
            filters = chain.get("filters", [])
            terminal = next((i for i, f in enumerate(filters) if f.get("name") in TERMINAL), None)
            if terminal is None:
                continue
            checked += 1
            protected = False
            for f in filters[:terminal]:
                plugin = wasm_config(f)
                if f.get("name") == "envoy.filters.network.wasm" and plugin.get("root_id") == "crowdsec-network":
                    lapi = lapi_config(plugin)
                    protected = bool(lapi) and lapi.get("enabled", True) is True
                    if protected:
                        break
            if not protected:
                failures.append(f"{listener.get('name', '?')} chain {index}: missing enabled crowdsec-network before terminal filter")
                continue
            manager = filters[terminal].get("typed_config", {})
            if "type_url" in manager:
                manager = manager.get("value", {})
            for http_filter in manager.get("http_filters", []):
                if not http_filter.get("name", "").startswith("envoy.filters.http.wasm"):
                    continue
                http = wasm_config(http_filter)
                http_lapi = lapi_config(http)
                if not http_lapi or not http_lapi.get("enabled", True):
                    continue
                # Empty keys use the same injected CROWDSEC_LAPI_KEY. Explicitly
                # different keys are independent registered bouncers and caches.
                if lapi.get("key", "") != http_lapi.get("key", ""):
                    continue
                if plugin.get("vm_config", {}) != http.get("vm_config", {}):
                    failures.append(f"{listener.get('name', '?')} chain {index}: HTTP/network use the same LAPI key with different VM configuration")
    return checked, failures


def main():
    checked, failures = uncovered(json.load(sys.stdin))
    if not checked:
        failures.append("No TCP HTTP/proxy chains found; inspect the input config_dump")
    print(f"Checked {checked} TCP filter chains")
    for failure in failures:
        print(failure, file=sys.stderr)
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
