#!/usr/bin/env python3
"""Real Envoy network/HTTP integration tests. Requires h2 and Docker or Podman.

Build the WASM first, then run: python3 tests/network_integration.py
All services and certificates are local test fixtures; no live LAPI is contacted.
"""

import copy
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

import h2.config
import h2.connection
import h2.events


class State:
    def __init__(self):
        self.mode = "error"
        self.appsec_mode = "allow"
        self.decisions = {}
        self.deleted = []
        self.appsec_calls = 0
        self.syncs = 0
        self.revision = 0
        self.seen = {}
        self.startups = {}
        self.lock = threading.Lock()

    def ban(self, value, seconds=60, scope="Ip"):
        with self.lock:
            self.revision += 1
            self.decisions[value] = (time.time() + seconds, scope, self.revision)

    def clear(self):
        with self.lock:
            for value, (_, scope, _) in self.decisions.items():
                self.revision += 1
                self.deleted.append((self.revision, {
                    "value": value, "scope": scope, "type": "ban", "scenario": "test", "duration": "0s"}))
            self.decisions.clear()


STATE = State()


class API(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            # Buffer-limit tests intentionally reset keep-alive connections
            pass

    def log_message(self, *_args):
        pass

    def reply(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("content-length", str(len(body)))
        self.send_header("content-type", content_type)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if not self.path.startswith("/v1/decisions/stream"):
            self.reply(200, b"backend")
            return
        with STATE.lock:
            STATE.syncs += 1
            mode = STATE.mode
            key = self.headers.get("X-Api-Key")
            startup = "startup=true" in self.path
            since = self.seen_revision(key, startup)
            if mode == "healthy" and startup:
                STATE.startups[key] = STATE.startups.get(key, 0) + 1
            # A successful response consumes this bouncer key's delta stream.
            # Distinct caches with the same key would lose each other's updates.
            STATE.seen[key] = STATE.revision
            payload = {
                "new": [
                    {"value": value, "scope": scope, "type": "ban", "scenario": "test",
                     "duration": f"{max(0, until-time.time()):.3f}s"}
                    for value, (until, scope, revision) in STATE.decisions.items()
                    if until > time.time() and (startup or revision > since)
                ],
                "deleted": [] if startup else [d for revision, d in STATE.deleted if revision > since],
            }
        if mode == "reset":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
            return
        if mode == "error":
            self.reply(503, b"{}")
        elif mode == "unauthorized":
            self.reply(401, b"{}")
        elif mode == "malformed":
            self.reply(200, b"{broken")
        elif mode == "module_limit":
            self.reply(200, json.dumps(payload).encode() + b" " * (768 * 1024))
        elif mode == "host_limit":
            self.reply(200, json.dumps(payload).encode() + b" " * (2 * 1024 * 1024))
        else:
            self.reply(200, json.dumps(payload).encode())

    @staticmethod
    def seen_revision(key, startup):
        return 0 if startup else STATE.seen.get(key, 0)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", "0")))
        with STATE.lock:
            STATE.appsec_calls += 1
            mode = STATE.appsec_mode
        self.reply(200 if mode == "allow" else 503, b"{}")


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(4096):
                self.request.sendall(data)
        except (OSError, ssl.SSLError):
            pass


class GRPC(socketserver.BaseRequestHandler):
    def handle(self):
        conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        conn.initiate_connection()
        self.request.sendall(conn.data_to_send())
        try:
            while data := self.request.recv(65536):
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        # Keep the response open to exercise idle streaming RPC bans
                        conn.send_headers(event.stream_id, [(":status", "200"), ("content-type", "application/grpc")])
                    if isinstance(event, h2.events.DataReceived):
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                self.request.sendall(conn.data_to_send())
        except (OSError, h2.exceptions.H2Error):
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def free_port(ip="127.0.0.1"):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family) as sock:
        sock.bind((ip, 0))
        return sock.getsockname()[1]


def cluster(name, port, h2_backend=False):
    value = {"name": name, "type": "STATIC", "connect_timeout": "1s", "load_assignment": {
        "cluster_name": name, "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {
            "socket_address": {"address": "127.0.0.1", "port_value": port}}}}]}]}}
    if h2_backend:
        value["http2_protocol_options"] = {}
    return value


def wasm_filter(network, fail_open=False, lapi=True, appsec=False, appsec_open=False):
    # HTTP roots and the closed network root share one cache and one bouncer key.
    # The separate network failure-policy fixture uses a different registered key.
    vm_id = "lapi-disabled" if not lapi else ("lapi-open" if network and fail_open else "lapi-shared")
    settings = {"crowdsec": {
        "lapi": {"enabled": lapi, "fail_open": fail_open, "cluster": "lapi", "key": vm_id,
                 "sync_freq": 1, "max_body_size_kb": 512},
        "trusted_ips": ["127.0.0.5/32"],
        "appsec": {"enabled": appsec, "fail_open": appsec_open, "cluster": "appsec",
                   "key": "" if network else "test-key"},
    }}
    kind = "network" if network else "http"
    # Distinct HTTP roots retain their policies while sharing LAPI synchronization.
    root_id = "crowdsec-network" if network else f"crowdsec-http-{fail_open}-{appsec}-{appsec_open}"
    return {"name": f"envoy.filters.{kind}.wasm", "typed_config": {
        "@type": f"type.googleapis.com/envoy.extensions.filters.{kind}.wasm.v3.Wasm",
        "config": {"name": "crowdsec", "root_id": root_id,
                   "vm_config": {"vm_id": vm_id, "runtime": "envoy.wasm.runtime.v8",
                                 "code": {"local": {"filename": "/work/plugin.wasm"}}},
                   "configuration": {"@type": "type.googleapis.com/google.protobuf.StringValue",
                                     "value": json.dumps(settings)}}}}


def listener(name, port, filters, ip="127.0.0.1", tls=False, passthrough=False):
    chain = {"filters": filters}
    if tls:
        chain["transport_socket"] = {"name": "envoy.transport_sockets.tls", "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
            "common_tls_context": {"tls_certificates": [{"certificate_chain": {"filename": "/work/cert.pem"},
                                                          "private_key": {"filename": "/work/key.pem"}}]}}}
    item = {"name": name, "address": {"socket_address": {"address": ip, "port_value": port}},
            "filter_chains": [chain]}
    if passthrough:
        item["listener_filters"] = [{"name": "envoy.filters.listener.tls_inspector", "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector"}}]
    return item


def tcp_proxy(backend="echo"):
    return {"name": "envoy.filters.network.tcp_proxy", "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
        "stat_prefix": "tcp", "cluster": backend}}


def http_proxy(fail_open=False, appsec=True, appsec_open=False):
    return {"name": "envoy.filters.network.http_connection_manager", "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": "http", "codec_type": "AUTO", "route_config": {"name": "routes", "virtual_hosts": [
            {"name": "all", "domains": ["*"], "routes": [
                {"match": {"prefix": "/grpc"}, "route": {"cluster": "grpc", "timeout": "0s"}},
                {"match": {"prefix": "/"}, "route": {"cluster": "backend"}},
            ]}]}, "http_filters": [wasm_filter(False, fail_open, appsec=appsec, appsec_open=appsec_open),
                {"name": "envoy.filters.http.router", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]}}


def wait_for(description, predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                print(f"PASS {description}", flush=True)
                return
        except (OSError, http.client.HTTPException, h2.exceptions.H2Error):
            pass
        time.sleep(0.15)
    raise AssertionError(description)


def connect(port, ip="127.0.0.2", ipv6=False, tls=False):
    sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET)
    sock.settimeout(1)
    sock.bind((ip, 0))
    sock.connect(("::1" if ipv6 else "127.0.0.1", port))
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname="localhost")
    return sock


def echo_allowed(port, ip="127.0.0.2", **kwargs):
    try:
        with connect(port, ip, **kwargs) as sock:
            sock.sendall(b"test")
            return sock.recv(4) == b"test"
    except OSError:
        return False


def closed(sock):
    try:
        return sock.recv(1024) == b""
    except (ConnectionResetError, ssl.SSLError):
        return True
    except socket.timeout:
        return False


def http_status(port, ip="127.0.0.2", headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2, source_address=(ip, 0))
    try:
        conn.request("GET", "/", headers=headers or {})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def streaming_grpc(port):
    sock = connect(port, "127.0.0.5")
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    for stream, ip in [(1, "192.0.2.8"), (3, "192.0.2.9")]:
        conn.send_headers(stream, [(":method", "POST"), (":scheme", "http"), (":authority", "localhost"),
                                  (":path", "/grpc.Test/Watch"), ("content-type", "application/grpc"),
                                  ("x-forwarded-for", ip)], end_stream=True)
    sock.sendall(conn.data_to_send())
    seen = set()
    while len(seen) != 2:
        for event in conn.receive_data(sock.recv(65536)):
            if isinstance(event, h2.events.ResponseReceived):
                assert dict(event.headers)[b":status"] == b"200", event.headers
                seen.add(event.stream_id)
        sock.sendall(conn.data_to_send())
    print("PASS HTTP/2 streaming gRPC works through combined filters", flush=True)
    STATE.ban("192.0.2.8")
    resets = set()
    def reset_arrived():
        for event in conn.receive_data(sock.recv(65536)):
            if isinstance(event, h2.events.StreamReset):
                resets.add(event.stream_id)
        return 1 in resets
    wait_for("new forwarded-client ban resets existing RPC", reset_arrived)
    assert 3 not in resets, "unrelated proxied RPC reset"
    conn.ping(b"still-up")
    sock.sendall(conn.data_to_send())
    wait_for("unrelated RPC connection remains usable", lambda: any(
        isinstance(e, h2.events.PingAckReceived) for e in conn.receive_data(sock.recv(65536))))
    sock.close()
    STATE.clear()


def main():
    engine = os.environ.get("CONTAINER_ENGINE") or shutil.which("docker") or shutil.which("podman")
    if not engine:
        raise RuntimeError("Docker or Podman is required")
    root = Path(__file__).resolve().parents[1]
    artifact = root / "target/wasm32-wasip1/release/crowdsec_wasm_bouncer.wasm"
    if not artifact.exists():
        raise RuntimeError("Run make build first")
    name = "crowdsec-network-test-" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="crowdsec-network-test-") as work:
        work = Path(work)
        work.chmod(0o755)
        shutil.copy(artifact, work / "plugin.wasm")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", str(work / "key.pem"),
                        "-out", str(work / "cert.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (work / "key.pem").chmod(0o644)
        api = serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), API))
        echo = serve(TCPServer(("127.0.0.1", 0), Echo))
        grpc = serve(TCPServer(("127.0.0.1", 0), GRPC))
        ssl_echo = TCPServer(("127.0.0.1", 0), Echo)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(work / "cert.pem", work / "key.pem")
        ssl_echo.socket = tls.wrap_socket(ssl_echo.socket, server_side=True)
        ssl_port = serve(ssl_echo)
        ports = {k: free_port() for k in ["tcp", "open", "disabled", "tls", "pass", "http", "http_only", "http_open", "appsec_open"]}
        ports["v6"] = free_port("::1")
        network = wasm_filter(True, appsec=True)  # No AppSec key: network mode must ignore AppSec
        listeners = [
            listener("tcp", ports["tcp"], [copy.deepcopy(network), tcp_proxy()]),
            listener("tls", ports["tls"], [copy.deepcopy(network), tcp_proxy()], tls=True),
            listener("pass", ports["pass"], [copy.deepcopy(network), tcp_proxy("ssl_echo")], passthrough=True),
            listener("v6", ports["v6"], [copy.deepcopy(network), tcp_proxy()], ip="::1"),
            listener("open", ports["open"], [wasm_filter(True, True), tcp_proxy()]),
            listener("disabled", ports["disabled"], [wasm_filter(True, lapi=False), tcp_proxy()]),
            listener("http", ports["http"], [copy.deepcopy(network), http_proxy()]),
            listener("http_only", ports["http_only"], [http_proxy()]),
            listener("http_open", ports["http_open"], [http_proxy(True)]),
            listener("appsec_open", ports["appsec_open"], [http_proxy(appsec_open=True)]),
        ]
        config = {"static_resources": {"listeners": listeners, "clusters": [cluster("lapi", api),
                  cluster("appsec", api), cluster("echo", echo), cluster("ssl_echo", ssl_port),
                  cluster("backend", api), cluster("grpc", grpc, True)]},
                  "layered_runtime": {"layers": [{"name": "test-buffer", "static_layer": {
                      "http.async_response_buffer_limit": 1024 * 1024}}]}}
        (work / "envoy.json").write_text(json.dumps(config))
        with (work / "envoy.log").open("w+") as logs:
            process = subprocess.Popen([engine, "run", "--rm", "--name", name, "--network=host", "-v",
                f"{work}:/work:ro", "--entrypoint", "envoy", os.environ.get("ENVOY_IMAGE", "docker.io/envoyproxy/envoy:v1.36-latest"),
                "-c", "/work/envoy.json", "--concurrency", "2", "--log-level", "info"], stdout=logs, stderr=subprocess.STDOUT)
            try:
                wait_for("disabled LAPI allows TCP without a cache", lambda: echo_allowed(ports["disabled"]))
                wait_for("fail-open allows startup traffic", lambda: echo_allowed(ports["open"]))
                assert not echo_allowed(ports["tcp"]), "fail-closed allowed startup traffic"
                wait_for("HTTP fail-closed startup returns 503", lambda: http_status(ports["http_only"]) == 503)
                wait_for("HTTP fail-open startup still runs AppSec", lambda: http_status(ports["http_open"]) == 200)
                STATE.mode = "healthy"
                wait_for("TCP initial sync recovers", lambda: echo_allowed(ports["tcp"]))
                wait_for("combined HTTP/AppSec works", lambda: http_status(ports["http"]) == 200)
                wait_for("terminated TLS is protocol agnostic", lambda: echo_allowed(ports["tls"], tls=True))
                wait_for("TLS passthrough is protocol agnostic", lambda: echo_allowed(ports["pass"], tls=True))
                wait_for("IPv6 connections work", lambda: echo_allowed(ports["v6"], "::1", ipv6=True))
                with STATE.lock:
                    before = STATE.appsec_calls
                assert echo_allowed(ports["tcp"])
                with STATE.lock:
                    assert STATE.startups.get("lapi-shared") == 1, STATE.startups
                print("PASS HTTP/network roots and both workers share one startup sync", flush=True)
                assert STATE.appsec_calls == before, "raw TCP invoked AppSec"
                tls_idle = connect(ports["tls"], tls=True)
                passthrough_idle = connect(ports["pass"], tls=True)
                for sock in [tls_idle, passthrough_idle]:
                    sock.sendall(b"test")
                    assert sock.recv(4) == b"test"
                idle = connect(ports["tcp"])
                idle.sendall(b"test")
                assert idle.recv(4) == b"test"
                other = connect(ports["tcp"], "127.0.0.3")
                STATE.ban("127.0.0.2")
                wait_for("new ban closes idle TCP connection", lambda: closed(idle))
                wait_for("new ban closes idle terminated TLS", lambda: closed(tls_idle))
                wait_for("new ban closes idle TLS passthrough", lambda: closed(passthrough_idle))
                tls_idle.close()
                passthrough_idle.close()
                wait_for("banned new TLS termination is rejected", lambda: not echo_allowed(ports["tls"], tls=True))
                wait_for("banned new TLS passthrough is rejected", lambda: not echo_allowed(ports["pass"], tls=True))
                wait_for("banned new TCP connections are rejected", lambda: not echo_allowed(ports["tcp"]))
                wait_for("fail-open cache has received the ban", lambda: not echo_allowed(ports["open"]))
                other.sendall(b"test")
                assert other.recv(4) == b"test", "unrelated connection closed"
                idle.close()
                STATE.mode = "error"
                wait_for("known cached ban blocks even in fail-open", lambda: not echo_allowed(ports["open"]))
                wait_for("later sync failure denies unbanned new TCP", lambda: not echo_allowed(ports["tcp"], "127.0.0.3"))
                wait_for("later sync failure permits fail-open TCP", lambda: echo_allowed(ports["open"], "127.0.0.3"))
                other.sendall(b"test")
                assert other.recv(4) == b"test", "sync outage closed an established unbanned connection"
                other.close()
                print("PASS sync outage preserves established TCP connections", flush=True)
                STATE.clear()
                STATE.mode = "healthy"
                wait_for("deleted ban and healthy sync restore TCP", lambda: echo_allowed(ports["tcp"]))
                STATE.ban("127.0.0.2/32", scope="Range")
                wait_for("IPv4 CIDR decisions block", lambda: not echo_allowed(ports["tcp"]))
                STATE.clear()
                STATE.ban("0:0:0:0:0:0:0:1")
                wait_for("canonical IPv6 exact decisions block", lambda: not echo_allowed(ports["v6"], "::1", ipv6=True))
                STATE.clear()
                STATE.ban("::1/128", scope="Range")
                wait_for("IPv6 CIDR decisions block", lambda: not echo_allowed(ports["v6"], "::1", ipv6=True))
                STATE.clear()
                wait_for("CIDR removals restore traffic", lambda: echo_allowed(ports["v6"], "::1", ipv6=True))
                STATE.ban("127.0.0.2", seconds=3)
                wait_for("short decision is applied", lambda: not echo_allowed(ports["tcp"]))
                wait_for("decision TTL restores traffic without deletion", lambda: echo_allowed(ports["tcp"]), timeout=8)
                STATE.clear()
                streaming_grpc(ports["http"])
                STATE.appsec_mode = "error"
                wait_for("AppSec fail-closed is independent", lambda: http_status(ports["http_only"]) == 403)
                wait_for("AppSec fail-open is independent", lambda: http_status(ports["appsec_open"]) == 200)
                assert echo_allowed(ports["tcp"]), "AppSec failure affected TCP"
                STATE.appsec_mode = "allow"
                for mode in ["unauthorized", "malformed", "reset", "module_limit", "host_limit"]:
                    STATE.mode = mode
                    wait_for(f"{mode} marks LAPI unhealthy", lambda: http_status(ports["http_only"]) == 503)
                    wait_for(f"{mode} honors fail-open", lambda: echo_allowed(ports["open"]))
                    STATE.mode = "healthy"
                    wait_for(f"recovery after {mode}", lambda: http_status(ports["http_only"]) == 200)
                text = (work / "envoy.log").read_text()
                assert "panicked at" not in text and "RuntimeError" not in text, text[-5000:]
                assert "LAPI call failed without response headers" in text, "reset callback not exercised"
                assert "response body too large" in text, "module limit not exercised"
                print("PASS all network, TLS, HTTP/gRPC, fail-policy and callback tests", flush=True)
            except BaseException:
                print((work / "envoy.log").read_text()[-14000:], flush=True)
                raise
            finally:
                subprocess.run([engine, "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                process.wait(timeout=15)


if __name__ == "__main__":
    main()
