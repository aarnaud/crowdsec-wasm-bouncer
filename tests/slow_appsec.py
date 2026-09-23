"""A deliberately slow stand-in for AppSec, used to force the response-pause path.

Normally AppSec answers in about the same millisecond as the origin, so whether
on_http_response_headers actually pauses is down to luck and the enforcement path goes
untested. This server sleeps before answering, which guarantees the ordering the test
needs: the origin receives the request, processes it and starts responding, and only
then does the verdict arrive.

That ordering matters because it is the only enforcement path that exists for a request
with a streamed body. The filter forwards such a request upstream while the AppSec call
is in flight (proxy-wasm offers no downstream backpressure, so pausing would just fill
Envoy's connection buffer until it 413s), and blocks by calling send_http_response during
response encoding. If a local reply does not reliably win against an in-flight upstream
response, blocks fail silently and the client is served the origin's body instead.

Verdict is keyed off the request URI: anything containing "block" gets a 403.
"""

import http.server
import os
import time

DELAY_SECONDS = float(os.environ.get("APPSEC_DELAY_MS", "800")) / 1000.0


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)

        uri = self.headers.get("X-Crowdsec-Appsec-Uri", "")
        time.sleep(DELAY_SECONDS)

        # Empty body, so the filter falls back to a classic block rather than trying to
        # parse a challenge envelope
        self.send_response(403 if "block" in uri else 200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", 7422), Handler).serve_forever()
