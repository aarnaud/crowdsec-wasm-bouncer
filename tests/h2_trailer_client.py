"""Send an HTTP/2 POST whose stream is terminated by a TRAILERS frame.

This is the regression test for the trailer bypass, and HTTP/2 is the transport where
that bypass is actually reachable. When a stream ends in trailers, Envoy delivers the
last DATA frame with end_stream=false and signals termination through decodeTrailers, so
on_http_request_body never observes end_of_stream. Without an on_http_request_trailers
handler the AppSec call is never dispatched and the request reaches the origin entirely
uninspected. Verified directly: with the handler removed, a SQLi body sent this way
returns 200 instead of 403.

The HTTP/1.1 equivalent (tests/trailer_client.py) does NOT cover this. Envoy's HTTP/1
codec drops trailers unless Http1ProtocolOptions.enable_trailers is set, so it terminates
the stream on the final chunk instead and the ordinary body path dispatches. That test
passes whether or not the handler exists, which is why this one is needed.

Prints just the response status code, or "no-response".
"""

import socket
import sys

import h2.config
import h2.connection
import h2.events

host, port, path, body = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4].encode()

sock = socket.create_connection((host, port), 10)
sock.settimeout(10)

conn = h2.connection.H2Connection(
    config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

conn.send_headers(
    1,
    [
        (":method", "POST"),
        (":path", path),
        (":authority", host),
        (":scheme", "http"),
        ("content-type", "application/x-www-form-urlencoded"),
    ],
    end_stream=False,
)
sock.sendall(conn.data_to_send())

conn.send_data(1, body, end_stream=False)
sock.sendall(conn.data_to_send())

# Trailers, not an end-stream DATA frame, terminate the request
conn.send_headers(1, [("x-checksum", "deadbeef")], end_stream=True)
sock.sendall(conn.data_to_send())

status = None
try:
    while status is None:
        data = sock.recv(65536)
        if not data:
            break
        for event in conn.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                for name, value in event.headers:
                    if name == ":status":
                        status = value
        pending = conn.data_to_send()
        if pending:
            sock.sendall(pending)
except Exception:
    pass

print(status or "no-response")
