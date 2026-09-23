"""Send a chunked POST that terminates with a trailer section.

curl cannot emit HTTP trailers, and bash's /dev/tcp is not reliably available, so the
suite drives this from a throwaway container on the compose network instead.

This is the regression guard for the trailer bypass: when a request ends in trailers,
Envoy delivers the last body chunk with end_stream=false and signals termination through
decodeTrailers, so on_http_request_body never observes end_of_stream. Without an
on_http_request_trailers handler the AppSec call was never dispatched at all and the
request reached the origin completely uninspected. HTTP/2 trailer frames arrive on the
same filter callback, so this covers that path too.

Prints just the response status code, or "no-response".
"""

import socket
import sys

host, port, path, body = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4].encode()

request = (
    f"POST {path} HTTP/1.1\r\nHost: {host}\r\n".encode()
    + b"Content-Type: application/x-www-form-urlencoded\r\n"
    + b"Transfer-Encoding: chunked\r\n"
    + b"Trailer: X-Checksum\r\n"
    + b"Connection: close\r\n\r\n"
    + f"{len(body):x}\r\n".encode()
    + body
    + b"\r\n"
    # Terminating chunk followed by a trailer section rather than end-of-stream
    + b"0\r\nX-Checksum: deadbeef\r\n\r\n"
)

sock = socket.create_connection((host, port), 10)
sock.settimeout(10)
sock.sendall(request)

response = b""
try:
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
except socket.timeout:
    pass

status_line = response.split(b"\r\n")[0].decode("latin-1").split(" ")
print(status_line[1] if len(status_line) > 1 else "no-response")
