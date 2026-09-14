"""Loopback-only ALB append-mode emulator, NOT a production reverse proxy."""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address


HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"}


def build_proxy_headers(incoming, client_ip, upstream_host):
    # ALB append behavior: an attacker-controlled left prefix stays untrusted.
    client_ip = str(ip_address(client_ip))
    connection_headers = {s.strip().lower() for s in incoming.get("Connection", "").split(",")}
    excluded = HOP_HEADERS | connection_headers | {"host", "content-length", "forwarded"}
    headers = {key: value for key, value in incoming.items()
               if key.lower() not in excluded and not key.lower().startswith("x-forwarded-")}
    forwarded = incoming.get("X-Forwarded-For", "")
    headers["X-Forwarded-For"] = f"{forwarded}, {client_ip}" if forwarded else client_ip
    headers["X-Forwarded-Proto"] = "http"
    headers["Host"] = upstream_host
    return headers


def make_proxy(port, backend_port, source_ip="127.0.0.2"):
    if not ip_address(source_ip).is_loopback:
        raise ValueError("Lab proxy source must be loopback")
    class Handler(BaseHTTPRequestHandler):
        server_version = "PBL4-Local-Lab"

        def log_message(self, format, *args):
            pass  # Base handler would print raw URLs; target-side log owns audit input.

        def do_GET(self):
            if not self.path.startswith("/") or len(self.path) > 8192:
                self.send_error(414)
                return
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) > 1:
                self.send_error(400)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 <= size <= 16384:
                self.send_error(413)
                return
            self.connection.settimeout(5)
            connection = http.client.HTTPConnection("127.0.0.1", backend_port, timeout=10,
                                                    source_address=(source_ip, 0))
            try:
                body = self.rfile.read(size)
                if len(body) != size:
                    self.send_error(400)
                    return
                headers = build_proxy_headers(self.headers, self.client_address[0], f"127.0.0.1:{port}")
                connection.request(self.command, self.path, body=body, headers=headers)
                upstream = connection.getresponse()
                payload = upstream.read(2 * 1024 * 1024 + 1)
                if len(payload) > 2 * 1024 * 1024:
                    self.send_error(502)
                    return
                self.send_response(upstream.status)
                for key, value in upstream.getheaders():
                    if key.lower() not in HOP_HEADERS | {"content-length", "server", "date"}:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except (OSError, http.client.HTTPException):
                self.send_error(502)
            finally:
                connection.close()

        do_POST = do_GET
        do_HEAD = do_GET
        do_OPTIONS = do_GET

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server
