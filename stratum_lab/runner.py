"""Ein einzelner HTTP-Versuch gegen einen lokalen, hypothetischen Server."""
import http.client
import http.server
import http
import json
import os
import socketserver
import sys
import threading
import time
from urllib.parse import urlsplit

VERSION = "stratum-http-offline-v1"
METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}


def validate(p):
    if set(p) != {"direction", "url", "method", "headers", "body", "simulated_status", "simulated_body", "hypothesis", "source"}:
        raise ValueError("request fields")
    if p["direction"] not in {"incoming", "outgoing"}:
        raise ValueError("direction")
    u = urlsplit(p["url"])
    if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError("URL")
    if len(p["url"].encode()) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in p["url"]):
        raise ValueError("URL limit")
    if p["method"] not in METHODS or type(p["simulated_status"]) is not int or not 200 <= p["simulated_status"] <= 599:
        raise ValueError("method/status")
    if not p["hypothesis"].strip() or len(p["hypothesis"].encode()) > 2000:
        raise ValueError("hypothesis")
    if any(len(p[k].encode()) > 65536 for k in ("body", "simulated_body")) or len(p["headers"]) > 32:
        raise ValueError("body/header limit")
    names = set()
    for name, value in p["headers"]:
        key = name.lower()
        if not name or len(name) > 128 or any(not (c.isascii() and (c.isalnum() or c in "!#$%&'*+-.^_`|~")) for c in name):
            raise ValueError("header name")
        if len(value) > 2048 or any(not 32 <= ord(c) <= 126 for c in value) or key in names:
            raise ValueError("header value/duplicate")
        if key in {"host", "content-length", "transfer-encoding", "connection", "expect", "authorization", "proxy-authorization", "cookie", "upgrade", "trailer"}:
            raise ValueError("reserved header")
        names.add(key)
    # Die Authority erscheint nur im Host-Header, nie in connect oder DNS.
    authority = u.netloc.encode("ascii").decode()
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    path.encode("ascii")
    return authority, path


def replay(p):
    authority, path = validate(p)
    response_wire = []
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def handle_method(self):
            self.connection.settimeout(5)
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 65536:
                raise ValueError("content length")
            received.append({"method": self.command, "path": self.path, "host": self.headers.get("Host"), "body": self.rfile.read(length).decode("utf-8")})
            status = p["simulated_status"]
            body = p["simulated_body"].encode()
            phrase = http.HTTPStatus(status).phrase if status in http.HTTPStatus._value2member_map_ else "Simulated"
            lines = [f"HTTP/1.1 {status} {phrase}", "Content-Type: text/plain; charset=utf-8", "Connection: close", f"X-Stratum-Lab: {VERSION}"]
            if status not in {204, 304}:
                lines.append(f"Content-Length: {len(body)}")
            if self.command == "HEAD" or status in {204, 304}:
                body = b""
            wire = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
            response_wire.append(wire)
            self.connection.sendall(wire)
            self.close_connection = True

        do_GET = do_HEAD = do_OPTIONS = do_POST = do_PUT = do_PATCH = do_DELETE = handle_method

    class Connection(http.client.HTTPConnection):
        def send(self, data):
            request_wire.append(data)
            super().send(data)

    class Server(http.server.HTTPServer):
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name = "127.0.0.1"
            self.server_port = self.socket.getsockname()[1]

    request_wire = []
    # Beide Endpunkte liegen im selben abgeschotteten Loopback-Netz.
    server = Server(("127.0.0.1", 0), Handler)
    server.timeout = 5
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        conn = Connection("127.0.0.1", server.server_port, timeout=5)
        conn.putrequest(p["method"], path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", authority)
        conn.putheader("Connection", "close")
        for name, value in p["headers"]:
            conn.putheader(name, value)
        body = p["body"].encode()
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        response = conn.getresponse()
        response.read(65537)
        status = response.status
        conn.close()
        thread.join(6)
        if thread.is_alive() or len(received) != 1 or len(response_wire) != 1:
            raise ValueError("incomplete exchange")
        if received[0] != {"method": p["method"], "path": path, "host": authority, "body": p["body"]}:
            raise ValueError("request differs")
        return {"runner": VERSION, "status": status, "elapsed_ms": round((time.monotonic()-started)*1000), "request_wire": b"".join(request_wire).decode(), "response_wire": response_wire[0].decode(), "peer_ip": "127.0.0.1", "original_url": p["url"], "transport": "http_loopback", "tls_replayed": False, "redirects_followed": 0}
    finally:
        server.server_close()


def main():
    # Kein Fallback, wenn Netzwerkisolation fehlt.
    if set(os.listdir("/sys/class/net")) != {"lo"}:
        raise ValueError("network isolation missing")
    raw = sys.stdin.buffer.read(1024*1024+1)
    if len(raw) > 1024*1024:
        raise ValueError("input limit")
    result = replay(json.loads(raw))
    result["network_interfaces"] = ["lo"]
    result["python_version"] = sys.version.split()[0]
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, http.client.HTTPException) as error:
        print(f"HTTP lab: {type(error).__name__}: incomplete or invalid exchange", file=sys.stderr)
        sys.exit(1)
