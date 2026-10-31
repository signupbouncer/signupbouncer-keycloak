"""A small HTTP forward proxy for test/e2e.sh, standing in for a company's outgoing proxy.

    python3 -I test/proxy.py <port> <log file> [user:password]

It takes plain-HTTP requests in absolute form (POST http://127.0.0.1:8097/v1/check), forwards them to 127.0.0.1 only,
and appends one JSON line per request to the log: method, URL, whether the right Proxy-Authorization came with it, and
the User-Agent. With user:password, a request without those credentials gets 407 and a Basic challenge, as a proxy
that needs a login answers.
"""

import base64
import http.client
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(sys.argv[1])
LOG = sys.argv[2]
CREDS = sys.argv[3] if len(sys.argv) > 3 else None
EXPECTED = "Basic " + base64.b64encode(CREDS.encode()).decode() if CREDS else None
HOP = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "te", "upgrade"}
lock = threading.Lock()


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_any(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        target = urlsplit(self.path)
        if target.scheme != "http" or target.hostname != "127.0.0.1":
            return self.reply(400, b"absolute http://127.0.0.1 URLs only")
        auth_ok = EXPECTED is not None and self.headers.get("Proxy-Authorization") == EXPECTED
        with lock, open(LOG, "a") as f:
            f.write(
                json.dumps(
                    {
                        "method": self.command,
                        "url": self.path,
                        "auth": auth_ok,
                        "userAgent": self.headers.get("User-Agent"),
                    }
                )
                + "\n"
            )
        if EXPECTED is not None and not auth_ok:
            return self.reply(407, b"login needed", [("Proxy-Authenticate", 'Basic realm="e2e proxy"')])
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        conn = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=10)
        try:
            path = target.path + ("?" + target.query if target.query else "")
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            kept = [(k, v) for k, v in resp.getheaders() if k.lower() not in HOP and k.lower() != "content-length"]
            self.reply(resp.status, data, kept)
        except OSError:
            self.reply(502, b"upstream failed")
        finally:
            conn.close()

    do_GET = handle_any
    do_POST = handle_any


ThreadingHTTPServer(("127.0.0.1", PORT), Proxy).serve_forever()
