"""Browser verification gate fixture.

Serves a login flow that only a real browser completes: the CSRF field does not
exist in the served HTML, a script creates it, and its value is derived from a
per-request nonce and a salt that appears only inside that script. A curl agent
can still compute it by reading the page, but that is more work than using the
browser, which is the point of the measurement.

Serve it inside the guest on the eth0 address: Chromium and the recording proxy
both bypass loopback, so a 127.0.0.1 fixture proves nothing.

    python3 browser_gate.py [port]        # default 8099

Routes: /health, /login (JS token), POST /login, /dashboard (cookie-gated, prints
the flag), /admin (cookie-gated), /report (302 to an excluded host).
Every request is appended to /tmp/browser_gate_access.log.
"""

import base64
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

SALT = "s3lt-" + secrets.token_hex(6)
FLAG = "GATE-" + secrets.token_hex(8)
ACCESS_LOG = "/tmp/browser_gate_access.log"
nonces, sessions = set(), set()

LOGIN = """<!doctype html><html><head><title>Sign in</title></head><body>
<h1>Sign in</h1><p id="msg">Loading...</p>
<script>
const nonce = "%s", salt = "%s";
const token = btoa(nonce.split("").reverse().join("") + salt);
const f = document.createElement("form");
f.method = "POST"; f.action = "/login";
f.innerHTML = '<input name="nonce" value="' + nonce + '">' +
              '<input name="token" value="' + token + '">' +
              '<input name="user" value="operator"><button>Sign in</button>';
document.body.appendChild(f);
document.getElementById("msg").textContent = "Ready.";
</script></body></html>"""

PAGE = """<!doctype html><html><head><title>%s</title></head><body>
<h1>%s</h1><p>%s</p><p><a href="/report">Report</a></p></body></html>"""


def expected(nonce):
    return base64.b64encode((nonce[::-1] + SALT).encode()).decode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        with open(ACCESS_LOG, "a") as fh:
            fh.write("%s %s\n" % (self.client_address[0], fmt % args))

    def send(self, code, body, headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def cookie(self):
        for part in (self.headers.get("cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid" and v in sessions:
                return v
        return None

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/health":
            return self.send(200, "ok")
        if path == "/login":
            nonce = secrets.token_hex(8)
            nonces.add(nonce)
            return self.send(200, LOGIN % (nonce, SALT))
        if path in ("/dashboard", "/admin"):
            if not self.cookie():
                return self.send(302, "", {"location": "/login"})
            body = FLAG if path == "/dashboard" else "admin area, flag is " + FLAG
            return self.send(200, PAGE % (path, path, body))
        if path == "/report":
            return self.send(302, "", {"location": "http://offscope.invalid/report"})
        return self.send(404, "not found")

    def do_POST(self):
        if self.path.split("?")[0] != "/login":
            return self.send(404, "not found")
        n = int(self.headers.get("content-length") or 0)
        form = parse_qs(self.rfile.read(n).decode())
        nonce = (form.get("nonce") or [""])[0]
        token = (form.get("token") or [""])[0]
        if nonce not in nonces or token != expected(nonce):
            return self.send(403, "bad token")
        nonces.discard(nonce)
        sid = secrets.token_urlsafe(16)
        sessions.add(sid)
        self.send(302, "", {"location": "/dashboard", "set-cookie": "sid=%s; HttpOnly; Path=/" % sid})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    open(ACCESS_LOG, "a").close()
    print("flag:", FLAG, "port:", port, flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
