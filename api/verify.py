"""Vercel serverless function: POST /api/verify

{"envelope": {...}, "kind": "report" | "badge"} -> {"status": "verified" |
"tampered" | "unknown-key" | "unsigned"}

The report page verifies signatures in the browser (WebCrypto Ed25519).
This is the fallback for browsers that can't, and for anyone who'd rather
ask. It verifies against the published keys and stores nothing.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibecheck.core import signing  # noqa: E402
from vibecheck.core.ratelimit import RateLimiter, client_ip  # noqa: E402

MAX_BODY_BYTES = 200_000
LIMITER = RateLimiter("verify", [(60, 60)])
PREFIXES = {"report": signing.REPORT, "badge": signing.BADGE}


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        decision = LIMITER.check(client_ip(self.headers))
        if not decision.allowed:
            return self._json(429, {"error": decision.message}, {"Retry-After": str(decision.retry_after)})
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._json(400, {"error": "Invalid request."})
        try:
            body = json.loads(self.rfile.read(length))
            envelope, kind = body["envelope"], body.get("kind", "report")
            if not isinstance(envelope, dict) or kind not in PREFIXES:
                raise ValueError
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._json(400, {"error": "Send an envelope and a kind (report or badge)."})
        return self._json(200, {"status": signing.verify_envelope(envelope, PREFIXES[kind], signing.public_keys())})

    def _json(self, code, payload, extra_headers=None):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass
