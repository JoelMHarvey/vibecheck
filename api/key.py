"""Vercel serverless function: GET /.well-known/vibecheck-key (rewritten to /api/key)

The public keys that verify psychosecurity.io's signed reports and badges,
current first, then any retired ones still accepted. Derived from the
signing key in the environment, so the published key can't drift from the
one in use.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibecheck.core.signing import public_keys  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = {
            "keys": public_keys(),
            "about": "Ed25519 keys for vibecheck reports and badges. A signature covers the bytes "
                     "'vibecheck/report/1\\n' or 'vibecheck/badge/1\\n' followed by the envelope's p string.",
        }
        data = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=3600")
        # A public key, no cookies, nothing to steal: anyone verifying a badge
        # from their own page needs to read it.
        self.send_header("Access-Control-Allow-Origin", "*")  # vibecheck-ignore: cors-allow-all
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass
