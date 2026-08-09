"""Vercel serverless function: POST /api/scan-url

Accepts {"url": "https://example.com"} and scans the DEPLOYED site for
exposed files, source maps, missing security headers, open CORS and
robots.txt leaks.

Every outbound request (including redirects) goes through the SSRF guard
in vibecheck.netguard, so this endpoint can't be used to reach private
networks or cloud metadata.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibecheck.netguard import check_url  # noqa: E402
from vibecheck.report import to_json_dict  # noqa: E402
from vibecheck.urlscan import build_guarded_fetcher, scan_url  # noqa: E402

MAX_BODY_BYTES = 4_000


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._json(400, {"error": "Invalid request."})

        try:
            body = json.loads(self.rfile.read(length))
            target = body.get("url")
            if not isinstance(target, str) or not target.strip():
                raise ValueError
            target = target.strip()
        except (ValueError, AttributeError, json.JSONDecodeError):
            return self._json(400, {"error": "Please provide a URL to scan."})

        if "://" not in target:
            target = "https://" + target

        ok, reason = check_url(target)
        if not ok:
            return self._json(400, {"error": reason})

        result = scan_url(target, build_guarded_fetcher())
        payload = to_json_dict(result)
        payload["kind"] = "url"
        return self._json(200, payload)

    def _json(self, code, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # never log scanned URLs
        pass
