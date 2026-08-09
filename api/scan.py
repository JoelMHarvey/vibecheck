"""Vercel serverless function: POST /api/scan

Accepts {"files": [{"path": "...", "content": "..."}]} and returns the scan
result as JSON. Files are scanned in memory and never written to disk or
stored anywhere.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibecheck.report import to_json_dict  # noqa: E402
from vibecheck.scanner import scan_files  # noqa: E402

MAX_BODY_BYTES = 4_400_000  # Vercel's request limit is 4.5 MB
MAX_FILES = 2_000


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._json(400, {"error": "Empty request."})
        if length > MAX_BODY_BYTES:
            return self._json(413, {"error": "Upload too large (max ~4 MB of text). For big projects, use the CLI — it runs locally."})

        try:
            body = json.loads(self.rfile.read(length))
            raw_files = body.get("files")
            if not isinstance(raw_files, list) or not raw_files:
                raise ValueError
            pairs = []
            for item in raw_files[:MAX_FILES]:
                path, content = item.get("path"), item.get("content")
                if isinstance(path, str) and isinstance(content, str):
                    pairs.append((path, content))
            if not pairs:
                raise ValueError
        except (ValueError, AttributeError, json.JSONDecodeError):
            return self._json(400, {"error": "Invalid request body."})

        result = scan_files(pairs, root_label="uploaded project")
        payload = to_json_dict(result)
        payload["kind"] = "code"
        payload["truncated"] = len(raw_files) > MAX_FILES
        return self._json(200, payload)

    def _json(self, code, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # never log request contents
        pass
