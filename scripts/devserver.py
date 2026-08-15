"""Local dev server that mirrors the Vercel routing.

Serves index.html and rules.json statically, and routes /api/scan,
/api/scan-url and /api/badge to the same handler classes Vercel runs.

    python3 scripts/devserver.py [port]
"""

from __future__ import annotations

import importlib.util
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/rules.json": ("rules.json", "application/json; charset=utf-8"),
    "/guide.css": ("guide.css", "text/css; charset=utf-8"),
    "/og.png": ("og.png", "image/png"),
    "/robots.txt": ("robots.txt", "text/plain; charset=utf-8"),
    "/sitemap.xml": ("sitemap.xml", "application/xml; charset=utf-8"),
    # Vercel's cleanUrls resolves /guides/x to guides/x.html; mirror that.
    "/guides/lovable-app-security": ("guides/lovable-app-security.html", "text/html; charset=utf-8"),
    "/guides/bolt-app-security": ("guides/bolt-app-security.html", "text/html; charset=utf-8"),
    "/guides/v0-app-security": ("guides/v0-app-security.html", "text/html; charset=utf-8"),
    "/guides/ai-app-security-checklist": ("guides/ai-app-security-checklist.html", "text/html; charset=utf-8"),
}


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "api" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.handler


API = {
    "/api/scan": _load("scan_api", "scan.py"),
    "/api/scan-url": _load("scan_url_api", "scan-url.py"),
    "/api/badge": _load("badge_api", "badge.py"),
}


class DevHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _route(self, method: str):
        path = self.path.split("?")[0]
        handler_cls = API.get(path)
        if handler_cls:
            # Reuse the real handler's method against this connection.
            bound = handler_cls.__new__(handler_cls)
            bound.headers = self.headers
            bound.rfile = self.rfile
            bound.wfile = self.wfile
            bound.path = self.path
            bound.request_version = self.request_version
            bound.send_response = self.send_response
            bound.send_header = self.send_header
            bound.end_headers = self.end_headers
            getattr(bound, method)()
            return
        if method == "do_GET" and path in STATIC:
            filename, ctype = STATIC[path]
            body = (ROOT / filename).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._route("do_GET")

    def do_POST(self):
        self._route("do_POST")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"vibecheck dev server on http://127.0.0.1:{port}")
    # Threading matters: with HTTP/1.1 keep-alive a single-threaded server
    # blocks on an idle connection and can't serve a second browser tab.
    ThreadingHTTPServer(("127.0.0.1", port), DevHandler).serve_forever()
