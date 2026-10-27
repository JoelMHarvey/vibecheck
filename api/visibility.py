"""Vercel serverless function: POST /api/visibility

Accepts {"url": "https://example.com", "fresh": false} and checks how the
site looks to search engines and AI crawlers: rendering, robots.txt,
sitemap, llms.txt, structured data, titles, link previews, hosts.

The crawl runs here, server-side, never in the browser. Every request and
every redirect hop goes through the SSRF guard, and connects to the address
the guard vetted. Results are cached for 24 hours by URL; "fresh" skips the
cache (for checking a fix) but not the per-site limit.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibecheck.netguard import check_url  # noqa: E402
from vibecheck.ratelimit import RateLimiter, client_ip  # noqa: E402
from vibecheck.visibility import scan_visibility  # noqa: E402
from vibecheck.visibility.cache import ResultCache  # noqa: E402
from vibecheck.visibility.fetch import build_fetcher  # noqa: E402
from vibecheck.visibility.report import to_json_dict  # noqa: E402
from vibecheck.visibility.scan import normalise_input  # noqa: E402

MAX_BODY_BYTES = 4_000

# A scan is up to ~40 requests at a site the caller chose.
LIMITER = RateLimiter("visibility", [(10, 3600)])
# One scan a minute per target, whoever asks, so we never hammer a site.
HOST_LIMITER = RateLimiter("visibility-host", [(1, 60)])
# A ceiling on all outbound crawling.
GLOBAL_LIMITER = RateLimiter("visibility-global", [(200, 3600)])

CACHE = ResultCache()


def scan(target):
    """Separate so tests can swap the network out."""
    return scan_visibility(target, build_fetcher(guard=True))


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        decision = LIMITER.check(client_ip(self.headers))
        if not decision.allowed:
            return self._json(429, {"error": decision.message.replace("scans", "visibility scans")},
                              extra_headers={"Retry-After": str(decision.retry_after)})

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
            fresh = bool(body.get("fresh"))
        except (ValueError, AttributeError, json.JSONDecodeError):
            return self._json(400, {"error": "Please provide a URL to check."})

        target = normalise_input(target)
        ok, reason = check_url(target)
        if not ok:
            return self._json(400, {"error": reason})

        parts = urlsplit(target)
        cache_url = f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path or '/'}"
        if not fresh:
            cached = CACHE.get(cache_url)
            if cached:
                cached["cached"] = True
                return self._json(200, cached)

        host = (parts.hostname or "").lower()
        host = host[4:] if host.startswith("www.") else host
        decision = HOST_LIMITER.check(host)
        if decision.allowed:
            decision = GLOBAL_LIMITER.check("all")
        if not decision.allowed:
            return self._json(429, {"error": f"That site was checked moments ago. Try again in {decision.retry_after}s."},
                              extra_headers={"Retry-After": str(decision.retry_after)})

        payload = to_json_dict(scan(target))
        payload["cached"] = False
        CACHE.set(cache_url, payload)
        return self._json(200, payload)

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

    def log_message(self, *args):  # never log scanned URLs
        pass
