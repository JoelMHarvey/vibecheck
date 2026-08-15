"""Tests for the hosted API handlers (badge SVG + URL-scan validation).

These exercise the handler modules directly rather than over HTTP, so no
server or network is needed.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "api"))

import importlib.util  # noqa: E402


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "api" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


badge = load("badge_api", "badge.py")


class BadgeTest(unittest.TestCase):
    def test_grade_boundaries(self):
        self.assertEqual(badge.grade_for(100), "A")
        self.assertEqual(badge.grade_for(90), "A")
        self.assertEqual(badge.grade_for(89), "B")
        self.assertEqual(badge.grade_for(60), "C")
        self.assertEqual(badge.grade_for(39), "F")

    def test_renders_valid_svg(self):
        svg = badge.render_badge(94)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertIn("94/100 A", svg)

    def test_score_is_clamped(self):
        self.assertIn("100/100 A", badge.render_badge(9999))
        self.assertIn("0/100 F", badge.render_badge(-50))

    def test_no_injection_via_score(self):
        # Score is coerced to int, so markup can never reach the SVG body.
        svg = badge.render_badge(True)  # bool is an int subclass -> 1
        self.assertNotIn("<script", svg)
        self.assertIn("1/100 F", svg)


class RateLimitWireTest(unittest.TestCase):
    """The 429 must be a real HTTP response with a Retry-After header and a
    human-readable body, not a bare status code."""

    def setUp(self):
        import json as _json
        import threading
        from http.server import ThreadingHTTPServer

        self.scan_mod = load("scan_api_rl", "scan.py")
        # Deterministic, tiny limit, and independent of the ambient env.
        from vibecheck.ratelimit import MemoryBackend, RateLimiter
        self.scan_mod.LIMITER = RateLimiter(
            "test-scan", [(2, 60)], backend=MemoryBackend(), disabled=False)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.scan_mod.handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self._json = _json

    def post(self, ip="203.0.113.5"):
        import urllib.error
        import urllib.request

        body = self._json.dumps({"files": [{"path": "a.py", "content": "x = 1\n"}]}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/scan", data=body,
            headers={"Content-Type": "application/json", "X-Real-IP": ip}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, dict(r.headers), self._json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), self._json.loads(e.read())

    def test_returns_429_with_retry_after_and_message(self):
        self.assertEqual(self.post()[0], 200)
        self.assertEqual(self.post()[0], 200)

        status, headers, body = self.post()
        self.assertEqual(status, 429)
        retry_after = {k.lower(): v for k, v in headers.items()}.get("retry-after")
        self.assertIsNotNone(retry_after, "429 must carry Retry-After")
        self.assertTrue(1 <= int(retry_after) <= 60)
        self.assertIn("Rate limit reached", body["error"])
        self.assertIn("CLI", body["error"], "should point at the unlimited local option")

    def test_limit_is_per_ip(self):
        self.post(ip="203.0.113.5")
        self.post(ip="203.0.113.5")
        self.assertEqual(self.post(ip="203.0.113.5")[0], 429)
        self.assertEqual(self.post(ip="198.51.100.1")[0], 200,
                         "a different visitor must not inherit the block")


class UrlScanEndpointTest(unittest.TestCase):
    """The endpoint must refuse SSRF targets before fetching anything."""

    def test_guard_rejects_internal_targets(self):
        from vibecheck.netguard import check_url

        for bad in ("http://169.254.169.254/", "http://localhost/", "http://10.0.0.1/"):
            ok, reason = check_url(bad)
            self.assertFalse(ok, f"{bad} should be rejected")
            self.assertTrue(reason)


if __name__ == "__main__":
    unittest.main()
