"""POST /api/visibility over real HTTP on localhost, with the crawl itself
swapped for a fake site: private targets refused before anything is
fetched, the 24-hour cache, the per-site and per-IP limits."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from vis_fakes import NOW, healthy_site  # noqa: E402

from vibecheck import netguard  # noqa: E402
from vibecheck.ratelimit import MemoryBackend, RateLimiter  # noqa: E402
from vibecheck.visibility import scan_visibility  # noqa: E402
from vibecheck.visibility.cache import MemoryCache, ResultCache  # noqa: E402


def load():
    spec = importlib.util.spec_from_file_location("visibility_api_test", ROOT / "api" / "visibility.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VisibilityApiTest(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.mod.LIMITER = RateLimiter("t-vis", [(10, 3600)], backend=MemoryBackend(), disabled=False)
        self.mod.HOST_LIMITER = RateLimiter("t-vis-host", [(1, 60)], backend=MemoryBackend(), disabled=False)
        self.mod.GLOBAL_LIMITER = RateLimiter("t-vis-all", [(1000, 3600)], backend=MemoryBackend(), disabled=False)
        self.mod.CACHE = ResultCache(MemoryCache())
        # Names ending .test resolve to a public documentation address; the
        # real guard logic still runs on everything else.
        public = lambda host: ["93.184.216.34"] if host.endswith(".test") else netguard.resolve_host(host)  # noqa: E731
        self.mod.check_url = lambda url: netguard.check_url(url, resolver=public)
        self.scans = []

        def fake_scan(target):
            self.scans.append(target)
            return scan_visibility("groomly.test", healthy_site().fetch, now=NOW)

        self.mod.scan = fake_scan
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.mod.handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def post(self, body, ip="203.0.113.9"):
        data = json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/visibility", data=data,
                                     headers={"Content-Type": "application/json", "X-Real-IP": ip}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_scans_and_returns_the_report(self):
        status, body = self.post({"url": "groomly.test"})
        self.assertEqual(status, 200)
        self.assertEqual(body["kind"], "visibility")
        self.assertEqual(body["score"], 100)
        self.assertFalse(body["cached"])
        self.assertEqual(self.scans, ["https://groomly.test"])

    def test_private_addresses_are_refused_before_any_crawl(self):
        for bad in ("http://10.0.0.1/", "http://169.254.169.254/", "http://localhost:8080/", "http://192.168.1.1"):
            with self.subTest(bad):
                status, body = self.post({"url": bad})
                self.assertEqual(status, 400)
                self.assertTrue(body["error"])
        self.assertEqual(self.scans, [])

    def test_results_are_cached_for_a_day(self):
        self.post({"url": "groomly.test"})
        status, body = self.post({"url": "https://groomly.test/"})
        self.assertEqual(status, 200)
        self.assertTrue(body["cached"])
        self.assertEqual(len(self.scans), 1)

    def test_fresh_skips_the_cache_but_not_the_per_site_limit(self):
        self.post({"url": "groomly.test"})
        status, body = self.post({"url": "groomly.test", "fresh": True})
        self.assertEqual(status, 429)
        self.assertIn("checked moments ago", body["error"])

    def test_per_site_limit_covers_www_and_other_paths(self):
        self.post({"url": "groomly.test"})
        status, _ = self.post({"url": "https://www.groomly.test/pricing"})
        self.assertEqual(status, 429)

    def test_ten_scans_an_hour_per_visitor(self):
        for i in range(10):
            status, _ = self.post({"url": f"site{i}.test"})
            self.assertEqual(status, 200, i)
        status, body = self.post({"url": "site10.test"})
        self.assertEqual(status, 429)
        self.assertIn("Rate limit", body["error"])
        self.assertEqual(self.post({"url": "site11.test"}, ip="198.51.100.4")[0], 200)

    def test_bad_requests(self):
        self.assertEqual(self.post({})[0], 400)
        self.assertEqual(self.post({"url": "   "})[0], 400)
        self.assertEqual(self.post({"url": "ftp://groomly.test"})[0], 400)


class CacheTest(unittest.TestCase):
    def test_memory_cache_expires(self):
        now = [1000.0]
        cache = ResultCache(MemoryCache(clock=lambda: now[0]), ttl=60)
        cache.set("https://a.test/", {"score": 5})
        self.assertEqual(cache.get("https://a.test/"), {"score": 5})
        now[0] += 61
        self.assertIsNone(cache.get("https://a.test/"))

    def test_a_broken_backend_is_a_miss(self):
        class Broken:
            def get(self, key):
                raise OSError("down")

            def set(self, key, value, ttl):
                raise OSError("down")

        cache = ResultCache(Broken())
        cache.set("https://a.test/", {"x": 1})
        self.assertIsNone(cache.get("https://a.test/"))

    def test_kv_commands(self):
        from vibecheck.visibility.cache import KVCache
        sent = []

        def post(url, headers, commands):
            sent.append(commands)
            return [{"result": '{"score": 7}'}]

        kv = KVCache("https://kv.test", "tok", post=post)
        cache = ResultCache(kv, ttl=86400)
        cache.set("https://a.test/", {"score": 7})
        self.assertEqual(cache.get("https://a.test/"), {"score": 7})
        self.assertEqual(sent[0][0][0], "SET")
        self.assertEqual(sent[0][0][3:], ["EX", "86400"])


class BadgeLabelTest(unittest.TestCase):
    def test_visibility_label_and_no_injection(self):
        spec = importlib.util.spec_from_file_location("badge_vis", ROOT / "api" / "badge.py")
        badge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(badge)
        self.assertIn("visibility: 62/100 C", badge.render_badge(62, "visibility"))
        self.assertIn("vibe score: 62/100 C", badge.render_badge(62, "<script>alert(1)</script>"))
        self.assertEqual(badge.render_badge(94), badge.render_badge(94, "vibe score"))


if __name__ == "__main__":
    unittest.main()
