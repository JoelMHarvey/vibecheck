"""server/app.py, the site off Vercel: the static pages with vercel.json's
cleanUrls, nothing a deployment leaves out, the same headers, the two
rewrites, and every api/ function through its own handler class. Requests
go straight to the WSGI callable (and once over real HTTP); no network."""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock
from wsgiref.simple_server import WSGIRequestHandler, make_server
from wsgiref.util import setup_testing_defaults

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))

from vis_fakes import NOW, healthy_site  # noqa: E402

from server import app as server  # noqa: E402
from vibecheck.checks.visibility import scan_visibility  # noqa: E402
from vibecheck.core import netguard  # noqa: E402
from vibecheck.core.cache import MemoryCache, ResultCache  # noqa: E402
from vibecheck.core.ratelimit import MemoryBackend, RateLimiter  # noqa: E402
from vibecheck.core.signing import Signer, b64url  # noqa: E402

SEED = bytes(range(32))
VERCEL_HEADERS = {"x-content-type-options": "nosniff", "x-frame-options": "DENY",
                  "referrer-policy": "strict-origin-when-cross-origin"}


class Client:
    def __init__(self, site):
        self.site = site

    def request(self, method, path, body=b"", headers=None, environ=None):
        path, _, query = path.partition("?")
        env = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
               "REMOTE_ADDR": "203.0.113.20", "wsgi.input": io.BytesIO(body),
               "CONTENT_LENGTH": str(len(body)) if body else ""}
        for name, value in (headers or {}).items():
            key = name.upper().replace("-", "_")
            env[key if key in ("CONTENT_TYPE", "CONTENT_LENGTH") else "HTTP_" + key] = value
        env.update(environ or {})
        setup_testing_defaults(env)
        seen = {}

        def start_response(status, response_headers):
            seen["status"] = int(status.split()[0])
            seen["headers"] = response_headers

        data = b"".join(self.site(env, start_response))
        return seen["status"], {k.lower(): v for k, v in seen["headers"]}, data

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post_json(self, path, payload, ip="203.0.113.30"):
        return self.request("POST", path, json.dumps(payload).encode(),
                            headers={"Content-Type": "application/json", "X-Real-IP": ip})


def module_of(site, url):
    return site.modules[url]


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.site = server.Site()
        self.client = Client(self.site)


class StaticTest(ServerTestCase):
    def test_pages_and_assets(self):
        for path, ctype, needle in (("/", "text/html", b"<html"), ("/check", "text/html", b"<html"),
                                    ("/visibility", "text/html", b"<html"),
                                    ("/guides/llms-txt", "text/html", b"<html"),
                                    ("/rules.json", "application/json", b"{"),
                                    ("/report.js", "application/javascript", b""),
                                    ("/guide.css", "text/css", b""), ("/og.png", "image/png", b"\x89PNG"),
                                    ("/robots.txt", "text/plain", b""), ("/sitemap.xml", "application/xml", b"<"),
                                    ("/LICENSE", "application/octet-stream", b"MIT")):
            with self.subTest(path):
                status, headers, body = self.client.get(path)
                self.assertEqual(status, 200)
                self.assertTrue(headers["content-type"].startswith(ctype), headers["content-type"])
                self.assertIn(needle, body)
                self.assertEqual(headers["content-length"], str(len(body)))
                self.assertEqual(headers["cache-control"], "public, max-age=0, must-revalidate")

    def test_the_page_is_the_file(self):
        self.assertEqual(self.client.get("/check")[2], (ROOT / "check.html").read_bytes())
        self.assertEqual(self.client.get("/")[2], (ROOT / "index.html").read_bytes())

    def test_a_trailing_slash_on_a_page_is_tolerated(self):
        self.assertEqual(self.client.get("/check/")[0], 200)
        self.assertEqual(self.client.get("/guides/llms-txt/")[0], 200)
        self.assertEqual(self.client.get("/guides/")[0], 404)

    def test_html_addresses_redirect_to_the_clean_one(self):
        for path, location in (("/check.html", "/check"), ("/index.html", "/"), ("/index", "/"),
                               ("/guides/llms-txt.html", "/guides/llms-txt"),
                               ("/check.html?x=1", "/check?x=1"), ("/index.html?x=1", "/?x=1"),
                               ("/LICENSE.html", "/LICENSE")):
            with self.subTest(path):
                status, headers, _ = self.client.get(path)
                self.assertEqual(status, 308)
                self.assertEqual(headers["location"], location)

    def test_head_and_etag(self):
        status, headers, body = self.client.request("HEAD", "/check")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(headers["content-length"], str((ROOT / "check.html").stat().st_size))
        status, _, body = self.client.get("/check", headers={"If-None-Match": headers["etag"]})
        self.assertEqual((status, body), (304, b""))

    def test_a_page_takes_no_post(self):
        self.assertEqual(self.client.request("POST", "/check", b"x")[0], 405)

    def test_unknown_paths(self):
        for path in ("/nope", "/api/nope", "/CHECK", "/vibecheck/", "/posts"):
            with self.subTest(path):
                self.assertEqual(self.client.get(path)[0], 404)


class NotServedTest(ServerTestCase):
    """What a Vercel deployment leaves out, the server leaves out."""

    def test_vercelignore_gitignore_dotfiles_and_server_files(self):
        fixture = next(p for p in (ROOT / "vibecheck/checks/security/fixtures").rglob("*") if p.is_file())
        for path in ("/tests/test_api.py", "/tests/", "/PLAN.md", "/pyproject.toml", "/.gitignore",
                     "/.vercelignore", "/.vibecheckignore", "/.github/workflows/ci.yml", "/.git/config",
                     "/" + fixture.relative_to(ROOT).as_posix(),
                     "/vibecheck/checks/visibility/fixtures/", "/server/app.py", "/server/__init__.py",
                     "/Dockerfile", "/.dockerignore", "/README.md", "/vercel.json",
                     "/vibecheck/__pycache__/__init__.cpython-312.pyc"):
            with self.subTest(path):
                self.assertEqual(self.client.get(path)[0], 404)

    def test_no_url_reaches_the_filesystem(self):
        for path in ("/../vercel.json", "/guides/../PLAN.md", "/%2e%2e/PLAN.md", "//PLAN.md",
                     "/tests/../index.html", "/./PLAN.md"):
            with self.subTest(path):
                self.assertIn(self.client.get(path)[0], (404, 308))
                self.assertNotIn(b"PLAN", self.client.get(path)[2][:200])

    def test_the_function_source_redirects_to_the_function(self):
        for name in ("key", "badge", "visibility", "scan-url"):
            status, headers, _ = self.client.get(f"/api/{name}.py")
            self.assertEqual(status, 308)
            self.assertEqual(headers["location"], f"/api/{name}")

    def test_ignore_patterns(self):
        pats = ["tests/", "PLAN.md", "vibecheck/checks/*/fixtures/", "*.egg-info/", "report.md"]
        for rel, expect in (("tests/x.py", True), ("tests", False), ("a/tests/x.py", True),
                            ("PLAN.md", True), ("docs/PLAN.md", True),
                            ("vibecheck/checks/security/fixtures/a/b.py", True),
                            ("vibecheck/checks/security/scanner.py", False),
                            ("other/checks/security/fixtures/a.py", False),
                            ("x.egg-info/PKG-INFO", True), ("index.html", False)):
            with self.subTest(rel):
                self.assertEqual(server.ignored(rel, pats), expect)


class HeadersTest(ServerTestCase):
    def test_every_response_carries_vercel_json_headers(self):
        for method, path in (("GET", "/"), ("GET", "/nope"), ("GET", "/check.html"), ("GET", "/api/key"),
                             ("GET", "/badge/vibe.svg"), ("GET", "/api/scan"), ("GET", server.HEALTH_PATH)):
            with self.subTest(path):
                _, headers, _ = self.client.request(method, path)
                for name, value in VERCEL_HEADERS.items():
                    self.assertEqual(headers.get(name), value)
                self.assertEqual(headers["strict-transport-security"], "max-age=63072000")

    def test_the_headers_come_from_vercel_json(self):
        rules = json.loads((ROOT / "vercel.json").read_text())["headers"]
        self.assertEqual({h["key"].lower(): h["value"] for r in rules for h in r["headers"]}, VERCEL_HEADERS)

    def test_a_setting_the_server_does_not_know_stops_it(self):
        with self.assertRaises(RuntimeError):
            server.Site.understood({"cleanUrls": True, "redirects": []})
        server.Site.understood(json.loads((ROOT / "vercel.json").read_text()))

    def test_source_patterns(self):
        rx = server.source_regex("/badge/:check.svg")
        self.assertEqual(rx.match("/badge/vibe.svg").group("check"), "vibe")
        self.assertIsNone(rx.match("/badge/a/b.svg"))
        self.assertIsNone(rx.match("/badge/vibe.png"))
        self.assertTrue(server.source_regex("/(.*)").match("/anything/at/all"))
        self.assertTrue(server.source_regex("/.well-known/vibecheck-key").match("/.well-known/vibecheck-key"))
        self.assertIsNone(server.source_regex("/.well-known/vibecheck-key").match("/Xwell-known/vibecheck-key"))


class HealthTest(ServerTestCase):
    def test_live(self):
        status, headers, body = self.client.get(server.HEALTH_PATH)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})
        self.assertEqual(headers["cache-control"], "no-store")


class RewritesTest(ServerTestCase):
    def test_badge_svg(self):
        status, headers, body = self.client.get("/badge/vibe.svg")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "image/svg+xml; charset=utf-8")
        self.assertIn("default-src 'none'", headers["content-security-policy"])
        self.assertTrue(body.startswith(b"<svg"))

    def test_badge_keeps_the_query(self):
        badge = module_of(self.site, "/api/badge").badge
        with mock.patch.object(badge, "render", return_value="<svg/>") as render:
            self.client.get("/badge/visibility.svg?r=abc")
        self.assertEqual(render.call_args[0][:2], ("visibility", "abc"))

    def test_badge_name_cannot_add_parameters(self):
        badge = module_of(self.site, "/api/badge").badge
        with mock.patch.object(badge, "render", return_value="<svg/>") as render:
            self.client.get("/badge/vibe&r=forged.svg")
        self.assertEqual(render.call_args[0][:2], ("vibe&r=forged", ""))

    def test_well_known_key(self):
        with mock.patch.dict(os.environ, {"VIBECHECK_SIGNING_KEY": b64url(SEED)}):
            status, headers, body = self.client.get("/.well-known/vibecheck-key")
        self.assertEqual(status, 200)
        keys = json.loads(body)["keys"]
        self.assertEqual(keys[0]["kid"], Signer(SEED).kid)
        self.assertEqual(keys[0]["status"], "current")
        self.assertEqual(headers["access-control-allow-origin"], "*")
        self.assertNotIn(b64url(SEED), body.decode())


class ApiTest(ServerTestCase):
    def setUp(self):
        super().setUp()
        for url, names in (("/api/scan", ["LIMITER"]), ("/api/scan-url", ["LIMITER", "GLOBAL_LIMITER"]),
                           ("/api/verify", ["LIMITER"]), ("/api/vibechecked", ["LIMITER"])):
            mod = module_of(self.site, url)
            for name in names:
                setattr(mod, name, RateLimiter("t-" + url + name, [(1000, 60)], backend=MemoryBackend(),
                                               disabled=False))

    def test_every_function_is_mounted(self):
        expected = {"/api/" + p.stem for p in (ROOT / "api").glob("*.py")}
        self.assertEqual(set(self.site.functions), expected)
        self.assertGreaterEqual(expected, {"/api/scan", "/api/scan-url", "/api/visibility", "/api/badge",
                                           "/api/key", "/api/verify", "/api/vibechecked"})

    def test_scan(self):
        status, headers, body = self.client.post_json(
            "/api/scan", {"files": [{"path": "app.py", "content": "x = 1\n"}]})
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "code")
        self.assertIn("result", payload)

    def test_scan_bad_and_wrong_method(self):
        self.assertEqual(self.client.post_json("/api/scan", {"files": []})[0], 400)
        status, _, body = self.client.get("/api/scan")
        self.assertEqual(status, 501)
        self.assertIn(b"Unsupported method", body)

    def test_a_body_over_vercels_limit_is_refused_unread(self):
        stream = mock.Mock()
        status, _, _ = self.client.request("POST", "/api/scan", environ={
            "CONTENT_LENGTH": str(server.MAX_BODY_BYTES + 1), "wsgi.input": stream})
        self.assertEqual(status, 413)
        stream.read.assert_not_called()

    def test_scan_rate_limit_is_per_visitor(self):
        mod = module_of(self.site, "/api/scan")
        mod.LIMITER = RateLimiter("t-scan-1", [(1, 60)], backend=MemoryBackend(), disabled=False)
        files = {"files": [{"path": "a.py", "content": "x = 1\n"}]}
        self.assertEqual(self.client.post_json("/api/scan", files, ip="198.51.100.7")[0], 200)
        status, headers, _ = self.client.post_json("/api/scan", files, ip="198.51.100.7")
        self.assertEqual(status, 429)
        self.assertIn("retry-after", headers)
        self.assertEqual(self.client.post_json("/api/scan", files, ip="198.51.100.8")[0], 200)

    def test_scan_url_refuses_private_targets_before_fetching(self):
        mod = module_of(self.site, "/api/scan-url")
        with mock.patch.object(mod.CHECK, "scan_live") as scan_live:
            for bad in ("http://127.0.0.1/", "http://169.254.169.254/", "http://10.0.0.1/"):
                status, _, body = self.client.post_json("/api/scan-url", {"url": bad})
                self.assertEqual(status, 400, bad)
                self.assertTrue(json.loads(body)["error"])
            self.assertEqual(self.client.post_json("/api/scan-url", {})[0], 400)
        scan_live.assert_not_called()

    def test_verify(self):
        status, _, body = self.client.post_json("/api/verify", {"envelope": {"p": "{}", "sig": None}})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "unsigned")
        self.assertEqual(self.client.post_json("/api/verify", {"kind": "report"})[0], 400)

    def test_vibechecked_without_a_key(self):
        with mock.patch.dict(os.environ, {"VIBECHECK_SIGNING_KEY": ""}):
            status, _, body = self.client.post_json("/api/vibechecked", {"reports": []})
        self.assertEqual(status, 503)

    def test_vibechecked_with_a_key_checks_the_reports(self):
        with mock.patch.dict(os.environ, {"VIBECHECK_SIGNING_KEY": b64url(SEED)}):
            status, _, body = self.client.post_json("/api/vibechecked", {"reports": [{"p": "{}"}]})
        self.assertEqual(status, 400)
        self.assertIn("No vibechecked badge", json.loads(body)["error"])

    def test_badge_score(self):
        status, _, body = self.client.get("/api/badge?score=94")
        self.assertEqual(status, 200)
        self.assertIn(b"94/100 A", body)

    def test_a_crashing_function_is_a_500(self):
        mod = module_of(self.site, "/api/key")
        with mock.patch.object(mod, "public_keys", side_effect=RuntimeError("boom")), \
                mock.patch("sys.stderr", io.StringIO()):
            status, headers, _ = self.client.get("/api/key")
        self.assertEqual(status, 500)
        self.assertEqual(headers["x-frame-options"], "DENY")


class VisibilityTest(ServerTestCase):
    def setUp(self):
        super().setUp()
        mod = self.mod = module_of(self.site, "/api/visibility")
        mod.LIMITER = RateLimiter("t-vis", [(10, 3600)], backend=MemoryBackend(), disabled=False)
        mod.HOST_LIMITER = RateLimiter("t-vis-host", [(1, 60)], backend=MemoryBackend(), disabled=False)
        mod.GLOBAL_LIMITER = RateLimiter("t-vis-all", [(1000, 3600)], backend=MemoryBackend(), disabled=False)
        mod.CACHE = ResultCache(MemoryCache())
        public = lambda host: ["93.184.216.34"] if host.endswith(".test") else netguard.resolve_host(host)  # noqa: E731
        mod.check_url = lambda url: netguard.check_url(url, resolver=public)
        self.scans = []

        def fake_scan(target):
            self.scans.append(target)
            return scan_visibility("groomly.test", healthy_site().fetch, now=NOW)

        mod.scan = fake_scan

    def test_scans_caches_and_limits(self):
        status, _, body = self.client.post_json("/api/visibility", {"url": "groomly.test"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["check_id"], "visibility")
        status, _, body = self.client.post_json("/api/visibility", {"url": "https://groomly.test/"})
        self.assertTrue(json.loads(body)["cached"])
        self.assertEqual(self.scans, ["https://groomly.test"])
        self.assertEqual(self.client.post_json("/api/visibility", {"url": "groomly.test", "fresh": True})[0], 429)

    def test_private_targets(self):
        self.assertEqual(self.client.post_json("/api/visibility", {"url": "http://10.0.0.1/"})[0], 400)
        self.assertEqual(self.scans, [])


class ClientAddressTest(unittest.TestCase):
    """The rate limits key on client_ip(), which trusts X-Real-IP first, then
    X-Vercel-Forwarded-For. Off Vercel nothing vouches for the second."""

    def test_vercel_header_dropped(self):
        from vibecheck.core.ratelimit import client_ip
        headers = server.request_headers({"HTTP_X_VERCEL_FORWARDED_FOR": "6.6.6.6",
                                          "HTTP_X_FORWARDED_FOR": "6.6.6.6, 198.51.100.2"})
        self.assertEqual(client_ip(headers), "198.51.100.2")

    def test_caddys_x_real_ip_wins(self):
        from vibecheck.core.ratelimit import client_ip
        headers = server.request_headers({"HTTP_X_REAL_IP": "198.51.100.3", "REMOTE_ADDR": "172.18.0.2"})
        self.assertEqual(client_ip(headers), "198.51.100.3")

    def test_the_connection_when_no_proxy_says(self):
        from vibecheck.core.ratelimit import client_ip
        self.assertEqual(client_ip(server.request_headers({"REMOTE_ADDR": "127.0.0.1"})), "127.0.0.1")


class DeployedSettingsTest(unittest.TestCase):
    def test_not_deployed_says_nothing(self):
        self.assertEqual(server.check_deployed_settings({}), [])

    def test_limits_cannot_be_off_when_deployed(self):
        with self.assertRaises(RuntimeError):
            server.check_deployed_settings({"VIBECHECK_DEPLOYED": "1", "VIBECHECK_RATE_LIMIT_OFF": "1"})

    def test_warns_about_what_is_missing(self):
        warnings = server.check_deployed_settings({"VIBECHECK_DEPLOYED": "1"})
        self.assertEqual(len(warnings), 2)
        self.assertEqual(server.check_deployed_settings(
            {"VIBECHECK_DEPLOYED": "1", "VIBECHECK_SIGNING_KEY": "x", "KV_REST_API_URL": "https://kv"}), [])


class _Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


class OverHttpTest(unittest.TestCase):
    """Once through a real WSGI server, the way gunicorn will call it."""

    def setUp(self):
        site = server.Site()
        mod = module_of(site, "/api/scan")
        mod.LIMITER = RateLimiter("t-http", [(1000, 60)], backend=MemoryBackend(), disabled=False)
        self.httpd = make_server("127.0.0.1", 0, site, handler_class=_Quiet)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def test_page_and_scan(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/check", timeout=5) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        data = json.dumps({"files": [{"path": "a.py", "content": "x = 1\n"}]}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/scan", data=data,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual(json.loads(r.read())["kind"], "code")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/PLAN.md", timeout=5)
            self.fail("PLAN.md served")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)
            e.close()


if __name__ == "__main__":
    unittest.main()
