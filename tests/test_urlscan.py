"""Tests for the deployed-site scanner. A fake fetcher stands in for the
network, so these run offline and deterministically."""

import unittest

from vibecheck.urlscan import Response, scan_url


class FakeSite:
    """Maps URL -> Response. Unlisted URLs return a 404."""

    def __init__(self, pages):
        self.pages = pages

    def fetch(self, url):
        if url in self.pages:
            return self.pages[url]
        return Response(status=404, headers={}, text="Not found", url=url)


def html(body="<html><body>hi</body></html>", headers=None, url="https://site.com/"):
    h = {"content-type": "text/html"}
    if headers:
        h.update(headers)
    return Response(status=200, headers=h, text=body, url=url)


SECURE_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
}


class UrlScanTest(unittest.TestCase):
    def ids(self, result):
        return {f.rule_id for f in result.findings}

    def test_clean_site_scores_high(self):
        site = FakeSite({"https://site.com/": html(headers=SECURE_HEADERS)})
        result = scan_url("https://site.com", site.fetch)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.score, 100)

    def test_exposed_env_file_is_critical(self):
        site = FakeSite({
            "https://site.com/": html(headers=SECURE_HEADERS),
            "https://site.com/.env": Response(200, {"content-type": "text/plain"},
                                              "STRIPE_SECRET_KEY=sk_live_x\nDB_PASS=hunter2\n", "https://site.com/.env"),
        })
        result = scan_url("https://site.com", site.fetch)
        finding = next(f for f in result.findings if f.rule_id == "exposed-env-file")
        self.assertEqual(finding.severity, "critical")

    def test_spa_catchall_html_not_flagged_as_env(self):
        # Many SPAs return index.html (200) for unknown paths — must NOT be a hit.
        spa = html(headers=SECURE_HEADERS)
        site = FakeSite({
            "https://site.com/": spa,
            "https://site.com/.env": Response(200, {"content-type": "text/html"},
                                              "<html><body>app</body></html>", "https://site.com/.env"),
        })
        result = scan_url("https://site.com", site.fetch)
        self.assertNotIn("exposed-env-file", self.ids(result))

    def test_env_path_without_kv_is_ignored(self):
        site = FakeSite({
            "https://site.com/": html(headers=SECURE_HEADERS),
            "https://site.com/.env": Response(200, {"content-type": "text/plain"},
                                              "just some prose, no equals sign here", "https://site.com/.env"),
        })
        result = scan_url("https://site.com", site.fetch)
        self.assertNotIn("exposed-env-file", self.ids(result))

    def test_missing_security_headers_reported(self):
        site = FakeSite({"https://site.com/": html()})  # no security headers
        result = scan_url("https://site.com", site.fetch)
        ids = self.ids(result)
        self.assertIn("missing-hsts", ids)
        self.assertIn("missing-csp", ids)
        self.assertIn("missing-xcto", ids)
        self.assertIn("missing-xfo", ids)

    def test_cors_wildcard_flagged(self):
        headers = dict(SECURE_HEADERS)
        headers["access-control-allow-origin"] = "*"
        site = FakeSite({"https://site.com/": html(headers=headers)})
        result = scan_url("https://site.com", site.fetch)
        self.assertIn("cors-wildcard-live", self.ids(result))

    def test_source_map_detected(self):
        body = '<html><body><script src="/assets/app.js"></script></body></html>'
        site = FakeSite({
            "https://site.com/": html(body=body, headers=SECURE_HEADERS),
            "https://site.com/assets/app.js.map": Response(200, {"content-type": "application/json"},
                                                           '{"version":3,"sources":["src/App.tsx"]}', "https://site.com/assets/app.js.map"),
        })
        result = scan_url("https://site.com", site.fetch)
        self.assertIn("exposed-source-map", self.ids(result))

    def test_robots_leaks_admin_path(self):
        robots = "User-agent: *\nDisallow: /admin-panel/\nDisallow: /\n"
        site = FakeSite({
            "https://site.com/": html(headers=SECURE_HEADERS),
            "https://site.com/robots.txt": Response(200, {"content-type": "text/plain"}, robots, "https://site.com/robots.txt"),
        })
        result = scan_url("https://site.com", site.fetch)
        finding = next(f for f in result.findings if f.rule_id == "robots-leaks-paths")
        self.assertIn("/admin-panel/", finding.excerpt)

    def test_http_downgrade_flagged(self):
        site = FakeSite({"https://site.com/": html(headers=SECURE_HEADERS, url="http://site.com/")})
        result = scan_url("https://site.com", site.fetch)
        self.assertIn("no-https", self.ids(result))

    def test_unreachable_site(self):
        def fetch(url):
            return None
        result = scan_url("https://down.example", fetch)
        self.assertIn("site-unreachable", self.ids(result))

    def test_bare_domain_gets_https_scheme(self):
        site = FakeSite({"https://site.com/": html(headers=SECURE_HEADERS)})
        result = scan_url("site.com", site.fetch)  # no scheme
        self.assertEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
