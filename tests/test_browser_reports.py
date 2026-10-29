"""Browser tests for report.js on /visibility and /check: any CheckResult,
one or several side by side, and share links that round-trip.

Borrows the setup from test_browser.py (same dev server, same Chromium)
without inheriting its tests, so those run once and stay untouched.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_browser as tb  # noqa: E402

ROOT = tb.ROOT
BASE = tb.BASE
sync_playwright = tb.sync_playwright


@unittest.skipIf(sync_playwright is None, "playwright not installed")
class SharedReportTest(unittest.TestCase):
    """Results come from the recorded robinofloxley.com fixture and a fake
    site, so nothing touches the network."""

    setUpClass = classmethod(tb.BrowserTest.setUpClass.__func__)
    tearDownClass = classmethod(tb.BrowserTest.tearDownClass.__func__)
    page = tb.BrowserTest.page
    run_demo_scan = tb.BrowserTest.run_demo_scan
    server = pw = browser = None

    def results(self):
        import json
        visibility = json.loads((ROOT / "vibecheck" / "checks" / "visibility" / "fixtures"
                                  / "robinofloxley.expected.json").read_text(encoding="utf-8"))
        from vis_fakes import NOW, healthy_site
        from vibecheck.checks.security import CHECK
        from vibecheck.core.models import Context, Target
        security = CHECK.run(Target(url="https://groomly.test"),
                             Context(fetch_override=healthy_site().fetch, now=NOW)).to_dict()
        return security, visibility

    def render(self, page, path, results):
        page.goto(BASE + path)
        page.evaluate("rs => VibeReport.render(document.getElementById('report'), rs)", results)
        page.wait_for_selector("#report .vr-section")

    def share_round_trip(self, path, results):
        page = self.page()
        self.render(page, path, results)
        before = page.eval_on_selector_all(".vr-finding h3, .vr-passes strong, .vr-fix p",
                                           "els => els.map(e => e.textContent)")
        page.click("#shareBtn")
        page.wait_for_function("location.hash.startsWith('#r=')")
        url = page.evaluate("location.href")
        viewer = self.page()
        viewer.goto(url, wait_until="domcontentloaded")
        viewer.wait_for_selector("#sharedBanner", state="visible")
        after = viewer.eval_on_selector_all(".vr-finding h3, .vr-passes strong, .vr-fix p",
                                            "els => els.map(e => e.textContent)")
        self.assertEqual(before, after)
        self.assertNotIn("{excerpt}", viewer.inner_text("#report"))
        return viewer, url

    def test_visibility_report_round_trips(self):
        _security, visibility = self.results()
        viewer, url = self.share_round_trip("/visibility", [visibility])
        self.assertEqual(viewer.inner_text("#scoreNum"), "73")
        self.assertIn("deeper check coming soon", viewer.inner_text("#report"))
        self.assertLess(len(url), 4000)

    def test_combined_page_shows_both_side_by_side(self):
        viewer, _url = self.share_round_trip("/check", list(self.results()))
        titles = viewer.eval_on_selector_all(".vr-section > h2", "els => els.map(e => e.textContent)")
        self.assertEqual(titles, ["Security", "Visibility"])
        self.assertEqual(viewer.locator(".vr-mini").count(), 2)

    def test_an_integrity_report_round_trips(self):
        import json
        import tempfile
        from vibecheck.checks.integrity import CHECK
        from vibecheck.core.models import Context, Target
        with tempfile.TemporaryDirectory() as d:
            Path(d, "package.json").write_text(json.dumps({"dependencies": {"express": "4"}}))
            Path(d, "server.js").write_text("const p = process.env.PORT;\n")
            result = CHECK.run(Target(repo=d, label="groomly"), Context(guard=False)).to_dict()
        viewer, _url = self.share_round_trip("/check", [result])
        text = viewer.inner_text("#report")
        self.assertIn("No tests", text)
        self.assertIn("Observability", text)
        self.assertIn("How it was built", text)

    def test_ai_answers_render_as_a_snapshot_and_survive_a_share_link(self):
        from test_probe import INPUT, FakeSearch, run
        result = run(FakeSearch()).to_dict()
        viewer, url = self.share_round_trip("/visibility", [result])
        text = viewer.inner_text("#report")
        self.assertIn("What the AI said", text)
        self.assertIn("A snapshot", text)
        self.assertIn("flat-priced newcomer", text)
        self.assertLess(len(url), 8000)

    def test_the_ai_panel_fits_a_phone(self):
        page = self.page()
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(tb.BASE + "/visibility")
        page.click("#askAi summary")
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)

    def test_old_security_links_still_open(self):
        # A v1 link, as the home page made them before the framework.
        page = self.page()
        self.run_demo_scan(page)
        v1 = page.evaluate(r"""async () => {
          const p = {v: 1, s: 0, g: "F", n: 4, k: "code",
                     f: [["cors-allow-all", "medium", "server/index.js", 2, "app.use(cors());"]]};
          const bytes = new TextEncoder().encode(JSON.stringify(p));
          let s = ""; for (const b of bytes) s += String.fromCharCode(b);
          return "j" + btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        }""")
        viewer = self.page()
        viewer.goto(BASE + "/#r=" + v1, wait_until="domcontentloaded")
        viewer.wait_for_selector(".finding h3")
        self.assertEqual(viewer.inner_text(".finding h3"), "CORS allows every website")
        self.assertIn("cors({ origin:", viewer.inner_text("#findings"))



if __name__ == "__main__":
    unittest.main()


SEED_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"  # bytes(range(32)), test only


@unittest.skipIf(sync_playwright is None, "playwright not installed")
class SignedReportTest(unittest.TestCase):
    """Signed reports in a real browser: WebCrypto verifies them, an edited
    link says so, and the badges and key are served where the README links
    expect them."""

    page = tb.BrowserTest.page
    server = pw = browser = None

    @classmethod
    def setUpClass(cls):
        import os
        cls._saved = os.environ.get("VIBECHECK_SIGNING_KEY")
        os.environ["VIBECHECK_SIGNING_KEY"] = SEED_B64  # the dev server inherits it
        tb.BrowserTest.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        import os
        tb.BrowserTest.tearDownClass.__func__(cls)
        if cls._saved is None:
            os.environ.pop("VIBECHECK_SIGNING_KEY", None)
        else:
            os.environ["VIBECHECK_SIGNING_KEY"] = cls._saved

    def signed_results(self):
        from vis_fakes import NOW, healthy_site
        from vibecheck.checks.security import CHECK as SEC
        from vibecheck.checks.visibility import CHECK as VIS
        from vibecheck.core.models import Context, Target
        from vibecheck.core.signed import with_signatures
        ctx = Context(fetch_override=healthy_site().fetch, now=NOW.replace(year=2099))
        return [with_signatures(c.run(Target(url="https://groomly.test"), ctx)) for c in (SEC, VIS)]

    def open_shared(self, path, results):
        page = self.page()
        page.goto(BASE + path)
        page.evaluate("rs => VibeReport.render(document.getElementById('report'), rs)", results)
        page.wait_for_selector("#report .vr-section")
        page.click("#shareBtn")
        page.wait_for_function("location.hash.startsWith('#r=')")
        return page, page.evaluate("location.hash")

    def test_signed_link_is_verified_in_the_browser(self):
        _page, hash_ = self.open_shared("/visibility", self.signed_results()[1:])
        viewer = self.page()
        viewer.goto(BASE + "/report" + hash_, wait_until="domcontentloaded")
        viewer.wait_for_selector(".vr-prov.ok")
        self.assertIn("Verified", viewer.inner_text(".vr-prov"))
        self.assertIn("gold badge", viewer.inner_text("#report"))

    def test_an_edited_link_says_tampered(self):
        from vibecheck.core import badge
        result = self.signed_results()[1]
        env = dict(result["signed"]["report"])
        env["p"] = env["p"].replace('"total":100', '"total":99')
        viewer = self.page()
        viewer.goto(BASE + "/report#r=" + badge.encode_report_link([env]), wait_until="domcontentloaded")
        viewer.wait_for_selector(".vr-prov.bad")
        self.assertIn("Tampered", viewer.inner_text(".vr-prov"))

    def test_an_unsigned_run_link_is_only_ever_a_github_link(self):
        # The run URL in an unsigned claim is whatever the sender wrote.
        import json
        from vibecheck.core import badge, signing
        claim = json.loads(self.signed_results()[1]["signed"]["report"]["p"])
        for run, linked in (("javascript:alert(document.domain)", False),
                            ("https://github.com.evil.test/x", False),
                            ("https://github.com/o/r/actions/runs/1", True)):
            claim["provenance"] = {"by": "ci", "run": run}
            viewer = self.page()
            viewer.goto(BASE + "/report#r=" + badge.encode_report_link([signing.unsigned_envelope(claim)]),
                        wait_until="domcontentloaded")
            viewer.wait_for_selector(".vr-prov")
            viewer.wait_for_function("document.querySelector('.vr-prov').textContent.includes('GitHub Actions')")
            hrefs = viewer.eval_on_selector_all(".vr-prov a", "as => as.map(a => a.getAttribute('href'))")
            self.assertEqual(hrefs, [run] if linked else [], run)
            self.assertIn(run.replace("https://github.com/", "") if linked else run, viewer.inner_text(".vr-prov"))

    def test_badges_and_key_are_served(self):
        from vibecheck.core import badge
        page = self.page()
        key = page.goto(BASE + "/.well-known/vibecheck-key").json()
        self.assertEqual(key["keys"][0]["status"], "current")
        env = self.signed_results()[1]["signed"]["badge"]
        svg = page.goto(BASE + "/badge/visibility.svg?r=" + badge.encode_badge_param(env)).text()
        self.assertIn("gold", svg)

    def test_check_page_issues_the_vibechecked_badge(self):
        page, _hash = self.open_shared("/check", self.signed_results())
        page.click("#vibecheckedBtn")
        page.wait_for_function("document.getElementById('vibecheckedBtn').textContent.includes('Copied')")
        md = page.evaluate("navigator.clipboard.readText()")
        self.assertIn("/badge/vibechecked.svg?r=", md)
        self.assertIn("/report#r=", md)

    def test_badge_button_gives_signed_badges(self):
        page, _hash = self.open_shared("/visibility", self.signed_results()[1:])
        page.click("#badgeBtn")
        page.wait_for_function("document.getElementById('badgeBtn').textContent.includes('Copied')")
        md = page.evaluate("navigator.clipboard.readText()")
        self.assertTrue(md.startswith("[![vibecheck visibility: gold]("), md[:80])
        self.assertIn("/badge/visibility.svg?r=", md)
