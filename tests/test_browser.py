"""End-to-end browser tests for the hosted page.

These drive the real page in Chromium against a local dev server, because
the share-link round trip (gzip via CompressionStream, base64url, rule
rehydration) only exists in browser JS and can't be checked from Python.

Skipped automatically if Playwright isn't installed:

    pip install playwright        # browser binary ships with the image
    python3 -m unittest tests.test_browser
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 8321
BASE = f"http://127.0.0.1:{PORT}"

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None


def find_chromium():
    """Use a preinstalled Chromium if one is present, so the test doesn't
    depend on `playwright install` having matched this exact version."""
    for candidate in sorted(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux/chrome"), reverse=True):
        if candidate.exists():
            return str(candidate)
    return None


def wait_for_server(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(BASE + "/", timeout=1).read()
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    return False


@unittest.skipIf(sync_playwright is None, "playwright not installed")
class BrowserTest(unittest.TestCase):
    server = None
    pw = None
    browser = None

    @classmethod
    def setUpClass(cls):
        # Every browser request comes from the same address, so they'd all
        # share one rate-limit bucket and the suite would fail as it grows.
        # The 429 path is covered by tests/test_api.py instead.
        env = dict(os.environ, VIBECHECK_RATE_LIMIT_OFF="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts" / "devserver.py"), str(PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        if not wait_for_server():
            cls.server.kill()
            raise unittest.SkipTest("dev server did not start")
        cls.pw = sync_playwright().start()
        executable = find_chromium()
        try:
            cls.browser = cls.pw.chromium.launch(
                executable_path=executable) if executable else cls.pw.chromium.launch()
        except Exception as exc:  # pragma: no cover
            cls.pw.stop()
            cls.server.terminate()
            raise unittest.SkipTest(f"no usable Chromium: {exc}")
        # One context for the whole class: pages share a connection pool,
        # which keeps the local dev server responsive between tabs.
        cls.ctx = cls.browser.new_context()
        cls.ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin=BASE)

    @classmethod
    def tearDownClass(cls):
        if cls.browser:
            cls.browser.close()
        if cls.pw:
            cls.pw.stop()
        if cls.server:
            cls.server.terminate()
            cls.server.wait(timeout=10)

    def page(self):
        page = self.ctx.new_page()
        self.addCleanup(page.close)
        return page

    def run_demo_scan(self, page):
        page.goto(BASE + "/")
        page.click("#demoBtn")
        page.wait_for_selector("#report", state="visible")
        page.wait_for_function("document.querySelectorAll('.finding').length > 0")

    def test_demo_scan_renders_findings(self):
        page = self.page()
        self.run_demo_scan(page)
        self.assertEqual(page.inner_text("#scoreNum"), "0")
        self.assertIn("grade F", page.inner_text("#scoreGrade"))
        titles = page.eval_on_selector_all(".finding h3", "els => els.map(e => e.textContent)")
        self.assertIn("Stripe LIVE secret key exposed", titles)
        self.assertIn("Supabase service_role key exposed", titles)

    def test_secrets_are_redacted_in_rendered_excerpts(self):
        page = self.page()
        self.run_demo_scan(page)
        body = page.inner_text("#findings")
        self.assertIn("[redacted]", body)
        self.assertNotIn("sk_live_a1b2c3d4e5f6", body)

    def test_share_link_round_trip(self):
        """The core of the share feature: encode a report into the URL, open
        that URL fresh, and get the same report back — prose and all."""
        page = self.page()
        self.run_demo_scan(page)
        before = page.eval_on_selector_all(
            ".finding h3", "els => els.map(e => e.textContent)")
        prompts_before = page.eval_on_selector_all(
            ".fixwrap p", "els => els.map(e => e.textContent)")

        page.click("#shareBtn")
        page.wait_for_function("location.hash.startsWith('#r=')")
        share_url = page.evaluate("location.origin + location.pathname + location.hash")
        self.assertLess(len(share_url), 4000, "share link should stay pasteable")

        viewer = self.page()
        viewer.goto(share_url, wait_until="domcontentloaded")
        viewer.wait_for_selector("#report", state="visible")
        viewer.wait_for_function("document.querySelectorAll('.finding').length > 0")

        after = viewer.eval_on_selector_all(".finding h3", "els => els.map(e => e.textContent)")
        prompts_after = viewer.eval_on_selector_all(".fixwrap p", "els => els.map(e => e.textContent)")
        self.assertEqual(before, after, "shared report shows different findings")
        self.assertEqual(prompts_before, prompts_after, "fix prompts didn't rehydrate identically")
        self.assertEqual(viewer.inner_text("#scoreNum"), "0")

    def test_shared_view_shows_banner_and_hides_share_panel(self):
        page = self.page()
        self.run_demo_scan(page)
        page.click("#shareBtn")
        page.wait_for_function("location.hash.startsWith('#r=')")
        share_url = page.evaluate("location.origin + location.pathname + location.hash")

        viewer = self.page()
        viewer.goto(share_url, wait_until="domcontentloaded")
        viewer.wait_for_selector("#sharedBanner", state="visible")
        self.assertTrue(viewer.is_hidden("#sharePanel"))

    def test_fix_prompt_braces_unescaped_on_rehydrate(self):
        """The CORS rule's template contains {{ }} (Python format escaping).
        Rehydrated prompts must show single braces, like the server's do."""
        page = self.page()
        self.run_demo_scan(page)
        page.click("#shareBtn")
        page.wait_for_function("location.hash.startsWith('#r=')")
        share_url = page.evaluate("location.origin + location.pathname + location.hash")

        viewer = self.page()
        viewer.goto(share_url, wait_until="domcontentloaded")
        viewer.wait_for_function("document.querySelectorAll('.fixwrap p').length > 0")
        text = viewer.inner_text("#findings")
        self.assertIn("cors({ origin:", text)
        self.assertNotIn("{{", text)

    def test_corrupt_share_link_shows_error(self):
        page = self.page()
        page.goto(BASE + "/#r=zNOT_VALID_DATA", wait_until="domcontentloaded")
        page.wait_for_function("document.getElementById('status').textContent.includes('⚠')")
        self.assertIn("couldn't be read", page.inner_text("#status"))

    def test_url_tab_rejects_internal_address(self):
        page = self.page()
        page.goto(BASE + "/")
        page.click("#tabUrl")
        page.fill("#urlInput", "http://169.254.169.254/")
        page.click("#urlBtn")
        page.wait_for_function("document.getElementById('status').textContent.includes('⚠')")
        self.assertIn("private or internal network", page.inner_text("#status"))

    def test_badge_markdown_uses_score(self):
        page = self.page()
        self.run_demo_scan(page)
        page.click("#badgeBtn")
        page.wait_for_function("document.getElementById('badgeBtn').textContent.includes('Copied')")
        md = page.evaluate("navigator.clipboard.readText()")
        self.assertIn("/api/badge?score=0", md)
        self.assertTrue(md.startswith("[![Vibe Score]"))


if __name__ == "__main__":
    unittest.main()
