"""Phase 1 acceptance: robinofloxley.com, from recorded responses.

The fixture is every response a real crawl received (recorded on 27 October
2026). Replaying it must reproduce the snapshot exactly, so any change to a
check shows up here as a diff. When a change is deliberate, re-snapshot:

    python3 scripts/record_visibility_fixture.py --name robinofloxley --replay
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from record_visibility_fixture import FIXTURES, Replay, load_fixture, replay  # noqa: E402

from vibecheck.visibility import scan_visibility  # noqa: E402
from vibecheck.visibility.report import render_json, to_json_dict  # noqa: E402


class RobinOfLoxleyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = load_fixture("robinofloxley")
        cls.result = replay(cls.fixture)
        cls.ids = {f.rule_id: f for f in cls.result.findings}
        cls.passes = {p.check_id: p for p in cls.result.passes}

    def test_matches_the_snapshot(self):
        expected = (FIXTURES / "robinofloxley.expected.json").read_text(encoding="utf-8")
        self.assertEqual(render_json(self.result), expected,
                         "re-snapshot with: python3 scripts/record_visibility_fixture.py --name robinofloxley --replay")

    def test_replay_needs_nothing_unrecorded(self):
        replayer = Replay(self.fixture)
        now = dt.datetime.strptime(self.fixture["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        scan_visibility(self.fixture["url"], replayer.fetch, now=now)
        self.assertEqual(replayer.misses, [])

    # The acceptance list, one by one.

    def test_fragment_only_app_sections(self):
        f = self.ids["fragment-sections"]
        self.assertIn("#myownsession", f.excerpt)
        self.assertIn("11 sections", f.excerpt)

    def test_sitemap_has_four_urls_against_pages_found(self):
        f = self.ids["sitemap-incomplete"]
        self.assertIn("sitemap lists 4 URLs", f.excerpt)
        self.assertIn("the crawl found 5 pages", f.excerpt)

    def test_home_lastmod_older_than_content(self):
        f = self.ids["sitemap-lastmod-stale"]
        self.assertIn("/: lastmod 2026-09-28", f.excerpt)

    def test_bare_and_www_mismatch_against_llms_txt(self):
        f = self.ids["external-host-mixed"]
        for host in ("myowntrader.com", "myownlingo.com"):
            self.assertIn(f"{host} in page links", f.excerpt)
            self.assertIn(f"www.{host} in llms.txt", f.excerpt)

    def test_llms_txt_present(self):
        self.assertIn("llms-ok", self.passes)
        self.assertNotIn("llms-missing", self.ids)

    def test_server_rendered(self):
        self.assertIn("server-rendered", self.passes)
        self.assertFalse({"csr-vite", "csr-next", "csr-generic"} & set(self.ids))

    def test_open_graph_complete(self):
        self.assertIn("og-complete", self.passes)
        self.assertIn("1200x630", self.passes["og-complete"].evidence)

    def test_nothing_high_or_critical(self):
        self.assertFalse([f for f in self.result.findings if f.severity in ("critical", "high")])

    def test_json_round_trips(self):
        json.loads(json.dumps(to_json_dict(self.result)))


if __name__ == "__main__":
    unittest.main()
