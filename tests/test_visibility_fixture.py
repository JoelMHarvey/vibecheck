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

from vibecheck.checks.visibility import scan_visibility  # noqa: E402
from vibecheck.core.report import render_json  # noqa: E402


class RobinOfLoxleyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = load_fixture("robinofloxley")
        cls.result = replay(cls.fixture)
        cls.ids = {f.id: f for f in cls.result.problems}
        cls.passes = {p.id: p for p in cls.result.passes}

    def test_matches_the_snapshot(self):
        expected = (FIXTURES / "robinofloxley.expected.json").read_text(encoding="utf-8")
        self.assertEqual(render_json([self.result]), expected,
                         "re-snapshot with: python3 scripts/record_visibility_fixture.py --name robinofloxley --replay")

    def test_replay_needs_nothing_unrecorded(self):
        replayer = Replay(self.fixture)
        now = dt.datetime.strptime(self.fixture["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        scan_visibility(self.fixture["url"], replayer.fetch, now=now)
        self.assertEqual(replayer.misses, [])

    # The acceptance list, one by one.

    def test_fragment_only_app_sections(self):
        f = self.ids["fragment-sections"]
        self.assertIn("#myownsession", f.evidence)
        self.assertIn("11 sections", f.evidence)

    def test_sitemap_lists_every_indexable_page(self):
        # The plan's acceptance list had "sitemap has 4 URLs against 5 pages
        # found". The fifth page was /brand, which is marked noindex, so the
        # sitemap is right to leave it out: noindex pages aren't judged as
        # content any more, and the finding went with them (as did /brand's
        # missing canonical and Open Graph, both about a page that asks not to
        # be indexed).
        self.assertNotIn("sitemap-incomplete", self.ids)
        self.assertEqual(self.result.meta["pages_crawled"], 4)
        for f in self.result.problems:
            self.assertNotIn("/brand:", f.evidence)

    def test_home_lastmod_older_than_content(self):
        f = self.ids["sitemap-lastmod-stale"]
        self.assertIn("/: lastmod 2026-09-28", f.evidence)

    def test_bare_and_www_mismatch_against_llms_txt(self):
        f = self.ids["external-host-mixed"]
        for host in ("myowntrader.com", "myownlingo.com"):
            self.assertIn(f"{host} in page links", f.evidence)
            self.assertIn(f"www.{host} in llms.txt", f.evidence)

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
        json.loads(json.dumps(self.result.to_dict()))

    def test_scores(self):
        # Phase 1 shipped at 62 (Technical 5, AI 8, Content 6) and the
        # framework move kept it there. Leaving noindex pages out of the
        # content checks took three findings about /brand off: 73.
        self.assertEqual(self.result.total, 73)
        self.assertEqual({k: v for k, v in self.result.category_scores.items() if v is not None},
                         {"technical": 7, "ai": 8, "content": 7})


if __name__ == "__main__":
    unittest.main()
