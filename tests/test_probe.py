"""Visibility phases 3 and 4: the AI-answer probe and the off-site footprint.
Claude is never called: a fake search returns canned answers."""

from __future__ import annotations

import io
import json
import sys
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vis_fakes import NOW, healthy_site  # noqa: E402

from vibecheck.checks.visibility import CHECK, scan_visibility  # noqa: E402
from vibecheck.checks.visibility import footprint as fp  # noqa: E402
from vibecheck.checks.visibility import probe as pr  # noqa: E402
from vibecheck.checks.visibility import websearch as ws  # noqa: E402
from vibecheck.checks.visibility.rules import PASSES, RULES  # noqa: E402
from vibecheck.core.models import Context, Target  # noqa: E402
from vibecheck.core.ratelimit import MemoryBackend, RateLimiter  # noqa: E402
from vibecheck.core.report import render_markdown, render_terminal  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
INPUT = pr.ProbeInput("Groomly", "groomly.test", "booking software for dog groomers", "GB", ["Fresha", "Gingr"])


class FakeSearch:
    """Answers each question from a script; records what it was asked."""

    def __init__(self, mentions=(True, False, True, False, False), cited=(True,), competitors=("Fresha",),
                 directory_hits=("producthunt.com",), elsewhere=("reddit.com", "dogtimes.test"), exc=None,
                 limiter=None):
        self.mentions, self.cited, self.competitors = list(mentions), list(cited), competitors
        self.directory_hits, self.elsewhere, self.exc, self.limiter = directory_hits, elsewhere, exc, limiter
        self.asked = []
        self.lock = threading.Lock()
        self.n = 0

    def spend(self):
        if self.limiter is not None and not self.limiter.check("all").allowed:
            raise ws.SearchUnavailable("today's AI checks are used up; back tomorrow")

    def ask(self, question, *, country=None, allowed_domains=None, max_uses=3, system=None):
        with self.lock:
            self.asked.append((question, country, allowed_domains))
        if self.exc:
            raise self.exc
        if allowed_domains:     # the directory search
            return ws.Answer(question, "Found these.", [], [
                {"url": f"https://www.{h}/products/groomly", "title": "Groomly"} for h in self.directory_hits
            ] + [{"url": "https://www.g2.com/categories/pet-grooming", "title": "Best pet grooming software"}])
        if question.startswith("Search the web for"):
            return ws.Answer(question, "Pages.", [], [{"url": f"https://{h}/groomly-review", "title": "Groomly review"}
                                                     for h in self.elsewhere]
                             + [{"url": "https://groomly.test/pricing", "title": "Groomly pricing"}])
        with self.lock:
            i = self.n
            self.n += 1
        named = self.mentions[i % len(self.mentions)]
        text = ("Popular options are " + ", ".join(self.competitors) +
                (". Groomly is a flat-priced newcomer at £12 a month." if named else "."))
        cites = ["https://groomly.test/pricing"] if named and i < len(self.cited) and self.cited[i] else \
            ["https://fresha.test/"]
        return ws.Answer(question, text, cites, [])


def run(search, inp=INPUT, site=None):
    return scan_visibility("groomly.test", (site or healthy_site()).fetch, now=NOW, search=search, probe_input=inp)


def ids(result):
    return {f.id for f in result.problems}


def passes(result):
    return {f.id for f in result.passes}


def finding(result, rule_id):
    return next(f for f in result.findings if f.id == rule_id)


class QuestionsTest(unittest.TestCase):
    def test_five_buyer_questions_that_never_name_the_brand(self):
        qs = pr.questions(INPUT)
        self.assertEqual(len(qs), 5)
        self.assertFalse(any("Groomly" in q for q in qs))
        self.assertIn("in the UK", qs[0])
        self.assertTrue(any("alternatives to Fresha" in q for q in qs))
        self.assertTrue(any("Fresha or Gingr" in q for q in qs))

    def test_without_competitors_it_still_asks_five(self):
        qs = pr.questions(pr.ProbeInput("Groomly", "groomly.test", "booking software", "JP", []))
        self.assertEqual(len(qs), 5)
        self.assertIn("in Japan", qs[0])

    def test_inputs_are_tidied_and_capped(self):
        inp = pr.ProbeInput("  Groomly  ", "https://WWW.Groomly.test/x", "x" * 500, "gb", ["a", "b", "c", "d"]).clean()
        self.assertEqual((inp.brand, inp.domain, inp.country), ("Groomly", "groomly.test", "GB"))
        self.assertEqual(len(inp.category), 120)
        self.assertEqual(inp.competitors, ["a", "b", "c"])


class ParseTest(unittest.TestCase):
    def test_reads_text_citations_and_search_results_from_the_response(self):
        content = [
            {"type": "server_tool_use", "name": "web_search", "input": {"query": "x"}},
            {"type": "web_search_tool_result", "content": [{"url": "https://a.test/1", "title": "A"},
                                                           {"url": "https://b.test/2", "title": "B"}]},
            {"type": "text", "text": "Try Groomly. ", "citations": [{"type": "web_search_result_location",
                                                                     "url": "https://groomly.test/", "cited_text": "x"}]},
            {"type": "text", "text": "Or Fresha.", "citations": None},
            {"type": "web_search_tool_result", "content": {"type": "web_search_tool_result_error",
                                                           "error_code": "max_uses_exceeded"}},
        ]
        a = ws.parse("q", content, "end_turn")
        self.assertEqual(a.text, "Try Groomly. Or Fresha.")
        self.assertEqual(a.cited, ["https://groomly.test/"])
        self.assertEqual([r["url"] for r in a.results], ["https://a.test/1", "https://b.test/2"])

    def test_mentions_position_and_citation(self):
        a = ws.Answer("q", "Fresha is popular. Gingr too. groomly is cheaper.", ["https://www.groomly.test/p"], [])
        r = pr.read(a, INPUT)
        self.assertTrue(r.mentioned)
        self.assertTrue(r.cited)
        self.assertEqual(r.position, 3)
        self.assertEqual(r.competitors, ["Fresha", "Gingr"])

    def test_a_brand_inside_another_word_is_not_a_mention(self):
        a = ws.Answer("q", "Groomlyzer is great.", [], [])
        self.assertFalse(pr.read(a, INPUT).mentioned)

    def test_the_domain_written_out_counts(self):
        a = ws.Answer("q", "See groomly.test for prices.", [], [])
        self.assertTrue(pr.read(a, INPUT).mentioned)


class ProbeInTheScanTest(unittest.TestCase):
    def test_fills_brand_and_offsite_with_a_snapshot(self):
        result = run(FakeSearch())
        self.assertIsNotNone(result.category_scores["brand"])
        self.assertIsNotNone(result.category_scores["offsite"])
        probe = result.meta["probe"]
        self.assertEqual(probe["status"], "asked")
        self.assertEqual(probe["mention_rate"], 0.4)
        self.assertEqual(len(probe["answers"]), 5)
        self.assertIn("probe-mentioned", passes(result))
        # Reddit counts too: the general search turned up a Reddit page about Groomly.
        self.assertEqual(result.meta["footprint"]["listed"], ["Product Hunt", "Reddit"])

    def test_never_named_is_a_finding_that_names_the_competitors(self):
        result = run(FakeSearch(mentions=(False,)))
        f = finding(result, "probe-not-mentioned")
        self.assertIn("named in 0 of 5 answers", f.evidence)
        self.assertIn("Fresha (5)", f.evidence)

    def test_rarely_named_and_never_cited(self):
        result = run(FakeSearch(mentions=(True, False, False, False, False), cited=(False,)))
        self.assertIn("probe-rarely-mentioned", ids(result))
        self.assertIn("probe-not-cited", ids(result))

    def test_a_competitor_ahead(self):
        result = run(FakeSearch(mentions=(True, True, False, False, False)))
        self.assertIn("Fresha named in 5 answers", finding(result, "probe-behind-competitors").evidence)

    def test_off_site_mentions_count_only_pages_about_the_brand_not_your_own(self):
        result = run(FakeSearch(elsewhere=()))
        self.assertIn("offsite-no-mentions", ids(result))
        result = run(FakeSearch(elsewhere=("a.test", "b.test")))
        self.assertIn("2 other sites", finding(result, "offsite-few-mentions").evidence)

    def test_a_category_page_on_a_directory_is_not_a_listing(self):
        # g2.com/categories/pet-grooming is in every fake result; only /products/groomly counts.
        result = run(FakeSearch(directory_hits=(), elsewhere=("dogtimes.test",)))
        ev = finding(result, "offsite-missing-listings").evidence
        self.assertIn("G2", ev)
        self.assertIn("sell.g2.com/create-free-profile", ev)
        self.assertIn("Description to paste:", ev)
        self.assertNotIn("offsite-listed", passes(result))

    def test_the_paste_in_description_comes_from_llms_txt(self):
        result = run(FakeSearch(directory_hits=()))
        self.assertIn("dog groomers", finding(result, "offsite-missing-listings").evidence.split("Description to paste:")[1])

    def test_over_the_daily_cap_it_says_back_tomorrow_and_scores_nothing(self):
        limiter = RateLimiter("t", [(0, 86400)], backend=MemoryBackend(), disabled=False)
        search = FakeSearch(limiter=limiter)
        result = run(search)
        self.assertEqual(search.asked, [])
        self.assertIsNone(result.category_scores["brand"])
        self.assertIn("back tomorrow", result.meta["probe"]["status"])
        self.assertEqual(result.total, 100, "phase 1 is untouched")
        self.assertIn("AI answers: not run", render_terminal(result, use_color=False))

    def test_a_failed_search_leaves_both_unscored(self):
        result = run(FakeSearch(exc=ws.SearchUnavailable("the AI service didn't answer (APIError)")))
        self.assertIsNone(result.category_scores["brand"])
        self.assertIsNone(result.category_scores["offsite"])
        self.assertTrue(result.meta["probe"]["status"].startswith("not run"))

    def test_questions_carry_the_country(self):
        search = FakeSearch()
        run(search)
        self.assertTrue(all(c == "GB" for q, c, d in search.asked if not d and not q.startswith("Search")))

    def test_the_reports_show_what_the_ai_said_as_a_snapshot(self):
        result = run(FakeSearch())
        for text in (render_terminal(result, use_color=False), render_markdown(result)):
            self.assertIn("A snapshot", text)
            self.assertIn("flat-priced newcomer", text)

    def test_the_check_takes_the_probe_from_the_context(self):
        search = FakeSearch()
        result = CHECK.run(Target(url="https://groomly.test"),
                           Context(guard=False, fetch_override=healthy_site().fetch, now=NOW,
                                   options={"probe": (search, INPUT)}))
        self.assertEqual(len([a for a in search.asked if not a[2] and not a[0].startswith("Search")]), 5)
        self.assertIn("probe", result.meta)

    def test_every_new_id_has_prose(self):
        for rid in ("probe-not-mentioned", "probe-rarely-mentioned", "probe-not-cited", "probe-behind-competitors",
                    "offsite-no-mentions", "offsite-few-mentions", "offsite-missing-listings"):
            self.assertIn(rid, RULES)
        for pid in ("probe-mentioned", "probe-cited", "probe-share-ok", "offsite-mentions", "offsite-listed"):
            self.assertIn(pid, PASSES)


def sdk_response(content, stop="end_turn"):
    return SimpleNamespace(stop_reason=stop, content=content)


class ClaudeSearchTest(unittest.TestCase):
    def test_asks_opus_with_web_search_and_fallbacks(self):
        create = mock.Mock(return_value=sdk_response([SimpleNamespace(type="text", text="Hi", citations=None)]))
        client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
        ans = ws.ClaudeSearch(client=client).ask("q?", country="GB", allowed_domains=["g2.com"], max_uses=2)
        self.assertEqual(ans.text, "Hi")
        kw = create.call_args.kwargs
        self.assertEqual(kw["model"], "claude-opus-5-5")
        self.assertEqual(kw["tools"][0]["type"], "web_search_20260209")
        self.assertEqual(kw["tools"][0]["user_location"], {"type": "approximate", "country": "GB"})
        self.assertEqual(kw["tools"][0]["allowed_domains"], ["g2.com"])
        self.assertEqual(kw["fallbacks"], "default")
        self.assertIn("server-side-fallback-2026-07-01", kw["betas"])
        self.assertNotIn("temperature", kw)

    def test_a_paused_turn_is_resumed_and_every_block_kept(self):
        first = sdk_response([{"type": "web_search_tool_result", "content": [{"url": "https://a.test", "title": "A"}]}],
                             "pause_turn")
        second = sdk_response([{"type": "text", "text": "Done."}])
        create = mock.Mock(side_effect=[first, second])
        client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
        ans = ws.ClaudeSearch(client=client).ask("q?")
        self.assertEqual(create.call_count, 2)
        self.assertEqual(ans.text, "Done.")
        self.assertEqual(ans.results[0]["url"], "https://a.test")
        self.assertEqual(create.call_args.kwargs["messages"][-1]["role"], "assistant")

    def test_refusals_and_errors_are_unavailable(self):
        for side in (sdk_response([], "refusal"), ConnectionError("x")):
            create = mock.Mock(side_effect=[side] if isinstance(side, Exception) else None, return_value=side)
            client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
            with self.assertRaises(ws.SearchUnavailable):
                ws.ClaudeSearch(client=client).ask("q?")


class ApiTest(unittest.TestCase):
    def load(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("visibility_api_probe", ROOT / "api" / "visibility.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_probe_inputs_are_validated(self):
        api = self.load()
        ok = api.probe_input({"brand": "Groomly", "category": "booking software", "country": "gb",
                              "competitors": ["Fresha"]}, "https://www.groomly.test/")
        self.assertEqual((ok.brand, ok.domain, ok.country), ("Groomly", "groomly.test", "GB"))
        self.assertIsNone(api.probe_input(None, "https://x.test"))
        for bad in ({"brand": "", "category": "x"}, {"brand": "x" * 81, "category": "y"},
                    {"brand": "a", "category": "b", "competitors": ["1", "2", "3", "4"]},
                    {"brand": "a", "category": "b", "country": "GBR"}, "nope"):
            with self.subTest(bad), self.assertRaises(ValueError):
                api.probe_input(bad, "https://x.test")

    def test_no_key_no_probe(self):
        with mock.patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("ANTHROPIC_API_KEY", None)
            self.assertIsNone(self.load().prober())

    def test_with_a_key_the_probe_is_capped(self):
        with mock.patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-not-real"}):
            api = self.load()
            search = api.prober()
        self.assertIs(search.limiter, api.PROBE_LIMITER)
        self.assertFalse(api.PROBE_LIMITER.disabled)


class CliTest(unittest.TestCase):
    def test_brand_needs_a_category_and_a_site(self):
        from vibecheck.cli import main
        for argv in (["--visibility", "https://x.test", "--brand", "X"], ["--brand", "X", "--category", "y"]):
            with self.subTest(argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(argv)


if __name__ == "__main__":
    unittest.main()
