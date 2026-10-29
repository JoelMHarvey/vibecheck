"""The footprint's plain searches through Serper, and the hosted API's choice
of model and search for phases 3 and 4."""

import json
import os
import sys
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_probe import INPUT, FakeSearch, finding, passes, run  # noqa: E402

from vibecheck.checks.visibility import probe as pr  # noqa: E402
from vibecheck.checks.visibility import serper as sp  # noqa: E402
from vibecheck.checks.visibility import websearch as ws  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class FakeFinder:
    """Plain search: answers from a table of query -> results."""

    def __init__(self, listed=("producthunt.com",), elsewhere=("reddit.com", "dogtimes.test"), exc=None):
        self.listed, self.elsewhere, self.exc = listed, elsewhere, exc
        self.queries = []
        self.lock = threading.Lock()

    def results(self, query, num=10):
        with self.lock:
            self.queries.append((query, num))
        if self.exc:
            raise self.exc
        if query.startswith("site:"):
            host = query.split()[0][len("site:"):]
            if host in self.listed:
                return [{"url": f"https://www.{host}/products/groomly", "title": "Groomly"}]
            return [{"url": f"https://www.{host}/categories/pets", "title": "Pet software"}]
        return ([{"url": f"https://{h}/groomly-review", "title": "Groomly review"} for h in self.elsewhere]
                + [{"url": "https://groomly.test/", "title": "Groomly"}])


class SerperSearchTest(unittest.TestCase):
    def test_posts_the_query_and_reads_the_organic_results(self):
        sent = {}

        def post(url, body, headers, timeout):
            sent.update(url=url, body=json.loads(body), headers=headers)
            return json.dumps({"organic": [
                {"title": "Groomly on Product Hunt", "link": "https://www.producthunt.com/products/groomly"},
                {"title": "dupe", "link": "https://www.producthunt.com/products/groomly"},
                {"title": "no link"},
                {"title": "not a web page", "link": "javascript:alert(1)"},
            ], "knowledgeGraph": {}}).encode()

        search = sp.SerperSearch("k3y", post=post)
        out = search.results('site:producthunt.com "Groomly"', num=5)
        self.assertEqual(out, [{"url": "https://www.producthunt.com/products/groomly",
                                "title": "Groomly on Product Hunt"}])
        self.assertEqual(sent["url"], "https://google.serper.dev/search")
        self.assertEqual(sent["body"], {"q": 'site:producthunt.com "Groomly"', "num": 5})
        self.assertEqual(sent["headers"]["X-API-KEY"], "k3y")
        self.assertEqual(search.searches, 1)

    def test_failures_are_unavailable_not_crashes(self):
        for exc in (urllib.error.HTTPError("u", 403, "Forbidden", {}, None), TimeoutError(), ValueError("bad json")):
            def post(*_a, exc=exc):
                raise exc
            with self.subTest(exc=type(exc).__name__), self.assertRaises(ws.SearchUnavailable):
                sp.SerperSearch("k", post=post).results("q")

    def test_odd_responses_give_no_results(self):
        for body in (b"[]", b'{"organic": null}', b'{"organic": ["x", 1]}'):
            self.assertEqual(sp.SerperSearch("k", post=lambda *a, b=body: b).results("q"), [])


class FootprintThroughSerperTest(unittest.TestCase):
    def test_seven_plain_searches_and_no_claude_calls_for_the_footprint(self):
        search, finder = FakeSearch(), FakeFinder()
        from vibecheck.checks.visibility import scan_visibility
        from test_probe import NOW, healthy_site
        result = scan_visibility("groomly.test", healthy_site().fetch, now=NOW, search=search,
                                 probe_input=INPUT, finder=finder)
        # Claude got only the five buyer questions.
        self.assertEqual(len(search.asked), pr.QUESTIONS)
        self.assertFalse(any(q.startswith("Search") for q, _, _ in search.asked))
        queries = [q for q, _ in finder.queries]
        self.assertEqual(len(queries), 7)
        self.assertIn('"Groomly"', queries)
        self.assertIn('site:g2.com "Groomly"', queries)
        fp = result.meta["footprint"]
        self.assertEqual(fp["status"], "searched (Google, through Serper)")
        self.assertEqual(fp["listed"], ["Product Hunt", "Reddit"])
        self.assertIn("G2", fp["missing"])
        self.assertIn("offsite-listed", passes(result))
        # A directory's category page isn't a listing.
        self.assertNotIn("G2", fp["listed"])
        self.assertIn("G2", finding(result, "offsite-missing-listings").evidence)

    def test_a_search_outage_skips_only_the_footprint(self):
        from vibecheck.checks.visibility import scan_visibility
        from test_probe import NOW, healthy_site
        result = scan_visibility("groomly.test", healthy_site().fetch, now=NOW, search=FakeSearch(),
                                 probe_input=INPUT, finder=FakeFinder(exc=ws.SearchUnavailable("down")))
        self.assertEqual(result.meta["footprint"]["status"], "not run: down")
        self.assertEqual(result.meta["probe"]["status"], "asked")
        self.assertIsNone(result.category_scores["offsite"])

    def test_without_a_finder_claude_still_does_it(self):
        result = run(FakeSearch())
        self.assertEqual(result.meta["footprint"]["status"], "searched")

    def test_the_probe_caps_searches_per_question(self):
        search = mock.Mock()
        search.ask.return_value = ws.Answer("q", "Fresha.", [], [])
        from types import SimpleNamespace
        scan = SimpleNamespace(add=lambda *a: None, ok=lambda *a: None, ran=set())
        pr.run_probe(scan, search, INPUT)
        self.assertEqual({c.kwargs["max_uses"] for c in search.ask.call_args_list}, {pr.SEARCHES})
        self.assertEqual(pr.SEARCHES, 2)


class ApiChoiceTest(unittest.TestCase):
    def load(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("visibility_api_serper", ROOT / "api" / "visibility.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_probe_model_defaults_to_haiku_and_takes_a_claude_id(self):
        api = self.load()
        for value, want in (("", "claude-haiku-5-5"), ("claude-opus-5-5", "claude-opus-5-5"),
                            ("gpt-5", "claude-haiku-5-5"), ("claude-x; rm -rf /", "claude-haiku-5-5")):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"VIBECHECK_PROBE_MODEL": value}):
                self.assertEqual(api.probe_model(), want)

    def test_serper_only_when_keyed(self):
        api = self.load()
        with mock.patch.dict(os.environ, {"SERPER_API_KEY": ""}):
            self.assertIsNone(api.finder())
        with mock.patch.dict(os.environ, {"SERPER_API_KEY": " abc "}):
            self.assertEqual(api.finder().key, "abc")

    def test_the_scan_gets_both_when_keyed(self):
        api = self.load()
        seen = {}

        class Check:
            def run(self, target, ctx):
                seen.update(ctx.options)
                return "result"

        env = {"ANTHROPIC_API_KEY": "x", "SERPER_API_KEY": "y", "VIBECHECK_PROBE_MODEL": "claude-sonnet-5-5"}
        with mock.patch.dict(os.environ, env), mock.patch.object(api, "CHECK", Check()):
            api.scan("https://groomly.test", INPUT)
        self.assertEqual(seen["probe"][0].model, "claude-sonnet-5-5")
        self.assertIsInstance(seen["footprint"], sp.SerperSearch)


if __name__ == "__main__":
    unittest.main()
