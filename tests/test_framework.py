"""The shared check framework (vibecheck/core) and the two checks on it.

The security scan moved onto the framework with no change in behaviour: its
own tests run untouched, and these check that the plugin reports exactly
what the scanner always has.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from vis_fakes import NOW, healthy_site  # noqa: E402

from vibecheck.checks.security import CATEGORIES as SEC_CATEGORIES  # noqa: E402
from vibecheck.checks.security import CHECK as SECURITY  # noqa: E402
from vibecheck.checks.security import GUIDES, RULE_CATEGORY  # noqa: E402
from vibecheck.checks.visibility import CHECK as VISIBILITY  # noqa: E402
from vibecheck.core import fetcher as core_fetcher  # noqa: E402
from vibecheck.core import registry, report  # noqa: E402
from vibecheck.core.models import Category, Check, Context, Finding, Target  # noqa: E402
from vibecheck.core.scoring import badge_level, category_scores, grade_for, weighted_total  # noqa: E402
from vibecheck.core.walker import git_commit, walk  # noqa: E402
from vibecheck.scanner import scan, scan_files  # noqa: E402
from vibecheck.urlscan import Response, scan_url  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "vibecheck" / "checks" / "security" / "fixtures" / "sample-app"


class PluginContractTest(unittest.TestCase):
    def test_every_check_satisfies_the_protocol(self):
        for check in registry.checks().values():
            with self.subTest(check.id):
                self.assertIsInstance(check, Check)
                self.assertRegex(check.version, r"^\d+\.\d+\.\d+$")
                self.assertTrue(check.inputs <= {"url", "repo"} and check.inputs)
                self.assertTrue(all(isinstance(c, Category) and c.weight > 0 for c in check.categories))

    def test_registry_offers_only_what_a_target_can_satisfy(self):
        ids = lambda t: [c.id for c in registry.available_for(t)]  # noqa: E731
        self.assertEqual(ids(Target(repo=".")), ["security"])
        self.assertEqual(ids(Target(url="https://x.test")), ["security", "visibility"])
        self.assertEqual(ids(Target(files=[("a.py", "x")])), ["security"])
        with self.assertRaises(KeyError):
            registry.get("integrity")

    def test_target_records_what_was_scanned(self):
        t = Target(url="https://x.test/", repo="/tmp/app", commit="a" * 40)
        self.assertEqual(t.inputs, {"url", "repo"})
        self.assertEqual(t.to_dict(), {"url": "https://x.test/", "repo": "/tmp/app", "commit": "a" * 40})


class SecurityMoveTest(unittest.TestCase):
    """The plugin is a wrapper: same findings, same Vibe Score."""

    def test_folder_scan_matches_the_scanner(self):
        legacy = scan(str(SAMPLE))
        result = SECURITY.run(Target(repo=str(SAMPLE)), Context(guard=False, now=NOW))
        self.assertEqual(result.total, legacy.score)
        self.assertEqual([(f.id, f.severity, f.path, f.line, f.evidence, f.fix_prompt) for f in result.findings],
                         [(f.rule_id, f.severity, f.path, f.line, f.excerpt, f.fix_prompt) for f in legacy.findings])
        self.assertEqual(result.meta["files_scanned"], legacy.files_scanned)
        self.assertEqual(result.check_id, "security")
        self.assertEqual(result.scanned_at, "2026-10-27T12:00:00Z")

    def test_uploaded_files_match_scan_files(self):
        files = [(p.relative_to(SAMPLE).as_posix(), p.read_text()) for p in SAMPLE.rglob("*") if p.is_file()]
        legacy = scan_files(files)
        result = SECURITY.run(Target(files=files), Context(now=NOW))
        self.assertEqual(result.total, legacy.score)
        self.assertEqual(len(result.findings), len(legacy.findings))

    def test_url_scan_matches_scan_url(self):
        pages = {"https://site.test/": Response(200, {"content-type": "text/html"}, "<html>hi</html>", "https://site.test/")}
        fake = lambda u, method="GET": pages.get(u) or Response(404, {}, "", u)  # noqa: E731
        legacy = scan_url("https://site.test", fake)
        result = SECURITY.run(Target(url="https://site.test"), Context(fetch_override=fake, now=NOW))
        self.assertEqual(result.total, legacy.score)
        self.assertEqual({f.id for f in result.findings}, {f.rule_id for f in legacy.findings})
        # A URL scan doesn't read code, so the injection category didn't run.
        self.assertIsNone(result.category_scores["injection"])
        self.assertIsNotNone(result.category_scores["config"])

    def test_unreachable_site_is_not_a_clean_bill(self):
        result = SECURITY.run(Target(url="https://down.test"), Context(fetch_override=lambda u, m="GET": None, now=NOW))
        self.assertIsNone(result.total)
        self.assertEqual(result.grade, "–")

    def test_url_scan_keeps_its_limits(self):
        with mock.patch.object(core_fetcher, "build_fetcher", return_value=lambda u, m="GET": None) as built:
            SECURITY.run(Target(url="https://x.test"), Context(guard=True, now=NOW))
        kw = built.call_args.kwargs
        self.assertEqual((kw["guard"], kw["timeout"], kw["max_bytes"], kw["max_redirects"]), (True, 6.0, 600_000, 3))

    def test_every_rule_has_a_category_and_known_guides(self):
        from generate_rules_manifest import build_manifest
        rule_ids = set(json.loads(json.dumps(build_manifest()))["rules"])
        self.assertEqual(rule_ids - set(RULE_CATEGORY), set(), "give each new rule a category")
        self.assertEqual(set(RULE_CATEGORY.values()) - {c.id for c in SEC_CATEGORIES}, set())
        for guide in set(GUIDES.values()) | {"/guides/api-key-leaked"}:
            self.assertTrue((ROOT / (guide.lstrip("/") + ".html")).exists(), guide)

    def test_secret_findings_point_at_a_guide(self):
        result = SECURITY.run(Target(repo=str(SAMPLE)), Context(now=NOW))
        llm = next(f for f in result.findings if f.id == "dangerously-allow-browser")
        self.assertEqual(llm.guide_url, "/guides/openai-api-key-exposed")
        self.assertTrue(all(f.verify_hint for f in result.findings if f.fix_prompt))


class ScoringTest(unittest.TestCase):
    CATS = [Category("a", "A", 1.0), Category("b", "B", 3.0), Category("c", "C", 1.0)]

    def f(self, severity, category="a"):
        return Finding(id="x", check_id="t", category=category, severity=severity, title="x")

    def test_category_scores(self):
        scores = category_scores([self.f("high"), self.f("low"), self.f("pass"), self.f("medium", "b")],
                                 self.CATS, ran={"a", "b"})
        self.assertEqual(scores, {"a": 5, "b": 8, "c": None})

    def test_weighted_total_ignores_categories_that_did_not_run(self):
        self.assertEqual(weighted_total({"a": 5, "b": 8, "c": None}, self.CATS), round((5 + 24) / 4 * 10))
        self.assertIsNone(weighted_total({"a": None, "b": None, "c": None}, self.CATS))

    def test_grades(self):
        self.assertEqual([grade_for(s) for s in (100, 90, 89, 60, 39, None)], ["A", "A", "B", "C", "F", "–"])

    def test_badge_levels_need_a_score_and_no_open_criticals(self):
        self.assertEqual(badge_level(90, ["low"]), "gold")
        self.assertEqual(badge_level(90, ["high"]), "silver")
        self.assertEqual(badge_level(72, ["medium"]), "silver")
        self.assertEqual(badge_level(60, []), "bronze")
        self.assertIsNone(badge_level(99, ["critical"]))
        self.assertIsNone(badge_level(49, []))
        self.assertIsNone(badge_level(None, []))
        self.assertEqual(badge_level(85, ["pass", "info"]), "gold")


class WalkerTest(unittest.TestCase):
    def test_skips_dependencies_and_marks_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "node_modules" / "x").mkdir(parents=True)
            (root / "node_modules" / "x" / "i.js").write_text("eval(1)")
            (root / "src").mkdir()
            (root / "src" / "a.js").write_text("ok")
            (root / "package-lock.json").write_text("{}")
            (root / "ignored.js").write_text("x")
            (root / ".vibecheckignore").write_text("ignored.js\n")
            got = {e.rel: e.skipped for e in walk(root)}
        self.assertEqual(got, {"src/a.js": False, "package-lock.json": True, ".vibecheckignore": False})

    def test_reads_the_commit_without_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git" / "refs" / "heads").mkdir(parents=True)
            (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
            self.assertIsNone(git_commit(root))
            (root / ".git" / "packed-refs").write_text("# pack-refs\n" + "b" * 40 + " refs/heads/main\n")
            self.assertEqual(git_commit(root), "b" * 40)
            (root / ".git" / "refs" / "heads" / "main").write_text("c" * 40 + "\n")
            self.assertEqual(git_commit(root), "c" * 40)
        self.assertIsNone(git_commit(Path("/nonexistent")))


class ReportTest(unittest.TestCase):
    def results(self):
        site = healthy_site()
        ctx = Context(fetch_override=site.fetch, now=NOW)
        return [SECURITY.run(Target(url="https://groomly.test"), ctx),
                VISIBILITY.run(Target(url="https://groomly.test"), ctx)]

    def test_one_renderer_for_any_check(self):
        for r in self.results():
            with self.subTest(r.check_id):
                text = report.render_terminal(r, use_color=False)
                self.assertIn(r.check_id.title(), text)
                md = report.render_markdown(r)
                self.assertIn("| Category | Score |", md)
                json.dumps(r.to_dict())

    def test_combined_report(self):
        results = self.results()
        md = report.render_combined_markdown(results)
        self.assertIn("| Security |", md)
        self.assertIn("| Visibility |", md)
        d = report.to_json(results)
        self.assertEqual([r["check_id"] for r in d["results"]], ["security", "visibility"])

    def test_round_trip(self):
        r = self.results()[1]
        again = [Finding.from_dict(f) for f in r.to_dict()["findings"]]
        self.assertEqual(again, r.findings)


class CliTest(unittest.TestCase):
    def run_cli(self, *argv, site=None):
        from vibecheck import cli
        out, err = io.StringIO(), io.StringIO()
        patch = mock.patch.object(core_fetcher, "build_fetcher", return_value=(site or healthy_site()).fetch)
        with patch, redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_checks_flag_runs_several_with_one_exit_code(self):
        code, out, _ = self.run_cli("https://groomly.test", "--checks", "security,visibility", "--json")
        d = json.loads(out)
        self.assertEqual([r["check_id"] for r in d["results"]], ["security", "visibility"])
        self.assertEqual(code, 0)

    def test_a_url_runs_every_url_check_by_default(self):
        _code, out, _ = self.run_cli("groomly.test", "--no-color")
        self.assertIn("SECURITY:", out)
        self.assertIn("VISIBILITY: 100/100", out)

    def test_folder_with_a_url_check_skips_it_and_says_so(self):
        code, out, err = self.run_cli(str(SAMPLE), "--checks", "security,visibility", "--no-color")
        self.assertIn("skipping visibility", err)
        self.assertIn("SECURITY: 36/100", out)
        self.assertEqual(code, 1, "the sample app has a critical finding")

    def test_folder_and_url_together(self):
        _code, out, _ = self.run_cli(str(SAMPLE), "--url", "https://groomly.test",
                                     "--checks", "security,visibility", "--json")
        d = json.loads(out)
        self.assertEqual(d["target"]["url"], "https://groomly.test")
        self.assertIn("sample-app", d["target"]["repo"])

    def test_legacy_invocations_are_unchanged(self):
        code, out, _ = self.run_cli(str(SAMPLE), "--no-color")
        self.assertIn("VIBE SCORE: 36/100", out)
        self.assertEqual(code, 1)

    def test_unknown_check(self):
        with self.assertRaises(SystemExit):
            self.run_cli(".", "--checks", "integrity")

    def test_markdown_of_several(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.md"
            self.run_cli("https://groomly.test", "--checks", "security,visibility", "--markdown", str(path))
            self.assertIn("# vibecheck report", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
