"""Tests for the writeup filler.

The template's own header says it: "a security post with invented statistics
is worse than no post". Every failure mode here ends with a number in a
published document that nothing produced — a placeholder quietly replaced by a
default, a missing rule silently skipped, a float rendered as 71.0 next to a
sentence claiming precision it doesn't have. So the filler's job is as much
about refusing as filling.
"""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
spec = importlib.util.spec_from_file_location("fill_writeup", SCRIPTS / "fill_writeup.py")
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


def aggregate(**over):
    base = {
        "repos_scanned": 192,
        "clean_pct": 12.0,
        "targets_attempted": 200,
        "targets_excluded": 8,
        "score": {"mean": 67.2, "median": 85.0, "min": 0, "max": 100},
        "repos_with_severity": {
            "critical": {"count": 11, "pct": 5.7},
            "high": {"count": 69, "pct": 35.9},
        },
        "rules": [
            {"rule_id": "env-file-not-gitignored", "repos_affected": 60,
             "repos_affected_pct": 31.3, "total_occurrences": 120},
            {"rule_id": "dangerously-allow-browser", "repos_affected": 40,
             "repos_affected_pct": 20.8, "total_occurrences": 55},
            {"rule_id": "cors-allow-all", "repos_affected": 30,
             "repos_affected_pct": 15.6, "total_occurrences": 44},
            {"rule_id": "eval-usage", "repos_affected": 20,
             "repos_affected_pct": 10.4, "total_occurrences": 25},
            {"rule_id": "anthropic-api-key", "repos_affected": 11,
             "repos_affected_pct": 5.7, "total_occurrences": 14},
        ],
    }
    base.update(over)
    return base


class TestValues(unittest.TestCase):
    def test_numbers_come_from_the_file(self):
        v = fw.values_from(aggregate())
        self.assertEqual(v["N_REPOS"], 192)
        self.assertEqual(v["PCT_ANY_CRITICAL"], 5.7)
        self.assertEqual(v["PCT_ANY_HIGH"], 35.9)
        self.assertEqual(v["N_ANY_CRITICAL"], 11)

    def test_a_whole_number_median_is_not_rendered_with_a_decimal(self):
        # "the median score was 85.0 out of 100" reads like false precision.
        self.assertEqual(fw.values_from(aggregate())["MEDIAN_SCORE"], 85)

    def test_a_genuine_fraction_keeps_its_decimal(self):
        agg = aggregate()
        agg["score"]["median"] = 85.5
        self.assertEqual(fw.values_from(agg)["MEDIAN_SCORE"], 85.5)

    def test_disclosed_is_critical_plus_high_not_just_critical(self):
        # The disclosure run contacts everyone at or above high.
        self.assertEqual(fw.values_from(aggregate())["N_DISCLOSED"], 80)

    def test_rules_are_named_not_left_as_ids(self):
        # The post says "31.3% — .env file is not protected by .gitignore",
        # not "31.3% — env-file-not-gitignored".
        v = fw.values_from(aggregate())
        self.assertEqual(v["RULE_1_NAME"], ".env file is not protected by .gitignore")
        self.assertEqual(v["RULE_1_PCT"], 31.3)

    def test_an_unknown_rule_id_falls_back_to_the_id_rather_than_blank(self):
        agg = aggregate(rules=[{"rule_id": "not-a-real-rule", "repos_affected": 3,
                                "repos_affected_pct": 1.6, "total_occurrences": 3}])
        self.assertEqual(fw.values_from(agg)["RULE_1_NAME"], "not-a-real-rule")

    def test_missing_severities_produce_no_value_rather_than_zero(self):
        # A zero would read as "we checked and found none", which is a claim.
        agg = aggregate(repos_with_severity={})
        self.assertIsNone(fw.values_from(agg)["PCT_ANY_CRITICAL"])


class TestInfoRulesAreNotProblems(unittest.TestCase):
    """An info rule in a list headed "the most common problems" is a claim the
    scanner itself disagrees with — and, for the Supabase anon key, one the
    site's own guide spends a section refuting."""

    def rules_with_anon_key(self):
        return [
            {"rule_id": "env-file-not-gitignored", "repos_affected": 60,
             "repos_affected_pct": 31.3, "total_occurrences": 60},
            {"rule_id": "supabase-anon-key", "repos_affected": 34,
             "repos_affected_pct": 17.7, "total_occurrences": 40},
            {"rule_id": "cors-allow-all", "repos_affected": 30,
             "repos_affected_pct": 15.6, "total_occurrences": 44},
        ]

    def test_the_anon_key_is_not_listed_as_a_problem(self):
        kept, dropped = fw.problem_rules(self.rules_with_anon_key())
        self.assertEqual([r["rule_id"] for r in dropped], ["supabase-anon-key"])
        self.assertNotIn("supabase-anon-key", [r["rule_id"] for r in kept])

    def test_dropping_it_promotes_the_next_real_rule(self):
        agg = aggregate(rules=self.rules_with_anon_key())
        v = fw.values_from(agg)
        self.assertEqual(v["RULE_2_NAME"], "CORS allows every website")

    def test_severity_is_available_to_the_template(self):
        v = fw.values_from(aggregate())
        self.assertEqual(v["RULE_1_SEVERITY"], "high")

    def test_a_rule_of_unknown_severity_is_kept_rather_than_silently_dropped(self):
        # Losing a rule because its ID moved is worse than showing one too many.
        kept, dropped = fw.problem_rules([{"rule_id": "brand-new-rule",
                                           "repos_affected": 5,
                                           "repos_affected_pct": 2.6,
                                           "total_occurrences": 5}])
        self.assertEqual(len(kept), 1)
        self.assertEqual(dropped, [])

    def test_every_severity_resolves_for_every_rule_the_scanner_can_emit(self):
        # The three programmatic rules used to live in a second list that the
        # manifest knew about and nothing else did.
        severities = fw.rule_severities()
        for rule_id in ("supabase-anon-key", "supabase-service-role-key", "env-file-not-gitignored"):
            with self.subTest(rule_id):
                self.assertIn(rule_id, severities)


class TestFill(unittest.TestCase):
    def test_a_placeholder_with_no_value_is_reported_not_guessed(self):
        text, missing = fw.fill("scanned {{N_REPOS}}, found {{NOT_A_THING}}",
                                {"N_REPOS": 192})
        self.assertEqual(missing, ["NOT_A_THING"])
        self.assertIn("{{NOT_A_THING}}", text)

    def test_a_none_value_counts_as_missing(self):
        _, missing = fw.fill("{{PCT_ANY_CRITICAL}}%", {"PCT_ANY_CRITICAL": None})
        self.assertEqual(missing, ["PCT_ANY_CRITICAL"])

    def test_zero_is_a_real_value_and_fills(self):
        text, missing = fw.fill("{{PCT_CLEAN}}% clean", {"PCT_CLEAN": 0})
        self.assertEqual(missing, [])
        self.assertEqual(text, "0% clean")

    def test_the_instructional_comment_is_dropped(self):
        stripped = fw.strip_draft_note("<!--\nDRAFT — do this first\n-->\n\n# title\n")
        self.assertTrue(stripped.startswith("# title"))

    def test_a_template_without_a_comment_is_untouched(self):
        self.assertEqual(fw.strip_draft_note("# title\n"), "# title\n")


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.agg = self.root / "aggregate.json"
        self.out = self.root / "post.md"

    def run_it(self, agg, template=None):
        self.agg.write_text(json.dumps(agg), encoding="utf-8")
        argv = ["--aggregate", str(self.agg), "--out", str(self.out)]
        if template:
            path = self.root / "t.md"
            path.write_text(template, encoding="utf-8")
            argv += ["--template", str(path)]
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = fw.main(argv)
        return code, buf.getvalue() + err.getvalue()

    def test_the_real_template_fills_completely(self):
        # If someone adds a placeholder to the template with no source in
        # aggregate.json, this is where it surfaces — not in a published post.
        code, output = self.run_it(aggregate())
        self.assertEqual(code, 0, output)
        text = self.out.read_text(encoding="utf-8")
        self.assertNotIn("{{", text)
        self.assertIn("192", text)

    def test_it_refuses_to_write_when_something_is_missing(self):
        code, output = self.run_it(aggregate(), template="i scanned {{WHAT}} apps")
        self.assertEqual(code, 1)
        self.assertIn("WHAT", output)
        self.assertFalse(self.out.exists(), "wrote a post with a hole in it")

    def test_too_few_top_rules_is_a_refusal_not_a_gap(self):
        agg = aggregate(rules=aggregate()["rules"][:1])
        code, output = self.run_it(agg)
        self.assertEqual(code, 1)
        self.assertIn("RULE_2_NAME", output)
        self.assertFalse(self.out.exists())

    def test_the_output_carries_the_do_not_publish_yet_note(self):
        self.run_it(aggregate())
        self.assertIn("14 days", self.out.read_text(encoding="utf-8"))

    def test_a_corrupt_aggregate_is_an_error_not_a_traceback(self):
        self.agg.write_text("{not json", encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = fw.main(["--aggregate", str(self.agg), "--out", str(self.out)])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
