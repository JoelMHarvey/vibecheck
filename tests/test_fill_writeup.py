"""Tests for the writeup filler.

The template's own header says it: "a security post with invented statistics
is worse than no post". Every failure mode here ends with a number in a
published document that nothing produced — a placeholder quietly replaced by a
default, a missing rule silently skipped, a float rendered as 71.0 next to a
sentence claiming precision it doesn't have. So the filler's job is as much
about refusing as filling.
"""

import contextlib
import csv
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
spec = importlib.util.spec_from_file_location("fill_writeup", SCRIPTS / "fill_writeup.py")
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


def aggregate(**over):
    base = {
        "repos_scanned": 189,
        "clean_pct": 12.0,
        "repos_at_or_above_high": 71,
        "targets_attempted": 200,
        "targets_excluded": 7,
        "targets_failed": 4,
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
        self.assertEqual(v["N_REPOS"], 189)
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

    def test_disclosed_comes_from_the_scan_and_is_never_added_up(self):
        # Severity counts overlap: a repo with a critical and a high is in
        # both. 11 + 69 is 80, but the disclosure run found 71 repos, because
        # nine of them are in both buckets. Adding them invents nine projects.
        agg = aggregate(repos_at_or_above_high=71)
        self.assertEqual(fw.values_from(agg)["N_DISCLOSED"], 71)

    def test_an_aggregate_without_the_union_yields_no_value_at_all(self):
        # An older aggregate.json predates the field. No number is correct
        # here, so the filler must have none rather than reach for the sum.
        old = aggregate()
        del old["repos_at_or_above_high"]
        self.assertIsNone(fw.values_from(old)["N_DISCLOSED"])

    def test_the_disclosure_file_can_supply_it_instead_of_a_rescan(self):
        old = aggregate()
        del old["repos_at_or_above_high"]
        self.assertEqual(fw.values_from(old, disclosed=71)["N_DISCLOSED"], 71)

    def test_the_aggregate_wins_over_the_fallback(self):
        self.assertEqual(fw.values_from(aggregate(), disclosed=999)["N_DISCLOSED"], 71)


class TestDisclosureFileCount(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "disclosure.jsonl"

    def test_one_row_per_repo(self):
        self.path.write_text('{"repo":"a/b"}\n{"repo":"c/d"}\n', encoding="utf-8")
        self.assertEqual(fw.count_disclosures(self.path), 2)

    def test_blank_lines_are_not_repos(self):
        self.path.write_text('{"repo":"a/b"}\n\n\n', encoding="utf-8")
        self.assertEqual(fw.count_disclosures(self.path), 1)

    def test_a_missing_file_is_not_a_zero(self):
        # Zero would read as "nobody needed telling", which is a claim.
        self.assertIsNone(fw.count_disclosures(self.path))

    def test_an_empty_file_is_not_a_zero_either(self):
        self.path.write_text("", encoding="utf-8")
        self.assertIsNone(fw.count_disclosures(self.path))

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


class TestSampleAccounting(unittest.TestCase):
    """An exclusion and a failure are not the same thing.

    An exclusion is a filter that was chosen — a prompt directory with no
    application code, which would score 100 and mean nothing. A clone failure
    is a hole: probably a real app, contents unknown. Reporting the second as
    the first describes the sample as tidier than it was, in the one section
    of the post whose whole job is admitting what it doesn't cover.
    """

    def test_both_counts_are_available(self):
        v = fw.values_from(aggregate())
        self.assertEqual(v["N_EXCLUDED"], 7)
        self.assertEqual(v["N_FAILED"], 4)

    def test_they_account_for_the_whole_gap(self):
        # scanned + excluded + failed must equal attempted, or the caveat
        # leaves repos unaccounted for and a reader can spot it.
        v = fw.values_from(aggregate())
        self.assertEqual(v["N_REPOS"] + v["N_EXCLUDED"] + v["N_FAILED"],
                         v["N_ATTEMPTED"])

    def test_no_failures_is_zero_not_missing(self):
        # Zero is a real answer — everything cloned. It must fill, not refuse.
        v = fw.values_from(aggregate(targets_failed=0))
        self.assertEqual(v["N_FAILED"], 0)

    def test_an_aggregate_predating_the_field_refuses(self):
        old = aggregate()
        del old["targets_failed"]
        self.assertIsNone(fw.values_from(old)["N_FAILED"])


class TestRulesAddressableByName(unittest.TestCase):
    """Prose has to be able to cite a rule that didn't make the top five.

    The innerHTML caveat compares the escalated variant to the vague one, and
    only the vague one ranks. A comparison the reader can't see the second
    half of is an assertion, not evidence.
    """

    def test_a_rule_is_addressable_by_its_id(self):
        v = fw.values_from(aggregate())
        self.assertEqual(v["RULE_ENV_FILE_NOT_GITIGNORED_PCT"], 31.3)
        self.assertEqual(v["RULE_ENV_FILE_NOT_GITIGNORED_REPOS"], 60)
        self.assertEqual(v["RULE_ENV_FILE_NOT_GITIGNORED_SEVERITY"], "high")

    def test_the_name_is_the_human_title(self):
        v = fw.values_from(aggregate())
        self.assertEqual(v["RULE_CORS_ALLOW_ALL_NAME"], "CORS allows every website")

    def test_a_rule_that_fired_nowhere_is_zero(self):
        # Zero is a real answer: the scanner looked and found none.
        v = fw.values_from(aggregate(rules=[]))
        self.assertEqual(v["RULE_CORS_ALLOW_ALL_PCT"], 0)
        self.assertEqual(v["RULE_CORS_ALLOW_ALL_REPOS"], 0)

    def test_a_name_that_is_not_a_rule_gets_nothing(self):
        # So a typo in the template fails the run rather than reading as 0%.
        v = fw.values_from(aggregate())
        self.assertNotIn("RULE_CORS_ALOW_ALL_PCT", v)

    def test_it_does_not_collide_with_the_ranked_slots(self):
        # Rule IDs never start with a digit, so RULE_1_PCT stays the top of
        # the list rather than a rule called "1".
        v = fw.values_from(aggregate())
        self.assertEqual(v["RULE_1_NAME"], ".env file is not protected by .gitignore")
        self.assertNotEqual(v["RULE_1_NAME"], v["RULE_CORS_ALLOW_ALL_NAME"])

    def test_the_stem_is_derived_from_the_id(self):
        self.assertEqual(fw.placeholder_stem("innerhtml-untrusted-input"),
                         "RULE_INNERHTML_UNTRUSTED_INPUT")

    def test_every_rule_the_scanner_can_emit_is_addressable(self):
        # Including the ones built programmatically, which have historically
        # been the ones left out of a second list.
        v = fw.values_from(aggregate())
        for rule_id in ("supabase-service-role-key", "supabase-anon-key",
                        "env-file-not-gitignored", "innerhtml-untrusted-input"):
            with self.subTest(rule_id):
                self.assertIn(f"{fw.placeholder_stem(rule_id)}_PCT", v)


class TestTheStatedWeightsAreTheRealOnes(unittest.TestCase):
    """The post prints the scoring weights as prose, so they can drift.

    It says the score takes off 25 for a critical, 15 for a high, 7 for a
    medium and 3 for a low, and uses that to argue the median is partly an
    artefact of choices the author made. If someone retunes the weights, that
    paragraph becomes a confident false statement in the caveats section —
    the worst place in the piece to have one.
    """

    def template(self):
        text = (ROOT / "content" / "scanned-vibe-coded-apps.md").read_text(
            encoding="utf-8")
        return " ".join(text.split())   # the paragraph rewraps; the claim doesn't

    def test_the_claim_is_still_in_the_post(self):
        self.assertIn("takes off 25 for a critical, 15 for a high, "
                      "7 for a medium, 3 for a low", self.template(),
                      "the caveat's wording moved — re-check it against "
                      "SEVERITY_WEIGHTS by hand")

    def test_those_are_the_weights_the_scanner_uses(self):
        from vibecheck.rules import SEVERITY_WEIGHTS
        for severity, points in (("critical", 25), ("high", 15),
                                 ("medium", 7), ("low", 3)):
            with self.subTest(severity):
                self.assertEqual(
                    SEVERITY_WEIGHTS[severity], points,
                    f"{severity} is now {SEVERITY_WEIGHTS[severity]}, but the "
                    f"writeup still tells readers it is {points}")


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

    def tracker(self, reported=11, bounced=0, other=0, severity="critical"):
        """A tracker whose critical rows add up to the scan's count."""
        path = self.root / "tracker.csv"
        rows = ([("reported", i) for i in range(reported)]
                + [("bounced", 100 + i) for i in range(bounced)]
                + [("drafted", 200 + i) for i in range(other)])
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["repo", "worst_severity", "findings", "status",
                             "reported_on", "advisory_url", "note"])
            for status, i in rows:
                writer.writerow([f"o/r{i}", severity, 1, status, "", "", ""])
        return path

    def run_it(self, agg, template=None, tracker=None, **tracker_kw):
        self.agg.write_text(json.dumps(agg), encoding="utf-8")
        argv = ["--aggregate", str(self.agg), "--out", str(self.out),
                "--tracker", str(tracker or self.tracker(**tracker_kw))]
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
        self.assertIn("189", text)

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


class TestContactCounts(unittest.TestCase):
    """Who was actually told, read from the tracker rather than asserted.

    The post said "i contacted those maintainers privately" for five days while
    three of eleven messages had bounced — two addresses that don't exist and a
    domain that doesn't resolve. Nothing caught it because the claim was prose,
    and prose isn't checked against anything. So it is a number now.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "tracker.csv"

    def write(self, rows, severity="critical"):
        with open(self.path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["repo", "worst_severity", "findings", "status",
                             "reported_on", "advisory_url", "note"])
            for i, (status, sev) in enumerate(rows):
                writer.writerow([f"o/r{i}", sev or severity, 1, status, "", "", ""])

    def test_reported_rows_are_the_contacted_ones(self):
        self.write([("reported", None), ("reported", None), ("drafted", None)])
        self.assertEqual(fw.contact_counts(self.path)["N_CONTACTED"], 2)

    def test_bounced_rows_are_counted_as_unreachable(self):
        self.write([("reported", None), ("bounced", None), ("bounced", None)])
        counts = fw.contact_counts(self.path)
        self.assertEqual(counts["N_CONTACTED"], 1)
        self.assertEqual(counts["N_UNREACHABLE"], 2)

    def test_a_bounced_row_is_never_counted_as_contacted(self):
        # The whole bug, in one assertion.
        self.write([("bounced", None)])
        self.assertEqual(fw.contact_counts(self.path)["N_CONTACTED"], 0)

    def test_a_repo_with_no_route_is_unreachable_too(self):
        self.write([("unreachable", None)])
        self.assertEqual(fw.contact_counts(self.path)["N_UNREACHABLE"], 1)

    def test_drafted_is_neither(self):
        # Prepared and not sent. Counting it either way would be a claim.
        self.write([("drafted", None)])
        counts = fw.contact_counts(self.path)
        self.assertEqual((counts["N_CONTACTED"], counts["N_UNREACHABLE"]), (0, 0))

    def test_rows_below_critical_are_out_of_scope(self):
        self.write([("reported", "critical"), ("reported", "high")])
        self.assertEqual(fw.contact_counts(self.path)["N_CONTACTED"], 1)

    def test_a_missing_tracker_yields_nothing_not_zero(self):
        # Zero contacted would be a claim about the world. No tracker is an
        # absence of evidence, and it must stop the post rather than fill it.
        self.assertEqual(fw.contact_counts(Path("/nonexistent/tracker.csv")), {})

    def test_a_tracker_with_no_criticals_yields_nothing(self):
        self.write([("reported", "high")])
        self.assertEqual(fw.contact_counts(self.path), {})


class TestTheDenominatorComesFromTheScan(unittest.TestCase):
    """A critical repo the tracker never heard of must not vanish.

    Counting the tracker's own rows as the denominator would let a repo missing
    from it disappear from both halves of the fraction, and the post would
    claim complete coverage of a smaller world than the one it scanned.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "tracker.csv"

    def counts(self, reported, unreachable):
        return {"N_CONTACTED": reported, "N_UNREACHABLE": unreachable}

    def test_everyone_accounted_for_leaves_nothing_outstanding(self):
        v = fw.values_from(aggregate(), contacts=self.counts(8, 3))
        self.assertEqual(v["N_UNCONTACTED"], 0)

    def test_a_repo_the_tracker_does_not_know_about_is_uncontacted(self):
        # Scan found 11; tracker accounts for 10.
        v = fw.values_from(aggregate(), contacts=self.counts(8, 2))
        self.assertEqual(v["N_UNCONTACTED"], 1)

    def test_a_tracker_from_another_scan_shows_up_as_negative(self):
        v = fw.values_from(aggregate(), contacts=self.counts(11, 3))
        self.assertEqual(v["N_UNCONTACTED"], -3)

    def test_no_tracker_means_no_verdict_either_way(self):
        self.assertIsNone(fw.values_from(aggregate()).get("N_UNCONTACTED"))


class TestConditionalBlocks(unittest.TestCase):
    """The post has to be true under outcomes that need different sentences."""

    def test_a_zero_drops_the_block(self):
        # "0 i could not reach at all" is not a sentence anyone writes.
        out = fw.resolve_blocks("a{{?N}}b{{/N}}c", {"N": 0})
        self.assertEqual(out, "ac")

    def test_a_number_keeps_it(self):
        self.assertEqual(fw.resolve_blocks("a{{?N}}b{{/N}}c", {"N": 3}), "abc")

    def test_an_absent_value_drops_it(self):
        # It cannot be asserted, so it isn't.
        self.assertEqual(fw.resolve_blocks("a{{?N}}b{{/N}}c", {}), "ac")

    def test_placeholders_inside_a_kept_block_still_fill(self):
        text, missing = fw.fill("{{?N}}{{N}} unreachable{{/N}}", {"N": 3})
        self.assertEqual((text, missing), ("3 unreachable", []))

    def test_a_dropped_block_does_not_report_its_contents_as_missing(self):
        # Otherwise switching the block off would refuse to write the post.
        text, missing = fw.fill("{{?N}}{{N}} unreachable{{/N}}done", {"N": 0})
        self.assertEqual((text, missing), ("done", []))

    def test_the_real_template_says_nothing_about_unreachable_when_there_are_none(self):
        template = (ROOT / "content" / "scanned-vibe-coded-apps.md").read_text(
            encoding="utf-8")
        kept = fw.resolve_blocks(template, {"N_UNREACHABLE": 2})
        dropped = fw.resolve_blocks(template, {"N_UNREACHABLE": 0})
        self.assertIn("could not reach", kept)
        self.assertNotIn("could not reach", dropped)


class TestRefusingToOverclaim(unittest.TestCase):
    """The refusals that stop the post asserting a disclosure that didn't happen."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.agg = self.root / "aggregate.json"
        self.out = self.root / "post.md"

    def run_it(self, rows=None, tracker_path=None):
        self.agg.write_text(json.dumps(aggregate()), encoding="utf-8")
        path = tracker_path
        if path is None:
            path = self.root / "tracker.csv"
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["repo", "worst_severity", "findings", "status",
                                 "reported_on", "advisory_url", "note"])
                for i, status in enumerate(rows or []):
                    writer.writerow([f"o/r{i}", "critical", 1, status, "", "", ""])
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = fw.main(["--aggregate", str(self.agg), "--out", str(self.out),
                            "--tracker", str(path)])
        return code, buf.getvalue() + err.getvalue()

    def test_someone_untold_stops_the_post(self):
        code, output = self.run_it(["reported"] * 8 + ["bounced"] * 2)
        self.assertEqual(code, 1)
        self.assertIn("1", output)
        self.assertFalse(self.out.exists(), "published while someone was untold")

    def test_the_refusal_says_how_to_resolve_it(self):
        _, output = self.run_it(["reported"] * 8 + ["bounced"] * 2)
        self.assertIn("mark_reported.py --bounced", output)

    def test_a_tracker_from_a_different_scan_stops_the_post(self):
        code, output = self.run_it(["reported"] * 14)
        self.assertEqual(code, 1)
        self.assertIn("different run", output)
        self.assertFalse(self.out.exists())

    def test_no_tracker_at_all_stops_the_post(self):
        # Not a zero, not a pass. A disclosure claim needs something behind it.
        code, output = self.run_it(tracker_path=self.root / "absent.csv")
        self.assertEqual(code, 1)
        self.assertIn("N_CONTACTED", output)
        self.assertFalse(self.out.exists())

    def test_everyone_accounted_for_writes_the_post(self):
        code, output = self.run_it(["reported"] * 8 + ["bounced"] * 3)
        self.assertEqual(code, 0, output)
        text = self.out.read_text(encoding="utf-8")
        self.assertIn("i contacted 8 of", text)
        self.assertIn("3 i could not reach", text)

    def test_everyone_reached_leaves_the_caveat_out(self):
        code, output = self.run_it(["reported"] * 11)
        self.assertEqual(code, 0, output)
        text = self.out.read_text(encoding="utf-8")
        self.assertIn("i contacted 11 of", text)
        self.assertNotIn("could not reach", text)
