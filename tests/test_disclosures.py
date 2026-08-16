"""Tests for the disclosure draft generator.

These are contact with strangers about their security, generated in bulk. The
failure modes are not crashes — they're a draft that leaks a credential, a
critical finding silently dropped from the run, or a repo contacted twice.
"""

import contextlib
import csv
import importlib.util
import io
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
spec = importlib.util.spec_from_file_location("prepare_disclosures", SCRIPTS / "prepare_disclosures.py")
prep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prep)


def finding(rule_id="stripe-live-secret-key", severity="critical", path="src/server.js", line=12):
    return {"rule_id": rule_id, "severity": severity, "path": path, "line": line}


class TestRepoSlug(unittest.TestCase):
    def test_https_url(self):
        self.assertEqual(prep.repo_slug("https://github.com/owner/name"), "owner/name")

    def test_dot_git_and_trailing_slash(self):
        self.assertEqual(prep.repo_slug("https://github.com/owner/name.git"), "owner/name")
        self.assertEqual(prep.repo_slug("https://github.com/owner/name/"), "owner/name")

    def test_ssh_url(self):
        self.assertEqual(prep.repo_slug("git@github.com:owner/name.git"), "owner/name")

    def test_non_github_is_not_a_slug(self):
        self.assertEqual(prep.repo_slug("https://gitlab.com/owner/name"), "")
        self.assertEqual(prep.repo_slug("/local/path"), "")


class TestDraftContent(unittest.TestCase):
    def setUp(self):
        self.when = date(2026, 9, 1)
        self.titles = {"stripe-live-secret-key": "Stripe LIVE secret key exposed"}

    def body(self, findings):
        # Collapsed, because the text is hard-wrapped and a phrase that
        # straddles a line break is still present in the message someone reads.
        text = prep.advisory_body("someone/app", findings, self.titles, self.when)
        return " ".join(text.split())

    def test_path_and_line_are_present_so_they_can_verify(self):
        text = self.body([finding()])
        self.assertIn("`src/server.js`", text)
        self.assertIn("line 12", text)

    def test_known_rule_uses_its_title(self):
        self.assertIn("Stripe LIVE secret key exposed", self.body([finding()]))

    def test_unknown_rule_still_reads_as_english(self):
        text = self.body([finding(rule_id="some-new-rule")])
        self.assertIn("Some new rule", text)
        self.assertNotIn("some-new-rule", text)

    def test_says_it_contains_no_credential(self):
        self.assertIn("not included the value of any credential", self.body([finding()]))

    def test_tells_them_to_rotate_not_delete(self):
        text = self.body([finding()])
        self.assertIn("rotate", text)
        self.assertIn("git history", text)

    def test_quotes_the_publication_date(self):
        self.assertIn("2026-09-01", self.body([finding()]))

    def test_makes_no_ask(self):
        text = self.body([finding()]).lower()
        self.assertIn("no reply is necessary", text)
        for pitch in ("psychosecurity", "vibecheck", "check out", "my tool"):
            self.assertNotIn(pitch, text)

    def test_findings_are_ordered_worst_first(self):
        text = self.body([
            finding(rule_id="a-low", severity="high", path="z.js"),
            finding(rule_id="b-crit", severity="critical", path="a.js"),
        ])
        self.assertLess(text.index("B crit"), text.index("A low"))

    def test_line_zero_is_omitted_rather_than_printed(self):
        text = self.body([finding(line=0)])
        self.assertIn("`src/server.js`", text)
        self.assertNotIn("line 0", text)

    def test_severity_maps_to_github_levels(self):
        self.assertEqual(prep.advisory_payload("a/b", [finding()], {}, self.when)["severity"], "critical")
        self.assertEqual(
            prep.advisory_payload("a/b", [finding(severity="high")], {}, self.when)["severity"], "high")


class TestRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "disclosure.jsonl"
        self.out = self.root / "drafts"

    def write_source(self, rows):
        self.source.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    def run_it(self, *extra):
        # The script reports to stdout; tests assert on files, not chatter.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return prep.main(["--disclosures", str(self.source), "--out", str(self.out), *extra])

    def tracker(self):
        with open(self.out / "tracker.csv", newline="", encoding="utf-8") as fh:
            return {row["repo"]: row for row in csv.DictReader(fh)}

    def test_one_draft_per_repo(self):
        self.write_source([
            {"repo": "https://github.com/a/one", "findings": [finding()]},
            {"repo": "https://github.com/b/two", "findings": [finding(severity="high")]},
        ])
        self.assertEqual(self.run_it(), 0)
        self.assertTrue((self.out / "a__one.md").exists())
        self.assertTrue((self.out / "b__two.md").exists())

    def test_repos_below_the_threshold_are_not_contacted(self):
        self.write_source([{"repo": "https://github.com/a/one", "findings": [finding(severity="medium")]}])
        self.run_it()
        self.assertEqual(list(self.out.glob("*.md")), [])

    def test_only_the_qualifying_findings_appear(self):
        self.write_source([{"repo": "https://github.com/a/one", "findings": [
            finding(rule_id="big-one", severity="critical", path="a.js"),
            finding(rule_id="small-one", severity="low", path="b.js"),
        ]}])
        self.run_it()
        text = (self.out / "a__one.md").read_text()
        self.assertIn("Big one", text)
        self.assertNotIn("Small one", text)

    def test_tracker_lists_every_drafted_repo(self):
        self.write_source([
            {"repo": "https://github.com/a/one", "findings": [finding()]},
            {"repo": "https://github.com/b/two", "findings": [finding(severity="high")]},
        ])
        self.run_it()
        rows = self.tracker()
        self.assertEqual(set(rows), {"a/one", "b/two"})
        self.assertEqual(rows["a/one"]["worst_severity"], "critical")
        self.assertEqual(rows["a/one"]["status"], "drafted")

    def test_rerunning_does_not_lose_what_you_recorded(self):
        self.write_source([{"repo": "https://github.com/a/one", "findings": [finding()]}])
        self.run_it()
        path = self.out / "tracker.csv"
        rows = self.tracker()
        rows["a/one"].update(status="reported", reported_on="2026-08-16",
                             advisory_url="https://example/1")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=prep.TRACKER_COLUMNS)
            writer.writeheader()
            writer.writerow(rows["a/one"])

        self.run_it()  # second pass
        after = self.tracker()["a/one"]
        self.assertEqual(after["status"], "reported")
        self.assertEqual(after["reported_on"], "2026-08-16")
        self.assertEqual(after["advisory_url"], "https://example/1")

    def test_submit_refuses_without_yes(self):
        self.write_source([{"repo": "https://github.com/a/one", "findings": [finding()]}])
        self.assertEqual(self.run_it("--submit"), 2)

    def test_already_reported_repos_are_not_contacted_again(self):
        self.write_source([{"repo": "https://github.com/a/one", "findings": [finding()]}])
        self.run_it()
        rows = self.tracker()
        rows["a/one"]["status"] = "reported"
        with open(self.out / "tracker.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=prep.TRACKER_COLUMNS)
            writer.writeheader()
            writer.writerow(rows["a/one"])

        calls = []
        original = prep.submit
        prep.submit = lambda slug, payload: calls.append(slug) or ("reported", "")
        self.addCleanup(setattr, prep, "submit", original)
        self.run_it("--submit", "--yes")
        self.assertEqual(calls, [], "a repo already reported must not be reported twice")

    def test_output_is_gitignored_and_locked_down(self):
        self.write_source([{"repo": "https://github.com/a/one", "findings": [finding()]}])
        self.run_it()
        self.assertEqual((self.out / ".gitignore").read_text().strip(), "*")
        self.assertEqual(oct((self.out / "tracker.csv").stat().st_mode)[-3:], "600")
        self.assertEqual(oct(self.out.stat().st_mode)[-3:], "700")

    def test_missing_source_is_an_error_not_a_traceback(self):
        self.assertEqual(self.run_it(), 1)

    def test_publish_date_is_the_window_from_today(self):
        self.write_source([{"repo": "https://github.com/a/one", "findings": [finding()]}])
        self.run_it("--publish-after", "21")
        expected = (date.today() + timedelta(days=21)).isoformat()
        self.assertIn(expected, (self.out / "a__one.md").read_text())


if __name__ == "__main__":
    unittest.main()
