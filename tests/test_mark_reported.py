"""Tests for recording who was actually contacted.

Every failure here is quiet and one-directional. Marking a repo reported when
nobody was told leaves a row that looks finished, so that maintainer is never
chased and their live credential is never disclosed. Overwriting an existing
date restarts a disclosure window that had already run. Silently ignoring a
typo'd repo name means the one you meant to mark stays unmarked. None of
these announce themselves later — so they get asserted here.
"""

import contextlib
import csv
import importlib.util
import io
import os
import unittest
import tempfile
from unittest import mock
from datetime import date, timedelta
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
spec = importlib.util.spec_from_file_location("mark_reported", SCRIPTS / "mark_reported.py")
mr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mr)

TODAY = date.today()


class TrackerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tracker = Path(self.tmp.name) / "tracker.csv"

    def row(self, repo, severity="critical", status="reporting-disabled",
            reported_on="", note=""):
        return {"repo": repo, "worst_severity": severity, "findings": 3,
                "status": status, "reported_on": reported_on,
                "advisory_url": "", "note": note}

    def write(self, rows):
        mr.write_tracker(self.tracker, rows)

    def read(self):
        with open(self.tracker, newline="", encoding="utf-8") as fh:
            return {row["repo"]: row for row in csv.DictReader(fh)}

    def run_it(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = mr.main(["--tracker", str(self.tracker), "--yes", *argv])
        return code, buf.getvalue()


class TestPlanning(TrackerCase):
    def test_a_pending_repo_becomes_reported_today(self):
        self.write([self.row("a/one")])
        code, _ = self.run_it("a/one")
        self.assertEqual(code, 0)
        row = self.read()["a/one"]
        self.assertEqual(row["status"], "reported")
        self.assertEqual(row["reported_on"], TODAY.isoformat())

    def test_the_route_is_recorded_in_the_note(self):
        self.write([self.row("a/one")])
        self.run_it("a/one", "--route", "email")
        self.assertIn("contacted by email", self.read()["a/one"]["note"])

    def test_an_existing_note_is_kept(self):
        self.write([self.row("a/one", note="issues are off")])
        self.run_it("a/one")
        note = self.read()["a/one"]["note"]
        self.assertIn("issues are off", note)
        self.assertIn("contacted by email", note)

    def test_an_already_reported_repo_keeps_its_original_date(self):
        # The window runs from the first contact. Overwriting restarts it.
        self.write([self.row("a/one", status="reported", reported_on="2026-08-01")])
        self.run_it("a/one")
        self.assertEqual(self.read()["a/one"]["reported_on"], "2026-08-01")

    def test_repos_not_named_are_untouched(self):
        self.write([self.row("a/one"), self.row("b/two")])
        self.run_it("a/one")
        self.assertEqual(self.read()["b/two"]["status"], "reporting-disabled")

    def test_other_columns_survive_the_rewrite(self):
        self.write([self.row("a/one", severity="high")])
        self.run_it("a/one")
        row = self.read()["a/one"]
        self.assertEqual(row["worst_severity"], "high")
        self.assertEqual(row["findings"], "3")


class TestRefusals(TrackerCase):
    def test_an_unknown_repo_aborts_the_whole_run(self):
        # A typo must not quietly mark the others and drop this one.
        self.write([self.row("a/one")])
        code, output = self.run_it("a/one", "a/typo")
        self.assertEqual(code, 1)
        self.assertIn("a/typo", output)
        self.assertEqual(self.read()["a/one"]["status"], "reporting-disabled",
                         "wrote a partial change after refusing")

    def test_naming_nothing_is_an_error(self):
        self.write([self.row("a/one")])
        code, _ = self.run_it()
        self.assertEqual(code, 1)

    def test_a_future_date_is_refused(self):
        self.write([self.row("a/one")])
        tomorrow = (TODAY + timedelta(days=1)).isoformat()
        code, output = self.run_it("a/one", "--on", tomorrow)
        self.assertEqual(code, 1)
        self.assertIn("future", output)

    def test_a_nonsense_date_is_an_error_not_a_traceback(self):
        self.write([self.row("a/one")])
        code, _ = self.run_it("a/one", "--on", "last tuesday")
        self.assertEqual(code, 1)

    def confirm_with(self, answer):
        """Run without --yes, with the prompt answered."""
        buf = io.StringIO()
        with mock.patch.object(mr, "confirm", return_value=answer), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = mr.main(["--tracker", str(self.tracker), "a/one"])
        return code, buf.getvalue()

    def test_declining_the_confirmation_writes_nothing(self):
        self.write([self.row("a/one")])
        code, _ = self.confirm_with("n")
        self.assertEqual(code, 1)
        self.assertEqual(self.read()["a/one"]["status"], "reporting-disabled")

    def test_silence_is_not_consent(self):
        # Enter on its own must not mark eleven people as told.
        self.write([self.row("a/one")])
        code, _ = self.confirm_with("")
        self.assertEqual(code, 1)
        self.assertEqual(self.read()["a/one"]["status"], "reporting-disabled")

    def test_accepting_the_confirmation_writes(self):
        self.write([self.row("a/one")])
        code, _ = self.confirm_with("y")
        self.assertEqual(code, 0)
        self.assertEqual(self.read()["a/one"]["status"], "reported")


class TestNobodyToAsk(TrackerCase):
    """--from - spends stdin on the repo list, so the prompt has no input.

    Refusing is right, but refusing while printing "nothing written" reads as
    though the operator declined, and leaves the run impossible with no hint
    why. This is the shape that made the tool unusable the first time it was
    used for real.
    """

    def run_headless(self):
        buf = io.StringIO()
        with mock.patch.object(mr, "confirm", return_value=None), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = mr.main(["--tracker", str(self.tracker), "a/one"])
        return code, buf.getvalue()

    def test_it_refuses_rather_than_assuming_yes(self):
        self.write([self.row("a/one")])
        code, _ = self.run_headless()
        self.assertEqual(code, 1)
        self.assertEqual(self.read()["a/one"]["status"], "reporting-disabled")

    def test_it_explains_the_situation_and_the_way_out(self):
        self.write([self.row("a/one")])
        _, output = self.run_headless()
        self.assertIn("no terminal", output)
        self.assertIn("--yes", output)

    def test_it_does_not_read_as_the_operator_declining(self):
        self.write([self.row("a/one")])
        _, output = self.run_headless()
        self.assertNotIn("nothing written.", output)

    def test_yes_still_works_without_a_terminal(self):
        # The escape hatch the message points at has to actually work.
        self.write([self.row("a/one")])
        buf = io.StringIO()
        with mock.patch.object(mr, "confirm", return_value=None), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = mr.main(["--tracker", str(self.tracker), "--yes", "a/one"])
        self.assertEqual(code, 0)
        self.assertEqual(self.read()["a/one"]["status"], "reported")


class TestConfirm(unittest.TestCase):
    """confirm() itself: it must never invent an answer."""

    def test_an_interactive_stdin_is_asked(self):
        with mock.patch("sys.stdin") as stdin, \
                mock.patch("builtins.input", return_value="y") as asked:
            stdin.isatty.return_value = True
            self.assertEqual(mr.confirm("ok? "), "y")
        asked.assert_called_once()

    def test_a_spent_stdin_falls_back_to_the_terminal(self):
        opened = mock.mock_open(read_data="y\n")
        opened.return_value.readline.return_value = "y\n"
        with mock.patch("sys.stdin") as stdin, mock.patch("builtins.open", opened):
            stdin.isatty.return_value = False
            self.assertEqual(mr.confirm("ok? ").strip(), "y")

    def test_no_terminal_at_all_returns_none_not_a_blank(self):
        # A blank would be compared against "y" and read as a decline, which
        # is the wrong story. None means "nobody was asked".
        with mock.patch("sys.stdin") as stdin, \
                mock.patch("builtins.open", side_effect=OSError):
            stdin.isatty.return_value = False
            self.assertIsNone(mr.confirm("ok? "))


class TestReporting(TrackerCase):
    def test_it_says_how_many_criticals_are_still_unreported(self):
        self.write([self.row("a/one"), self.row("b/two"), self.row("c/high", severity="high")])
        _, output = self.run_it("a/one")
        self.assertIn("1 critical", output)

    def test_it_says_so_when_every_critical_is_covered(self):
        self.write([self.row("a/one"), self.row("c/high", severity="high")])
        _, output = self.run_it("a/one")
        self.assertIn("Every critical repo", output)

    def test_it_prints_the_earliest_publication_date(self):
        self.write([self.row("a/one")])
        _, output = self.run_it("a/one", "--on", "2026-08-21", "--window", "14")
        self.assertIn("2026-09-04", output)

    @unittest.skipIf(os.name == "nt", "Windows chmod only honours the read-only bit")
    def test_the_tracker_stays_locked_down(self):
        self.write([self.row("a/one")])
        self.run_it("a/one")
        self.assertEqual(oct(self.tracker.stat().st_mode)[-3:], "600")


class TestSlugInput(TrackerCase):
    def test_slugs_can_come_from_a_file(self):
        self.write([self.row("a/one"), self.row("b/two")])
        listing = Path(self.tmp.name) / "sent.txt"
        listing.write_text("# the ones I emailed\na/one\n\nb/two\n", encoding="utf-8")
        code, _ = self.run_it("--from", str(listing))
        self.assertEqual(code, 0)
        self.assertEqual(self.read()["b/two"]["status"], "reported")

    def test_a_repo_named_twice_is_handled_once(self):
        self.write([self.row("a/one")])
        code, output = self.run_it("a/one", "a/one")
        self.assertEqual(code, 0)
        self.assertEqual(output.count("-> reported"), 1)


if __name__ == "__main__":
    unittest.main()
