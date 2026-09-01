"""Tests for the contact finder.

The consequential mistakes here are quiet ones: picking an address out of an
unfilled SECURITY.md template, treating a noreply address as a route, or
dropping a repository from the list because a lookup failed. Each one ends
with somebody's live credential never being reported.
"""

import contextlib
import csv
import importlib.util
import io
import os
import tempfile
import unittest
from datetime import date
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
spec = importlib.util.spec_from_file_location("find_contacts", SCRIPTS / "find_contacts.py")
fc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fc)


class TestEmailExtraction(unittest.TestCase):
    def test_plain_address(self):
        self.assertEqual(fc.first_email("Report to security@acme.dev please."), "security@acme.dev")

    def test_trailing_punctuation_is_not_part_of_the_address(self):
        self.assertEqual(fc.first_email("Contact: me@my-site.co.uk."), "me@my-site.co.uk")
        self.assertEqual(fc.first_email("(see security@acme.dev)"), "security@acme.dev")

    def test_placeholder_domains_are_not_routes(self):
        # An unfilled template is worse than nothing: it looks like a route.
        for text in (
            "Email security@example.com to report",
            "mail us at you@yourdomain.com",
            "contact admin@domain.tld here",
        ):
            with self.subTest(text):
                self.assertEqual(fc.first_email(text), "")

    def test_no_address_at_all(self):
        self.assertEqual(fc.first_email("Open an issue, we don't do email."), "")
        self.assertEqual(fc.first_email(""), "")

    def test_the_first_real_address_wins_over_a_later_placeholder(self):
        self.assertEqual(
            fc.first_email("Write to real@acme.dev, not to test@example.com"),
            "real@acme.dev",
        )


class TestRouteSelection(unittest.TestCase):
    def test_security_md_outranks_everything(self):
        route, _ = fc.route_for("s@x.com", "p@x.com", "c@x.com", True)
        self.assertEqual(route, "security.md")

    def test_profile_email_comes_before_a_commit_email(self):
        # One was published as a contact address; the other just happens to be
        # in the git history.
        route, _ = fc.route_for("", "p@x.com", "c@x.com", True)
        self.assertEqual(route, "profile email")

    def test_commit_email_carries_a_warning_about_its_use(self):
        route, note = fc.route_for("", "", "c@x.com", True)
        self.assertEqual(route, "commit email")
        self.assertIn("this use only", note)

    def test_a_noreply_address_is_not_a_route(self):
        route, _ = fc.route_for("", "", "1+u@users.noreply.github.com", True)
        self.assertEqual(route, "public issue")

    def test_public_issue_needs_issues_to_be_enabled(self):
        route, note = fc.route_for("", "", "1+u@users.noreply.github.com", False)
        self.assertEqual(route, "none found")
        self.assertIn("no route", note)

    def test_the_issue_route_points_at_the_no_details_template(self):
        _, note = fc.route_for("", "", "", True)
        self.assertIn("no details", note)


class TestDeadAddressesAreNotRoutes(unittest.TestCase):
    """An address known to bounce is not a route, however well-published.

    The routes are all derived from the repository, so putting a bounced repo
    back in the queue re-derives whatever was tried the first time. On the
    real run this handed back security@wheelsandwins.com — the address that
    had permanently failed four days earlier — under the heading of the route
    to use. A dead lead presented as a live one is worse than none: it looks
    actionable and silently isn't.
    """

    DEAD = frozenset({"s@x.com"})

    def test_a_bounced_security_address_falls_through_to_the_profile(self):
        route, _ = fc.route_for("s@x.com", "p@x.com", "c@x.com", True, self.DEAD)
        self.assertEqual(route, "profile email")

    def test_it_keeps_falling_through(self):
        dead = frozenset({"s@x.com", "p@x.com"})
        route, _ = fc.route_for("s@x.com", "p@x.com", "c@x.com", True, dead)
        self.assertEqual(route, "commit email")

    def test_every_address_dead_leaves_the_public_issue(self):
        dead = frozenset({"s@x.com", "p@x.com", "c@x.com"})
        route, _ = fc.route_for("s@x.com", "p@x.com", "c@x.com", True, dead)
        self.assertEqual(route, "public issue")

    def test_every_address_dead_and_issues_off_is_no_route(self):
        dead = frozenset({"s@x.com", "p@x.com", "c@x.com"})
        route, _ = fc.route_for("s@x.com", "p@x.com", "c@x.com", False, dead)
        self.assertEqual(route, "none found")

    def test_the_note_says_which_address_was_skipped(self):
        # Otherwise the fallback looks arbitrary and someone "corrects" it
        # back to the SECURITY.md address.
        _, note = fc.route_for("s@x.com", "p@x.com", "", True, self.DEAD)
        self.assertIn("s@x.com bounced", note)

    def test_the_commit_warning_survives_the_skip(self):
        dead = frozenset({"s@x.com", "p@x.com"})
        _, note = fc.route_for("s@x.com", "p@x.com", "c@x.com", True, dead)
        self.assertIn("this use only", note)
        self.assertIn("bounced", note)

    def test_matching_ignores_case(self):
        route, _ = fc.route_for("S@X.com", "p@x.com", "", True, self.DEAD)
        self.assertEqual(route, "profile email")

    def test_no_dead_addresses_changes_nothing(self):
        self.assertEqual(fc.route_for("s@x.com", "p@x.com", "c@x.com", True),
                         fc.route_for("s@x.com", "p@x.com", "c@x.com", True, frozenset()))


class TestReadingBouncesFromTheTracker(unittest.TestCase):
    """mark_reported.py writes the note; this has to be able to read it back."""

    def test_it_finds_the_address(self):
        self.assertEqual(
            fc.dead_addresses("contacted by email · email bounced 2026-08-25 s@x.com"),
            {"s@x.com"})

    def test_it_finds_more_than_one(self):
        self.assertEqual(
            fc.dead_addresses("email bounced 2026-08-21 a@x.com · "
                              "email bounced 2026-08-25 b@x.com"),
            {"a@x.com", "b@x.com"})

    def test_an_ordinary_note_yields_nothing(self):
        self.assertEqual(fc.dead_addresses("contacted by email"), set())
        self.assertEqual(fc.dead_addresses(""), set())

    def test_it_does_not_mistake_the_contact_note_for_a_bounce(self):
        self.assertEqual(fc.dead_addresses("acknowledged 2026-08-22"), set())


class TestSelection(unittest.TestCase):
    """Which rows get looked up at all."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tracker = self.root / "tracker.csv"
        self.out = self.root / "contacts.csv"

    def write_tracker(self, rows):
        with open(self.tracker, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=[
                "repo", "worst_severity", "findings", "status",
                "reported_on", "advisory_url", "note"])
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    def row(self, repo, severity="critical", status="reporting-disabled"):
        return {"repo": repo, "worst_severity": severity, "findings": 1,
                "status": status, "reported_on": "", "advisory_url": "", "note": ""}

    def run_it(self, *extra, investigate=None):
        looked_up = []
        original = fc.investigate
        fc.investigate = investigate or (lambda slug, dead=frozenset(): (
            looked_up.append((slug, dead) if dead else slug) or {
            "owner": "o", "owner_type": "User", "issues_enabled": "yes",
            "security_md_email": "", "profile_email": "p@x.com",
                "commit_email": "", "best_route": "profile email", "note": ""}))
        self.addCleanup(setattr, fc, "investigate", original)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = fc.main(["--tracker", str(self.tracker), "--out", str(self.out), *extra])
        return code, looked_up

    def test_defaults_to_criticals_only(self):
        # The disclosure rule the research runs under is about criticals.
        self.write_tracker([self.row("a/crit"), self.row("b/high", severity="high")])
        _, looked = self.run_it()
        self.assertEqual(looked, ["a/crit"])

    def test_severity_can_be_widened(self):
        self.write_tracker([self.row("a/crit"), self.row("b/high", severity="high")])
        _, looked = self.run_it("--severity", "high")
        self.assertEqual(sorted(looked), ["a/crit", "b/high"])

    def test_the_bounced_address_reaches_the_lookup(self):
        # The seam that was missing entirely: the note is in the tracker and
        # the route selection reads it, but nothing carried it between them.
        self.write_tracker([dict(self.row("a/bounced", status="bounced"),
                                 note="email bounced 2026-08-25 dead@x.com")])
        _, looked = self.run_it()
        self.assertEqual(looked, [("a/bounced", {"dead@x.com"})])

    def test_a_bounced_repo_is_handed_back(self):
        # A bounce means nobody was told. If `bounced` were treated like
        # `reported`, the repo would drop out of here permanently and the
        # maintainer would never be reached by any route.
        self.write_tracker([self.row("a/bounced", status="bounced"),
                            self.row("b/done", status="reported")])
        _, looked = self.run_it()
        self.assertEqual(looked, ["a/bounced"])

    def test_repos_already_reported_are_left_alone(self):
        self.write_tracker([self.row("a/done", status="reported"), self.row("b/todo")])
        _, looked = self.run_it()
        self.assertEqual(looked, ["b/todo"])

    def test_errors_still_need_a_route(self):
        self.write_tracker([self.row("a/err", status="error")])
        _, looked = self.run_it()
        self.assertEqual(looked, ["a/err"])

    def test_limit_caps_the_lookups(self):
        self.write_tracker([self.row(f"a/r{n}") for n in range(5)])
        _, looked = self.run_it("--limit", "2")
        self.assertEqual(len(looked), 2)

    def test_a_failed_lookup_still_produces_a_row(self):
        # Silently dropping a repo means nobody ever tells that maintainer.
        self.write_tracker([self.row("a/gone")])
        self.run_it(investigate=lambda slug, dead=frozenset(): {
            "owner": "", "owner_type": "", "issues_enabled": "",
            "security_md_email": "", "profile_email": "", "commit_email": "",
            "best_route": "unreachable", "note": "repo not found"})
        with open(self.out, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["best_route"], "unreachable")

    def test_missing_tracker_is_an_error_not_a_traceback(self):
        code, _ = self.run_it()
        self.assertEqual(code, 1)

    def test_nothing_pending_exits_cleanly(self):
        self.write_tracker([self.row("a/done", status="reported")])
        code, looked = self.run_it()
        self.assertEqual(code, 0)
        self.assertEqual(looked, [])

    @unittest.skipIf(os.name == "nt", "Windows chmod only honours the read-only bit")
    def test_contacts_file_holds_addresses_so_it_is_locked_down(self):
        self.write_tracker([self.row("a/one")])
        self.run_it()
        self.assertEqual(oct(self.out.stat().st_mode)[-3:], "600")


if __name__ == "__main__":
    unittest.main()


class TestTheWriterAndTheReaderAgree(unittest.TestCase):
    """One module writes the bounce note, another parses it back out.

    Nothing but this test holds the format together, and a silent divergence
    reads exactly like the original bug: find_contacts.py proposes an address
    mark_reported.py has already recorded as dead.
    """

    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "mark_reported", SCRIPTS / "mark_reported.py")
        self.mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mr)

    def note_from_mark_reported(self, address, on):
        rows = [{"repo": "a/one", "status": "reported", "reported_on": "2026-08-21",
                 "note": "contacted by email"}]
        changes, _, _ = self.mr.plan_bounced(rows, ["a/one"], date.fromisoformat(on),
                                             address)
        return changes[0][2]["note"]

    def test_find_contacts_reads_what_mark_reported_writes(self):
        note = self.note_from_mark_reported("gone@example.com", "2026-08-25")
        self.assertEqual(fc.dead_addresses(note), {"gone@example.com"})

    def test_both_modules_parse_it_the_same_way(self):
        note = self.note_from_mark_reported("gone@example.com", "2026-08-25")
        self.assertEqual(set(self.mr.dead_addresses(note)), fc.dead_addresses(note))

    def test_a_second_bounce_is_readable_too(self):
        note = self.note_from_mark_reported("gone@example.com", "2026-08-25")
        rows = [{"repo": "a/one", "status": "bounced", "reported_on": "", "note": note}]
        changes, _, _ = self.mr.plan_bounced(rows, ["a/one"], date(2026, 8, 26),
                                             "also@example.com")
        self.assertEqual(fc.dead_addresses(changes[0][2]["note"]),
                         {"gone@example.com", "also@example.com"})
