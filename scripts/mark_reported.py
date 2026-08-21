"""Record that a maintainer was actually contacted.

    python3 scripts/mark_reported.py owner/repo owner/other --route email
    python3 scripts/mark_reported.py --route email --on 2026-08-21 --from -

prepare_disclosures.py writes `reported` only for advisories it filed through
the GitHub API. Private vulnerability reporting reached zero of seventy-one
repositories, so in practice the contacting happens by email, outside any
tool — and nothing on disk knows it happened. The next find_contacts.py run
then hands back the same people to contact again, and the answer to "was
everyone told?" lives in a sent-mail folder that gets harder to reconstruct
every week.

## Why this asks for repositories by name

Marking a repo reported when nobody was told is the one error here that ends
with a live credential never being disclosed, and it is invisible afterwards:
the row looks done. So there is no "mark them all" — every repository is named
explicitly, a name that isn't in the tracker is an error rather than a silent
no-op, and the run prints exactly what it will change and asks, unless you
pass --yes.

A repo already marked reported keeps its original date. The first time someone
was told is the date the disclosure window runs from, and overwriting it would
quietly restart the clock.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import date, timedelta
from pathlib import Path

TRACKER_COLUMNS = [
    "repo", "worst_severity", "findings", "status", "reported_on",
    "advisory_url", "note",
]
ROUTES = ("email", "issue", "advisory", "other")
DEFAULT_WINDOW = 14


def read_tracker(path: Path):
    with open(path, newline="", encoding="utf-8") as fh:
        return [row for row in csv.DictReader(fh) if row.get("repo")]


def write_tracker(path: Path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=TRACKER_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in TRACKER_COLUMNS})
    os.chmod(path, 0o600)


def note_for(existing: str, route: str) -> str:
    """Keep whatever was already noted; add how they were reached."""
    added = f"contacted by {route}"
    if not existing:
        return added
    if added in existing:
        return existing
    return f"{existing} · {added}"


def plan(rows, wanted, route, on):
    """What each named repo would become. Returns (changes, skipped, missing)."""
    by_repo = {row["repo"]: row for row in rows}
    changes, skipped, missing = [], [], []
    for slug in wanted:
        row = by_repo.get(slug)
        if row is None:
            missing.append(slug)
        elif row.get("status") == "reported":
            # The window runs from the first time they were told.
            skipped.append((slug, row.get("reported_on", "")))
        else:
            changes.append((slug, row.get("status", ""), {
                "status": "reported",
                "reported_on": on.isoformat(),
                "note": note_for(row.get("note", ""), route),
            }))
    return changes, skipped, missing


def confirm(question: str):
    """Ask, even when stdin was spent on the repo list.

    `--from -` consumes stdin, so a later input() sees EOF straight away.
    Treating that as "no" is safe but leaves the run impossible and the
    reason unexplained, so try the terminal directly first. Returns None
    when there is nobody to ask — a caller must not read that as consent.
    """
    try:
        if sys.stdin.isatty():
            return input(question)
    except (OSError, ValueError):
        pass
    try:
        with open("/dev/tty", "r+") as tty:   # not on Windows, hence the guard
            tty.write(question)
            tty.flush()
            return tty.readline()
    except OSError:
        return None


def read_slugs(source: str):
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()
            and not line.startswith("#")]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("repos", nargs="*", help="owner/repo, as it appears in the tracker")
    parser.add_argument("--from", dest="source", metavar="FILE",
                        help="read repo slugs from a file, one per line ('-' for stdin)")
    parser.add_argument("--tracker", default="research/disclosures/tracker.csv")
    parser.add_argument("--route", default="email", choices=ROUTES,
                        help="how they were contacted (default: email)")
    parser.add_argument("--on", help="date contacted, YYYY-MM-DD (default: today)")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW,
                        help=f"days before publishing (default: {DEFAULT_WINDOW})")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation")
    args = parser.parse_args(argv)

    wanted = list(args.repos)
    if args.source:
        wanted += read_slugs(args.source)
    # Deduplicate but keep the order they were given in.
    wanted = list(dict.fromkeys(wanted))
    if not wanted:
        print("name at least one repository, or pass --from", file=sys.stderr)
        return 1

    try:
        on = date.fromisoformat(args.on) if args.on else date.today()
    except ValueError:
        print(f"--on {args.on} is not a YYYY-MM-DD date", file=sys.stderr)
        return 1
    if on > date.today():
        print(f"--on {on.isoformat()} is in the future", file=sys.stderr)
        return 1

    tracker_path = Path(args.tracker)
    if not tracker_path.exists():
        print(f"no tracker at {tracker_path} — run prepare_disclosures.py first", file=sys.stderr)
        return 1

    rows = read_tracker(tracker_path)
    changes, skipped, missing = plan(rows, wanted, args.route, on)

    for slug, was, _ in changes:
        print(f"  {was or 'unset':20} -> reported   {slug}")
    for slug, when in skipped:
        print(f"  already reported{' on ' + when if when else '':<8} {slug}")
    if missing:
        # A typo here means a repo silently never gets marked, and later never
        # gets chased. Refuse the whole run rather than do part of it.
        print("\nnot in the tracker:", file=sys.stderr)
        for slug in missing:
            print(f"  {slug}", file=sys.stderr)
        print("check the spelling against tracker.csv — nothing was written.", file=sys.stderr)
        return 1
    if not changes:
        print("\nnothing to change.")
        return 0

    if not args.yes:
        answer = confirm(f"\nmark {len(changes)} repositories reported on "
                         f"{on.isoformat()}? [y/N] ")
        if answer is None:
            # Nobody to ask. Say which of the two situations this is, rather
            # than printing a refusal that reads like the user declined.
            print("\ncannot ask for confirmation — there is no terminal to read "
                  "from.\nRe-run with --yes if the list above is right, or pass "
                  "--from a file\ninstead of - so stdin stays free.", file=sys.stderr)
            return 1
        if answer.strip().lower() not in {"y", "yes"}:
            print("nothing written.")
            return 1

    updates = {slug: fields for slug, _, fields in changes}
    for row in rows:
        row.update(updates.get(row["repo"], {}))
    write_tracker(tracker_path, rows)

    publish_after = on + timedelta(days=args.window)
    remaining = sum(1 for row in rows
                    if row.get("worst_severity") == "critical"
                    and row.get("status") != "reported")
    print(f"\n  {len(changes)} marked reported -> {tracker_path}")
    print(f"  Earliest honest publication date: {publish_after.isoformat()}")
    if remaining:
        print(f"\n  {remaining} critical repo(s) still not reported. Those are the ones "
              f"with a\n  live credential, and the post's claim to have contacted them "
              f"isn't true yet.")
    else:
        print("\n  Every critical repo is now marked reported.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
