"""Find a way to reach the maintainers who still need telling.

    python3 scripts/find_contacts.py                    # criticals (the default)
    python3 scripts/find_contacts.py --severity high    # widen it

Private vulnerability reporting reached zero of seventy-one repositories in
the first real run: it is off by default and these are personal side projects
whose owners have mostly never heard of it. So the advisory route needs a
fallback, and the fallback is per-repository research — which is exactly the
kind of work that doesn't get done at scale. This does the looking-up and
leaves the judgement.

## The routes, in the order worth trying

0. **Not an address already known to bounce.** `mark_reported.py --bounced`
   records the dead address in the tracker note; every route below skips it.
   Without that, a repo put back in this list gets the same dead address
   proposed again, which is how a bounce turns into two bounces.

1. **SECURITY.md** — someone who wrote one has said how they want to be told.
2. **A public profile email** — published deliberately, on their own page.
3. **A commit author email** — published by them in the git history. Using one
   to report a security problem is reasonable; using it for anything else, or
   adding it to any list, is not. Ever.
4. **A public issue containing no details**, asking them to enable private
   reporting. Template 3 in content/disclosure-templates.md. This is last
   because it is visible, and because seventy of them in an afternoon reads as
   spam to GitHub's abuse detection.

`@users.noreply.github.com` addresses are recorded and marked unusable rather
than quietly dropped, so a repo that genuinely has no route says so instead of
looking unexamined.

## Why this defaults to criticals

The rule the research is run under, in research_scan.py's own words: "Anyone
with a live critical finding gets contacted and given time to rotate." Fifteen
repositories is a person-sized amount of careful work. Seventy-one is the kind
of number that produces a rushed job or no job at all.

Output holds people's email addresses, so contacts.csv is written 0600 inside
the already-gitignored disclosures directory. It is research material for one
purpose. Nothing about it is a mailing list.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
NOREPLY = "users.noreply.github.com"
SECURITY_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

CONTACT_COLUMNS = [
    "repo", "worst_severity", "owner", "owner_type", "best_route",
    "security_md_email", "profile_email", "commit_email", "issues_enabled",
    "note",
]

# Statuses that mean "still needs a route". A repo already reported is done —
# but `bounced` is not done: the message was sent and never arrived, so the
# repo needs a different route, not a second copy of the same email.
NEEDS_CONTACT = {"reporting-disabled", "error", "drafted", "bounced"}


def gh_json(path: str):
    """GET a GitHub API path and parse it. Returns None on any failure."""
    try:
        result = subprocess.run(
            ["gh", "api", path], capture_output=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout.decode("utf-8", errors="replace"))
    except ValueError:
        return None


def first_email(text: str) -> str:
    """The first plausible address in a SECURITY.md.

    Skips example.com and the like: a template nobody filled in is worse than
    no address, because it looks like a route and isn't.
    """
    for match in EMAIL_RE.finditer(text or ""):
        address = match.group(0).rstrip(".,;:)>]")
        domain = address.split("@")[-1].lower()
        if domain.startswith(("example.", "domain.", "yourdomain.")) or domain in {
            "example.com", "email.com", "test.com",
        }:
            continue
        return address
    return ""


def security_md_email(slug: str) -> str:
    for path in SECURITY_PATHS:
        payload = gh_json(f"/repos/{slug}/contents/{path}")
        if not isinstance(payload, dict) or "content" not in payload:
            continue
        try:
            text = base64.b64decode(payload["content"]).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            continue
        found = first_email(text)
        if found:
            return found
    return ""


def commit_email(slug: str) -> str:
    """An author address from recent history, preferring a usable one."""
    commits = gh_json(f"/repos/{slug}/commits?per_page=20")
    if not isinstance(commits, list):
        return ""
    fallback = ""
    for entry in commits:
        author = ((entry or {}).get("commit") or {}).get("author") or {}
        address = (author.get("email") or "").strip()
        if not address:
            continue
        if NOREPLY in address:
            fallback = fallback or address
            continue
        return address
    return fallback


ADDRESS_FOR_ROUTE = {
    "security.md": "security_md_email",
    "profile email": "profile_email",
    "commit email": "commit_email",
}

DEAD_ADDRESS_RE = re.compile(r"email bounced \d{4}-\d{2}-\d{2} (\S+@\S+)")


def dead_addresses(note: str):
    """Addresses this repo's note records as having bounced.

    Written by mark_reported.py --bounced. Reading it here is the whole
    point of recording it: the routes below are derived from the repository,
    so they reproduce whatever address was tried the first time.
    """
    return {match.lower() for match in DEAD_ADDRESS_RE.findall(note or "")}


def route_for(security, profile, commit, issues_enabled, dead=frozenset()):
    """Which route to actually use, and why the others were passed over.

    `dead` is the set of addresses already known to bounce for this repo. An
    address in it is not a route, however well-published it is: proposing a
    SECURITY.md address whose domain does not resolve is worse than proposing
    nothing, because it looks like a live lead and it silently isn't.
    """
    def usable(address):
        return bool(address) and address.lower() not in dead

    skipped = " · ".join(f"{address} bounced" for address in sorted(dead))
    def annotate(note):
        return " · ".join(part for part in (note, skipped) if part)

    if usable(security):
        return "security.md", annotate("")
    if usable(profile):
        return "profile email", annotate("")
    if usable(commit) and NOREPLY not in commit:
        return "commit email", annotate("published by them in git history — this use only")
    if issues_enabled:
        return "public issue", annotate(
            "template 3: no details, ask them to enable private reporting")
    return "none found", annotate(
        "no route — issues are off and every address is noreply")


def investigate(slug: str, dead=frozenset()) -> dict:
    repo = gh_json(f"/repos/{slug}")
    if not isinstance(repo, dict):
        return {"owner": "", "owner_type": "", "issues_enabled": "",
                "security_md_email": "", "profile_email": "", "commit_email": "",
                "best_route": "unreachable", "note": "repo not found — renamed or deleted"}

    owner = (repo.get("owner") or {}).get("login", "")
    owner_type = (repo.get("owner") or {}).get("type", "")
    issues_enabled = bool(repo.get("has_issues"))

    security = security_md_email(slug)
    user = gh_json(f"/users/{owner}") if owner else None
    profile = ((user or {}).get("email") or "").strip()
    commit = commit_email(slug)

    best, note = route_for(security, profile, commit, issues_enabled, dead)
    if repo.get("archived"):
        note = (note + " · repo is archived").strip(" ·")
    return {
        "owner": owner,
        "owner_type": owner_type,
        "issues_enabled": "yes" if issues_enabled else "no",
        "security_md_email": security,
        "profile_email": profile,
        "commit_email": commit,
        "best_route": best,
        "note": note,
    }


def read_tracker(path: Path):
    with open(path, newline="", encoding="utf-8") as fh:
        return [row for row in csv.DictReader(fh) if row.get("repo")]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tracker", default="research/disclosures/tracker.csv")
    parser.add_argument("--out", default="research/disclosures/contacts.csv")
    parser.add_argument("--severity", default="critical", choices=list(SEVERITY_RANK),
                        help="look up repos at or above this severity (default: critical, "
                             "which is what the research's own disclosure rule covers)")
    parser.add_argument("--limit", type=int, help="only look up this many")
    args = parser.parse_args(argv)

    tracker_path = Path(args.tracker)
    if not tracker_path.exists():
        print(f"no tracker at {tracker_path} — run prepare_disclosures.py first", file=sys.stderr)
        return 1

    limit = SEVERITY_RANK[args.severity]
    pending = [
        row for row in read_tracker(tracker_path)
        if SEVERITY_RANK.get(row.get("worst_severity", ""), 99) <= limit
        and row.get("status") in NEEDS_CONTACT
    ]
    if args.limit:
        pending = pending[: args.limit]
    if not pending:
        print(f"nothing at or above {args.severity} still needs a contact route.")
        return 0

    print(f"looking up {len(pending)} repositories\n")
    rows = []
    for i, row in enumerate(pending, 1):
        slug = row["repo"]
        dead = dead_addresses(row.get("note", ""))
        found = investigate(slug, dead)
        found["repo"] = slug
        found["worst_severity"] = row.get("worst_severity", "")
        rows.append(found)
        # Show the address for the route actually chosen. Falling through the
        # three columns in order printed whichever address came first, which
        # on a repo with a bounced SECURITY.md address is the dead one — the
        # exact address the route selection had just rejected.
        detail = ADDRESS_FOR_ROUTE.get(found["best_route"], "")
        detail = found.get(detail, "") if detail else ""
        print(f"[{i}/{len(pending)}] {slug}\n      {found['best_route']:14} {detail or '—'}")
        if dead:
            print(f"      {'':14} skipping {', '.join(sorted(dead))} — bounced")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CONTACT_COLUMNS)
        writer.writeheader()
        for row in sorted(rows, key=lambda r: (SEVERITY_RANK.get(r["worst_severity"], 9), r["repo"])):
            writer.writerow({column: row.get(column, "") for column in CONTACT_COLUMNS})
    os.chmod(out_path, 0o600)

    tally = {}
    for row in rows:
        tally[row["best_route"]] = tally.get(row["best_route"], 0) + 1
    print(f"\n{len(rows)} looked up — routes found:")
    for route, count in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {count:4}  {route}")
    print(f"\n  contacts -> {out_path}")
    print("\n  These are addresses people published, for one purpose: telling them\n"
          "  about this. Not a list. The drafts in this directory are the message.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
