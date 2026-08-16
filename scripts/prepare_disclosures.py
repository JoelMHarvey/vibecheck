"""Turn research/disclosure.jsonl into per-repo disclosure drafts.

    python3 scripts/prepare_disclosures.py                 # write drafts
    python3 scripts/prepare_disclosures.py --submit --yes  # file them

Seventy-one blank advisories is the kind of task that quietly doesn't happen,
and the whole ethical position of the research rests on it happening. So this
does the typing: one draft per repository, findings filled in, ready to read
and send.

## Why security advisories rather than email

GitHub's private vulnerability reporting puts the report in front of the
person who can fix it, inside the repository it concerns, with no public trace
until they choose to publish one. An unsolicited email about a leaked key is
indistinguishable from the scam that farms panic clicks — an advisory is not.
It also timestamps the disclosure, which is what lets you say "reported on the
4th, published on the 18th" and have it be checkable.

Not every repository has it enabled. Those come back as failures in the
tracker, and template 3 in content/disclosure-templates.md covers what to do:
a public issue asking them to turn it on, containing no details.

## What never goes in a draft

The credential. Not partially redacted, not "the one starting sk-". The rule
name, the path and the line are enough for someone to look in their own repo
and confirm it, which is the point — they should not have to trust a stranger.
Putting the value in the report copies the secret into another mailbox and
makes the message read as a threat.

Drafts name repositories and file paths, so the output directory is written
0600 and gitignored, exactly like disclosure.jsonl.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# GitHub's advisory severities. Ours map cleanly onto the top two; nothing
# below "high" is worth a stranger's advisory.
GH_SEVERITY = {"critical": "critical", "high": "high"}

TRACKER_COLUMNS = [
    "repo", "worst_severity", "findings", "status", "reported_on",
    "advisory_url", "note",
]


def load_rule_titles():
    """rule_id -> human title, from the manifest the site already ships."""
    try:
        manifest = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {rid: spec.get("t", rid) for rid, spec in manifest.get("rules", {}).items()}


def read_disclosures(path: Path):
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def repo_slug(url: str) -> str:
    """owner/name from a GitHub URL, or '' if it isn't one."""
    cleaned = url.rstrip("/").removesuffix(".git")
    if "github.com" not in cleaned:
        return ""
    parts = cleaned.split("github.com", 1)[1].lstrip(":/").split("/")
    return "/".join(parts[:2]) if len(parts) >= 2 else ""


def worst(findings) -> str:
    return min((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 99))


def rule_title(rule_id: str, titles) -> str:
    """Human title, or a readable fallback.

    A rule the manifest doesn't know about still has to read like English —
    "stripe-live-secret-key" in a message to a stranger looks like output from
    a bot that doesn't know what it found.
    """
    if rule_id in titles:
        return titles[rule_id]
    words = rule_id.replace(".", " ").replace("_", " ").replace("-", " ").strip()
    return words[:1].upper() + words[1:] if words else rule_id


def summary_line(finding, titles) -> str:
    title = rule_title(finding["rule_id"], titles)
    line = finding.get("line") or 0
    where = f"`{finding['path']}`" + (f" line {line}" if line > 0 else "")
    return f"- **{title}** — {where}"


def advisory_body(slug: str, findings, titles, publish_after: date) -> str:
    """The report itself. Verifiable without trusting the sender, no ask."""
    ranked = sorted(findings, key=lambda f: (SEVERITY_RANK.get(f["severity"], 99), f["path"]))
    listed = "\n".join(summary_line(f, titles) for f in ranked)
    plural = "these" if len(ranked) > 1 else "this"
    return f"""\
A scan of public repositories built with AI coding tools flagged the
following in {slug}:

{listed}

Please check {plural} in your own repository rather than taking my word for
it — I'm a stranger reporting a security problem, which is also what a scam
looks like. The path and line are there so you can confirm it yourself in
under a minute. I have deliberately not included the value of any credential.

**If a credential is real, rotate it at the provider before anything else.**
Removing it from the file is not enough on its own: it stays in the git
history, and public repositories are crawled for keys within minutes of a
push.

I found this while measuring how often these mistakes reach production in
AI-built apps. The writeup reports aggregate numbers only — no repository
names, no owners, no paths, no code. You will not be identifiable in it, and
nothing is published before {publish_after.isoformat()}.

Nothing is needed from me and no reply is necessary. I just didn't want to
know about this and say nothing.
"""


def advisory_payload(slug: str, findings, titles, publish_after: date) -> dict:
    level = worst(findings)
    return {
        "summary": f"Exposed credentials or insecure configuration in {slug.split('/')[-1]}"[:1024],
        "description": advisory_body(slug, findings, titles, publish_after),
        "severity": GH_SEVERITY.get(level, "high"),
    }


def write_draft(out_dir: Path, slug: str, payload: dict, findings) -> Path:
    path = out_dir / (slug.replace("/", "__") + ".md")
    path.write_text(
        f"# {slug}\n\n"
        f"**Severity:** {payload['severity']}  ·  **Findings:** {len(findings)}\n\n"
        f"**Summary:** {payload['summary']}\n\n---\n\n"
        f"{payload['description']}\n",
        encoding="utf-8",
    )
    return path


def submit(slug: str, payload: dict):
    """File a private vulnerability report via the gh CLI.

    Returns (status, note). Never raises: one repository with reporting
    disabled must not stop the other seventy.
    """
    args = [
        "gh", "api", "--method", "POST",
        f"/repos/{slug}/security-advisories/reports",
        "-f", f"summary={payload['summary']}",
        "-f", f"description={payload['description']}",
        "-f", f"severity={payload['severity']}",
    ]
    try:
        result = subprocess.run(args, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "error", f"{type(exc).__name__}: {exc}"[:200]
    if result.returncode != 0:
        err = result.stderr.decode("utf-8", errors="replace").strip().replace("\n", " ")
        # The common one by far: private reporting not enabled on the repo.
        if "Disabled" in err or "not enabled" in err or "404" in err:
            return "reporting-disabled", "use template 3: public issue asking them to enable it"
        return "error", err[:200]
    try:
        body = json.loads(result.stdout.decode("utf-8", errors="replace"))
    except ValueError:
        return "reported", ""
    return "reported", body.get("html_url", "")


def load_tracker(path: Path):
    """Existing rows, so a re-run never overwrites what you've recorded."""
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8") as fh:
        return {row["repo"]: row for row in csv.DictReader(fh) if row.get("repo")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--disclosures", default="research/disclosure.jsonl")
    parser.add_argument("--out", default="research/disclosures")
    parser.add_argument("--publish-after", type=int, default=14,
                        help="days before publishing, quoted in each report (default: 14)")
    parser.add_argument("--severity", default="high", choices=["critical", "high"],
                        help="report repos at or above this severity (default: high)")
    parser.add_argument("--submit", action="store_true",
                        help="file the reports via gh, not just write drafts")
    parser.add_argument("--yes", action="store_true",
                        help="required with --submit; contacting people is not a dry run")
    args = parser.parse_args(argv)

    source = Path(args.disclosures)
    if not source.exists():
        print(f"no disclosures at {source} — run research_scan.py first", file=sys.stderr)
        return 1
    if args.submit and not args.yes:
        print("--submit files reports on other people's repositories. "
              "Re-run with --yes once you've read the drafts.", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)

    titles = load_rule_titles()
    publish_after = date.today() + timedelta(days=args.publish_after)
    limit = SEVERITY_RANK[args.severity]

    tracker_path = out_dir / "tracker.csv"
    tracker = load_tracker(tracker_path)

    considered = drafted = below_threshold = 0
    # A non-GitHub host can't take an advisory, but it can still be hiding a
    # live key. Counting it as "below threshold" would quietly drop someone who
    # needs telling, so these are named and handed back for manual contact.
    elsewhere = []
    for row in read_disclosures(source):
        considered += 1
        findings = [f for f in row.get("findings", [])
                    if SEVERITY_RANK.get(f["severity"], 99) <= limit]
        if not findings:
            below_threshold += 1
            continue
        slug = repo_slug(row.get("repo", ""))
        if not slug:
            elsewhere.append((row.get("repo", "?"), worst(findings), len(findings)))
            continue

        payload = advisory_payload(slug, findings, titles, publish_after)
        write_draft(out_dir, slug, payload, findings)
        drafted += 1

        existing = tracker.get(slug, {})
        record = {
            "repo": slug,
            "worst_severity": worst(findings),
            "findings": len(findings),
            "status": existing.get("status") or "drafted",
            "reported_on": existing.get("reported_on", ""),
            "advisory_url": existing.get("advisory_url", ""),
            "note": existing.get("note", ""),
        }

        # Already reported? Leave it alone. Re-reporting is not diligence.
        if args.submit and record["status"] != "reported":
            status, note = submit(slug, payload)
            record["status"] = status
            if status == "reported":
                record["reported_on"] = date.today().isoformat()
                record["advisory_url"] = note
                record["note"] = ""
            else:
                record["note"] = note
            print(f"  {status:20} {slug}")

        tracker[slug] = record

    with open(tracker_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=TRACKER_COLUMNS)
        writer.writeheader()
        for slug in sorted(tracker, key=lambda s: (SEVERITY_RANK.get(tracker[s]["worst_severity"], 9), s)):
            writer.writerow(tracker[slug])
    os.chmod(tracker_path, 0o600)

    gitignore = out_dir / ".gitignore"
    gitignore.write_text("*\n", encoding="utf-8")

    counts = {}
    for record in tracker.values():
        counts[record["status"]] = counts.get(record["status"], 0) + 1

    print(f"\n{drafted} drafts in {out_dir} "
          f"({considered} rows read, {below_threshold} below {args.severity})")
    for status, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {count:4}  {status}")
    print(f"\n  tracker -> {tracker_path}")

    if elsewhere:
        print(f"\n  {len(elsewhere)} not on GitHub — advisories can't reach these, "
              "contact them by hand:")
        for url, level, count in elsewhere:
            print(f"    {level:9} {count:3} finding(s)  {url}")
    if not args.submit:
        print("\n  Read a few drafts, then: --submit --yes")
    else:
        print(f"\n  Earliest honest publication date: {publish_after.isoformat()}")
        if counts.get("reporting-disabled"):
            print(f"  {counts['reporting-disabled']} repos have private reporting off — "
                  "template 3 in content/disclosure-templates.md covers those.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
