"""Scan a corpus of public repos and produce ANONYMISED aggregate stats.

This is the data-collection harness behind the "I scanned N vibe-coded apps"
writeup. It is deliberately built so the publishable output cannot identify
anyone.

    python3 scripts/research_scan.py targets.txt --out research/

`targets.txt` holds one git URL (or local path) per line; blank lines and
`#` comments are ignored.

Two outputs:

  aggregate.json   Safe to publish. Counts, percentages, score
                   distribution. No repo names, no file paths, no
                   excerpts, no secrets.

  disclosure.jsonl PRIVATE. Per-repo findings so you can notify people
                   whose credentials are exposed. Written 0600 and
                   gitignored. Contains repo URLs and file paths but never
                   secret values — the scanner redacts those before they
                   reach any output.

## Rules this tool follows, and you should too

1. **Never test a discovered credential.** Not once, not "just to check if
   it's live". That crosses from reading public code into unauthorised
   access. This script makes no outbound request to anything but the git
   remotes you list.
2. **Disclose privately before publishing.** Anyone with a live critical
   finding gets contacted and given time to rotate.
3. **Publish aggregates only.** No repo names, no owners, no paths, no
   distinguishing quotes — "one app had X" plus a rare enough X is an
   identifier.
4. **Public does not mean fair game.** People published code, not consent
   to be made an example of.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vibecheck.rules import SEVERITY_ORDER  # noqa: E402
from vibecheck.scanner import scan  # noqa: E402

BANNER = """\
vibecheck research scan
  · aggregate.json is anonymised and safe to publish
  · disclosure.jsonl is PRIVATE — for notifying people, never for posting
  · never test a credential you find; disclose before you publish
"""


def read_targets(path: Path):
    targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    return targets


def fetch(target: str, workdir: Path):
    """Shallow-clone a remote, or return a local path as-is."""
    local = Path(target).expanduser()
    if local.exists():
        return local, False
    dest = workdir / "repo"
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", target, str(dest)],
        capture_output=True, text=True, timeout=180,
    )
    if result.returncode != 0:
        return None, True
    return dest, True


def anonymise(results):
    """Reduce per-repo results to publishable aggregates."""
    scanned = len(results)
    rule_repo_counts = Counter()   # repos affected by each rule
    rule_total_counts = Counter()  # total occurrences
    severity_repo_counts = Counter()
    grades = Counter()
    scores = []
    clean = 0

    for r in results:
        scores.append(r["score"])
        grades[r["grade"]] += 1
        if not r["findings"]:
            clean += 1
        seen_rules, seen_sevs = set(), set()
        for f in r["findings"]:
            rule_total_counts[f["rule_id"]] += 1
            seen_rules.add(f["rule_id"])
            seen_sevs.add(f["severity"])
        for rule_id in seen_rules:
            rule_repo_counts[rule_id] += 1
        for sev in seen_sevs:
            severity_repo_counts[sev] += 1

    def pct(n):
        return round(100.0 * n / scanned, 1) if scanned else 0.0

    return {
        "repos_scanned": scanned,
        "clean_repos": clean,
        "clean_pct": pct(clean),
        "score": {
            "mean": round(statistics.mean(scores), 1) if scores else None,
            "median": statistics.median(scores) if scores else None,
            "min": min(scores) if scores else None,
            "max": max(scores) if scores else None,
        },
        "grades": {g: grades.get(g, 0) for g in "ABCDF"},
        "repos_with_severity": {
            sev: {"count": severity_repo_counts.get(sev, 0), "pct": pct(severity_repo_counts.get(sev, 0))}
            for sev in SEVERITY_ORDER
        },
        "rules": sorted(
            (
                {
                    "rule_id": rule_id,
                    "repos_affected": count,
                    "repos_affected_pct": pct(count),
                    "total_occurrences": rule_total_counts[rule_id],
                }
                for rule_id, count in rule_repo_counts.items()
            ),
            key=lambda d: -d["repos_affected"],
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Scan a corpus of repos; emit anonymised stats.")
    parser.add_argument("targets", help="file with one git URL or local path per line")
    parser.add_argument("--out", default="research", help="output directory (default: research/)")
    parser.add_argument("--limit", type=int, help="only scan the first N targets")
    args = parser.parse_args(argv)

    print(BANNER)

    targets = read_targets(Path(args.targets))
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        print("No targets found.")
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    results, disclosures, failed = [], [], []

    for i, target in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {target}")
        with tempfile.TemporaryDirectory() as tmp:
            path, cloned = fetch(target, Path(tmp))
            if path is None:
                failed.append(target)
                print("      could not clone — skipped")
                continue
            result = scan(str(path))

        findings = [
            {"rule_id": f.rule_id, "severity": f.severity, "path": f.path, "line": f.line}
            for f in result.findings
        ]
        results.append({"score": result.score, "grade": result.grade, "findings": findings})

        worst = [f for f in findings if f["severity"] in ("critical", "high")]
        if worst:
            disclosures.append({"repo": target, "score": result.score, "findings": worst})
        print(f"      score {result.score} ({result.grade}), {len(findings)} findings")

    aggregate = anonymise(results)
    aggregate["targets_attempted"] = len(targets)
    aggregate["targets_failed"] = len(failed)

    agg_path = out_dir / "aggregate.json"
    agg_path.write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")

    disc_path = out_dir / "disclosure.jsonl"
    with open(disc_path, "w", encoding="utf-8") as fh:
        for row in disclosures:
            fh.write(json.dumps(row) + "\n")
    os.chmod(disc_path, 0o600)

    gitignore = out_dir / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("disclosure.jsonl\n", encoding="utf-8")

    print(f"\nScanned {aggregate['repos_scanned']} repos "
          f"({aggregate['targets_failed']} failed to clone)")
    print(f"  mean score {aggregate['score']['mean']}, "
          f"{aggregate['clean_pct']}% completely clean")
    for sev in ("critical", "high"):
        row = aggregate["repos_with_severity"][sev]
        print(f"  {row['pct']}% of repos had at least one {sev} finding")
    print(f"\n  publishable stats -> {agg_path}")
    print(f"  PRIVATE disclosures -> {disc_path} ({len(disclosures)} repos need contacting)")
    if disclosures:
        print("\n  Contact those maintainers and give them time to rotate BEFORE publishing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
