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
from vibecheck.scanner import SKIP_DIRS, scan  # noqa: E402

# A repository has to contain an application before it can be evidence about
# applications. Prompt collections, link directories and slide decks are
# almost pure markdown, so they scan perfectly clean — and a handful of them
# in the sample quietly inflates the "completely clean" percentage, which is
# the single number the writeup rests on. Excluding them is not tidying: it
# is the difference between a statistic and an artefact.
APP_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
    ".html", ".py", ".rb", ".php", ".go", ".java", ".cs", ".swift", ".kt",
}

def looks_like_an_app(root: Path) -> bool:
    """True if the repo contains any application source at all.

    One file is the bar, deliberately. The temptation is a threshold — "at
    least three source files" — but that quietly excludes the two-file static
    page, which is a real vibe-coded app and exactly the kind this research is
    about. Zero source files is a definition, not a judgement call: a
    repository of markdown cannot be evidence about how apps are built.
    """
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix.lower() in APP_EXTENSIONS:
                return True
    return False

BANNER = """\
vibecheck research scan
  · aggregate.json is anonymised and safe to publish
  · disclosure.jsonl is PRIVATE — for notifying people, never for posting
  · never test a credential you find; disclose before you publish
"""


PROGRESS_FILE = "scanned.jsonl"


def read_progress(path: Path):
    """Load an interrupted run's results, keyed by target.

    A malformed trailing line is expected rather than exceptional — it's what
    a kill mid-write leaves behind — so it's dropped and the run continues.
    """
    done = {}
    if not path.exists():
        return done
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("repo"):
            done[record["repo"]] = record
    return done


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
        capture_output=True, timeout=180,
        # Bytes, not text. git echoes branch and path names straight from the
        # repository, and a repo using a non-UTF-8 encoding makes a decoding
        # subprocess raise UnicodeDecodeError from inside communicate() — which
        # killed a 200-repo run at number 163. We only need the return code.
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
    parser.add_argument(
        "--restart", action="store_true",
        help=f"discard {PROGRESS_FILE} and scan everything again "
             "(default: resume, skipping targets already done)",
    )
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

    # Progress is written per repo, not at the end, so a crash 163 repos into
    # a 200-repo run costs one repo instead of all of them. This file holds
    # repo names and paths, so it's as private as disclosure.jsonl.
    progress_path = out_dir / PROGRESS_FILE
    done = {} if args.restart else read_progress(progress_path)
    if done:
        print(f"resuming: {len(done)} of {len(targets)} already scanned "
              f"(--restart to start over)\n")

    progress = open(progress_path, "w" if args.restart else "a", encoding="utf-8")
    os.chmod(progress_path, 0o600)

    with progress:
        for i, target in enumerate(targets, 1):
            if target in done:
                continue
            print(f"[{i}/{len(targets)}] {target}")
            record = {"repo": target}
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    path, _ = fetch(target, Path(tmp))
                    if path is None:
                        record["error"] = "clone failed"
                        print("      could not clone — skipped")
                    elif not looks_like_an_app(path):
                        record["skipped"] = "no application code"
                        print("      not an app (no application code) — excluded")
                    else:
                        result = scan(str(path))
                        record.update(
                            score=result.score,
                            grade=result.grade,
                            findings=[
                                {"rule_id": f.rule_id, "severity": f.severity,
                                 "path": f.path, "line": f.line}
                                for f in result.findings
                            ],
                        )
                        print(f"      score {result.score} ({result.grade}), "
                              f"{len(record['findings'])} findings")
            except subprocess.TimeoutExpired:
                record["error"] = "clone timed out"
                print("      clone timed out — skipped")
            except Exception as exc:  # noqa: BLE001 — one bad repo must not end the run
                record["error"] = f"{type(exc).__name__}: {exc}"[:200]
                print(f"      {record['error']} — skipped")

            done[target] = record
            progress.write(json.dumps(record) + "\n")
            progress.flush()

    # Three outcomes, kept apart on purpose. A repo we couldn't reach is a gap
    # in the data; a repo we deliberately left out is a statement about what
    # the sample is. Folding them together would hide the second.
    scanned = [r for r in done.values() if "error" not in r and "skipped" not in r]
    failed = [r for r in done.values() if "error" in r]
    excluded = [r for r in done.values() if "skipped" in r]
    disclosures = [
        {"repo": r["repo"], "score": r["score"],
         "findings": [f for f in r["findings"] if f["severity"] in ("critical", "high")]}
        for r in scanned
        if any(f["severity"] in ("critical", "high") for f in r["findings"])
    ]

    aggregate = anonymise(scanned)
    aggregate["targets_attempted"] = len(targets)
    aggregate["targets_failed"] = len(failed)
    aggregate["targets_excluded"] = len(excluded)
    # Why each one dropped out, so the writeup can describe its own sample.
    aggregate["failure_reasons"] = dict(Counter(r["error"] for r in failed))
    aggregate["exclusion_reasons"] = dict(Counter(r["skipped"] for r in excluded))

    agg_path = out_dir / "aggregate.json"
    agg_path.write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")

    disc_path = out_dir / "disclosure.jsonl"
    with open(disc_path, "w", encoding="utf-8") as fh:
        for row in disclosures:
            fh.write(json.dumps(row) + "\n")
    os.chmod(disc_path, 0o600)

    # Both of these name repositories; only aggregate.json is publishable.
    gitignore = out_dir / ".gitignore"
    gitignore.write_text(f"disclosure.jsonl\n{PROGRESS_FILE}\n", encoding="utf-8")

    print(f"\nScanned {aggregate['repos_scanned']} of {len(targets)} targets")
    for label, reasons in (("could not scan", aggregate["failure_reasons"]),
                           ("excluded from the sample", aggregate["exclusion_reasons"])):
        if reasons:
            print(f"  {label}:")
            for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
                print(f"    {count:4}  {reason}")
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
