"""Build the corpus: find public repos that were built with AI app builders.

    python3 scripts/collect_targets.py --limit 200 > targets.txt
    python3 scripts/research_scan.py targets.txt --out research/

Uses the `gh` CLI so it borrows the auth you already have — no token handling
here. It only ever reads GitHub's search API and writes a list of clone URLs.
It does not clone, scan, or contact anything; research_scan.py does that.

## What counts as vibe-coded

There is no flag for it, so this looks for the fingerprints these tools leave
behind — the dependency Lovable injects, the README line Bolt writes, the
attribution v0 adds. Each query is one angle, and a repo needs only one of
them to qualify. That's deliberate: no single signal finds everything, and
the point of the writeup is breadth.

## What gets filtered out, and why it matters

A corpus full of templates and tutorials would produce a number that means
nothing. Starters get copied unmodified thousands of times, so one insecure
template would show up as a hundred insecure "apps". Forks duplicate their
parents. The tool vendors' own repos aren't anyone's side project. All of
those are dropped, and the count of what was dropped is printed to stderr so
the writeup can say what the sample actually is.

## The rules this corpus is collected under

Finding a repo is not permission to test it. research_scan.py never uses a
credential it finds, disclosure happens privately before anything is
published, and only aggregates get published — see the header of that script.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import OrderedDict

# Each entry is (label, GitHub search query, search kind).
#
# These are all code searches, and that is the whole point. An earlier version
# also searched descriptions for "lovable.dev", "bolt.new" and "vibe coded",
# which conflated two completely different things: an app *built by* one of
# these tools, and a repo that merely *mentions* one. The mention queries
# dragged in prompt directories, Lovable downloaders, MCP servers and
# conference slides — and because those repos are mostly markdown, they
# scanned clean and inflated the "completely clean" figure, which is the one
# statistic the writeup turns on.
#
# A generated app carries a fingerprint it did not choose: an injected dev
# dependency, or the project URL the tool writes into the README. Talking
# about Lovable does not give you a `lovable-tagger` entry in package.json.
QUERIES = [
    # Lovable injects this dev dependency into every project it generates.
    ("lovable-tagger", '"lovable-tagger" filename:package.json', "code"),
    # The generated README links back to the specific project that made it.
    ("lovable-readme", '"lovable.dev/projects" filename:README.md', "code"),
    # Bolt's WebContainer projects and its README attribution.
    ("bolt-readme", '"bolt.new" filename:README.md', "code"),
    # v0 writes an attribution block into generated READMEs.
    ("v0-readme", '"Built with v0" filename:README.md', "code"),
    ("v0-vercel", '"v0.dev" filename:README.md', "code"),
]

# Repos that would distort the sample rather than describe it.
EXCLUDE_OWNERS = {
    "lovable-dev", "lovable-labs", "stackblitz", "stackblitz-labs",
    "vercel", "vercel-labs", "shadcn-ui", "supabase", "firebase",
}
EXCLUDE_NAME_WORDS = re.compile(
    r"\b(template|starter|boilerplate|scaffold|example|examples|demo|demos|"
    r"tutorial|course|workshop|clone|awesome|playground|sandbox|test|testing"
    # Written *about* these tools rather than *by* them: prompt collections,
    # downloaders, MCP servers, themes, slide decks.
    r"|prompt|prompts|cheatsheet|directory|downloader|mcp|theme|themes"
    r"|docs|slides|talk|guide|guides|resources|collection|toolkit)\b",
    re.I,
)


def gh(args: list) -> str:
    result = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(f"  gh failed: {result.stderr.strip()[:200]}", file=sys.stderr)
        return ""
    return result.stdout


def search_repos(query: str, limit: int):
    raw = gh(["search", "repos", query, "--limit", str(limit),
              "--json", "fullName,isFork,isArchived,stargazersCount,description"])
    try:
        return json.loads(raw) if raw else []
    except ValueError:
        return []


def search_code(query: str, limit: int):
    """Code search returns file hits; collapse them to their repositories."""
    raw = gh(["search", "code", query, "--limit", str(limit), "--json", "repository"])
    try:
        hits = json.loads(raw) if raw else []
    except ValueError:
        return []
    seen = OrderedDict()
    for hit in hits:
        repo = hit.get("repository") or {}
        name = repo.get("nameWithOwner") or repo.get("fullName")
        if name:
            seen.setdefault(name, {"fullName": name, "isFork": False,
                                   "isArchived": False, "stargazersCount": 0,
                                   "description": repo.get("description") or ""})
    return list(seen.values())


def reject(repo: dict) -> str:
    """Why this repo is not part of the sample, or '' to keep it."""
    full = repo.get("fullName") or ""
    if "/" not in full:
        return "malformed"
    owner, name = full.split("/", 1)
    if owner.lower() in EXCLUDE_OWNERS:
        return "vendor"
    if repo.get("isFork"):
        return "fork"
    if repo.get("isArchived"):
        return "archived"
    # Underscores are word characters, so \b never fires around them and
    # "Ultimate_Prompts_Directory" would sail past a \bprompts\b. Repo names
    # use _ and - interchangeably as separators; treat them that way.
    haystack = f"{name} {repo.get('description') or ''}".replace("_", " ")
    if EXCLUDE_NAME_WORDS.search(haystack):
        return "template/demo"
    return ""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--limit", type=int, default=200,
                        help="target corpus size (default: 200)")
    parser.add_argument("--per-query", type=int, default=60,
                        help="results to pull per search (default: 60)")
    parser.add_argument("--min-stars", type=int, default=0,
                        help="skip repos below this star count (default: 0 — "
                             "popular repos are the least representative ones)")
    args = parser.parse_args(argv)

    if not shutil.which("gh"):
        print("gh CLI not found. Install it and run `gh auth login`.", file=sys.stderr)
        return 1

    kept = OrderedDict()
    rejected = {}
    per_source = {}

    for label, query, kind in QUERIES:
        print(f"searching: {label}", file=sys.stderr)
        found = search_code(query, args.per_query) if kind == "code" else search_repos(query, args.per_query)
        added = 0
        for repo in found:
            full = repo.get("fullName") or ""
            if full in kept:
                continue
            reason = reject(repo)
            if not reason and repo.get("stargazersCount", 0) < args.min_stars:
                reason = "below min-stars"
            if reason:
                rejected[reason] = rejected.get(reason, 0) + 1
                continue
            kept[full] = label
            added += 1
            if len(kept) >= args.limit:
                break
        per_source[label] = added
        print(f"  +{added} (running total {len(kept)})", file=sys.stderr)
        if len(kept) >= args.limit:
            break

    # stdout is the targets file; stderr is the commentary. Keeps
    # `> targets.txt` clean.
    print("# vibecheck research corpus")
    print(f"# {len(kept)} repositories")
    print("#")
    print("# Collected by scripts/collect_targets.py from public GitHub search.")
    print("# Forks, archived repos, templates/demos and vendor repos excluded.")
    print("#")
    for label, count in per_source.items():
        print(f"#   {label}: {count}")
    print()
    for full in kept:
        print(f"https://github.com/{full}")

    print(f"\n{len(kept)} repos collected", file=sys.stderr)
    if rejected:
        print("excluded from the sample:", file=sys.stderr)
        for reason, count in sorted(rejected.items(), key=lambda kv: -kv[1]):
            print(f"  {count:5}  {reason}", file=sys.stderr)
    print("\nnext: python3 scripts/research_scan.py targets.txt --out research/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
