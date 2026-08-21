"""Fill the writeup's placeholders from research/aggregate.json.

    python3 scripts/fill_writeup.py            # -> research/scanned-vibe-coded-apps.md
    python3 scripts/fill_writeup.py --stdout   # just show the numbers it would use

The template says it plainly: "a security post with invented statistics is
worse than no post". Typing eleven numbers out of a JSON file by hand is
exactly the kind of task that produces one transposed digit, in the one
document where a transposed digit is the whole problem. So it isn't typed.

Two things this refuses to do:

* **Emit a post with a placeholder left in it.** A `{{RULE_4_NAME}}` that
  survived into a published post is embarrassing; one that got replaced with a
  plausible guess is dishonest. Any unfilled placeholder is an error and no
  file is written.
* **Write anywhere but research/.** The filled post quotes real figures from a
  scan whose disclosure window may not have closed, and research/ is
  gitignored. The template in content/ stays a template.

It does not check that anyone has actually been contacted — it can't know
that. Step 4 of the template's own running order is still yours.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vibecheck.rules import ALL_RULES  # noqa: E402

TEMPLATE = ROOT / "content" / "scanned-vibe-coded-apps.md"
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
TOP_RULES = 5


def rule_severities() -> dict:
    """rule_id -> severity, straight from the rule objects."""
    return {rule.id: rule.severity for rule in ALL_RULES}


def problem_rules(rules):
    """The rules worth calling problems, and the ones held back.

    An info-severity rule is not a finding — it is the scanner saying "this is
    normal, here is the thing to check". A Supabase anon key is the example
    that matters: it is public by design, our own guide tells people to stop
    worrying about it, and listing it under "the most common problems" would
    contradict the advice on the same website.

    Returns (kept, dropped) rather than filtering silently, because a list
    that quietly lost an entry reads as the whole picture when it isn't.
    """
    severity = rule_severities()
    kept, dropped = [], []
    for rule in rules:
        if severity.get(rule["rule_id"]) == "info":
            dropped.append(rule)
        else:
            kept.append(rule)
    return kept, dropped


def rule_titles() -> dict:
    """rule_id -> human title, from the manifest the site already ships."""
    try:
        manifest = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {rid: spec.get("t", rid) for rid, spec in manifest.get("rules", {}).items()}


def count_disclosures(path: Path):
    """How many repos the disclosure run actually listed, one row each.

    A fallback for aggregates written before the scanner recorded the union,
    so an existing corpus doesn't have to be rescanned to get one number
    right. disclosure.jsonl is the disclosure set itself, so it is at least
    as authoritative as the aggregate. Returns None if it isn't there.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    return sum(1 for line in lines if line.strip()) or None


def values_from(aggregate: dict, disclosed=None) -> dict:
    """Every placeholder the template can ask for, and nothing invented."""
    titles = rule_titles()
    severity = aggregate.get("repos_with_severity", {})
    score = aggregate.get("score", {})

    values = {
        "N_REPOS": aggregate.get("repos_scanned"),
        "PCT_CLEAN": aggregate.get("clean_pct"),
        "MEDIAN_SCORE": score.get("median"),
        "MEAN_SCORE": score.get("mean"),
        "PCT_ANY_CRITICAL": (severity.get("critical") or {}).get("pct"),
        "PCT_ANY_HIGH": (severity.get("high") or {}).get("pct"),
        "N_ANY_CRITICAL": (severity.get("critical") or {}).get("count"),
        "N_ANY_HIGH": (severity.get("high") or {}).get("count"),
        "N_EXCLUDED": aggregate.get("targets_excluded"),
        "N_ATTEMPTED": aggregate.get("targets_attempted"),
    }
    # Everyone at critical *or* high: the set the disclosure run contacts.
    # This is a union and must come from the scan, because the severity counts
    # overlap — a repo with both a critical and a high is in each of them, so
    # adding them up overstates the number of affected projects. An aggregate
    # written before the scanner recorded it has no value here rather than a
    # wrong one.
    values["N_DISCLOSED"] = aggregate.get("repos_at_or_above_high") or disclosed

    severity = rule_severities()
    ranked, _ = problem_rules(aggregate.get("rules", []))
    for i, rule in enumerate(ranked[:TOP_RULES], 1):
        values[f"RULE_{i}_NAME"] = titles.get(rule["rule_id"], rule["rule_id"])
        values[f"RULE_{i}_PCT"] = rule["repos_affected_pct"]
        values[f"RULE_{i}_REPOS"] = rule["repos_affected"]
        values[f"RULE_{i}_SEVERITY"] = severity.get(rule["rule_id"], "")

    # A median that happens to be an integer should read "71", not "71.0".
    for key, value in values.items():
        if isinstance(value, float) and value.is_integer():
            values[key] = int(value)
    return values


def fill(template: str, values: dict):
    """Substitute, then report anything left over. Returns (text, missing)."""
    missing = []

    def replace(match):
        name = match.group(1)
        if name not in values or values[name] is None:
            missing.append(name)
            return match.group(0)
        return str(values[name])

    return PLACEHOLDER_RE.sub(replace, template), sorted(set(missing))


def strip_draft_note(text: str) -> str:
    """Drop the leading instructional comment; it's addressed to the filler."""
    if text.startswith("<!--"):
        _, _, rest = text.partition("-->")
        return rest.lstrip("\n")
    return text


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--aggregate", default="research/aggregate.json")
    parser.add_argument("--disclosures", default="research/disclosure.jsonl",
                        help="counted only to fill in the number of repos needing "
                             "disclosure when the aggregate predates that field")
    parser.add_argument("--out", default="research/scanned-vibe-coded-apps.md")
    parser.add_argument("--template", default=str(TEMPLATE))
    parser.add_argument("--stdout", action="store_true",
                        help="print the values and the post, write nothing")
    args = parser.parse_args(argv)

    agg_path = Path(args.aggregate)
    if not agg_path.exists():
        print(f"no aggregate at {agg_path} — run research_scan.py first", file=sys.stderr)
        return 1
    try:
        aggregate = json.loads(agg_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"{agg_path} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    template = Path(args.template).read_text(encoding="utf-8")
    values = values_from(aggregate, count_disclosures(Path(args.disclosures)))
    text, missing = fill(strip_draft_note(template), values)

    print("values from the scan:")
    for key in sorted(values):
        if f"{{{{{key}}}}}" in template:
            print(f"  {key:20} {values[key]}")
    unused = [k for k in sorted(values) if f"{{{{{k}}}}}" not in template and values[k] is not None]
    if unused:
        print("\n  available but unused by the template: " + ", ".join(unused))

    _, dropped = problem_rules(aggregate.get("rules", []))
    if dropped:
        titles = rule_titles()
        print("\n  held back from the list of problems (info severity — not findings):")
        for rule in dropped:
            name = titles.get(rule["rule_id"], rule["rule_id"])
            print(f"    {rule['repos_affected_pct']:5}%  {name}")
        print("    Mentioning these in the post is fine; calling them problems is not.")

    if missing:
        print("\nnot written — no value for: " + ", ".join(missing), file=sys.stderr)
        print("Fill these by hand in the template or leave them out; do not guess.",
              file=sys.stderr)
        return 1

    header = (
        f"<!-- Figures filled from {agg_path} by scripts/fill_writeup.py.\n"
        f"     {values['N_REPOS']} repos scanned. Do not publish until everyone in\n"
        "     research/disclosure.jsonl has been contacted and given 14 days. -->\n\n"
    )
    if args.stdout:
        print("\n" + "-" * 60 + "\n")
        print(header + text, end="")
        return 0

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(header + text, encoding="utf-8")
    print(f"\n  filled post -> {out_path}")
    print("  Read it before it goes anywhere. The disclosure window is still yours.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
