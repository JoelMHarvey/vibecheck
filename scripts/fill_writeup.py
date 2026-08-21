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
TEMPLATE = ROOT / "content" / "scanned-vibe-coded-apps.md"
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
TOP_RULES = 5


def rule_titles() -> dict:
    """rule_id -> human title, from the manifest the site already ships."""
    try:
        manifest = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {rid: spec.get("t", rid) for rid, spec in manifest.get("rules", {}).items()}


def values_from(aggregate: dict) -> dict:
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
    # N_DISCLOSED is everyone at critical *or* high — the set the disclosure
    # run actually contacts, which is not the same as the critical count.
    critical = (severity.get("critical") or {}).get("count")
    high = (severity.get("high") or {}).get("count")
    values["N_DISCLOSED"] = None if critical is None or high is None else critical + high

    for i, rule in enumerate(aggregate.get("rules", [])[:TOP_RULES], 1):
        values[f"RULE_{i}_NAME"] = titles.get(rule["rule_id"], rule["rule_id"])
        values[f"RULE_{i}_PCT"] = rule["repos_affected_pct"]
        values[f"RULE_{i}_REPOS"] = rule["repos_affected"]

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
    values = values_from(aggregate)
    text, missing = fill(strip_draft_note(template), values)

    print("values from the scan:")
    for key in sorted(values):
        if f"{{{{{key}}}}}" in template:
            print(f"  {key:20} {values[key]}")
    unused = [k for k in sorted(values) if f"{{{{{k}}}}}" not in template and values[k] is not None]
    if unused:
        print("\n  available but unused by the template: " + ", ".join(unused))

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
