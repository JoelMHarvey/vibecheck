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

## The disclosure sentence

It used to say this could not know whether anyone had been contacted. It can:
the tracker records it, so the post's claim about disclosure is filled from the
same place as every other number rather than written by hand.

That claim was wrong for three of eleven repos and stayed wrong for five days.
The post said "i contacted those maintainers privately" while three of the
messages had bounced — two addresses that do not exist and one domain that does
not resolve. Nothing caught it, because that sentence was prose and prose does
not get checked against anything.

So N_CONTACTED and N_UNREACHABLE come out of the tracker, and the sentence is
written around them. Counts only — no repositories, no owners, no addresses.
Sending is still yours; asserting that you sent is not.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vibecheck.rules import ALL_RULES  # noqa: E402

TEMPLATE = ROOT / "content" / "scanned-vibe-coded-apps.md"
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TOP_RULES = 5


def rule_severities() -> dict:
    """rule_id -> severity, straight from the rule objects."""
    return {rule.id: rule.severity for rule in ALL_RULES}


def placeholder_stem(rule_id: str) -> str:
    """RULE_INNERHTML_UNTRUSTED_INPUT from innerhtml-untrusted-input.

    Rule IDs never start with a digit, so these can't collide with the
    RULE_1..RULE_5 slots that hold the top of the list.
    """
    return "RULE_" + rule_id.upper().replace("-", "_")


def named_rule_values(aggregate: dict) -> dict:
    """Every rule addressable by name, so prose can cite one that didn't
    make the top five.

    The caveat about innerHTML claims the escalated variant is "a much
    smaller number" than the vague one. That comparison has to be shown, not
    asserted, and the vague one is the only half of it that ranks.

    A rule the scanner can emit but that fired nowhere gets 0, because zero
    is a real answer. A name that isn't a rule at all gets nothing, so a
    typo in the template fails the run instead of quietly reading as 0%.
    """
    stats = {rule["rule_id"]: rule for rule in aggregate.get("rules", [])}
    titles = rule_titles()
    severity = rule_severities()
    values = {}
    for rule_id in severity:
        stem = placeholder_stem(rule_id)
        found = stats.get(rule_id)
        values[f"{stem}_PCT"] = found["repos_affected_pct"] if found else 0
        values[f"{stem}_REPOS"] = found["repos_affected"] if found else 0
        values[f"{stem}_NAME"] = titles.get(rule_id, rule_id)
        values[f"{stem}_SEVERITY"] = severity[rule_id]
    return values


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


# A row is "reached" only if someone received the message. Every other status
# is a repo nobody has been told about, whatever the reason.
REACHED = {"reported"}
# Tried and provably failed, as opposed to not yet tried. The post distinguishes
# these because they mean different things about the work: one is a gap in the
# effort, the other is the effort hitting a wall.
UNREACHABLE = {"bounced", "unreachable"}


def contact_counts(path: Path, severity: str = "critical") -> dict:
    """How many repos at this severity the tracker records as reached.

    Reads the tracker, not the sent-mail folder and not an assumption. The
    tracker is private and stays private: what leaves this function is two
    integers.

    Only positive outcomes are counted, and that is deliberate. The denominator
    comes from the scan, not from the number of rows here — a critical repo the
    tracker has never heard of would otherwise vanish from both halves of the
    fraction and leave the post claiming full coverage of a smaller world. Not
    knowing about someone is not the same as there being no one.

    Returns {} when there is no tracker, which leaves the placeholders unfilled
    and stops the post being written at all — the right outcome, because a post
    that claims disclosure without a tracker to back it is the exact thing this
    is here to prevent.
    """
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            rows = [row for row in csv.DictReader(fh) if row.get("repo")]
    except OSError:
        return {}

    limit = SEVERITY_RANK[severity]
    at_severity = [row for row in rows
                   if SEVERITY_RANK.get(row.get("worst_severity", ""), 99) <= limit]
    if not at_severity:
        return {}

    return {
        "N_CONTACTED": sum(1 for row in at_severity if row.get("status") in REACHED),
        "N_UNREACHABLE": sum(1 for row in at_severity
                             if row.get("status") in UNREACHABLE),
    }


def values_from(aggregate: dict, disclosed=None, contacts=None) -> dict:
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
        # Repos that could not be cloned. Not the same thing as an exclusion
        # and the post must not merge the two: an exclusion is a filter we
        # chose, a failure is a hole in the sample we don't know the contents
        # of. Both have to be subtracted from the attempted count for the
        # arithmetic in the caveat to work.
        "N_FAILED": aggregate.get("targets_failed"),
        "N_ATTEMPTED": aggregate.get("targets_attempted"),
    }
    # Everyone at critical *or* high: the set the disclosure run contacts.
    # This is a union and must come from the scan, because the severity counts
    # overlap — a repo with both a critical and a high is in each of them, so
    # adding them up overstates the number of affected projects. An aggregate
    # written before the scanner recorded it has no value here rather than a
    # wrong one.
    values["N_DISCLOSED"] = aggregate.get("repos_at_or_above_high") or disclosed

    values.update(contacts or {})
    # Everyone at critical the scan found, minus everyone the tracker can
    # account for. Anything left is a repo nobody has been told about — whether
    # because it was missed, or because the tracker predates it.
    if contacts and values["N_ANY_CRITICAL"] is not None:
        values["N_UNCONTACTED"] = (values["N_ANY_CRITICAL"]
                                   - contacts["N_CONTACTED"]
                                   - contacts["N_UNREACHABLE"])
    values.update(named_rule_values(aggregate))

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


BLOCK_RE = re.compile(
    r"\{\{\?([A-Z0-9_]+)\}\}\n?(.*?)\{\{/\1\}\}\n?", re.S)


def resolve_blocks(template: str, values: dict) -> str:
    """Keep {{?NAME}}...{{/NAME}} only when NAME is a non-zero number.

    The post has to be true under outcomes that need different sentences. "0
    of them i could not reach" is not a sentence anyone writes, and the
    alternative — leaving the clause in and hoping the number is never zero —
    is how the disclosure claim went stale in the first place.

    Deliberately the smallest thing that works: no else, no nesting, no
    expressions. A template language in here would be a second place for the
    post to go wrong.
    """
    def keep(match):
        name, body = match.group(1), match.group(2)
        # An absent value drops the block. It cannot be asserted, so it isn't.
        return body if values.get(name) else ""

    return BLOCK_RE.sub(keep, template)


def fill(template: str, values: dict):
    """Substitute, then report anything left over. Returns (text, missing)."""
    template = resolve_blocks(template, values)
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
    parser.add_argument("--tracker", default="research/disclosures/tracker.csv",
                        help="where the disclosure outcomes are recorded; the post's "
                             "claim about who was contacted is filled from it")
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
    values = values_from(aggregate, count_disclosures(Path(args.disclosures)),
                         contact_counts(Path(args.tracker)))
    # Someone at critical who is neither reached nor established as
    # unreachable has simply not been told, and publishing then is the harm
    # the whole disclosure process exists to prevent. Refuse before writing.
    outstanding = values.get("N_UNCONTACTED")
    if outstanding is not None and outstanding < 0:
        # More accounted for than the scan found: the tracker is from a
        # different scan. Publishing either number would be a guess. Checked
        # before the shortfall branch, which a negative would also satisfy.
        print(f"\nthe tracker accounts for more critical repos than this scan "
              f"found ({values['N_ANY_CRITICAL']}). It is from a different run.\n"
              f"Nothing was written.", file=sys.stderr)
        return 1
    if outstanding:
        print(f"\n{values['N_ANY_CRITICAL']} repos are at critical in the scan, but "
              f"the tracker accounts for only {values['N_CONTACTED']} contacted and "
              f"{values['N_UNREACHABLE']} unreachable.\n"
              f"{outstanding} nobody has been told about. Contact them, or record "
              f"why they cannot be reached (mark_reported.py --bounced --address "
              f"...), then re-run.\n"
              f"Nothing was written.", file=sys.stderr)
        return 1

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
