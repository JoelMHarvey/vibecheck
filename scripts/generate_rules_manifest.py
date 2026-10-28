"""Generate rules.json — the client-side rule manifest.

Share links encode only the *facts* of a scan (rule id, severity, path,
line, excerpt). The long prose — title, description, fix-prompt template —
lives in this manifest, which the page fetches once. That keeps a shared
report URL small enough to paste into a chat message.

visibility-rules.json does the same for the visibility mode (/visibility),
with each rule's severity, category, "how to check it worked" and guide.

Run after changing rules.py or visibility/rules.py:

    python3 scripts/generate_rules_manifest.py

tests/test_rules_manifest.py fails if the committed file is out of date.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibecheck.rules import ALL_RULES  # noqa: E402
from vibecheck.urlscan import iter_url_rules  # noqa: E402

MANIFEST_PATH = Path(__file__).resolve().parent.parent / "rules.json"
VIS_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "visibility-rules.json"
INTEGRITY_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "integrity-rules.json"


def build_manifest() -> dict:
    from vibecheck.checks.security import CATEGORIES, GUIDES, RULE_CATEGORY, SECRET_GUIDE, VERIFY

    def extra(rule_id: str, fix_prompt: str) -> dict:
        category = RULE_CATEGORY[rule_id]
        out = {"c": category}
        if fix_prompt:
            out["v"] = VERIFY[category]
        guide = GUIDES.get(rule_id) or (SECRET_GUIDE if category == "secrets" else None)
        if guide:
            out["g"] = guide
        return out

    rules = {}
    for rule in ALL_RULES:
        rules[rule.id] = {"t": rule.title, "d": rule.description, "f": rule.fix_prompt,
                          **extra(rule.id, rule.fix_prompt)}
    # Deployed-site rules are built by urlscan, not from Rule objects.
    for rule_id, title, description, fix_prompt in iter_url_rules():
        rules[rule_id] = {"t": title, "d": description, "f": fix_prompt, **extra(rule_id, fix_prompt)}
    # Severity isn't here: the scanner can raise it per finding (a key in
    # browser code), so a share link carries it with each finding.
    return {"version": 2, **_check_header("security"), "rules": rules,
            "categories": [[c.id, c.label, c.weight] for c in CATEGORIES]}


def _check_header(check_id: str) -> dict:
    """What report.js needs to word a report without knowing the check."""
    from vibecheck.core.registry import get

    check = get(check_id)
    return {"check": check.id, "check_version": check.version, "title": check.title,
            "blurbs": dict(check.blurbs), "footer": check.footer, "not_run": check.not_run}


def render() -> str:
    return json.dumps(build_manifest(), indent=1, sort_keys=True) + "\n"


def _table_manifest(check_id: str, RULES, PASSES, categories) -> dict:
    """A check whose prose is a rule table (visibility, integrity)."""
    rules = {}
    for rule in RULES.values():
        entry = {"t": rule.title, "s": rule.severity, "c": rule.category,
                 "d": rule.description, "f": rule.fix_prompt, "v": rule.verify}
        if rule.guide:
            entry["g"] = rule.guide
        rules[rule.id] = entry
    for pass_id, (title, category) in PASSES.items():
        rules[pass_id] = {"t": title, "s": "pass", "c": category}
    return {"version": 2, **_check_header(check_id), "rules": rules,
            "categories": [[c.id, c.label, c.weight] for c in categories]}


def build_integrity_manifest() -> dict:
    from vibecheck.checks.integrity.rules import CATEGORIES, PASSES, RULES

    return _table_manifest("integrity", RULES, PASSES, CATEGORIES)


def render_integrity() -> str:
    return json.dumps(build_integrity_manifest(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def build_visibility_manifest() -> dict:
    from vibecheck.checks.visibility import config
    from vibecheck.checks.visibility.rules import PASSES, RULES

    rules = {}
    for rule in RULES.values():
        entry = {"t": rule.title, "s": rule.severity, "c": rule.category,
                 "d": rule.description, "f": rule.fix_prompt, "v": rule.verify}
        if rule.guide:
            entry["g"] = rule.guide
        rules[rule.id] = entry
    for check_id, (title, category) in PASSES.items():
        rules[check_id] = {"t": title, "s": "pass", "c": category}
    return {"version": 2, **_check_header("visibility"), "rules": rules,
            "categories": [[c.id, c.label, c.weight] for c in config.CATEGORIES]}


def render_visibility() -> str:
    return json.dumps(build_visibility_manifest(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    MANIFEST_PATH.write_text(render(), encoding="utf-8")
    print(f"wrote {MANIFEST_PATH} ({len(build_manifest()['rules'])} rules)")
    VIS_MANIFEST_PATH.write_text(render_visibility(), encoding="utf-8")
    print(f"wrote {VIS_MANIFEST_PATH} ({len(build_visibility_manifest()['rules'])} rules)")
    INTEGRITY_MANIFEST_PATH.write_text(render_integrity(), encoding="utf-8")
    print(f"wrote {INTEGRITY_MANIFEST_PATH} ({len(build_integrity_manifest()['rules'])} rules)")
