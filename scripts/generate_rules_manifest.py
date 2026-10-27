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


def build_manifest() -> dict:
    all_rules = ALL_RULES
    rules = {}
    for rule in all_rules:
        rules[rule.id] = {"t": rule.title, "d": rule.description, "f": rule.fix_prompt}
    # Deployed-site rules are built by urlscan, not from Rule objects.
    for rule_id, title, description, fix_prompt in iter_url_rules():
        rules[rule_id] = {"t": title, "d": description, "f": fix_prompt}
    return {"version": 1, "rules": rules}


def render() -> str:
    return json.dumps(build_manifest(), indent=1, sort_keys=True) + "\n"


def build_visibility_manifest() -> dict:
    from vibecheck.visibility import config
    from vibecheck.visibility.rules import PASSES, RULES

    rules = {}
    for rule in RULES.values():
        entry = {"t": rule.title, "s": rule.severity, "c": rule.category,
                 "d": rule.description, "f": rule.fix_prompt, "v": rule.verify}
        if rule.guide:
            entry["g"] = rule.guide
        rules[rule.id] = entry
    return {"version": 1, "rules": rules, "passes": dict(PASSES),
            "categories": [list(c) for c in config.CATEGORIES]}


def render_visibility() -> str:
    return json.dumps(build_visibility_manifest(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    MANIFEST_PATH.write_text(render(), encoding="utf-8")
    print(f"wrote {MANIFEST_PATH} ({len(build_manifest()['rules'])} rules)")
    VIS_MANIFEST_PATH.write_text(render_visibility(), encoding="utf-8")
    print(f"wrote {VIS_MANIFEST_PATH} ({len(build_visibility_manifest()['rules'])} rules)")
