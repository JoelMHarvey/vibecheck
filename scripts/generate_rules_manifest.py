"""Generate rules.json — the client-side rule manifest.

Share links encode only the *facts* of a scan (rule id, severity, path,
line, excerpt). The long prose — title, description, fix-prompt template —
lives in this manifest, which the page fetches once. That keeps a shared
report URL small enough to paste into a chat message.

Run after changing rules.py:

    python3 scripts/generate_rules_manifest.py

tests/test_rules_manifest.py fails if the committed file is out of date.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibecheck.rules import (  # noqa: E402
    ENV_NOT_IGNORED,
    RULES,
    SUPABASE_ANON_INFO,
    SUPABASE_SERVICE_ROLE,
)
from vibecheck.urlscan import iter_url_rules  # noqa: E402

MANIFEST_PATH = Path(__file__).resolve().parent.parent / "rules.json"


def build_manifest() -> dict:
    # The scanner can emit rules that aren't in the RULES list (they're
    # produced programmatically), so include them explicitly.
    all_rules = list(RULES) + [SUPABASE_SERVICE_ROLE, SUPABASE_ANON_INFO, ENV_NOT_IGNORED]
    rules = {}
    for rule in all_rules:
        rules[rule.id] = {"t": rule.title, "d": rule.description, "f": rule.fix_prompt}
    # Deployed-site rules are built by urlscan, not from Rule objects.
    for rule_id, title, description, fix_prompt in iter_url_rules():
        rules[rule_id] = {"t": title, "d": description, "f": fix_prompt}
    return {"version": 1, "rules": rules}


def render() -> str:
    return json.dumps(build_manifest(), indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    MANIFEST_PATH.write_text(render(), encoding="utf-8")
    print(f"wrote {MANIFEST_PATH} ({len(build_manifest()['rules'])} rules)")
