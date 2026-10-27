"""The committed rules.json must match rules.py.

Share links rehydrate their prose from rules.json, so if it drifts, shared
reports show stale or missing text for a rule.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from generate_rules_manifest import (  # noqa: E402
    MANIFEST_PATH, VIS_MANIFEST_PATH, build_manifest, build_visibility_manifest, render, render_visibility,
)

from vibecheck.rules import RULES  # noqa: E402
from vibecheck.urlscan import iter_url_rules  # noqa: E402


class RulesManifestTest(unittest.TestCase):
    def test_manifest_is_committed_and_current(self):
        self.assertTrue(
            MANIFEST_PATH.exists(),
            "rules.json is missing — run python3 scripts/generate_rules_manifest.py",
        )
        self.assertEqual(
            MANIFEST_PATH.read_text(encoding="utf-8"),
            render(),
            "rules.json is out of date — run python3 scripts/generate_rules_manifest.py",
        )

    def test_every_rule_has_prose(self):
        manifest = build_manifest()
        for rule_id, entry in manifest["rules"].items():
            self.assertTrue(entry["t"], f"{rule_id} has no title")
            self.assertTrue(entry["d"], f"{rule_id} has no description")

    def test_includes_programmatic_rules(self):
        # These are emitted by the scanner but aren't in the RULES list.
        ids = set(build_manifest()["rules"])
        for special in ("supabase-service-role-key", "supabase-anon-key", "env-file-not-gitignored"):
            self.assertIn(special, ids)

    def test_includes_every_listed_rule(self):
        ids = set(build_manifest()["rules"])
        for rule in RULES:
            self.assertIn(rule.id, ids)

    def test_includes_deployed_site_rules(self):
        ids = set(build_manifest()["rules"])
        for rule_id, *_ in iter_url_rules():
            self.assertIn(rule_id, ids)
        self.assertIn("exposed-env-file", ids)
        self.assertIn("missing-csp", ids)


class VisibilityManifestTest(unittest.TestCase):
    """/visibility rehydrates shared reports from visibility-rules.json."""

    def test_committed_and_current(self):
        self.assertTrue(VIS_MANIFEST_PATH.exists(),
                        "visibility-rules.json is missing — run python3 scripts/generate_rules_manifest.py")
        self.assertEqual(VIS_MANIFEST_PATH.read_text(encoding="utf-8"), render_visibility(),
                         "visibility-rules.json is out of date — run python3 scripts/generate_rules_manifest.py")

    def test_carries_what_the_page_needs(self):
        from vibecheck.checks.visibility.rules import PASSES, RULES

        manifest = build_visibility_manifest()
        self.assertEqual(set(manifest["rules"]), set(RULES) | set(PASSES))
        self.assertEqual(len(manifest["categories"]), 6)
        for rule_id, entry in manifest["rules"].items():
            keys = ("t", "s", "c") if entry["s"] == "pass" else ("t", "s", "c", "d", "v")
            for key in keys:
                self.assertTrue(entry.get(key), f"{rule_id} has no {key}")


if __name__ == "__main__":
    unittest.main()
