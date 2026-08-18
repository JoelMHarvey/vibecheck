"""SARIF output tests.

The shape matters more than usual here: GitHub code scanning silently rejects
a document it can't parse, so a broken field means findings quietly stop
appearing rather than failing loudly.
"""

import json
import unittest

from vibecheck.sarif import SECURITY_SEVERITY, render_sarif, to_sarif_dict
from vibecheck.scanner import Finding, ScanResult


def finding(rule_id="secret.openai", severity="critical", path="src/app.js", line=12, title="Key exposed"):
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        path=path,
        line=line,
        excerpt="const k = 'sk-pro…[redacted]'",
        description="An API key is hardcoded here.",
        fix_prompt="Move the key in {} to an environment variable.".format(path),
    )


def result(*findings):
    r = ScanResult(root="/repo")
    r.findings = list(findings)
    r.files_scanned = 10
    return r


class TestSarif(unittest.TestCase):
    def test_document_skeleton(self):
        doc = to_sarif_dict(result(finding()), "0.1.0")
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", doc["$schema"])
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "vibecheck")
        self.assertEqual(driver["version"], "0.1.0")

    def test_result_points_at_the_finding(self):
        doc = to_sarif_dict(result(finding()), "0.1.0")
        res = doc["runs"][0]["results"][0]
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "src/app.js")
        self.assertEqual(loc["region"]["startLine"], 12)
        self.assertEqual(res["level"], "error")
        self.assertEqual(res["ruleIndex"], 0)
        self.assertEqual(res["ruleId"], "secret.openai")

    def test_path_prefix_is_applied(self):
        doc = to_sarif_dict(result(finding()), "0.1.0", path_prefix="apps/web")
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "apps/web/src/app.js")

    def test_path_prefix_tolerates_slashes_and_backslashes(self):
        doc = to_sarif_dict(result(finding()), "0.1.0", path_prefix="\\apps\\web\\")
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "apps/web/src/app.js")

    def test_line_zero_becomes_one(self):
        # URL-scan findings have no line number, and code scanning rejects a
        # region starting at line 0.
        doc = to_sarif_dict(result(finding(line=0)), "0.1.0")
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 1)

    def test_severity_levels_map_to_sarif_levels(self):
        # info is absent on purpose — see TestInfoExcluded.
        doc = to_sarif_dict(
            result(
                finding(rule_id="a", severity="critical"),
                finding(rule_id="b", severity="high"),
                finding(rule_id="c", severity="medium"),
                finding(rule_id="d", severity="low"),
            ),
            "0.1.0",
        )
        levels = [r["level"] for r in doc["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "error", "warning", "note"])

    def test_rules_are_deduplicated_by_id(self):
        doc = to_sarif_dict(
            result(
                finding(path="a.js"),
                finding(path="b.js"),
                finding(rule_id="other.rule", path="c.js"),
            ),
            "0.1.0",
        )
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], ["secret.openai", "other.rule"])
        self.assertEqual(len(doc["runs"][0]["results"]), 3)

    def test_rule_takes_the_worst_severity_seen(self):
        # The same rule escalates in frontend files, so one run can hold both.
        doc = to_sarif_dict(
            result(
                finding(severity="high", path="server.js"),
                finding(severity="critical", path="public/app.js"),
            ),
            "0.1.0",
        )
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], SECURITY_SEVERITY["critical"])
        self.assertEqual(rule["defaultConfiguration"]["level"], "error")
        # ...while each result keeps its own accurate level.
        self.assertEqual([r["level"] for r in doc["runs"][0]["results"]], ["error", "error"])

    def test_rule_severity_does_not_get_downgraded_by_a_later_finding(self):
        doc = to_sarif_dict(
            result(
                finding(severity="critical", path="public/app.js"),
                finding(severity="high", path="server.js"),
            ),
            "0.1.0",
        )
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], SECURITY_SEVERITY["critical"])

    def test_help_markdown_carries_the_fix_prompt(self):
        doc = to_sarif_dict(result(finding()), "0.1.0")
        markdown = doc["runs"][0]["tool"]["driver"]["rules"][0]["help"]["markdown"]
        self.assertIn("Move the key in src/app.js", markdown)
        self.assertIn("```text", markdown)

    def test_fingerprints_are_stable_and_distinct(self):
        a = to_sarif_dict(result(finding(path="a.js")), "0.1.0")
        again = to_sarif_dict(result(finding(path="a.js")), "0.1.0")
        b = to_sarif_dict(result(finding(path="b.js")), "0.1.0")
        key = "vibecheckFingerprint/v1"
        self.assertEqual(
            a["runs"][0]["results"][0]["partialFingerprints"][key],
            again["runs"][0]["results"][0]["partialFingerprints"][key],
        )
        self.assertNotEqual(
            a["runs"][0]["results"][0]["partialFingerprints"][key],
            b["runs"][0]["results"][0]["partialFingerprints"][key],
        )

    def test_clean_scan_is_still_valid_sarif(self):
        doc = json.loads(render_sarif(result(), "0.1.0"))
        self.assertEqual(doc["runs"][0]["results"], [])
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"], [])

    def test_secrets_stay_redacted(self):
        # Excerpts are redacted at scan time; SARIF must not reintroduce a raw
        # value by rendering something else.
        doc = render_sarif(result(finding()), "0.1.0")
        self.assertNotIn("sk-proj", doc)


if __name__ == "__main__":
    unittest.main()


class TestInfoExcluded(unittest.TestCase):
    """Code scanning is an alert queue, not a report.

    GitHub renders its alerts as inline review comments. An informational
    finding — a credential in a test fixture, worth zero points — became a
    comment on vibecheck's own pull request telling the author to rotate a key
    that was never real. That is cry-wolf arriving through a different door.
    """

    def test_info_findings_do_not_become_alerts(self):
        doc = to_sarif_dict(result(
            finding(rule_id="real", severity="critical", path="src/app.js"),
            finding(rule_id="fixture", severity="info", path="tests/x.py"),
        ), "0.1.0")
        self.assertEqual([r["ruleId"] for r in doc["runs"][0]["results"]], ["real"])

    def test_an_excluded_finding_leaves_no_orphan_rule(self):
        doc = to_sarif_dict(result(finding(severity="info")), "0.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"], [])
        self.assertEqual(doc["runs"][0]["results"], [])

    def test_every_other_severity_still_reports(self):
        doc = to_sarif_dict(result(
            finding(rule_id="c", severity="critical"),
            finding(rule_id="h", severity="high"),
            finding(rule_id="m", severity="medium"),
            finding(rule_id="l", severity="low"),
        ), "0.1.0")
        self.assertEqual([r["ruleId"] for r in doc["runs"][0]["results"]], ["c", "h", "m", "l"])

    def test_rule_indices_stay_aligned_after_exclusion(self):
        # An off-by-one here points every alert at the wrong rule.
        doc = to_sarif_dict(result(
            finding(rule_id="skipped", severity="info"),
            finding(rule_id="kept", severity="high"),
        ), "0.1.0")
        run = doc["runs"][0]
        for res in run["results"]:
            self.assertEqual(run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"], res["ruleId"])
