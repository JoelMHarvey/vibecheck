"""Tests for the compact CI report used in job summaries and PR comments."""

import unittest

from vibecheck.report import CI_COMMENT_MARKER, render_ci_markdown
from vibecheck.scanner import Finding, ScanResult


def finding(severity="critical", path="src/app.js", line=3, title="Key exposed", fix="Move it."):
    return Finding(
        rule_id="secret.openai",
        title=title,
        severity=severity,
        path=path,
        line=line,
        excerpt="const k = 'sk-pro…[redacted]'",
        description="An API key is hardcoded here.",
        fix_prompt=fix,
    )


def result(*findings, files=42):
    r = ScanResult(root="/repo")
    r.findings = list(findings)
    r.files_scanned = files
    return r


class TestCiMarkdown(unittest.TestCase):
    def test_marker_leads_so_the_comment_can_be_found_again(self):
        self.assertTrue(render_ci_markdown(result()).startswith(CI_COMMENT_MARKER))

    def test_clean_scan_says_so(self):
        text = render_ci_markdown(result())
        self.assertIn("No findings.", text)
        self.assertIn("42 files scanned", text)

    def test_findings_appear_in_the_table(self):
        text = render_ci_markdown(result(finding()))
        self.assertIn("| 🔴 critical | Key exposed | `src/app.js:3` |", text)

    def test_counts_row_only_lists_severities_present(self):
        text = render_ci_markdown(result(finding(severity="medium")))
        self.assertIn("| Medium |", text)
        self.assertNotIn("| Critical |", text)

    def test_path_prefix_makes_locations_repository_relative(self):
        text = render_ci_markdown(result(finding()), path_prefix="web")
        self.assertIn("`web/src/app.js:3`", text)
        self.assertIn("**`web/src/app.js:3` — Key exposed**", text)

    def test_fix_prompts_are_folded_away(self):
        text = render_ci_markdown(result(finding()))
        self.assertIn("<details>", text)
        self.assertIn("Move it.", text)

    def test_no_details_block_when_nothing_has_a_prompt(self):
        text = render_ci_markdown(result(finding(fix="")))
        self.assertNotIn("<details>", text)

    def test_long_reports_are_capped_with_a_count_of_the_rest(self):
        many = [finding(line=n) for n in range(1, 51)]
        text = render_ci_markdown(result(*many), limit=10)
        self.assertIn("_…and 40 more_", text)
        self.assertEqual(text.count("| 🔴 critical |"), 10)

    def test_score_and_grade_are_in_the_heading(self):
        text = render_ci_markdown(result(finding()))
        self.assertIn("Vibe Score 75/100 (grade B)", text)


if __name__ == "__main__":
    unittest.main()
