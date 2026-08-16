"""Tests for suppression: inline comments and path exclusion.

The scanner's own repository is the motivating case — its guides quote
vulnerable code on purpose and its tests are full of deliberate fixtures — so
these paths need to be silenceable without turning the whole rule off.
"""

import tempfile
import unittest
from pathlib import Path

from vibecheck.scanner import PathFilter, scan, scan_files, scan_text


def fake_stripe_live_key():
    return "sk_" + "live_" + "a1b2c3d4e5f6" * 2


VULNERABLE_JS = 'const client = new OpenAI({{ dangerouslyAllowBrowser: true }}); {comment}\n'


class TestInlineIgnore(unittest.TestCase):
    def test_baseline_is_a_finding(self):
        findings = scan_text("app.js", VULNERABLE_JS.format(comment=""))
        self.assertEqual([f.rule_id for f in findings], ["dangerously-allow-browser"])

    def test_same_line_comment_suppresses(self):
        findings = scan_text("app.js", VULNERABLE_JS.format(comment="// vibecheck-ignore"))
        self.assertEqual(findings, [])

    def test_next_line_comment_suppresses_the_line_below(self):
        text = "// vibecheck-ignore-next-line\n" + VULNERABLE_JS.format(comment="")
        self.assertEqual(scan_text("app.js", text), [])

    def test_next_line_comment_does_not_suppress_its_own_line(self):
        text = VULNERABLE_JS.format(comment="// vibecheck-ignore-next-line")
        self.assertEqual(len(scan_text("app.js", text)), 1)

    def test_plain_comment_does_not_reach_the_next_line(self):
        text = "// vibecheck-ignore\n" + VULNERABLE_JS.format(comment="")
        self.assertEqual(len(scan_text("app.js", text)), 1)

    def test_suppression_does_not_leak_further_down(self):
        text = (
            "// vibecheck-ignore-next-line\n"
            + VULNERABLE_JS.format(comment="")
            + VULNERABLE_JS.format(comment="")
        )
        findings = scan_text("app.js", text)
        self.assertEqual([f.line for f in findings], [3])

    def test_named_rule_suppresses_only_that_rule(self):
        findings = scan_text(
            "app.js", VULNERABLE_JS.format(comment="// vibecheck-ignore: dangerously-allow-browser")
        )
        self.assertEqual(findings, [])

    def test_naming_a_different_rule_leaves_the_finding(self):
        findings = scan_text("app.js", VULNERABLE_JS.format(comment="// vibecheck-ignore: sql-string-building"))
        self.assertEqual(len(findings), 1)

    def test_rule_list_is_accepted(self):
        comment = "// vibecheck-ignore: sql-string-building, dangerously-allow-browser"
        self.assertEqual(scan_text("app.js", VULNERABLE_JS.format(comment=comment)), [])

    def test_works_with_hash_comments_too(self):
        text = f'requests.get(url, verify=False)  # vibecheck-ignore\n'
        self.assertEqual(scan_text("app.py", text), [])

    def test_suppresses_a_secret(self):
        text = f'const k = "{fake_stripe_live_key()}"; // vibecheck-ignore\n'
        self.assertEqual(scan_text("server.js", text), [])

    def test_substituted_rule_id_can_be_named(self):
        # A Supabase service_role JWT is reported under its own rule id, not
        # the generic JWT rule that matched it.
        import base64
        import json

        def b64u(obj):
            raw = base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()
            return raw.rstrip("=")

        token = b64u({"alg": "HS256"}) + "." + b64u({"role": "service_role"}) + "." + "s1GnAtUrE" * 3
        plain = f'const k = "{token}";\n'
        found = scan_text("server.js", plain)
        self.assertTrue(found, "expected the fixture to produce a finding")
        rule_id = found[0].rule_id
        silenced = f'const k = "{token}"; // vibecheck-ignore: {rule_id}\n'
        self.assertEqual(scan_text("server.js", silenced), [])


class TestPathFilter(unittest.TestCase):
    def test_empty_filter_matches_nothing(self):
        self.assertFalse(PathFilter([]).matches("a/b.js"))
        self.assertFalse(bool(PathFilter([])))

    def test_directory_name_matches_everything_under_it(self):
        f = PathFilter(["guides"])
        self.assertTrue(f.matches("guides/x.html"))
        self.assertTrue(f.matches("guides/deep/y.html"))
        self.assertFalse(f.matches("src/guides.js"))

    def test_trailing_slash_is_accepted(self):
        self.assertTrue(PathFilter(["tests/"]).matches("tests/test_x.py"))

    def test_glob_on_filename(self):
        f = PathFilter(["*.test.js"])
        self.assertTrue(f.matches("src/thing.test.js"))
        self.assertFalse(f.matches("src/thing.js"))

    def test_full_path_glob(self):
        self.assertTrue(PathFilter(["src/legacy/*"]).matches("src/legacy/old.js"))

    def test_exact_file(self):
        f = PathFilter(["index.html"])
        self.assertTrue(f.matches("index.html"))
        self.assertFalse(f.matches("src/app.js"))

    def test_comments_and_blanks_are_ignored(self):
        f = PathFilter(["# a comment", "   ", "guides"])
        self.assertEqual(f.patterns, ["guides"])


class TestScanExclusion(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, rel, content):
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def test_exclude_argument_drops_the_finding(self):
        self.write("docs/example.js", VULNERABLE_JS.format(comment=""))
        self.assertEqual(len(scan(str(self.root)).findings), 1)
        self.assertEqual(scan(str(self.root), exclude=["docs"]).findings, [])

    def test_excluded_files_are_not_counted_as_scanned(self):
        self.write("docs/example.js", VULNERABLE_JS.format(comment=""))
        self.write("app.js", "console.log(1)\n")
        self.assertEqual(scan(str(self.root), exclude=["docs"]).files_scanned, 1)

    def test_vibecheckignore_file_is_read(self):
        self.write("docs/example.js", VULNERABLE_JS.format(comment=""))
        self.write(".vibecheckignore", "# our guides quote bad code on purpose\ndocs\n")
        self.assertEqual(scan(str(self.root)).findings, [])

    def test_ignore_file_and_argument_combine(self):
        self.write("docs/a.js", VULNERABLE_JS.format(comment=""))
        self.write("fixtures/b.js", VULNERABLE_JS.format(comment=""))
        self.write(".vibecheckignore", "docs\n")
        self.assertEqual(scan(str(self.root), exclude=["fixtures"]).findings, [])

    def test_excluding_one_directory_leaves_the_others(self):
        self.write("docs/a.js", VULNERABLE_JS.format(comment=""))
        self.write("src/b.js", VULNERABLE_JS.format(comment=""))
        findings = scan(str(self.root), exclude=["docs"]).findings
        self.assertEqual([f.path for f in findings], ["src/b.js"])

    def test_scan_files_honours_an_uploaded_ignore_file(self):
        # The ignore file can arrive after the file it excludes.
        result = scan_files(
            [
                ("docs/a.js", VULNERABLE_JS.format(comment="")),
                (".vibecheckignore", "docs\n"),
            ]
        )
        self.assertEqual(result.findings, [])

    def test_scan_files_exclude_argument(self):
        result = scan_files([("docs/a.js", VULNERABLE_JS.format(comment=""))], exclude=["docs"])
        self.assertEqual(result.findings, [])

    def test_scan_files_without_exclusion_still_finds_it(self):
        result = scan_files([("docs/a.js", VULNERABLE_JS.format(comment=""))])
        self.assertEqual(len(result.findings), 1)


if __name__ == "__main__":
    unittest.main()
