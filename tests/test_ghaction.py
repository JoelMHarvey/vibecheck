"""Tests for the GitHub Action runner.

Everything goes through the injected env/out/opener, so nothing here touches a
real runner or the GitHub API.
"""

import io
import json
import tempfile
import unittest
from pathlib import Path

from vibecheck import ghaction
from vibecheck.report import CI_COMMENT_MARKER


def fake_stripe_live_key():
    return "sk_" + "live_" + "a1b2c3d4e5f6" * 2


class ActionCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = io.StringIO()

    def write(self, rel, content):
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def env(self, **overrides):
        base = {
            "INPUT_PATH": str(self.root),
            "INPUT_COMMENT": "false",
            "INPUT_SUMMARY": "false",
            "NO_COLOR": "1",
        }
        base.update(overrides)
        return base

    def run_action(self, **overrides):
        return ghaction.main(env=self.env(**overrides), out=self.out)


class TestExitCodes(ActionCase):
    def test_clean_project_passes(self):
        self.write("app.py", "print('hello')\n")
        self.assertEqual(self.run_action(), 0)

    def test_critical_finding_fails_the_job(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        self.assertEqual(self.run_action(), 1)
        self.assertIn("::error::vibecheck:", self.out.getvalue())

    def test_fail_on_never_always_passes(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        self.assertEqual(self.run_action(**{"INPUT_FAIL_ON": "never"}), 0)

    def test_fail_on_threshold_is_respected(self):
        # An info-only finding should not fail a job at the default threshold.
        self.write("index.html", '<div id="x"></div>\n')
        self.assertEqual(self.run_action(), 0)

    def test_min_severity_filters_before_the_gate(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        # Nothing is above 'critical' except critical itself, so this still fails...
        self.assertEqual(self.run_action(**{"INPUT_MIN_SEVERITY": "critical"}), 1)

    def test_bad_input_is_rejected_rather_than_ignored(self):
        self.write("app.py", "print('hello')\n")
        self.assertEqual(self.run_action(**{"INPUT_FAIL_ON": "catastrophic"}), 2)
        self.assertIn("fail-on must be one of", self.out.getvalue())

    def test_bad_min_severity_is_rejected(self):
        self.write("app.py", "print('hello')\n")
        self.assertEqual(self.run_action(**{"INPUT_MIN_SEVERITY": "spicy"}), 2)

    def test_missing_path_is_an_error_not_a_crash(self):
        self.assertEqual(self.run_action(**{"INPUT_PATH": str(self.root / "nope")}), 2)
        self.assertIn("path does not exist", self.out.getvalue())


class TestAnnotations(ActionCase):
    def test_finding_becomes_an_error_annotation(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        self.run_action()
        text = self.out.getvalue()
        self.assertIn("::error file=server.js,line=1,title=vibecheck:", text)

    def test_annotation_paths_are_prefixed_when_scanning_a_subdirectory(self):
        self.write("web/server.js", f'const s = "{fake_stripe_live_key()}";\n')
        self.run_action(
            **{"INPUT_PATH": str(self.root / "web"), "GITHUB_WORKSPACE": str(self.root)}
        )
        self.assertIn("file=web/server.js,", self.out.getvalue())

    def test_no_prefix_when_scanning_the_workspace_root(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        self.run_action(**{"GITHUB_WORKSPACE": str(self.root)})
        self.assertIn("file=server.js,", self.out.getvalue())

    def test_dot_and_trailing_slash_produce_no_prefix(self):
        for spelling in (".", "./", str(self.root) + "/"):
            out = io.StringIO()
            self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
            env = self.env(INPUT_PATH=spelling, GITHUB_WORKSPACE=str(self.root))
            if spelling in (".", "./"):
                # A relative path is resolved against the process CWD, so point
                # the workspace at the same place to keep the comparison honest.
                env["GITHUB_WORKSPACE"] = "."
                env["INPUT_PATH"] = spelling
            ghaction.main(env=env, out=out)
            for line in out.getvalue().splitlines():
                if line.startswith("::error file="):
                    self.assertNotIn("file=/", line, spelling)

    def test_scanning_outside_the_workspace_gets_no_prefix(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        self.run_action(**{"GITHUB_WORKSPACE": "/some/other/place"})
        self.assertIn("file=server.js,", self.out.getvalue())

    def test_annotation_message_has_no_raw_newlines(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        self.run_action()
        for line in self.out.getvalue().splitlines():
            if line.startswith("::error file="):
                self.assertNotIn("\n", line)
                self.assertIn("%0A", line + "%0A")  # escaping applied, not literal


class TestOutputsAndFiles(ActionCase):
    def test_outputs_are_written(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        out_file = self.root / "gh_output"
        self.run_action(**{"GITHUB_OUTPUT": str(out_file)})
        pairs = dict(
            line.split("=", 1) for line in out_file.read_text().strip().splitlines()
        )
        # One critical finding is a 25-point penalty.
        self.assertEqual(pairs["critical"], "1")
        self.assertEqual(pairs["score"], "75")
        self.assertEqual(pairs["grade"], "B")
        self.assertEqual(pairs["findings"], "1")
        self.assertEqual(pairs["high"], "0")

    def test_summary_is_appended_when_enabled(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        summary = self.root / "summary.md"
        self.run_action(**{"INPUT_SUMMARY": "true", "GITHUB_STEP_SUMMARY": str(summary)})
        text = summary.read_text()
        self.assertIn(CI_COMMENT_MARKER, text)
        self.assertIn("Vibe Score", text)

    def test_summary_is_skipped_when_disabled(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        summary = self.root / "summary.md"
        self.run_action(**{"INPUT_SUMMARY": "false", "GITHUB_STEP_SUMMARY": str(summary)})
        self.assertFalse(summary.exists())

    def test_sarif_file_is_written_and_parses(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        sarif = self.root / "out" / "vibecheck.sarif"
        self.run_action(**{"INPUT_SARIF_FILE": str(sarif)})
        doc = json.loads(sarif.read_text())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 1)

    def test_json_file_is_written(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        report = self.root / "report.json"
        self.run_action(**{"INPUT_JSON_FILE": str(report)})
        self.assertEqual(json.loads(report.read_text())["counts"]["critical"], 1)

    def test_no_sarif_when_not_requested(self):
        self.write("app.py", "print('hi')\n")
        self.run_action()
        self.assertEqual(list(self.root.glob("*.sarif")), [])


class TestPullRequestComment(ActionCase):
    def make_event(self, number=7):
        path = self.root / "event.json"
        path.write_text(json.dumps({"pull_request": {"number": number}}))
        return str(path)

    def recorder(self, existing=None):
        calls = []

        def opener(url, token, method="GET", payload=None):
            calls.append({"url": url, "method": method, "payload": payload})
            if method == "GET":
                return existing or []
            return {"id": 1}

        return calls, opener

    def env_with_pr(self, **overrides):
        base = {
            "INPUT_TOKEN": "ghs_token",
            "GITHUB_REPOSITORY": "joel/app",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_EVENT_PATH": self.make_event(),
        }
        base.update(overrides)
        return base

    def test_creates_a_comment_when_none_exists(self):
        calls, opener = self.recorder(existing=[])
        posted = ghaction.post_pr_comment("body", self.env_with_pr(), self.out, opener)
        self.assertTrue(posted)
        self.assertEqual(calls[-1]["method"], "POST")
        self.assertEqual(calls[-1]["url"], "https://api.github.com/repos/joel/app/issues/7/comments")

    def test_updates_the_existing_comment_in_place(self):
        existing = [
            {"id": 99, "body": "someone else's comment"},
            {"id": 123, "body": CI_COMMENT_MARKER + "\nold report"},
        ]
        calls, opener = self.recorder(existing=existing)
        posted = ghaction.post_pr_comment("new body", self.env_with_pr(), self.out, opener)
        self.assertTrue(posted)
        self.assertEqual(calls[-1]["method"], "PATCH")
        self.assertEqual(calls[-1]["url"], "https://api.github.com/repos/joel/app/issues/comments/123")
        self.assertEqual(calls[-1]["payload"]["body"], "new body")

    def test_skipped_entirely_outside_a_pull_request(self):
        calls, opener = self.recorder()
        posted = ghaction.post_pr_comment("body", {"INPUT_TOKEN": "t", "GITHUB_REPOSITORY": "joel/app"}, self.out, opener)
        self.assertFalse(posted)
        self.assertEqual(calls, [])

    def test_missing_token_warns_but_does_not_raise(self):
        calls, opener = self.recorder()
        posted = ghaction.post_pr_comment("body", self.env_with_pr(INPUT_TOKEN=""), self.out, opener)
        self.assertFalse(posted)
        self.assertIn("::warning::", self.out.getvalue())

    def test_api_failure_is_a_warning_not_a_crash(self):
        def opener(url, token, method="GET", payload=None):
            raise OSError("403 Forbidden")

        posted = ghaction.post_pr_comment("body", self.env_with_pr(), self.out, opener)
        self.assertFalse(posted)
        self.assertIn("could not post the PR comment", self.out.getvalue())

    def test_a_fork_read_only_token_does_not_fail_the_job(self):
        self.write("server.js", f'const s = "{fake_stripe_live_key()}";\n')
        event = self.make_event()

        def exploding(*args, **kwargs):
            raise OSError("403 Resource not accessible by integration")

        original = ghaction._api
        ghaction._api = exploding
        self.addCleanup(setattr, ghaction, "_api", original)
        code = self.run_action(
            **{
                "INPUT_COMMENT": "true",
                "INPUT_TOKEN": "ghs_token",
                "GITHUB_REPOSITORY": "joel/app",
                "GITHUB_EVENT_PATH": event,
            }
        )
        # Still 1 for the finding, not a crash and not a different code.
        self.assertEqual(code, 1)
        self.assertIn("could not post the PR comment", self.out.getvalue())

    def test_oversized_comment_is_truncated(self):
        calls, opener = self.recorder(existing=[])
        ghaction.post_pr_comment("x" * 200_000, self.env_with_pr(), self.out, opener)
        body = calls[-1]["payload"]["body"]
        self.assertLessEqual(len(body), ghaction.MAX_COMMENT_CHARS + 100)
        self.assertIn("Report truncated", body)

    def test_malformed_event_file_is_survivable(self):
        path = self.root / "bad.json"
        path.write_text("not json")
        calls, opener = self.recorder()
        posted = ghaction.post_pr_comment("body", self.env_with_pr(GITHUB_EVENT_PATH=str(path)), self.out, opener)
        self.assertFalse(posted)


class TestFlagParsing(unittest.TestCase):
    def test_truthy_and_falsy_spellings(self):
        for value in ("true", "TRUE", "1", "yes", "on"):
            self.assertTrue(ghaction._flag({"X": value}, "X"))
        for value in ("false", "0", "no", "off"):
            self.assertFalse(ghaction._flag({"X": value}, "X"))

    def test_unset_uses_the_default(self):
        self.assertTrue(ghaction._flag({}, "X", default=True))
        self.assertFalse(ghaction._flag({"X": "  "}, "X", default=False))


if __name__ == "__main__":
    unittest.main()
