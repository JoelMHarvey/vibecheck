"""Tests for demoting findings by where they live.

Every fixture path here is a real one, taken from a 192-repository scan whose
fifteen criticals contained four things that were never secrets: Expo's own
certificate fixtures vendored into an app, a test file, a blog post about
security testing, and a tutorial page about not telling AI your keys.

The test that matters most is the last one. A live Stripe key was sitting in a
DEPLOYMENT_SUCCESS.md, and a rule demoting secrets in markdown would have
buried the single most serious finding in the corpus.
"""

import unittest

from vibecheck.scanner import is_prose_path, is_test_path, scan_text
from pathlib import PurePosixPath

PRIVATE_KEY = ("-----BEGIN RSA PRIVATE KEY-----\n"
               "MIIEowIBAAKCAQEAxyz\n"
               "-----END RSA PRIVATE KEY-----")
STRIPE_LIVE = 'STRIPE_SECRET_KEY=sk_' + 'live_' + 'a1b2c3d4e5f6a1b2c3d4e5f6'


def severities(path, content):
    return [f.severity for f in scan_text(path, content)]


class TestPathClassification(unittest.TestCase):
    def test_test_directories(self):
        for path in (
            "src/__tests__/thing.ts",
            "core/tests/fireproof/utils.ts",
            "app/test/helper.js",
            "pkg/__snapshots__/x.snap",
            "a/fixtures/certificates.ts",
            "ios/Tests/Support/certificates/privatekeys/chainRoot-privateKey.pem",
        ):
            with self.subTest(path):
                self.assertTrue(is_test_path(PurePosixPath(path)))

    def test_test_filenames(self):
        for path in ("src/utils.test.ts", "src/utils.spec.js", "a/foo_test.py", "a/x.ts.snap"):
            with self.subTest(path):
                self.assertTrue(is_test_path(PurePosixPath(path)))

    def test_ordinary_app_paths_are_not_test_paths(self):
        for path in ("src/server.js", "frontend/certs/key.pem", "DEPLOYMENT.md",
                     "src/latest/index.ts", "app/protest/views.py"):
            with self.subTest(path):
                self.assertFalse(is_test_path(PurePosixPath(path)))

    def test_prose_by_extension_and_by_directory(self):
        self.assertTrue(is_prose_path(PurePosixPath("README.md")))
        self.assertTrue(is_prose_path(PurePosixPath("docs/CI_CD.md")))
        self.assertTrue(is_prose_path(PurePosixPath("packages/web/src/app/blog/posts/guide.ts")))
        self.assertFalse(is_prose_path(PurePosixPath("src/server.js")))


class TestTestPathDemotion(unittest.TestCase):
    def test_a_fixture_credential_is_informational(self):
        self.assertEqual(severities("core/tests/fireproof/utils.test.ts", PRIVATE_KEY), ["info"])

    def test_vendored_expo_certificate_fixtures(self):
        path = "app/packages/@expo/cli/src/utils/__tests__/fixtures/certificates.ts"
        self.assertEqual(severities(path, PRIVATE_KEY), ["info"])

    def test_everything_in_a_test_path_is_demoted_not_just_secrets(self):
        # Otherwise the rule is indefensible: why is a fake key informational
        # while string-built SQL beside it is high?
        sql = 'cur.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        self.assertEqual(severities("tests/test_queries.py", sql), ["info"])
        # ...and the identical line in application code is not demoted.
        self.assertEqual(severities("app/db.py", sql), ["high"])

    def test_demoted_not_dropped(self):
        # A real key committed in a test is still worth seeing.
        self.assertEqual(len(scan_text("tests/conftest.py", PRIVATE_KEY)), 1)

    def test_the_same_content_in_app_code_is_untouched(self):
        self.assertEqual(severities("src/keys.ts", PRIVATE_KEY), ["critical"])


class TestProseDemotion(unittest.TestCase):
    def test_private_key_in_a_tutorial(self):
        path = "docs/Basic-old/05-advanced/5.3-security/5.3.2-never-tell-ai.md"
        self.assertEqual(severities(path, PRIVATE_KEY), ["low"])

    def test_private_key_in_a_blog_post(self):
        path = "packages/web/src/app/blog/posts/mcp-tool-poisoning-guide.ts"
        self.assertEqual(severities(path, PRIVATE_KEY), ["low"])

    def test_a_live_stripe_key_in_markdown_stays_critical(self):
        # The most serious finding in a 192-repo scan looked exactly like
        # this. Demoting secrets in markdown generally would have hidden it.
        self.assertEqual(severities("DEPLOYMENT_SUCCESS.md", STRIPE_LIVE), ["critical"])

    def test_prose_demotion_applies_to_the_private_key_rule_only(self):
        # That rule matches the PEM header alone — no key material, no
        # entropy — which is why every worked example trips it. Provider
        # credentials are matched by format and mean what they say.
        self.assertEqual(severities("docs/setup.md", STRIPE_LIVE), ["critical"])

    def test_a_committed_key_outside_prose_and_tests_is_still_critical(self):
        self.assertEqual(severities("frontend/certs/key.pem", PRIVATE_KEY), ["critical"])


class TestVendoredDirectories(unittest.TestCase):
    def test_vendored_trees_are_skipped_entirely(self):
        from vibecheck.scanner import SKIP_DIRS
        for name in ("third_party", "bower_components", "Pods", ".yarn", "vendored"):
            with self.subTest(name):
                self.assertIn(name, SKIP_DIRS)


if __name__ == "__main__":
    unittest.main()
