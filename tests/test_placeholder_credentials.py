"""Telling a documented example apart from somebody's actual password.

The URI rules match `user:pass@host`, which is also exactly how every piece
of database documentation writes a connection string. One real repository
produced twenty-five of these out of README files, deployment guides and a
.env.production.example — one of them inside a document about not committing
secrets — against six from code that runs.

Both directions of error matter, and they are not symmetric:

* Reporting a placeholder is how a scanner trains people to ignore it, and
  how a disclosure email gets deleted unread.
* Suppressing a real credential is silent and permanent. So the match is on
  the whole password, never a substring: "password" is an illustration,
  "MyPassword2024!" is a credential, and a substring test cannot tell them
  apart.
"""

import unittest

from vibecheck.rules import looks_like_placeholder
from vibecheck.scanner import scan_files


def findings_for(path, line):
    return scan_files([(path, line + "\n")]).findings


class TestPlaceholdersAreNotLeaks(unittest.TestCase):
    def assertPlaceholder(self, text):
        self.assertTrue(looks_like_placeholder(text), f"should be ignored: {text}")

    def test_the_canonical_documentation_example(self):
        self.assertPlaceholder("postgresql://user:password@localhost:5432/dbname")

    def test_the_local_development_default(self):
        self.assertPlaceholder("postgresql://postgres:postgres@localhost:5432/mydb")

    def test_an_uppercase_template(self):
        self.assertPlaceholder("postgresql://USERNAME:PASSWORD@host:5432/db")
        self.assertPlaceholder("mongodb://user:DB_PASSWORD@host/db")

    def test_an_unexpanded_variable(self):
        self.assertPlaceholder("postgresql://user:${DB_PASSWORD}@host:5432/db")

    def test_a_redaction(self):
        self.assertPlaceholder("postgresql://user:xxxx@host/db")
        self.assertPlaceholder("postgresql://user:****@host/db")

    def test_short_stand_ins(self):
        for secret in ("pass", "secret", "changeme", "admin", "root"):
            with self.subTest(secret):
                self.assertPlaceholder(f"mongodb+srv://u:{secret}@cluster0.mongodb.net/")


class TestRealCredentialsSurvive(unittest.TestCase):
    """The failure that cannot be noticed afterwards."""

    def assertReal(self, text):
        self.assertFalse(looks_like_placeholder(text), f"suppressed a credential: {text}")

    def test_a_high_entropy_password(self):
        self.assertReal("postgresql://myuser:s3cr3t-real-value@db.prod.internal:5432/app")
        self.assertReal("mongodb://svc:9f3Ab-Qz71kLm@cluster0.abcd.mongodb.net/prod")

    def test_a_password_that_merely_contains_the_word_password(self):
        # A substring check would throw this away. It is somebody's credential.
        self.assertReal("postgresql://app:MyPassword2024!@prod-db.internal/app")
        self.assertReal("postgresql://app:correcthorsebatterystaple@db/app")

    def test_a_password_that_starts_with_a_placeholder_word(self):
        self.assertReal("postgresql://app:secretsauce9931@db.internal/app")

    def test_a_mixed_case_value_is_not_a_template_token(self):
        self.assertReal("postgresql://app:Ab3Cd9Ef@db.internal/app")


class TestThroughTheScanner(unittest.TestCase):
    def test_a_documented_example_produces_nothing(self):
        self.assertEqual(
            findings_for("README.md", "DATABASE_URL=postgresql://user:password@localhost:5432/app"),
            [],
        )

    def test_the_same_shape_in_code_with_a_real_password_still_fires(self):
        found = findings_for(
            "backend/db.py",
            'DSN = "postgresql://svc:9f3Ab-Qz71kLm@db.prod.internal:5432/app"',
        )
        self.assertEqual([f.rule_id for f in found], ["postgres-uri-credentials"])
        self.assertEqual(found[0].severity, "high")

    def test_a_real_credential_in_markdown_is_still_reported(self):
        # The most serious finding in the 192-repo scan was a live key in a
        # DEPLOYMENT_SUCCESS.md. Prose is not a safe place for a secret.
        found = findings_for(
            "DEPLOYMENT_SUCCESS.md",
            "Set DATABASE_URL=postgresql://svc:9f3Ab-Qz71kLm@db.prod.internal/app",
        )
        self.assertEqual([f.rule_id for f in found], ["postgres-uri-credentials"])

    def test_mongo_gets_the_same_treatment(self):
        self.assertEqual(
            findings_for("docs/setup.md", "mongodb+srv://admin:changeme@cluster0.mongodb.net/"),
            [],
        )
        self.assertTrue(
            findings_for("app/conf.py", 'URI = "mongodb://svc:9f3Ab-Qz71kLm@c0.mongodb.net/p"')
        )

    def test_an_env_example_file_is_quiet(self):
        self.assertEqual(
            findings_for(".env.production.example",
                         "DATABASE_URL=postgresql://user:password@host:5432/dbname"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
