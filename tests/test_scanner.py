"""Unit tests for the vibecheck scanner.

All fake secrets are built by string concatenation at runtime so that no
secret-shaped literal ever exists in this repository (which would trip
GitHub push protection — and vibecheck itself).
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from vibecheck.scanner import scan, scan_files


def fake_anthropic_key():
    return "sk-" + "ant-" + "api03-" + "a1b2c3d4" * 5


def fake_stripe_live_key():
    return "sk_" + "live_" + "a1b2c3d4e5f6" * 2


def fake_telegram_token():
    return "123456789" + ":" + "AA" + "Hf" * 16 + "Q"


def fake_jwt(role):
    def b64u(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return b64u({"alg": "HS256", "typ": "JWT"}) + "." + b64u({"role": role, "iss": "supabase", "ref": "abcdefgh"}) + "." + "s1GnAtUrE" * 3


class ScannerTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, content):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def rule_ids(self, result):
        return {f.rule_id for f in result.findings}

    def test_detects_hardcoded_anthropic_key(self):
        self.write("app.py", f'client = Anthropic(api_key="{fake_anthropic_key()}")\n')
        result = scan(str(self.root))
        self.assertIn("anthropic-api-key", self.rule_ids(result))

    def test_secret_in_frontend_is_boosted_to_critical(self):
        self.write("public/app.js", f'const key = "{fake_anthropic_key()}";\n')
        result = scan(str(self.root))
        finding = next(f for f in result.findings if f.rule_id == "anthropic-api-key")
        self.assertEqual(finding.severity, "critical")

    def test_stripe_live_key_is_critical(self):
        self.write("server.js", f'const stripe = require("stripe")("{fake_stripe_live_key()}");\n')
        result = scan(str(self.root))
        finding = next(f for f in result.findings if f.rule_id == "stripe-live-key")
        self.assertEqual(finding.severity, "critical")

    def test_telegram_token_detected(self):
        self.write("bot.py", f'TOKEN = "{fake_telegram_token()}"\n')
        result = scan(str(self.root))
        self.assertIn("telegram-bot-token", self.rule_ids(result))

    def test_placeholder_keys_are_ignored(self):
        self.write("readme_snippet.py", 'api_key = "sk-ant-your-key-goes-here-xxxxxxxxxxxxxxxx"\n')
        result = scan(str(self.root))
        self.assertNotIn("anthropic-api-key", self.rule_ids(result))

    def test_secret_is_redacted_in_excerpt(self):
        key = fake_anthropic_key()
        self.write("app.py", f'client = Anthropic(api_key="{key}")\n')
        result = scan(str(self.root))
        finding = next(f for f in result.findings if f.rule_id == "anthropic-api-key")
        self.assertNotIn(key, finding.excerpt)
        self.assertIn("[redacted]", finding.excerpt)

    def test_non_secret_finding_excerpt_still_redacts_keys(self):
        key = fake_anthropic_key()
        self.write("src/chat.js", f'const c = new Anthropic({{ apiKey: "{key}", dangerouslyAllowBrowser: true }});\n')
        result = scan(str(self.root))
        finding = next(f for f in result.findings if f.rule_id == "dangerously-allow-browser")
        self.assertNotIn(key, finding.excerpt)

    def test_supabase_service_role_jwt_is_critical(self):
        self.write("src/db.js", f'const supabase = createClient(url, "{fake_jwt("service_role")}");\n')
        result = scan(str(self.root))
        finding = next(f for f in result.findings if f.rule_id == "supabase-service-role-key")
        self.assertEqual(finding.severity, "critical")

    def test_supabase_anon_jwt_is_info(self):
        self.write("src/db.js", f'const supabase = createClient(url, "{fake_jwt("anon")}");\n')
        result = scan(str(self.root))
        finding = next(f for f in result.findings if f.rule_id == "supabase-anon-key")
        self.assertEqual(finding.severity, "info")

    def test_env_file_contents_not_flagged_but_gitignore_is(self):
        self.write(".env", f"ANTHROPIC_API_KEY={fake_anthropic_key()}\n")
        result = scan(str(self.root))
        self.assertNotIn("anthropic-api-key", self.rule_ids(result))
        self.assertIn("env-file-not-gitignored", self.rule_ids(result))

    def test_gitignored_env_file_is_fine(self):
        self.write(".env", f"ANTHROPIC_API_KEY={fake_anthropic_key()}\n")
        self.write(".gitignore", "node_modules/\n.env\n")
        result = scan(str(self.root))
        self.assertNotIn("env-file-not-gitignored", self.rule_ids(result))

    def test_env_example_is_exempt(self):
        self.write(".env.example", "ANTHROPIC_API_KEY=\n")
        result = scan(str(self.root))
        self.assertNotIn("env-file-not-gitignored", self.rule_ids(result))

    def test_dangerously_allow_browser(self):
        self.write("src/chat.ts", "const client = new Anthropic({ apiKey, dangerouslyAllowBrowser: true });\n")
        result = scan(str(self.root))
        finding = next(f for f in result.findings if f.rule_id == "dangerously-allow-browser")
        self.assertEqual(finding.severity, "critical")

    def test_llm_call_only_flagged_in_frontend(self):
        self.write("public/chat.js", 'fetch("https://api.anthropic.com/v1/messages", opts);\n')
        self.write("server/llm.js", 'fetch("https://api.anthropic.com/v1/messages", opts);\n')
        result = scan(str(self.root))
        paths = [f.path for f in result.findings if f.rule_id == "llm-api-call-in-frontend"]
        self.assertEqual(paths, ["public/chat.js"])

    def test_sql_interpolation_python_and_js(self):
        self.write("db.py", 'cur.execute(f"SELECT * FROM users WHERE id = {user_id}")\n')
        self.write("db.js", "pool.query(`SELECT * FROM users WHERE id = ${userId}`);\n")
        result = scan(str(self.root))
        paths = sorted(f.path for f in result.findings if f.rule_id == "sql-string-building")
        self.assertEqual(paths, ["db.js", "db.py"])

    def test_innerhtml_static_string_not_flagged(self):
        self.write(
            "src/ui.js",
            "box.innerHTML = '<div class=\"none\">No matches</div>';\n"
            'list.innerHTML = "";\n'
            "out.innerHTML = results;\n"
            "el.innerHTML = `<p>${message}</p>`;\n",
        )
        result = scan(str(self.root))
        lines = sorted(f.line for f in result.findings if f.rule_id == "innerhtml-assignment")
        self.assertEqual(lines, [3, 4])

    def test_flask_debug(self):
        self.write("app.py", "app.run(host='0.0.0.0', debug=True)\n")
        result = scan(str(self.root))
        self.assertIn("flask-debug-enabled", self.rule_ids(result))

    def test_node_modules_skipped(self):
        self.write("node_modules/lib/index.js", f'const key = "{fake_stripe_live_key()}";\n')
        result = scan(str(self.root))
        self.assertEqual(result.findings, [])

    def test_clean_project_scores_100(self):
        self.write("app.py", 'import os\nkey = os.environ["ANTHROPIC_API_KEY"]\n')
        result = scan(str(self.root))
        self.assertEqual(result.findings, [])
        self.assertEqual(result.score, 100)
        self.assertEqual(result.grade, "A")

    def test_score_drops_with_findings(self):
        self.write("server.js", f'const stripe = require("stripe")("{fake_stripe_live_key()}");\n')
        result = scan(str(self.root))
        self.assertEqual(result.score, 75)
        self.assertEqual(result.grade, "B")

    def test_mongodb_uri_with_credentials(self):
        self.write("config.js", 'const uri = "mongodb+srv://admin:supersecret123@cluster0.mongodb.net/app";\n')
        result = scan(str(self.root))
        self.assertIn("mongodb-uri-credentials", self.rule_ids(result))

    def test_public_env_prefix_with_secret_name(self):
        self.write("src/lib.ts", "const key = import.meta.env.VITE_STRIPE_SECRET_KEY;\n")
        result = scan(str(self.root))
        self.assertIn("public-env-var-holds-secret", self.rule_ids(result))


class ScanFilesTest(unittest.TestCase):
    """The in-memory API used by the hosted scanner."""

    def test_matches_disk_scanner_behaviour(self):
        result = scan_files([
            ("app.py", f'client = Anthropic(api_key="{fake_anthropic_key()}")\n'),
            ("public/chat.js", f'const key = "{fake_anthropic_key()}";\n'),
        ])
        by_path = {f.path: f for f in result.findings if f.rule_id == "anthropic-api-key"}
        self.assertEqual(by_path["app.py"].severity, "high")
        self.assertEqual(by_path["public/chat.js"].severity, "critical")
        self.assertEqual(result.files_scanned, 2)

    def test_skip_dirs_and_lockfiles_respected(self):
        result = scan_files([
            ("node_modules/lib/index.js", f'const k = "{fake_stripe_live_key()}";\n'),
            ("package-lock.json", "{}\n"),
            ("src/ok.js", "const x = 1;\n"),
        ])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.files_scanned, 1)

    def test_env_gitignore_check_in_memory(self):
        with_ignore = scan_files([
            (".env", f"KEY={fake_anthropic_key()}\n"),
            (".gitignore", ".env\n"),
        ])
        self.assertNotIn("env-file-not-gitignored", {f.rule_id for f in with_ignore.findings})

        without_ignore = scan_files([(".env", f"KEY={fake_anthropic_key()}\n")])
        self.assertIn("env-file-not-gitignored", {f.rule_id for f in without_ignore.findings})

    def test_windows_paths_normalized(self):
        result = scan_files([("src\\db.py", 'cur.execute(f"SELECT {x}")\n')])
        finding = next(f for f in result.findings if f.rule_id == "sql-string-building")
        self.assertEqual(finding.path, "src/db.py")


if __name__ == "__main__":
    unittest.main()
