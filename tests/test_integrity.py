"""The integrity check (phase A) against small made-up repositories."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from vibecheck.checks.integrity import CHECK  # noqa: E402
from vibecheck.checks.integrity import code  # noqa: E402
from vibecheck.checks.integrity.repo import from_files  # noqa: E402
from vibecheck.checks.integrity.rules import CATEGORIES, PASSES, RULES  # noqa: E402
from vibecheck.core import registry  # noqa: E402
from vibecheck.core.models import Context, Target  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

WELL_BUILT = {
    "package.json": json.dumps({
        "name": "groomly", "scripts": {"test": "vitest run --coverage", "lint": "eslint .", "ci": "vitest run"},
        "dependencies": {"next": "16.0.0", "@sentry/nextjs": "^9.0.0", "pino": "^9.0.0", "@prisma/client": "^6.0.0"},
        "devDependencies": {"vitest": "^3.0.0", "eslint": "^9.0.0", "prettier": "^3.0.0",
                            "@playwright/test": "^1.50.0", "typescript": "^5.6.0"}}),
    "package-lock.json": "{}",
    "tsconfig.json": '{\n  // strict all the way\n  "compilerOptions": {"strict": true,},\n}',
    "eslint.config.mjs": "export default [];",
    ".prettierrc": "{}",
    ".env.example": "DATABASE_URL=\nSENTRY_DSN=\n",
    "vercel.json": "{}",
    "checkly.config.ts": "export default {};",
    "docs/RUNBOOK.md": "# Runbook\n",
    "prisma/schema.prisma": "model User { id String @id }",
    "prisma/migrations/0001_init/migration.sql": "CREATE TABLE x();",
    "instrumentation.ts": "import * as Sentry from '@sentry/nextjs';\nSentry.init({ dsn: process.env.SENTRY_DSN });\n",
    "src/app/api/health/route.ts": "export function GET() { return Response.json({ ok: true }); }\n",
    "src/lib/billing.ts": "export function price(n: number) {\n  return n * 12;\n}\n",
    "src/lib/billing.test.ts": "import { price } from './billing';\ntest('x', () => expect(price(1)).toBe(12));\n",
    "e2e/signup.spec.ts": "test('signs up', async () => {});\n",
    ".github/workflows/ci.yml": "on:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  test:\n"
                                "    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n      - run: npm run lint\n"
                                "      - run: npm test\n",
}


def write(files):
    d = tempfile.TemporaryDirectory()
    for rel, text in files.items():
        p = Path(d.name) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return d


def run(files, url=None, fetch=None):
    with write(files) as d:
        ctx = Context(guard=False, fetch_override=fetch) if fetch else Context(guard=False)
        return CHECK.run(Target(repo=d, url=url), ctx)


def ids(result):
    return {f.id for f in result.problems}


def passes(result):
    return {f.id for f in result.passes}


def finding(result, rule_id):
    return next(f for f in result.findings if f.id == rule_id)


def but(**changes):
    files = dict(WELL_BUILT)
    for k, v in changes.items():
        k = k.replace("__", "/").replace("_DOT_", ".")
        if v is None:
            files.pop(k, None)
        else:
            files[k] = v
    return files


class WellBuiltTest(unittest.TestCase):
    def test_full_marks_with_every_pass(self):
        r = run(WELL_BUILT)
        self.assertEqual([(f.id, f.evidence) for f in r.problems], [])
        self.assertEqual(r.total, 100)
        self.assertEqual(set(r.category_scores), {c.id for c in CATEGORIES})
        self.assertTrue({"obs-error-tracking", "obs-structured-logging", "obs-health-endpoint", "alert-configured",
                         "alert-runbook", "build-env-example", "build-migrations", "build-lockfile",
                         "tests-present", "tests-in-ci", "tests-e2e", "tests-coverage", "quality-linter",
                         "quality-formatter", "quality-lint-in-ci", "quality-ts-strict"} <= passes(r))
        self.assertIn("Next.js", finding(r, "build-stack").evidence)

    def test_works_on_uploaded_files_too(self):
        r = CHECK.run(Target(files=list(WELL_BUILT.items()), label="groomly"), Context(guard=False))
        self.assertEqual(r.total, 100)


class BareRepoTest(unittest.TestCase):
    FILES = {
        "package.json": json.dumps({"dependencies": {"express": "4.19.0", "left-pad": "*"}}),
        "server.js": "const port = process.env.PORT;\nrequire('express')().listen(port);\n",
    }

    def test_reports_what_a_quick_ai_build_leaves_out(self):
        r = run(self.FILES)
        self.assertEqual(finding(r, "tests-none").severity, "critical")
        self.assertTrue({"obs-no-error-tracking", "obs-no-structured-logging", "obs-no-health-endpoint",
                         "alert-none", "alert-no-runbook", "build-no-env-example", "build-no-lockfile",
                         "build-floating-versions", "quality-no-linter", "quality-no-formatter"} <= ids(r))
        self.assertIn("left-pad@*", finding(r, "build-floating-versions").evidence)
        self.assertNotIn("tests-not-in-ci", ids(r), "no tests means one finding, not two")
        self.assertLess(r.total, 50)
        self.assertEqual(r.category_scores["tests"], 0)

    def test_a_static_site_isnt_asked_for_a_health_route_or_paging(self):
        r = run({"index.html": "<h1>Hi</h1>", "package.json": json.dumps({"devDependencies": {"vite": "5"}}),
                 "src/main.js": "console.log(1)"})
        self.assertFalse({"obs-no-health-endpoint", "alert-none", "alert-no-runbook", "obs-no-structured-logging"} & ids(r))


class SignalTest(unittest.TestCase):
    def test_a_tracker_installed_but_never_started(self):
        r = run(but(instrumentation_DOT_ts=None))
        self.assertIn("obs-error-tracking-not-initialised", ids(r))

    def test_words_in_docs_and_tests_are_not_evidence(self):
        r = run(but(instrumentation_DOT_ts=None, package_DOT_json=json.dumps({"dependencies": {"next": "16"}}),
                    **{"README.md": "Call Sentry.init() and wire PagerDuty at https://events.pagerduty.com",
                       "src/lib/x.test.ts": "Sentry.init({})",
                       "checkly.config.ts": None}))
        self.assertIn("obs-no-error-tracking", ids(r))
        self.assertIn("alert-none", ids(r))

    def test_a_library_file_called_health_is_not_a_route(self):
        r = run(but(**{"src/app/api/health/route.ts": None, "src/lib/health.ts": "export const ok = 1;"}))
        self.assertIn("obs-no-health-endpoint", ids(r))

    def test_an_express_health_route_counts(self):
        r = run(but(**{"src/app/api/health/route.ts": None,
                       "src/server.ts": "app.get('/healthz', (req, res) => res.send('ok'));"}))
        self.assertIn("obs-health-endpoint", passes(r))

    def test_tests_that_ci_never_runs(self):
        wf = "on:\n  pull_request:\njobs:\n  b:\n    steps:\n      - run: npm run build\n"
        r = run(but(**{".github/workflows/ci.yml": wf}))
        self.assertEqual(finding(r, "tests-not-in-ci").severity, "high")
        r = run(but(**{".github/workflows/ci.yml": None}))
        self.assertIn("no CI workflow at all", finding(r, "tests-not-in-ci").evidence)

    def test_ci_that_runs_a_script_that_runs_the_tests_counts(self):
        wf = "on: [push]\njobs:\n  t:\n    steps:\n      - run: npm run ci\n      - run: npx eslint .\n"
        r = run(but(**{".github/workflows/ci.yml": wf}))
        self.assertIn("tests-in-ci", passes(r))

    def test_typescript_strict_through_a_local_base_config(self):
        r = run(but(tsconfig_DOT_json='{"extends": "./tsconfig.base.json"}',
                    **{"tsconfig.base.json": '{"compilerOptions": {"strict": true}}'}))
        self.assertIn("quality-ts-strict", passes(r))
        r = run(but(tsconfig_DOT_json='{"compilerOptions": {"strict": false}}'))
        self.assertEqual(finding(r, "quality-ts-not-strict").evidence, "tsconfig.json")

    def test_schema_without_migrations(self):
        r = run(but(**{"prisma/migrations/0001_init/migration.sql": None}))
        self.assertIn("build-no-migrations", ids(r))

    def test_hand_applied_sql_beside_the_schema_counts_as_migrations(self):
        r = run(but(**{"prisma/migrations/0001_init/migration.sql": None, "prisma/2026_users.sql": "ALTER TABLE x;"}))
        self.assertIn("build-migrations", passes(r))

    def test_public_source_maps(self):
        r = run(but(**{"next.config.ts": "export default { productionBrowserSourceMaps: true };"}))
        self.assertIn("productionBrowserSourceMaps", finding(r, "obs-sourcemaps-public").evidence)

    def test_leftovers_but_not_real_files_with_backup_in_the_name(self):
        r = run(but(**{"src/lib/billing.ts.bak": "x", "src/lib/billing copy.ts": "x",
                       "tools/restore-backup.js": "module.exports = 1;"}))
        ev = finding(r, "debt-leftover-files").evidence
        self.assertIn("billing.ts.bak", ev)
        self.assertIn("billing copy.ts", ev)
        self.assertNotIn("restore-backup", ev)

    def test_todo_density_and_large_files(self):
        big = "\n".join(f"export const a{i} = {i}; // TODO tidy" if i % 50 == 0 else f"export const a{i} = {i};"
                        for i in range(1200))
        r = run(but(**{"src/lib/big.ts": big}))
        self.assertIn("src/lib/big.ts (1,200 lines)", finding(r, "debt-large-files").evidence)
        todo = "\n".join("// TODO: fix" for _ in range(30)) + "\n" + "\n".join(f"let v{i} = 1;" for i in range(1000))
        r = run(but(**{"src/lib/todo.ts": todo}))
        self.assertIn("30 TODO/FIXME/HACK", finding(r, "debt-todo-density").evidence)


class LiveSignalTest(unittest.TestCase):
    def fetch(self, healthy=True, status_link=True):
        def f(url, method="GET"):
            if url.endswith("/api/health"):
                return SimpleNamespace(status=200 if healthy else 404, text="ok")
            if url.endswith(("/health", "/healthz")):
                return SimpleNamespace(status=404, text="")
            link = '<a href="https://status.groomly.test">Status</a>' if status_link else ""
            return SimpleNamespace(status=200, text=f"<html><body>{link}</body></html>")
        return f

    def test_health_answers_and_a_status_page_is_linked(self):
        r = run(WELL_BUILT, url="https://groomly.test", fetch=self.fetch())
        self.assertIn("obs-health-responding", passes(r))
        self.assertIn("obs-status-page", passes(r))

    def test_a_health_route_that_doesnt_answer(self):
        r = run(WELL_BUILT, url="https://groomly.test", fetch=self.fetch(healthy=False, status_link=False))
        self.assertIn("obs-health-not-responding", ids(r))


class CodeMetricsTest(unittest.TestCase):
    def test_python_functions_are_measured_exactly(self):
        src = "def f(x):\n" + "".join(f"    if x == {i}:\n        return {i}\n" for i in range(30)) + "    return -1\n"
        (fn,) = code.python_functions("a.py", src)
        self.assertEqual((fn.name, fn.length, fn.branches), ("f", 62, 30))

    def test_js_functions_by_braces(self):
        src = ("export async function handle(req) {\n" + "  if (a) { b(); }\n" * 10 + "}\n"
               "const tiny = (x) => {\n  return x;\n};\n")
        funcs = {f.name: f for f in code.js_functions("a.ts", src)}
        self.assertEqual(funcs["handle"].length, 12)
        self.assertEqual(funcs["handle"].branches, 10)
        self.assertIn("tiny", funcs)

    def test_long_and_branchy_functions_are_reported(self):
        body = "".join(f"  if (x === {i}) {{ y += {i}; }}\n" for i in range(160))
        r = run(but(**{"src/lib/huge.ts": "export function huge(x) {\n  let y = 0;\n" + body + "  return y;\n}\n"}))
        self.assertIn("huge in src/lib/huge.ts:1", finding(r, "quality-long-functions").evidence)
        self.assertIn("(160 branches)", finding(r, "quality-complex-functions").evidence)

    def test_duplicated_blocks(self):
        block = "".join(f"  const value{i} = compute(input, {i}) + offset;\n" for i in range(30))
        files = {f"src/lib/copy{n}.ts": f"export function f{n}(input, offset) {{\n{block}  return 0;\n}}\n" for n in range(3)}
        r = run(but(**files))
        self.assertIn("are copies of blocks elsewhere", finding(r, "quality-duplication").evidence)
        dup, total, _ex = code.duplicated_blocks({"a.ts": block, "b.ts": "something else entirely here\n" * 3})
        self.assertEqual(dup, 0)


class FrameworkTest(unittest.TestCase):
    def test_registered_for_repos_only_and_never_hosted(self):
        repo_checks = [c.id for c in registry.available_for(Target(repo="."))]
        self.assertIn("integrity", repo_checks)
        self.assertNotIn("integrity", [c.id for c in registry.available_for(Target(url="https://x.test"))])
        self.assertNotIn("integrity", [c.id for c in registry.hosted_for(Target(repo="."))])

    def test_the_combined_badge_doesnt_require_it(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("vibechecked_api", ROOT / "api" / "vibechecked.py")
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        env = [{"p": json.dumps({"target": {"repo": "uploaded project"}})}]
        self.assertEqual(api.required_checks(env), ["security"])

    def test_every_rule_formats_and_every_pass_has_a_category(self):
        cats = {c.id for c in CATEGORIES}
        for rule in RULES.values():
            with self.subTest(rule.id):
                self.assertIn(rule.severity, ("critical", "high", "medium", "low", "info"))
                self.assertIn(rule.category, cats)
                self.assertTrue(rule.title and rule.description and rule.verify)
                for tpl in (rule.description, rule.fix_prompt):
                    tpl.format(path="/x", excerpt="e")
                self.assertNotIn("\u2014", rule.description + rule.fix_prompt + rule.verify, "no em-dashes")
        for pass_id, (_title, cat) in PASSES.items():
            self.assertIn(cat, cats, pass_id)

    def test_cli_runs_it_and_fails_on_high(self):
        from vibecheck.cli import main
        with write(BareRepoTest.FILES) as d:
            out = io.StringIO()
            with redirect_stdout(out):
                code_ = main([d, "--checks", "integrity", "--json"])
        data = json.loads(out.getvalue())
        self.assertEqual(data["check_id"], "integrity")
        self.assertEqual(code_, 1)

    def test_manifest_is_committed_and_current(self):
        from generate_rules_manifest import INTEGRITY_MANIFEST_PATH, render_integrity
        self.assertEqual(INTEGRITY_MANIFEST_PATH.read_text(encoding="utf-8"), render_integrity(),
                         "integrity-rules.json is out of date: run python3 scripts/generate_rules_manifest.py")


if __name__ == "__main__":
    unittest.main()
