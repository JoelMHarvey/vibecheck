"""Integrity rules: the prose behind every finding and pass.

Same shape as the visibility rules: a finding carries facts (id, path,
evidence) and the words come from here, so a share link stays short and
integrity-rules.json can rehydrate it. Prompts may use {path} and {excerpt}.

Scoring rewards presence and wiring (tests that CI runs on every pull
request), never volume: test counts and line counts are easy to inflate with
generated code, so the findings about them are low. The absences that matter
most are severe on purpose: no tests at all is critical (no badge), and no
error tracking or alerting is high (no gold).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from ...core.models import Category

CATEGORIES = [
    Category("observability", "Observability", 0.20),
    Category("alerting", "Alerting", 0.15),
    Category("build", "How it was built", 0.15),
    Category("tests", "Tests", 0.25),
    Category("quality", "Code quality", 0.15),
    Category("debt", "Tech debt", 0.10),
]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    description: str
    fix_prompt: str
    verify: str
    guide: Optional[str] = None


_RULES = [
    # ---- Observability ----------------------------------------------------
    Rule("obs-no-error-tracking", "No error tracking", "high", "observability",
         "Nothing in the code reports errors to a tracker (Sentry, OpenTelemetry, Datadog and the like). "
         "When something breaks in production you'll hear about it from a user, if at all, and without "
         "the stack trace that says where.",
         "My app has no error tracking. Add Sentry (or OpenTelemetry if I already use a tracing backend) "
         "for my stack: install the SDK, initialise it once at startup with the DSN from an environment "
         "variable, report unhandled errors on the server and in the browser, set the release to the git "
         "commit, and turn off sending personal data by default. Show me where each piece goes.",
         "Throw a test error from a route in a preview deployment and check it arrives in the tracker "
         "with a stack trace."),
    Rule("obs-error-tracking-not-initialised", "Error tracker installed but never started", "high", "observability",
         "{excerpt} is a dependency, but nothing calls its init. Installed and never started, it reports nothing.",
         "My project depends on {excerpt} but never initialises it. Add the init call where my framework "
         "expects it (for Next.js, instrumentation.ts and the sentry.*.config files), reading the DSN "
         "from an environment variable.",
         "Throw a test error in a preview deployment and check it reaches the tracker."),
    Rule("obs-no-structured-logging", "Logs are plain text", "low", "observability",
         "No structured logger (pino, winston, structlog and the like) is in use. Plain console or print "
         "lines are hard to search when you're trying to find the one request that failed.",
         "Add a structured logger to my server code (pino for Node, structlog or the logging module with "
         "a JSON formatter for Python). Log one JSON line per event with a level, a message, a request id "
         "and the route, and never log secrets or personal data.",
         "Hit a route and check the log line is JSON with a level and a request id."),
    Rule("obs-no-health-endpoint", "No health endpoint", "low", "observability",
         "There's no /health (or /api/health) route. Uptime monitors and load balancers need a cheap "
         "address that says the app is up, and ideally whether its database is.",
         "Add a GET /api/health route that returns 200 with {{\"ok\": true}} when the app can serve "
         "requests, without auth. Add a second, cached check of the database if I have one, so a monitor "
         "can tell 'app down' from 'database down'. Keep it fast and free of secrets.",
         "curl -i https://yoursite/api/health should return 200 in well under a second."),
    Rule("obs-sourcemaps-public", "Source maps shipped to the browser", "medium", "observability",
         "{excerpt} publishes source maps with the production build, so anyone can read your original "
         "source in DevTools. Error trackers want the maps; browsers don't need them.",
         "My build publishes source maps publicly ({excerpt}). Stop serving them: turn the setting off, "
         "or generate them hidden and upload them to my error tracker during the build, then delete them "
         "from the output.",
         "Open a production page, look for a .map request in DevTools' Network tab: there should be none."),
    Rule("obs-health-not-responding", "Health endpoint doesn't answer", "low", "observability",
         "None of /api/health, /health or /healthz answered 200 on the live site, so an uptime monitor has "
         "nothing reliable to watch.",
         "Add or fix a public GET /api/health that returns 200 when the app is up, and check my hosting "
         "doesn't put it behind auth.",
         "curl -i https://yoursite/api/health should return 200."),

    # ---- Alerting -------------------------------------------------------------
    Rule("alert-none", "Nothing alerts anyone", "high", "alerting",
         "There's no sign of an uptime monitor, alert rule or paging integration in the repository. "
         "Errors can be tracked and still go unread; something has to wake a person when the site is down.",
         "Set up alerting for my app: an uptime check on /api/health every few minutes (Better Stack, "
         "Checkly or a scheduled GitHub Action), an alert rule in my error tracker for new or spiking "
         "errors, and both sending to email or my phone. Keep the configuration in the repository where "
         "the tool allows it.",
         "Take a preview deployment's health route down on purpose and check the alert arrives."),
    Rule("alert-no-runbook", "No runbook", "low", "alerting",
         "There's no runbook or incident doc. At 2am, the person (or AI) fixing an outage does better "
         "with a page that says how to roll back, where the logs are and who to tell.",
         "Write docs/RUNBOOK.md for my app: how to tell what's broken (logs, error tracker, status), how "
         "to roll back a deploy, how to put up a maintenance page, where backups are and how to restore "
         "one, and who to tell. Use only what's true of my setup.",
         "Ask someone who didn't write it to follow it for a pretend outage."),

    # ---- How it was built ---------------------------------------------------
    Rule("build-no-env-example", "No .env.example", "low", "build",
         "The code reads environment variables ({excerpt}) but there's no .env.example saying which. "
         "The next person, or the next AI session, has to guess.",
         "Create .env.example listing every environment variable my code reads, each with a placeholder "
         "value and a one-line comment saying what it's for. No real values. Make sure .env itself is in "
         ".gitignore.",
         "Compare .env.example with a search for process.env / os.environ: nothing missing."),
    Rule("build-no-migrations", "Database schema without migrations", "medium", "build",
         "There's a database schema ({excerpt}) but no migrations folder. Without migrations, every schema "
         "change in production is done by hand or by a tool that may drop data.",
         "My project has a schema ({excerpt}) and no migrations. Set up the migration tool for it "
         "(prisma migrate, drizzle-kit, alembic, Django migrations), create a baseline migration from the "
         "current production schema without changing it, and commit the migrations folder.",
         "Run the migration tool's status command against a copy of production: it should report nothing pending."),
    Rule("build-no-lockfile", "No lockfile", "medium", "build",
         "{excerpt} has no lockfile, so every install can pull different versions of your dependencies. "
         "A build that worked yesterday can break, or pick up a compromised release, today.",
         "My project has no lockfile ({excerpt}). Generate one with my package manager (npm install, pnpm "
         "install, uv lock, poetry lock), commit it, and make CI install from it (npm ci, pnpm install "
         "--frozen-lockfile).",
         "Check the lockfile is committed and CI uses the frozen install."),
    Rule("build-floating-versions", "Dependencies on any version", "low", "build",
         "Some dependencies accept any version at all ({excerpt}). Even with a lockfile, the next update "
         "can jump a major version.",
         "In package.json these dependencies use '*' or 'latest': {excerpt}. Pin each to the version the "
         "lockfile has now with a caret range (for example ^4.2.0).",
         "Search package.json for \"*\" and \"latest\": none left."),
    Rule("build-no-deploy-config", "No deploy configuration in the repo", "info", "build",
         "There's no deploy configuration (vercel.json, Dockerfile, fly.toml and so on). Zero-config "
         "hosting is fine; just know that how it's deployed lives only in a dashboard.",
         "", "Nothing to do if your host deploys it with no configuration."),

    # ---- Tests ----------------------------------------------------------------
    Rule("tests-none", "No tests", "critical", "tests",
         "There are no test files. Every change, yours or an AI's, goes out with nothing checking that the "
         "parts that worked still do.",
         "My project has no tests. Add a test runner that fits my stack (vitest for Vite or Next.js, pytest "
         "for Python), then write tests for the code where a bug costs most: money (billing, payments), "
         "access (auth, permissions) and anything that deletes data. Start with a handful that run in "
         "seconds, and add a test script to package.json or the README.",
         "Run the test command: it should find and pass the new tests."),
    Rule("tests-not-in-ci", "Tests don't run on every change", "high", "tests",
         "The tests exist, but {excerpt}. Tests that only run when someone remembers stop being run, and "
         "the first sign of a broken change is a broken site.",
         "Make my tests run on every pull request and every push to the main branch: a GitHub Actions "
         "workflow that installs dependencies from the lockfile and runs the test command, and fails the "
         "check if a test fails. Then require that check before merging.",
         "Open a pull request with a deliberately failing test and check the workflow goes red."),
    Rule("tests-few", "Few tests for the size of the code", "low", "tests",
         "{excerpt}. Not a target to hit, and generated tests are worth little, but large untested areas "
         "are where regressions live.",
         "My project has {excerpt}. Find the five modules where a bug would cost most (money, access, data "
         "loss, the main user journey) and write focused tests for each, testing behaviour rather than "
         "implementation.",
         "Re-run this check."),
    Rule("tests-no-e2e", "No end-to-end tests", "low", "tests",
         "Unit tests don't catch a broken sign-up page. One end-to-end test that clicks through the main "
         "journey in a real browser catches what they miss.",
         "Add Playwright to my project and write one end-to-end test of the main journey (sign up, do the "
         "core thing, see the result) against a local build. Run it in CI on pull requests.",
         "Break the journey on purpose (rename a button) and check the end-to-end test fails."),
    Rule("tests-no-coverage", "No coverage report", "info", "tests",
         "Coverage isn't configured. It's no target, but it shows which files no test touches.",
         "", "Optional: add coverage to the test command and look at which files show 0%."),

    # ---- Code quality ---------------------------------------------------------
    Rule("quality-no-linter", "No linter", "medium", "quality",
         "No linter is configured (ESLint, Biome, Ruff and the like). A linter catches unused variables, "
         "missing awaits and suspicious comparisons before they ship, and keeps AI-written code honest.",
         "Add a linter for my stack (ESLint with my framework's recommended config, or Biome; Ruff for "
         "Python), fix or explicitly disable what it reports today, add a lint script, and run it in CI.",
         "Run the lint command: it should exit 0."),
    Rule("quality-no-formatter", "No formatter", "low", "quality",
         "No formatter is configured (Prettier, Biome, Black, Ruff format). Without one, diffs fill with "
         "whitespace churn and reviews get harder.",
         "Add a formatter (Prettier or Biome; Ruff format or Black for Python), format the codebase once in "
         "its own commit, and add a format check to CI.",
         "Run the formatter's check mode: no files to change."),
    Rule("quality-lint-not-in-ci", "Linter not run in CI", "low", "quality",
         "A linter is configured, but no CI workflow runs it, so it only catches what someone remembers "
         "to run it on.",
         "Add a lint step to my CI workflow that runs on pull requests and fails on errors.",
         "Open a pull request with an unused variable and check the lint step fails."),
    Rule("quality-ts-not-strict", "TypeScript isn't in strict mode", "medium", "quality",
         "{excerpt} doesn't set \"strict\": true. Without it TypeScript lets null and undefined through "
         "everywhere, which is most of what it's for.",
         "Turn on \"strict\": true in {excerpt}. Fix the errors it reports in small commits, starting with "
         "the code that handles money and auth; where a fix is large, leave a typed TODO rather than any.",
         "Run tsc --noEmit: it should pass with strict on."),
    Rule("quality-long-functions", "Very long functions", "low", "quality",
         "Some functions run to hundreds of lines ({excerpt}). Long functions are where bugs hide and where "
         "AI edits go wrong, because the whole thing doesn't fit in view.",
         "These functions are very long: {excerpt}. Split each into smaller named steps without changing "
         "behaviour, with tests around it first if it has none.",
         "Re-run this check."),
    Rule("quality-complex-functions", "Functions with a lot of branches", "low", "quality",
         "Some functions have a very large number of branches ({excerpt}). Every branch is a path that "
         "needs a test, and few have them.",
         "These functions branch a lot: {excerpt}. Simplify each: early returns, lookup tables instead of "
         "long if/else chains, and small helpers for the separate cases. Keep behaviour identical.",
         "Re-run this check."),
    Rule("quality-duplication", "Duplicated code", "low", "quality",
         "{excerpt}. Copied blocks drift apart: a fix lands in one copy and not the others.",
         "My codebase has duplicated blocks ({excerpt}). Find the repeated logic, move it into one shared "
         "function or component, and call it from each place.",
         "Re-run this check."),

    # ---- Tech debt -----------------------------------------------------------
    Rule("debt-todo-density", "A lot of TODOs and FIXMEs", "low", "debt",
         "{excerpt}. Each is a known problem nobody has scheduled.",
         "List every TODO, FIXME and HACK in my code with its file and line, group them by what they're "
         "about, and tell me which look like real bugs. Fix those first; turn the rest into issues and "
         "delete the comments.",
         "Re-run this check."),
    Rule("debt-large-files", "Very large source files", "low", "debt",
         "Some source files are very long ({excerpt}). Big files collect unrelated code and are hard to "
         "review or change safely.",
         "These files are very long: {excerpt}. Propose how to split each by responsibility, then do it one "
         "file at a time without changing behaviour.",
         "Re-run this check."),
    Rule("debt-leftover-files", "Leftover copies and backups", "low", "debt",
         "{excerpt} look like old copies or backups. They confuse search, reviews and AI tools that read the "
         "whole repo.",
         "Check whether these files are used anywhere: {excerpt}. Delete the ones that aren't; git keeps the history.",
         "Re-run this check."),
]

RULES: Dict[str, Rule] = {r.id: r for r in _RULES}

PASSES: Dict[str, Tuple[str, str]] = {
    "obs-error-tracking": ("Errors are tracked", "observability"),
    "obs-structured-logging": ("Logs are structured", "observability"),
    "obs-health-endpoint": ("Has a health endpoint", "observability"),
    "obs-health-responding": ("Health endpoint answers on the live site", "observability"),
    "obs-status-page": ("Links a status page", "observability"),
    "alert-configured": ("Something alerts a person", "alerting"),
    "alert-runbook": ("Has a runbook", "alerting"),
    "build-stack": ("Stack identified", "build"),
    "build-env-example": ("Environment variables are documented", "build"),
    "build-migrations": ("Schema changes go through migrations", "build"),
    "build-lockfile": ("Dependencies are locked", "build"),
    "build-deploy-config": ("Deploy configuration is in the repo", "build"),
    "tests-present": ("Has tests", "tests"),
    "tests-in-ci": ("CI runs the tests", "tests"),
    "tests-e2e": ("Has end-to-end tests", "tests"),
    "tests-coverage": ("Coverage is configured", "tests"),
    "quality-linter": ("A linter is configured", "quality"),
    "quality-formatter": ("A formatter is configured", "quality"),
    "quality-lint-in-ci": ("CI runs the linter", "quality"),
    "quality-ts-strict": ("TypeScript is strict", "quality"),
}

assert len(RULES) == len(_RULES), "duplicate integrity rule id"
