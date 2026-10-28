"""The pattern tables the integrity signals match against.

Data only, like the security rule table: it names the SDKs, endpoints, paths
and commands that count as evidence. Kept apart from the logic in
signals.py so this repository's own .vibecheckignore can skip just this
file (its patterns would otherwise be evidence of themselves).
"""

from __future__ import annotations

LONG_FUNCTION = 150      # lines
COMPLEX_FUNCTION = 25    # branches
LARGE_FILE = 1000        # lines
TODO_PER_KLOC = 5
FEW_TESTS_RATIO = 0.1
FEW_TESTS_MIN_SOURCE = 30
DUPLICATION_SHARE = 0.05

ERROR_TRACKERS = {
    "@sentry/*": "Sentry", "sentry-sdk": "Sentry", "@opentelemetry/*": "OpenTelemetry",
    "opentelemetry-*": "OpenTelemetry", "@vercel/otel": "OpenTelemetry", "dd-trace": "Datadog",
    "ddtrace": "Datadog", "@datadog/browser-rum": "Datadog", "@honeybadger-io/*": "Honeybadger",
    "honeybadger": "Honeybadger", "rollbar": "Rollbar", "@bugsnag/*": "Bugsnag", "bugsnag": "Bugsnag",
    "@highlight-run/*": "Highlight", "@axiomhq/*": "Axiom", "newrelic": "New Relic", "@appsignal/*": "AppSignal",
}
TRACKER_INIT = (r"\bSentry\.init\(|\bsentry_sdk\.init\(|\bregisterOTel\(|\bnew NodeSDK\(|"
                r"\btracer\.init\(|require\(['\"]dd-trace['\"]\)\.init|\bHoneybadger\.(configure|init)\(|"
                r"\bnew Rollbar\(|\bRollbar\.init\(|\bBugsnag\.start\(|\bH\.init\(|"
                r"require\(['\"]newrelic['\"]\)|^import ['\"]newrelic['\"]|\bwithSentryConfig\(|"
                r"\bSentry\.captureRequestError\b")
LOGGERS = ("pino", "winston", "bunyan", "structlog", "python-json-logger", "loguru", "@logtail/*",
           "@axiomhq/*", "consola", "logtape", "@logtape/*", "tslog", "roarr", "signale")

# A route, not any file called health: api/health(/route.ts), a SvelteKit
# +server, or a top-level health handler.
HEALTH_PATH = (r"(^|/)api/(health|healthz|healthcheck|health-check|livez|readyz|ping)"
               r"(/route\.[cm]?[jt]sx?|/index\.[cm]?[jt]sx?|\.[cm]?[jt]sx?|\.py|/\+server\.[jt]s)$"
               r"|(^|/)(app|routes|src/routes)/(health|healthz|livez|readyz)(/route\.[cm]?[jt]s|/\+server\.[jt]s)$")
# A route definition, not just the string: a monitor script calling
# "/api/health" isn't a health endpoint.
HEALTH_ROUTE = (r"""(?:\.(?:get|route|head|all)|@(?:app|router|bp|api|blueprint)\.(?:get|route|head))\(\s*"""
                r"""["'`](?:/api)?/(?:health|healthz|healthcheck|livez|readyz)["'`]|\bpath\(\s*["']health""")

ALERT_DEPS = ("@pagerduty/*", "pdpyras", "opsgenie-sdk", "@betterstack/*", "checkly", "@checkly/*",
              "@sentry/cli", "cronitor", "healthchecks-io", "@uptime-kuma/*")
# Addresses an alerting service is called at. Words alone ("pagerduty") turn
# up in docs and in tools like this one, so only endpoints count.
ALERT_TEXT = (r"https?://(events\.pagerduty\.com|api\.opsgenie\.com|hc-ping\.com|cronitor\.link|"
              r"uptime\.betterstack\.com|betteruptime\.com|api\.uptimerobot\.com|[\w.-]+\.statuspage\.io)")
ALERT_PATH = (r"(^|/)(checkly\.config\.[jt]s|__checks__/|\.?alerts?/|alertmanager|prometheus/.*rules|"
              r"api/cron/alerts|uptime[^/]*\.ya?ml$|monitor[^/]*\.ya?ml$|watch[^/]*\.ya?ml$|"
              r"grafana/.*alert)")
RUNBOOK_PATH = r"(^|/)[^/]*(runbook|incident|on-?call|postmortem|disaster-recovery)[^/]*\.(md|mdx|txt)$"

ENV_READ = (r"process\.env\.[A-Z_]|process\.env\[|os\.environ|os\.getenv\(|import\.meta\.env\.|"
            r"Deno\.env\.get|env\(\s*['\"][A-Z_]+|ENV\[['\"]")
ENV_EXAMPLE = r"(^|/)(\.env\.(example|sample|template|dist|defaults)|\.env\.[a-z]+\.example|example\.env|env\.example)$"

SCHEMA_PATH = (r"(^|/)(schema\.prisma|drizzle\.config\.[jt]s|alembic\.ini|knexfile\.[jt]s|ormconfig\.|"
               r"models\.py|schema\.sql|supabase/config\.toml|db/schema\.rb)$")
MIGRATION_PATH = (r"(^|/)(prisma/migrations/|migrations?/|drizzle/[^/]+\.sql$|alembic/versions/|"
                  r"supabase/migrations/|db/migrate/|prisma/[^/]+\.sql$|migrate/[^/]+\.sql$)")

DEPLOY_PATH = (r"(^|/)(vercel\.json|netlify\.toml|dockerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml|"
               r"fly\.toml|render\.ya?ml|railway\.(json|toml)|app\.ya?ml|procfile|serverless\.ya?ml|"
               r"wrangler\.(toml|jsonc?)|amplify\.ya?ml|firebase\.json|pulumi\.ya?ml|[^/]+\.tf|"
               r"apprunner\.ya?ml|nixpacks\.toml|zeabur\.json|\.platform\.app\.yaml)$")

TEST_CMD = (r"\b(npm|pnpm|yarn|bun)\s+(run\s+)?test|\bvitest\b|\bjest\b|\bpytest\b|unittest|go\s+test|"
            r"cargo\s+test|mvn\s+.*test|gradlew?\s+.*test|\brspec\b|rails\s+test|phpunit|playwright\s+test|"
            r"make\s+test|\btox\b|\bnox\b|deno\s+test|npm\s+run\s+test:|\bci:test\b")
LINT_CMD = (r"\b(npm|pnpm|yarn|bun)\s+(run\s+)?lint|\beslint\b|ruff(\s+check)?\b|flake8|pylint|biome\s+(check|ci|lint)|"
            r"golangci-lint|next\s+lint|rubocop|\bmypy\b|\btsc\b")
CI_TRIGGERS = r"pull_request|merge_request|\bpush\b|on:\s*\[?\s*push|workflow_call|pipelines?:|stages?:"

LINTER_PATH = (r"(^|/)(eslint\.config\.[cm]?[jt]s|\.eslintrc(\.[a-z]+)?|biome\.jsonc?|ruff\.toml|\.ruff\.toml|"
               r"\.flake8|\.pylintrc|\.golangci\.ya?ml|\.rubocop\.yml|deno\.jsonc?|oxlint[^/]*\.json)$")
FORMATTER_PATH = r"(^|/)(\.prettierrc(\.[a-z]+)?|prettier\.config\.[cm]?[jt]s|biome\.jsonc?|\.editorconfig|rustfmt\.toml)$"

E2E_DEPS = ("@playwright/test", "playwright", "cypress", "puppeteer", "webdriverio", "@wdio/*", "testcafe",
            "nightwatch", "pytest-playwright", "selenium")
COVERAGE = r"--coverage|coverage:|\bc8\b|\bnyc\b|pytest-cov|--cov\b|\.coveragerc|codecov|coveralls|\[tool\.coverage"

FRAMEWORKS = [
    ("next", "Next.js"), ("@remix-run/*", "Remix"), ("@sveltejs/kit", "SvelteKit"), ("nuxt", "Nuxt"),
    ("astro", "Astro"), ("vite", "Vite"), ("react", "React"), ("vue", "Vue"), ("svelte", "Svelte"),
    ("express", "Express"), ("fastify", "Fastify"), ("hono", "Hono"), ("koa", "Koa"), ("@nestjs/core", "NestJS"),
    ("flask", "Flask"), ("django", "Django"), ("fastapi", "FastAPI"), ("streamlit", "Streamlit"),
    ("expo", "Expo"), ("react-native", "React Native"), ("electron", "Electron"),
    ("@prisma/client", "Prisma"), ("drizzle-orm", "Drizzle"), ("@supabase/supabase-js", "Supabase"),
    ("firebase", "Firebase"), ("sqlalchemy", "SQLAlchemy"), ("@clerk/*", "Clerk"), ("stripe", "Stripe"),
]
# Read from paths, dependency names and the README's opening only: these
# names turn up in prose everywhere (this tool's guides among them).
BUILDERS = [
    (r"^dep:lovable-tagger$|lovable\.dev/projects/", "Lovable"), (r"(^|/)\.bolt/", "Bolt"),
    (r"v0\.dev/chat|v0\.app/chat", "v0"), (r"(^|/)\.replit$|(^|/)replit\.nix$", "Replit"),
    (r"(^|/)\.cursor/|(^|/)\.cursorrules$", "Cursor"), (r"(^|/)CLAUDE\.md$|(^|/)\.claude/", "Claude Code"),
    (r"(^|/)\.windsurfrules$", "Windsurf"), (r"(^|/)AGENTS\.md$", "an AI agent (AGENTS.md)"),
]

SERVER_HINTS = (r"(^|/)(app|src/app)/api/|(^|/)pages/api/|(^|/)api/[^/]+\.(py|[jt]s)$|route\.[jt]s$|"
                r"(^|/)netlify/functions/|(^|/)supabase/functions/|(^|/)server\.(js|ts|py)$|(^|/)manage\.py$|"
                r"(^|/)wsgi\.py$|(^|/)app\.py$|(^|/)main\.py$|(^|/)worker\.[jt]s$")
SERVER_DEPS = ("express", "fastify", "hono", "koa", "@nestjs/core", "flask", "django", "fastapi", "next",
               "@remix-run/*", "@sveltejs/kit", "nuxt", "starlette", "aiohttp")

# Copies an editor or a file manager leaves behind: foo.bak, foo.orig, foo~,
# "foo copy.js", "foo (2).js", and folders called old or backup. A file whose
# name merely contains "backup" (restore-backup.js) is real code.
LEFTOVER = r"(\.(bak|orig|old|tmp|swp)$|~$| copy( \d+)?\.\w+$| \(\d+\)\.\w+$|(^|/)(old|backup|backups)/)"
