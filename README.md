# vibecheck 🔒✨

**Security scanner for AI-built apps.** You vibe-coded it — now make sure it
won't leak your keys, your database, or your users' data.

vibecheck scans a project folder for the security mistakes AI app builders
make most often, then explains each one in plain English and gives you a
**fix prompt you can paste straight back into Cursor, Claude Code, Lovable,
Bolt, or v0** to have it fixed for you.

No dependencies. Pure Python standard library. Your code never leaves your
machine.

## Quick start

```bash
# from this directory
python3 -m vibecheck /path/to/your/app

# or install it as a command
pip install -e .
vibecheck /path/to/your/app
```

## What it looks like

```
  vibecheck v0.1 — /Users/you/my-saas
  214 files scanned

  VIBE SCORE: 45/100 (grade D)   — 1 critical, 2 high, 1 medium
  Serious problems. Fix the critical/high items before anything else.

  CRITICAL ────────────────────────────────────────────

  ✗ Stripe LIVE secret key exposed   server.js:12
     const stripe = require("stripe")("sk_liv…[redacted]");
     This is a LIVE Stripe secret key. Anyone who has it can create charges,
     issue refunds, and read customer data on your real Stripe account.
     Fix prompt (paste into your AI coding tool):
       "A live Stripe secret key is hardcoded in server.js on line 12. Move all
       Stripe API calls to server-side code that reads the key from an
       environment variable named STRIPE_SECRET_KEY, ..."
```

## What it checks (v0.1)

**Leaked secrets** — Anthropic, OpenAI, Stripe (live vs test), AWS, Google,
GitHub, Slack, and Telegram keys/tokens; private key files; MongoDB/Postgres
connection strings with embedded passwords; hardcoded JWTs and passwords.
Secrets found in browser-served files are escalated, because a key in
frontend code is a key every visitor has. Matched secrets are always
redacted in reports.

**Supabase-aware** — hardcoded JWTs get their payload decoded: a
`service_role` key (bypasses all Row Level Security) is flagged **critical**,
while an `anon` key produces an informational reminder to verify RLS.

**Vibe-coding architecture mistakes** — `dangerouslyAllowBrowser: true`,
LLM APIs called directly from frontend code, secrets stored in
`VITE_`/`NEXT_PUBLIC_`/`REACT_APP_` variables (which compile into the public
bundle), `.env` files not covered by `.gitignore`.

**Classic web vulnerabilities** — SQL built by string interpolation, shell
commands built from variables, `innerHTML`/XSS patterns, `eval()`, CORS open
to every origin, debug mode left on, TLS verification disabled.

**Sensible about false positives** — placeholder values (`your-key-here`,
`sk-ant-xxxx…`) are ignored; secrets *inside* a gitignored `.env` file are
fine (that's where they belong); `node_modules`, lockfiles, minified bundles
and binary files are skipped.

## Scan a deployed site (no source code needed)

Point vibecheck at a live URL and it checks the things that leak from a
running app regardless of how it was built:

```bash
vibecheck --url https://myapp.com
```

It looks for a publicly readable `.env` / `.git` / AWS credentials file,
published JavaScript **source maps** (which reconstruct your original
code), missing security headers (HSTS, CSP, `X-Content-Type-Options`,
`X-Frame-Options`), `Access-Control-Allow-Origin: *`, plain-HTTP serving,
and sensitive paths advertised in `robots.txt`. Same scoring, same
copy-paste fix prompts.

## Usage

```bash
vibecheck .                          # scan current directory
vibecheck --url https://myapp.com    # scan a deployed site instead
vibecheck . --markdown report.md     # also write a shareable Markdown report
vibecheck . --json report.json       # machine-readable output
vibecheck . --min-severity medium    # hide low/info noise
vibecheck . --fail-on critical       # CI mode: exit 1 only on criticals
vibecheck . --fail-on never          # always exit 0
```

Default exit code is `1` if anything **high or critical** is found — drop it
into CI or a pre-commit hook as-is.

## The Vibe Score

Every project starts at 100. Findings subtract points by severity
(critical −25, high −15, medium −7, low −3). 90+ is an A. Below 40 means
**do not launch yet**.

## Two rules of thumb vibecheck enforces

1. **Browser code cannot keep a secret.** If a key ships to the frontend —
   hardcoded, via a `NEXT_PUBLIC_` variable, or through an SDK running in
   the browser — every visitor has it.
2. **Deleting a leaked key does not un-leak it.** Every fix prompt for an
   exposed credential ends with a reminder to *rotate* it at the provider.

## The hosted version

`index.html` plus the `api/` functions are the psychosecurity.io site:
drag in a folder or paste a live URL, get the same report in the browser.

**Share links carry the report inside the URL.** Clicking "Copy share
link" compresses the findings into the URL fragment — which browsers
never send to a server — so a shared report is readable by anyone with
the link and stored by nobody. The long prose is rehydrated client-side
from `rules.json`, keeping a typical link around 700 characters.

### Rate limiting

Both endpoints cost money per call, and `/api/scan-url` makes outbound
requests from your servers to a URL a stranger chose — so both are rate
limited per IP (`/api/scan`: 10/min, 60/hour; `/api/scan-url`: 3/min,
15/hour, plus a 300/hour global ceiling on outbound scanning).

By default counters live in memory, per serverless instance — best-effort,
but it stops one client hammering one endpoint with zero setup. For exact
limits across instances, add Vercel KV to the project; the limiter detects
`KV_REST_API_URL` / `KV_REST_API_TOKEN` and switches to it automatically,
with no code change and no dependency to install. If the store ever fails,
the limiter fails **open** — a broken limiter must not break the product.

Set `VIBECHECK_RATE_LIMIT_OFF=1` for local development. Never in production.

There's also a score badge for READMEs:

```markdown
[![Vibe Score](https://psychosecurity.io/api/badge?score=94)](https://psychosecurity.io)
```

## Research harness

`scripts/research_scan.py` scans a corpus of public repos and produces
**anonymised** aggregate statistics — the data behind the writeup in
`content/`.

```bash
python3 scripts/research_scan.py targets.txt --out research/
```

It writes two files. `aggregate.json` is safe to publish: counts,
percentages and score distribution, with no repo names, paths, excerpts
or secrets. `disclosure.jsonl` is **private** (mode 0600, gitignored) and
exists so you can notify people whose credentials are exposed.

The rules it's built around, which are worth following whether or not you
use this script: never test a credential you find — reading public code
is fine, using a key is unauthorised access. Disclose privately and leave
time to rotate before publishing. Publish aggregates only; a specific
enough anecdote identifies someone as surely as a name does.

## Development

```bash
python3 -m unittest discover -s tests -v   # 66 tests

python3 scripts/devserver.py               # run the hosted site locally
python3 scripts/generate_rules_manifest.py # after editing rules.py
```

The browser tests need Playwright (`pip install playwright`); they use
the Chromium already on the image and skip themselves if none is found.

**If you change `rules.py`, regenerate `rules.json`** — a test fails if
the two drift, because shared links read their descriptions from it.

## Roadmap

See [PLAN.md](PLAN.md) — hosted version, deployed-URL scanning, GitHub
Action, and platform-specific guides (Lovable/Bolt/v0) are next.
