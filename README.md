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

## Development

```bash
python3 -m unittest discover -s tests -v
```

## Roadmap

See [PLAN.md](PLAN.md) — hosted version, deployed-URL scanning, GitHub
Action, and platform-specific guides (Lovable/Bolt/v0) are next.
