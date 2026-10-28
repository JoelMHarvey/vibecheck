# vibecheck 🔒✨

[![ci](https://github.com/JoelMHarvey/vibecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/JoelMHarvey/vibecheck/actions/workflows/ci.yml)
[![vibe score](https://www.psychosecurity.io/api/badge?score=100)](https://www.psychosecurity.io)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Security scanner for AI-built apps.** You vibe-coded it — now make sure it
won't leak your keys, your database, or your users' data.

Try it without installing anything at **[psychosecurity.io](https://www.psychosecurity.io)**.

vibecheck scans a project folder for the security mistakes AI app builders
make most often, then explains each one in plain English and gives you a
**fix prompt you can paste straight back into Cursor, Claude Code, Lovable,
Bolt, or v0** to have it fixed for you.

No dependencies. Pure Python standard library. Your code never leaves your
machine.

## Quick start

```bash
git clone https://github.com/JoelMHarvey/vibecheck
cd vibecheck
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

## Is anyone finding it? (visibility)

A third mode checks how a deployed site looks to search engines and to AI
assistants like ChatGPT, Claude and Perplexity. Try it at
**[psychosecurity.io/visibility](https://www.psychosecurity.io/visibility)** or:

```bash
vibecheck --visibility https://myapp.com
vibecheck --visibility https://myapp.com --markdown report.md
vibecheck --visibility https://myapp.com --json        # JSON to stdout
```

It reads robots.txt, the sitemap, llms.txt, the home page and up to 20 more
pages, and reports on: text missing from the raw HTML (the blank page most
Lovable, Bolt and Vite apps serve to crawlers), robots.txt blocks, sitemap
gaps and stale dates, titles and descriptions, H1s, link previews, sections
that only exist as `#fragments`, www against bare, HTTP against HTTPS,
redirect chains, structured data (Organization, Offer, FAQPage), llms.txt,
alt text, heavy images and trust details. Which AI crawlers you block is
reported, never scored.

Each finding says why it matters, gives a fix prompt and says how to check
the fix worked. Scores run 0 to 10 in six categories (Technical, AI
readiness, Content & keywords, Positioning, Off-site, Brand clarity) plus a
weighted total; phase 1 fills the first three. Weights and limits live in
`vibecheck/checks/visibility/config.py`. Exit code is 1 on any high or critical.

### The positioning review

`--positioning` adds one call to Claude (Haiku) about the home page's copy: can
a stranger tell what it is and who it's for, is there a price, a reason to
pick it over a named alternative, social proof, one main call to action, and
how many audiences the page is talking to. Each miss comes with a fix prompt
that rewrites the copy. It fills the Positioning category.

```bash
pip install anthropic
ANTHROPIC_API_KEY=... vibecheck --visibility https://myapp.com --positioning
```

The key is yours and stays on your machine. The page is treated as untrusted:
a criterion only counts as met when the review quotes the page and the quote is
really there, so copy that tells the reviewer to mark it perfect gets nowhere.
On psychosecurity.io the review runs on the server when it has a key, cached
for a week by a hash of the copy, under a daily cap.

The hosted crawl identifies itself as
`vibecheck-visibility/1.0 (+https://psychosecurity.io/visibility)`, obeys
robots.txt, vets every request and redirect against private addresses and
connects only to the address it vetted. It allows 10 scans an hour per visitor
and one a minute per site, and keeps results for 24 hours. Design notes:
[`docs/visibility-design.md`](docs/visibility-design.md).

### Would an AI recommend you?

```bash
ANTHROPIC_API_KEY=... vibecheck --visibility https://groomly.com \
  --brand Groomly --category "booking software for dog groomers" \
  --competitor Fresha --competitor Gingr --country GB
```

Asks Claude, with web search on, five questions a buyer would ask about your
category without naming you, and reports how often it names you, cites your
site, and names your competitors instead, with what it actually said. Then it
searches for you off your own site and on Product Hunt, AlternativeTo, G2,
Capterra, Crunchbase and Reddit, and lists where you're missing with where to
sign up and a description to paste. The answers are a snapshot: they vary from
run to run.

The questions go to Claude Haiku 5.5 with up to two searches each, a few
pence a run on your key; `--probe-model claude-opus-5-5` (or
`VIBECHECK_PROBE_MODEL`) asks a larger model instead. With `SERPER_API_KEY`
set, the directory searches are seven plain Google searches through
[Serper](https://serper.dev) instead of two more Claude calls.
`scripts/compare_probe_models.py` runs the questions on two models side by
side.

## Integrity: is it well built and looked after?

```bash
vibecheck ./app --checks integrity                 # one check
vibecheck ./app --checks security,integrity        # both, one exit code
vibecheck ./app --checks integrity --badge         # badge Markdown (CI-attested in GitHub Actions)
ANTHROPIC_API_KEY=... vibecheck ./app --architecture   # plus a model's read of the boundary code
```

Reads the repository, never uploads it, and scores six categories:
observability (error tracking started, a health route, structured logs),
alerting (an uptime monitor or alert rule, a runbook), how it was built
(lockfile, migrations, `.env.example`), tests (present and run by CI on every
pull request, end-to-end), code quality (linter, formatter, TypeScript
`strict`, very long or branchy functions, duplication) and tech debt
(TODO density, huge files, leftover copies). It rewards what's wired up, not
how much there is. `--architecture` adds an opt-in read by Claude of the code
at the boundaries (routes, webhooks, auth, database clients), sent redacted
and capped on your own key; every problem it reports must quote a real line,
or it's dropped. Design notes: [`docs/integrity-design.md`](docs/integrity-design.md).

## Several checks, one report

Security and visibility run on one framework (`vibecheck/core`, see
[`docs/framework-design.md`](docs/framework-design.md)), so you can run them
together and get one report and one exit code:

```bash
vibecheck https://myapp.com                                   # every check that takes a URL
vibecheck ./app --url https://myapp.com --checks security,visibility
vibecheck ./app --checks security --json                      # the common result model, to stdout
```

On the web, [psychosecurity.io/check](https://www.psychosecurity.io/check) runs
both against a live site side by side.

## Badges you can check

A scan run on psychosecurity.io is signed (Ed25519), so its badge can be
verified: the badge links to the report, and the report page checks the
signature against the key at `/.well-known/vibecheck-key` and says
**verified** or **tampered**. Levels need a score and nothing serious open:
gold is 85+ with no critical or high findings, silver 70+ with no criticals,
bronze 50+ with no criticals. Badges show the scan date and go grey after 30
days. A site badge pins the address scanned, a code badge the commit.
`vibecheck --badge` prints badges for your README; from your own machine they
say "self-reported", from GitHub Actions "CI run". Nothing is stored: the
signed report travels in the link. Details in
[`docs/badges-design.md`](docs/badges-design.md).

## Usage

```bash
vibecheck .                          # scan current directory
vibecheck --url https://myapp.com    # scan a deployed site instead
vibecheck . --markdown report.md     # also write a shareable Markdown report
vibecheck . --json report.json       # machine-readable output
vibecheck . --min-severity medium    # hide low/info noise
vibecheck . --exclude tests --exclude 'docs/*'   # skip paths (repeatable)
vibecheck . --fail-on critical       # CI mode: exit 1 only on criticals
vibecheck . --fail-on never          # always exit 0
```

Default exit code is `1` if anything **high or critical** is found — drop it
into CI or a pre-commit hook as-is.

## GitHub Action

Scan every pull request, comment the findings on it, and annotate the diff:

```yaml
# .github/workflows/vibecheck.yml
name: vibecheck
on: [pull_request]

permissions:
  contents: read
  pull-requests: write   # only needed for the PR comment

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: JoelMHarvey/vibecheck@v1
```

That's the whole setup. There's no `setup-python` step and nothing to
install — vibecheck is pure standard library, so it runs on the runner's own
interpreter in about a second.

Findings surface four ways, because each one reaches a different person:

| Where | Needs |
|---|---|
| **Inline annotations** on the diff | nothing |
| **Job summary** — the full report with fix prompts | nothing |
| **PR comment**, updated in place on each push | `pull-requests: write` |
| **Security tab / code scanning alerts** | `sarif-file` + upload step |

### Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to scan, relative to the repository root |
| `fail-on` | `high` | Fail the job at or above this severity; `never` to never fail |
| `min-severity` | `info` | Hide findings below this severity |
| `exclude` | — | Globs to skip, one per line or comma-separated |
| `comment` | `true` | Post/update the pull request comment |
| `summary` | `true` | Write the job summary |
| `sarif-file` | — | Write SARIF here for code scanning upload |
| `json-file` | — | Write a JSON report here |
| `token` | `github.token` | Token used for the comment |

Outputs: `score`, `grade`, `findings`, `critical`, `high`, `medium`, `low`,
`info`, `sarif-file`.

### Code scanning

With SARIF uploaded, each finding becomes a tracked alert in the Security
tab — and because the fix prompt travels in the SARIF `help` field, the alert
page carries its own paste-ready prompt.

```yaml
      - uses: JoelMHarvey/vibecheck@v1
        with:
          sarif-file: vibecheck.sarif
          fail-on: never          # let code scanning own the gate
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibecheck.sarif
```

That needs `security-events: write`. Code scanning is free on public
repositories and requires GitHub Advanced Security on private ones — the
inline annotations work either way, which is why they aren't gated behind it.

**Informational findings are left out of SARIF.** GitHub renders code scanning
alerts as inline review comments, so a zero-point finding — a credential in a
test fixture — would arrive as a comment telling the author to rotate a key
that was never real. They still appear in the job summary, the PR comment and
the JSON report; only the alert queue is reserved for things that are alerts.

### Notes

- **Forks.** A pull request from a fork gets a read-only token, so the
  comment step is skipped with a warning rather than failing the build.
- **Gating a monorepo.** Point `path` at one project; annotation and comment
  paths are rewritten to be repository-relative so they line up with the diff.
- **Pinning.** `@v1` tracks the latest v1.x. Pin a full SHA if you'd rather
  nothing move under you.

## Silencing false positives

Some of this happens on its own.

**Findings in test paths are demoted to info** — `__tests__/`, `tests/`,
`fixtures/`, `*.test.*`, `*.spec.*`, `*.snap` and friends. Nothing in a test
file ships, so nothing in one is a live exposure, and info scores zero points.
Demoted rather than dropped: silently discarding is how a scanner misses the
one real key somebody did commit in a test.

**Private keys quoted in prose are demoted to low** — `.md`, `docs/`, `blog/`,
`examples/`. The private-key rule matches the PEM header alone, with no key
material and no entropy, so every tutorial and worked example that quotes one
trips it. This applies to *that rule only*: a Stripe or Supabase key keeps
full severity in a markdown file, because pasting real credentials into a
`DEPLOYMENT.md` is a thing people genuinely do.

Vendored trees (`third_party/`, `Pods/`, `bower_components/`, `.yarn/`) are
skipped outright, like `node_modules`.

For everything else there's manual suppression, because a scanner you can't
quiet is a scanner people turn off, and some code is insecure on purpose —
worked examples in documentation, a rule table that describes the very thing
it detects.

**One line**, with a comment. The rule id is optional; without it the whole
line goes quiet:

```js
const q = `SELECT * FROM t WHERE id = ${id}`;  // vibecheck-ignore: sql-string-building

// vibecheck-ignore-next-line
const client = new OpenAI({ dangerouslyAllowBrowser: true });
```

**Whole paths**, with `.vibecheckignore` at the project root — globs, one per
line, `#` for comments:

```
guides/          # our own worked examples of bad code
tests/           # fixtures are broken on purpose
*.test.js
```

Or `--exclude GLOB` on the command line (repeatable), or the `exclude` input
on the action. Both combine with the ignore file rather than replacing it.

This repository has its own [`.vibecheckignore`](.vibecheckignore), and every
entry in it says why. That's the standard worth holding: if a line is there
to hide a real finding, fix the finding instead.

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
[![Vibe Score](https://www.psychosecurity.io/api/badge?score=94)](https://www.psychosecurity.io)
```

## Research harness

Two scripts produce the data behind the writeup in `content/`: one builds
the sample, the other scans it and emits **anonymised** aggregates.

```bash
python3 scripts/collect_targets.py --limit 200 > targets.txt
python3 scripts/research_scan.py targets.txt --out research/
```

`collect_targets.py` searches GitHub (via your `gh` auth) for the
fingerprints these tools leave behind — the dev dependency Lovable injects,
the README lines Bolt and v0 write. All of them are code searches, on
purpose: searching descriptions for "lovable.dev" finds repos that *mention*
Lovable, which is a different set entirely, full of prompt directories and
Lovable downloaders.

Two filters keep the sample honest, because the number the writeup rests on
is "how many were clean". By name: forks, archived repos, vendor repos and
anything self-describing as a template, starter, demo, tutorial, prompt
collection or MCP server. Structurally, at scan time: a repository with no
application source at all is excluded, because a pile of markdown scans
perfectly clean and a few of those quietly turn a real finding into a
comfortable one. Both counts are reported so the writeup can describe its own
sample.

`research_scan.py` writes three files. `aggregate.json` is safe to publish: counts,
percentages and score distribution, with no repo names, paths, excerpts
or secrets. `disclosure.jsonl` is **private** (mode 0600, gitignored) and
exists so you can notify people whose credentials are exposed.
`scanned.jsonl` is the resume log — also private, for the same reason.

Progress is written per repo rather than at the end, so an interrupted run
picks up where it stopped. Re-run the same command to resume; pass
`--restart` to scan everything again. No single repository can end a run
either: a clone that fails, times out, or trips over a non-UTF-8 path is
recorded as a failure and the scan moves on, with the reasons counted in
`aggregate.json` so the writeup can describe its own sample honestly.

### Disclosing what you find

`prepare_disclosures.py` turns `research/disclosure.jsonl` into one draft per
repository, then files them as GitHub private security advisories:

```bash
python3 scripts/prepare_disclosures.py                        # write drafts, read them
python3 scripts/prepare_disclosures.py --submit --yes --limit 1   # try one
python3 scripts/prepare_disclosures.py --submit --yes          # file the rest
```

Do the `--limit 1` run first. One real report tells you whether your `gh` auth
and the endpoint work; without it you spend seventy attempts finding out. A run
also stops itself after three consecutive errors, because a systemic problem
fails identically on every repository and grinding through the rest just makes
seventy pointless requests against strangers' repos.

Advisories rather than email, because an unsolicited message about a leaked
key is indistinguishable from the scam that farms panic clicks — a report
inside the repository is not, and it timestamps the disclosure.

**Expect most of them to bounce.** Private reporting is off by default and
has to be switched on; in the first real run it reached 0 of 71 repositories.
So `find_contacts.py` works out how else to reach the ones it missed:

```bash
python3 scripts/find_contacts.py                  # criticals (the default)
python3 scripts/find_contacts.py --severity high  # widen it
```

It tries `SECURITY.md`, then a public profile email, then a commit author
address, and falls back to "open a public issue with no details" only when
there's nothing else — that route is visible, and seventy of them in an
afternoon reads as spam to GitHub's abuse detection. `@users.noreply` is
recorded and marked unusable rather than quietly dropped, so a repo with no
route says so instead of looking unexamined. Output is `contacts.csv`, mode
0600, in the same gitignored directory.

It defaults to criticals because that is what the rule above actually says.
Fifteen repositories is a person-sized amount of careful work; seventy-one is
the number that produces a rushed job or no job at all. Repos with
private reporting turned off come back as failures in `tracker.csv`, and
template 3 in `content/disclosure-templates.md` covers those. Nothing is sent
without `--yes`, a repo already marked reported is never contacted twice, and
no draft ever contains a credential.

The rules it's built around, which are worth following whether or not you
use this script: never test a credential you find — reading public code
is fine, using a key is unauthorised access. Disclose privately and leave
time to rotate before publishing. Publish aggregates only; a specific
enough anecdote identifies someone as surely as a name does.

## Development

```bash
python3 -m unittest discover -s tests -v   # 264 tests

python3 scripts/devserver.py               # run the hosted site locally
python3 scripts/generate_rules_manifest.py # after editing rules.py
```

The browser tests need Playwright (`pip install playwright`); they use
the Chromium already on the image and skip themselves if none is found.

**If you change `rules.py`, regenerate `rules.json`** — a test fails if
the two drift, because shared links read their descriptions from it.

## Roadmap

See [PLAN.md](PLAN.md). The hosted site, deployed-URL scanning, the guides
and the GitHub Action have all shipped; auto-fix pull requests are next.
