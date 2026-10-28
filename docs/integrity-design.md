# Integrity check: design note

The third check on the framework (plan §7, phase A). Security asks "is it
safe?", visibility "is anyone finding it?"; integrity asks "is it well built
and looked after?": would you hear about a failure, could you fix it
quickly, and does anything stop a bad change going out.

## Where it runs

Repo-based: a live URL can't show tests or code quality. It runs where the
code already is, the CLI and CI (`vibecheck ./app --checks integrity`), and
never uploads anything. So its reports are self-reported or, in GitHub
Actions, CI-attested; psychosecurity.io never signs them, and the combined
"vibechecked" badge only requires checks the server can sign
(`IntegrityCheck.hosted = False`, `registry.hosted_for`). With a URL as
well, it checks the live health route and looks for a status page link.

## Layout

| File | What it holds |
| --- | --- |
| `checks/integrity/repo.py` | One walk (the shared walker, so `.vibecheckignore` applies): every path, the text of manifests, configs, CI files and source, npm and Python dependency names. |
| `checks/integrity/patterns.py` | The pattern tables: SDKs, endpoints, paths and commands that count as evidence. Data only. |
| `checks/integrity/signals.py` | The signals, one function per category. |
| `checks/integrity/code.py` | Function length and branch count (Python via `ast`, JS/TS by brace matching), duplicated blocks. |
| `checks/integrity/rules.py` | Categories, rule prose and fix prompts, pass titles; `integrity-rules.json` is generated from it. |

## Signals (phase A, deterministic)

| Category | Weight | Signals |
| --- | --- | --- |
| Observability | 0.20 | error tracker installed *and* started (`Sentry.init`, `registerOTel`, ...); structured logger; a health route; source maps not published; live: health answers, status page linked |
| Alerting | 0.15 | an uptime monitor, alert rule or paging integration (by dependency, config path, or an alerting endpoint in code or CI); a runbook |
| How it was built | 0.15 | stack and builder (Lovable, Bolt, v0, Claude Code ...); `.env.example` when code reads env; migrations when there's a schema; a lockfile; no `*`/`latest` versions; deploy config (info) |
| Tests | 0.25 | tests exist; CI runs them on pull requests or pushes (directly or through a package script); end-to-end tests for web apps; coverage configured (info); few tests for the size (low) |
| Code quality | 0.15 | linter, formatter, lint in CI, TypeScript `strict` (following a local `extends`), very long or very branchy functions, duplicated blocks |
| Tech debt | 0.10 | TODO/FIXME density, very large files, leftover copies (`.bak`, `foo copy.js`, `old/`) |

Server-only signals (health route, structured logging, alerting, runbook)
apply only when the repo has server code: API routes, a server framework, a
`server.js`. A static site isn't asked for a pager.

## Scoring

The shared penalties (critical 10, high 4, medium 2, low 1, info 0 per
category). It rewards presence and wiring, not volume: test counts and line
counts are easy to inflate with generated code, so "few tests" is low. The
absences that matter most are severe on purpose: no tests at all is
critical (no badge at any level), no error tracking or alerting is high (no
gold). A quick AI build with none of these scores in the 40s.

## False positives, and how they're kept down

- Words aren't evidence. "Sentry", "PagerDuty" and "Lovable" turn up in
  docs, guides and tools like this one, so trackers must be *started*
  (`Sentry.init(`), alerting needs an endpoint or config, builders are read
  from paths, dependency names and the README's opening only, and every code
  grep reads source files, not tests or docs.
- A health endpoint is a route (`api/health/route.ts`, `app.get('/healthz')`),
  not any file called `health.ts`.
- `restore-backup.js` is code; `billing.ts.bak` and `billing copy.ts` are
  leftovers.
- Tried on vibecheck itself and six of the family's repos before shipping;
  the false positives found that way are the ones fixed above.

## Not in phase A

Dependency age and known-vulnerable versions (needs a registry or OSV lookup,
which sends dependency names off the machine, so it'll be opt-in); dead-file
detection by import graph; the browser upload; phase B, a short model-written
architecture read of the repo, capped and cached like the visibility
positioning review.
