# The check framework: design note

Plan §0.5. Visibility is the second of at least three checks (security,
visibility, integrity), so the plumbing is built once and each check is a
plugin. The security scan moved onto it with no change in behaviour: its
tests run unchanged (including the browser tests), and the plugin is checked
against the scanner finding for finding.

## Layout

```
vibecheck/core/            shared plumbing
  models.py                Check (the plugin contract), Target, Context, Finding, CheckResult
  fetcher.py               the safe fetcher: SSRF guard on every hop, pinned to the vetted address
  netguard.py, ratelimit.py, cache.py
  walker.py                folder walking with the shared skip rules, redaction, git commit
  scoring.py               category scores, weighted total, grade, badge level
  report.py                terminal / Markdown / JSON for any CheckResult, or several
  registry.py              every check, and which ones a target can satisfy
vibecheck/checks/security/     scanner.py, rules/, urlscan.py, fixtures/, and the plugin in __init__.py
vibecheck/checks/visibility/   scan.py, page.py, rules/, config.py, fixtures/, plugin in __init__.py
```

`vibecheck/scanner.py`, `rules.py`, `urlscan.py`, `netguard.py` and
`ratelimit.py` stay at their old paths as aliases (the same module object, not
a copy), so scripts, the GitHub Action and existing imports keep working.
`report.py`, `sarif.py` and `ghaction.py` are the security scan's original
outputs and stay where they are.

## The contract

```python
class Check(Protocol):
    id: str                  # "security" | "visibility" | "integrity"
    version: str             # semver; bump when scoring changes
    inputs: set[str]         # subset of {"url", "repo"}; any one is enough
    categories: list[Category]   # id, label, weight
    title: str
    def run(self, target: Target, ctx: Context) -> CheckResult: ...
```

`Target` holds a URL, a repo (a local folder, or uploaded files held in
memory) or both, plus the commit SHA when there's a repo (read from `.git`
without running git). `Context` hands a check the fetcher (guarded and
pinned for anything hosted, plain urllib for the CLI, a fake in tests), the
walker, an optional LLM client, a time budget and the provenance of the scan
(`server`, `ci` or `self`, for the badges).

A check also carries the words a report needs (`blurbs` per grade, a
`footer`, and `not_run` for a category it couldn't score), so the renderers
know nothing about any particular check.

## Findings and results

One `Finding` for every check: `id, check_id, category, severity, title,
why_it_matters, evidence, fix_prompt, verify_hint, guide_url`, plus `path`
and `line` for where. Two differences from the plan's list, both deliberate:

- **Severity keeps `info`** beside `pass`. Both checks already report things
  that are worth saying and never scored: security's Supabase anon-key
  reminder, visibility's list of blocked AI crawlers.
- **`path` and `line`** sit beside `evidence`. A code finding without
  `server.js:12` isn't actionable, and the security fix prompts are
  templated on both.

`CheckResult` is `check_id, check_version, target, scanned_at (UTC),
category_scores {id: 0-10 or None}, total (0-100 or None), findings, meta`.
None means "didn't run", never zero: a URL-only security scan doesn't read
code, so Injection is None, and an unreachable site has no total at all (the
old scanner gave it 100).

## Scoring

Category scores are the same everywhere: 10, less 10/4/2/1/0 per
critical/high/medium/low/info finding in it, floored at 0. Visibility's total
is the weighted mean of the categories that ran. **Security's total is still
the Vibe Score** (100 less 25/15/7/3 per finding), so no score and no badge
shifts with the move; its category scores are shown alongside. Badge levels
(gold, silver, bronze) are computed here for every check (plan §0.6).

## Reports

- **CLI**: `python3 -m vibecheck <path-or-url> --checks security,visibility
  [--url URL] [--json [FILE]] [--markdown FILE]`. Exit 1 on any high or
  critical across the selected checks. A check the target can't satisfy is
  skipped with a note. Without `--checks`, a folder runs the security scan
  exactly as before and a URL runs every URL check. `--url` and
  `--visibility` keep working.
- **Web**: `report.js` + `report.css` draw any CheckResult, or several side
  by side, with share links, badge Markdown and Markdown download. The home
  page, `/visibility` and the new combined page `/check` all use it.
  `/api/scan` and `/api/scan-url` return the old shape plus `result`;
  `/api/visibility` returns a CheckResult.
- **Share links**: v2 carries any number of results as facts
  (`[id, severity, path, line, evidence]` per finding) and rehydrates the
  words from each check's manifest (`rules.json`, `visibility-rules.json`).
  v1 links from before the framework still open.

## Adding a check

1. `vibecheck/checks/<id>/__init__.py` with a `CHECK` that satisfies `Check`.
2. Register it in `core/registry.py`.
3. A manifest for share links: add it to `scripts/generate_rules_manifest.py`
   and to `MANIFEST_URLS` in `report.js`.
4. Tests in `tests/test_<id>.py`; fixtures in `checks/<id>/fixtures/`.
