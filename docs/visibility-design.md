# Visibility mode: design note

"Is anyone finding it?" is a third mode beside "Scan my code" and "Scan a live
site". It checks how a site looks to search engines and AI crawlers, and gives
every finding the same three parts the security scan does: why it matters, a
fix prompt to paste back into the AI tool, and how to check the fix worked.

This note maps the build plan (`VISIBILITY_PLAN.md`, phase 1) onto what the
repository already has.

## The question the plan said to stop on

> Stop and report if the live fetcher runs in the browser.

It doesn't. "Scan a live site" posts the URL to `api/scan-url.py`, a Vercel
Python function, and every request goes out from there through
`vibecheck.netguard`. The visibility crawl follows the same route
(`api/visibility.py`), so CORS never comes into it.

## What is reused, and what is new

| Plan item | Existing piece | What changes |
| --- | --- | --- |
| Finding model | `scanner.Finding` (rule id, severity, title, path, excerpt, description, fix prompt) | Used as is. A finding's `path` is the page path and its `excerpt` is the evidence. Category, "how to check it worked" and the guide link come from the rule table (`visibility/rules.py`), keyed by rule id, so `Finding` keeps its shape. |
| Passes | none (the security scan reports only problems) | New `Pass` (check id, evidence). The acceptance list asks for passes ("llms.txt present (pass)"), and a visibility report that only lists faults hides what a site already does right. |
| Live fetcher | `urlscan.build_guarded_fetcher` | A new fetcher in `visibility/fetch.py`: it needs the redirect chain (the hosts checks read it), a 2 MB cap, HEAD requests for image sizes and its own user agent. It vets every hop with `netguard`, as the old one does, and goes further: it connects to the address it vetted, so a DNS answer that changes between the check and the connect (rebinding) can't reach a private network. |
| SSRF guard | `netguard.check_url` | New `netguard.vet_url`, which returns the vetted address as well. `check_url` is unchanged. |
| Rate limit | `ratelimit.RateLimiter` | Two new limiters: 10 scans an hour per IP, one a minute per target host. Same memory/KV backends. |
| 24-hour cache | none | `visibility/cache.py`: memory, or Vercel KV / Upstash when its env vars are set, the same switch the limiter uses. Keyed by normalised URL. What's cached is a public site's own HTML, read the way any crawler reads it; nothing a visitor sends is kept. A `fresh` flag skips the cache (still behind the per-host limit), so someone checking a fix isn't shown yesterday's result. |
| Share link | `index.html` `encodeReport` (gzip + base64url in the fragment) and `rules.json` | Same scheme on `/visibility`. Prose comes from `visibility-rules.json`, built by `scripts/generate_rules_manifest.py` and checked by the manifest test, like `rules.json`. Fix prompts may use `{excerpt}` as well as `{path}`, so a prompt can name the hosts or sections it's about. |
| Score badge | `api/badge.py` | Takes `label=visibility`, chosen from a fixed list, so caller text still never reaches the SVG. |
| Markdown export | `report.render_markdown` | `visibility/report.py` renders terminal, Markdown and JSON in the same style, plus the six category scores and the passes. |
| CLI | `python3 -m vibecheck` | `--visibility URL`. `--json` with no file prints JSON to stdout. Default exit code is still 1 on any high or critical. Like `--url`, the CLI does not apply the SSRF guard: checking your own staging box is a fair use of a tool on your own machine. |

## Where it runs

`/visibility` is its own page (`visibility.html`), not only a third tab on the
home page. That is the plan's own advice: one URL can only rank once, and the
crawler's user agent, `vibecheck-visibility/1.0 (+https://psychosecurity.io/visibility)`,
needs a page at that address saying what the bot is. The home page gets a
third tab that links to it.

## Crawl

1. Normalise the input to an origin; the home page is `/`. A path the user
   typed is crawled too.
2. Fetch `/robots.txt`. If it blocks our user agent from `/`, report that and
   go no further than the crawl files. The block for Googlebot and Bingbot is
   a separate, critical finding.
3. Fetch the home page, `/sitemap.xml` (and any sitemap `robots.txt` names,
   one level of sitemap index) and `/llms.txt`.
4. Up to 20 more pages on the same host: sitemap URLs first, then links found
   on the pages crawled so far. Robots rules are honoured for each.
5. Then the side checks: the other host form (www or bare), `http://`, the
   Open Graph image, and HEAD requests for up to 12 images.

Six requests in flight at most, a 10 s timeout on each, and an overall budget
of 40 s; the function's `maxDuration` is 60 s. A page that doesn't come back in
time is left out and the report says how many were crawled.

Two kinds of page aren't judged as content. Sign-in, sign-up and other
account screens (`config.APP_PATHS`: login, sign-in, sign-up, register,
forgot, reset, auth, sso, oauth, callback, with or without a language prefix)
aren't crawled at all: a login form drawn in the browser is normal and
nothing needs it to rank. Pages marked noindex (meta robots or googlebot, or
an X-Robots-Tag header) are fetched, their links followed, and then left out
of every page check. A noindex home page is the exception, and critical
(`home-noindex`).

An SPA host often answers every path with `index.html`. An HTML answer to
`/robots.txt`, `/sitemap.xml` or `/llms.txt` counts as missing, the same rule
`urlscan` uses for `/.env`.

## Checks and categories

Each rule belongs to one category. Phase 1 fills three:

- **Technical**: raw-HTML rendering, robots.txt, sitemap, canonical, lang,
  viewport, www vs bare, HTTPS, redirect chains, oversized images.
- **AI readiness**: llms.txt, AI crawler access (reported, never scored),
  JSON-LD, Organization, Offer, FAQPage, machine-readable data.
- **Content & keywords**: title, description, H1, heading order, Open Graph,
  fragment-only sections, internal links, alt text, trust signals.

Positioning is filled by phase 2 (below) when it runs. Off-site and Brand
clarity show "run the deeper check" until phases 3 and 4 exist.

Findings that would repeat page by page (a missing description on twelve
pages) are one finding naming the pages, so the list stays readable.

## Scoring

All in `visibility/config.py`: a category starts at 10 and loses points per
finding (critical 10, high 4, medium 2, low 1, info 0), floored at 0. The total
is the weighted mean of the categories that ran, scaled to 0–100, with the
security scan's grade letters. The report says how many categories it's based
on.

## Phase 1 acceptance, against robinofloxley.com

Recorded responses live in `tests/fixtures/robinofloxley.json.gz`
(`scripts/record_visibility_fixture.py` re-records them) and
`tests/test_visibility_fixture.py` replays them and checks:

- fragment-only app sections (`fragment-sections`)
- sitemap has 4 URLs against the pages found (`sitemap-incomplete`); since
  noindex pages are left out of the content checks this one no longer
  fires: the fifth page, /brand, is noindex, so the sitemap is right
- home lastmod older than the content (`sitemap-lastmod-stale`)
- bare vs www mismatch for myowntrader.com and myownlingo.com between the page
  and llms.txt (`external-host-mixed`)
- llms.txt present, server-rendered, Open Graph complete (passes)

The full result is snapshotted, so a change to any check shows as a diff.
Synthetic fixtures cover a fresh Lovable build (expects the client-side
rendering finding), `Disallow: /` (expects critical) and a private address
(expects refusal).

## Phase 2: the positioning review

`checks/visibility/positioning.py`. After the crawl, the home page's copy
(title, description, H1, the first 1,500 words of raw-HTML text, and lines
that mention prices, from a pricing page too if one was crawled) goes to
Claude Haiku with a fixed rubric and a JSON schema
(`output_config.format`), output capped at 4,000 tokens. It answers five
criteria (who and what, price, differentiator, social proof, one primary call
to action), each with `met`, a verbatim `quote` and a one-line `note`, plus
the list of audiences the page addresses.

- **Grounding.** The page is untrusted input and a signed badge rides on the
  score, so `ground()` counts a criterion as met only when its quote (6+
  characters, compared case- and space-insensitively) is in the copy. A
  missing or invented quote is a miss, and the note says why.
- **Price.** When phase 1 already saw a price on the home page, that wins over
  the model.
- **Findings.** Each miss is a positioning finding whose `{excerpt}` is the
  reviewer's note, so the fix prompt carries what was wrong. Three or more
  audiences is `positioning-audience-sprawl`. The category is scored like any
  other: 10 less the usual penalties.
- **Where it runs.** The check takes a reviewer from `Context.llm`; with none,
  nothing changes. `/api/visibility` builds one when `ANTHROPIC_API_KEY` is
  set: `CachingReviewer` (7 days, keyed by a hash of the copy, rubric version
  and model) around `ClaudeReviewer`, whose daily cap
  (`POSITIONING_DAILY_CAP`, default 1,000) is checked only when a call is
  about to be made, so cached reviews cost nothing against it. The CLI runs it
  with `--positioning` and the user's own key.
- **When it can't run** (no copy in the raw HTML, over the cap, refused, API
  down) the category stays unscored and `meta.positioning` says why; the
  report shows it and the rest of the scan is untouched.

## Not in phase 1 or 2

The AI-answer probe (phase 3), off-site
footprint (phase 4) and suite mode. Rank tracking, backlinks and keyword
volumes are out of scope; the report points to Google Search Console.
