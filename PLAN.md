# vibecheck — business & build plan

*The pitch: "You vibe-coded your app. Now vibecheck it before someone else
does." A security scanner built for AI app builders, not security engineers —
plain English, a score, and fix prompts you paste back into your AI tool.*

## Why this wins

- **Real, documented pain.** Exposed API keys, missing auth, and open
  Supabase tables are the best-known failure mode of AI-generated apps.
  Stories of five-figure surprise API bills from leaked keys circulate
  constantly in the Lovable/Bolt/Cursor communities.
- **The differentiator is the output format.** gitleaks and trufflehog exist,
  but they speak CVE and entropy — to developers. vibecheck speaks to someone
  who has never heard of RLS: *what happened, why it matters, and the exact
  prompt to paste into your AI builder to fix it.* The fix prompt IS the
  product.
- **The audience self-identifies and congregates** (X, r/nocode,
  r/lovable, Discords), and searches predictable phrases ("is my Lovable app
  safe", "Bolt app security") that almost nobody is writing content for yet.

## Product ladder (free → paid)

| Tier | What | Price |
|---|---|---|
| Free CLI (this repo) | Local scan, full ruleset, Vibe Score | $0 — distribution & trust |
| Hosted scan | Paste a GitHub repo URL or drag a zip → shareable report card | Free (lead gen), 3 scans/mo |
| Pro | Unlimited scans, deployed-URL scanning, GitHub App with PR checks, re-scan alerts | $19/mo |
| Teams/agency | Multiple projects, client-ready white-label PDF reports | $49–99/mo |

The Vibe Score badge ("Vibe Score: 94 🔒 — vibecheck.dev") is the viral loop:
builders who pass want to show it off, and every badge is an ad.

## Roadmap

**v0.1 — this repo (done).** Python CLI, ~25 rules, severity scoring,
terminal/Markdown/JSON reports, fix prompts, zero dependencies.

**v0.2 — sharpen the rules (1–2 weeks).** Run against real vibe-coded repos
scraped from GitHub ("built with lovable/bolt" topics), tune false
positives, add rules for: Firebase config abuse, open Supabase storage
buckets, missing rate limiting on API routes, webhook signature verification.

**v0.3 — hosted version (2–4 weeks).** Next.js front end + this scanner
behind an API. GitHub OAuth → pick a repo → report card at a shareable URL.
This is the SEO/distribution engine.

**v0.4 — deployed-URL scanner (done, CLI).** `vibecheck --url https://site`
checks for exposed `/.env` `/.git` and AWS-credentials files, published
source maps, missing security headers, open CORS, plain-HTTP serving, and
`robots.txt` leaking admin paths. No repo access needed — zero-friction top
of funnel ("free website security check"). Next: expose it in the hosted UI
as a URL box alongside the folder drop (server-side fetch via the existing
Python function).

**v0.45 — share links + badge (done).** "Copy share link" compresses the
report into the URL fragment, so a shared report costs no storage, needs no
account, and never reaches a server — the privacy story ("we literally
cannot read your report") is itself a selling point against future
competitors. `/api/badge?score=N` renders the Vibe Score badge for READMEs.
Both halves of the viral loop are live; what's missing is a reason to click
through, which is the next item.

**v0.46 — rate limiting (done).** Shipped before promoting the site, because
both endpoints are unauthenticated compute and `/api/scan-url` fans out ~8
outbound requests to a caller-chosen host from our IPs. Per-IP windows plus a
global outbound ceiling; in-memory by default, auto-upgrading to Vercel KV if
present. Also removes an obvious line of attack on the product's credibility:
vibecheck's own fix prompts tell users to rate limit their API routes.

**v0.47 — distribution basics (done).** Social preview card, so a shared
report link renders as a card instead of a naked URL — it had to be generic,
because reports live in the URL fragment and no unfurler can see one. Plus
the first two SEO guides (the head-term checklist and the Lovable page),
`sitemap.xml`, `robots.txt`, and internal linking. These are what a shared
link or a search result lands on; without them the viral loop had nowhere
to point.

The Bolt guide followed. Remaining content, in rough priority: v0,
Cursor/Claude Code, then "my API key leaked, what now" — the highest-intent
search of the lot, because it's what people type at the exact moment they
need the tool.

Each platform guide should lead with what's genuinely specific to that tool
rather than restating the checklist. Lovable's is Supabase RLS; Bolt's is
that the WebContainer preview makes secrets feel private when they aren't.
If a page has no such angle, it's a doorway page and shouldn't be written.

**v0.5 — GitHub Action + PR bot.** `vibecheck` as a check on every push;
Pro-gated auto-fix PRs.

## Launch channels (in order)

1. **Show HN / r/SideProject / r/nocode** with the free CLI + a writeup:
   "I scanned 100 vibe-coded apps; here's what leaked." (Do the scan of
   public repos for real — responsibly, reporting privately first — it's the
   single best content asset possible here.)
2. **SEO pages per platform**: "Lovable app security checklist",
   "Is my Bolt app secure?", "Cursor security best practices" — each ends
   with the hosted scanner.
3. **X/Twitter build-in-public** thread series; the report screenshots are
   inherently shareable.
4. **Community presence**: answer every "my key leaked" post in Lovable/Bolt
   Discords with genuine help + the tool.

## Honest risks

- **Platforms absorb the feature** (Lovable already added a security scan).
  Mitigation: stay cross-platform — builders use 2–3 tools per project, and
  the scanner that works on *the whole repo regardless of origin* remains
  useful. The deployed-URL scanner is fully platform-independent.
- **False-positive fatigue.** A scanner that cries wolf gets uninstalled.
  Bias rules toward precision; keep noisy checks at low/info.
- **"Passive" income isn't.** Rules need maintenance as key formats and
  frameworks change. Budget ~2–4 hrs/week post-launch.

## North-star metric

Shared report URLs per week — it captures both usage and the viral loop.
