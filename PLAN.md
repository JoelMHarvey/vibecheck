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

Bolt, v0, and the leaked-key emergency page followed. The last one is the
highest-intent page on the site — people search it mid-incident, so it's
built as triage rather than an essay: the three actions sit above the
explanation, because a panicking reader may only read one screen.

The Cursor/Claude Code guide completed the set. It needed a different frame
from the app-builder ones: those tools generate code, agents *act* — read
every file, run commands, commit — so the risks are secrets in context,
prompt injection from anything the agent reads, and auto-accept removing the
only human check.

The Firebase page covers the one major database story the others missed.
Its angle is a myth-buster, because that's the search intent: the config in
your HTML is public *by design*, and the reason that's fine is also the
reason Security Rules carry the entire weight. From there it's the specific
rules mistakes — test mode's expiry date and the `if true` fix people reach
for during the resulting outage, `request.auth != null` mistaken for
authorisation, Firestore not cascading into subcollections while Realtime
Database cascades and can't be revoked deeper, Storage being a separate rule
set, and rules not being filters (which is why unconstrained queries fail
and people loosen the rule instead of the query).

**Per-provider pages (done).** Three more, split out of the leaked-key
table, for the searches people actually type at the moment it happens:
Supabase `service_role`, Stripe secret key, OpenAI/Anthropic key. These earn
their place because the *response* differs, not just the dashboard URL —
which is the same doorway-page test the platform guides have to pass.

Supabase: the anon and service_role keys look identical, so the page opens by
decoding the JWT, and half the readers can stop there. Rotation has a real
cost (regenerating the JWT secret signs every user out), and the aftermath is
about data rather than billing. Stripe: money can move, the prefix tells you
whether it's live, rolling has an expiry window that's a genuine trade-off,
Developers → Logs gives a definitive answer about use, and the right
replacement is a restricted key rather than another secret key. OpenAI: it's
a bill and not a breach — past completions aren't retrievable and revoking
costs nothing — so the page spends its length on the cause, which is nearly
always `dangerouslyAllowBrowser` or a `VITE_`-prefixed variable, and on spend
caps as the thing that actually bounds the damage.

Supabase went first because it was the most common real leak in the corpus:
five of the fifteen criticals. Sections 5 of the Supabase and Stripe pages
report where the keys were actually found — migration scripts, deployment
markdown, platform config — anonymised, and it's the part of each page that
couldn't have been written without the research.

Ten pages, fully interlinked. `tests/test_site.py` now asserts the wiring
that used to be four manual edits per page: sitemap entry, dev-server route,
home-page card, canonical matching the filename, no link to a page that
doesn't exist, and at least three outbound links so no page is a dead end.
Adding a guide and forgetting the sitemap was previously silent, and silent
is the whole problem with SEO plumbing. It caught two over-long meta
descriptions on the first run.

Each platform guide should lead with what's genuinely specific to that tool
rather than restating the checklist. Lovable's is Supabase RLS; Bolt's is
that the WebContainer preview makes secrets feel private when they aren't;
v0's is the invisible Next.js server/client boundary and Server Actions
being public endpoints. If a page has no such angle, it's a doorway page
and shouldn't be written.

**v0.5 — GitHub Action (done).** The scanner as a check on every pull
request. Zero-dependency pays off here: no `setup-python`, no install step,
about a second of runner time, and one `uses:` line is the whole setup.

Findings surface four ways because each reaches a different person, and
because the free tiers differ. Inline annotations and the job summary need no
permissions at all. The pull request comment needs `pull-requests: write` and
is updated in place rather than re-posted, so a ten-push branch has one
comment and not ten. SARIF is the fourth, and the most interesting: with it
uploaded, each finding becomes a tracked alert in the Security tab, and
because the fix prompt travels in the SARIF `help` field, the alert page
carries its own paste-ready prompt. That path is gated — code scanning is
free on public repos but needs Advanced Security on private ones — which is
exactly why annotations exist as the ungated fallback rather than SARIF being
the only integration.

Building it forced a gap into the open: vibecheck scanned its own repository
at grade **F**, entirely on its own guides quoting vulnerable code and its own
test fixtures being broken on purpose. That is survivable in a CLI someone
runs by hand and fatal in a CI gate, which gets deleted the first week it
cries wolf. So suppression shipped alongside: `vibecheck-ignore` and
`vibecheck-ignore-next-line` comments (optionally naming a rule), a
`.vibecheckignore` glob file, `--exclude` on the CLI, and an `exclude` action
input. The repo now scores 100/100 on itself with every exclusion documented
and justified in the file — which is the standard to hold users to as well.

Two things needed care. Paths: findings are relative to whatever directory
was scanned, but GitHub resolves annotations from the repository root, so the
prefix is derived by resolving the scan path against `GITHUB_WORKSPACE`
rather than by reusing the input string — an absolute path or a `./web`
otherwise produces a prefix pointing nowhere, and annotations silently land
on files that don't exist. Forks: their tokens are read-only, so a failed
comment is a warning and never a failed build.

**v0.51 — the public split (done).** None of the above reached anyone at
first, because the project lived inside a private personal monorepo and a
private repo's action is only usable inside it. So it got its own home: this
repository, MIT, with the history filtered by `git subtree split` so the
build stays legible commit by commit rather than starting from a squashed
"initial commit". Tagged `v1.0.0` plus a moving `v1`, so
`uses: JoelMHarvey/vibecheck@v1` resolves for a stranger.

Publishing a git history is one-way, so it was audited before rather than
after: all 125 distinct blobs from every commit, scanned both with vibecheck
itself and with a raw credential-shape sweep deliberately independent of its
placeholder filter. No real credentials, nothing belonging to the other
projects in that monorepo, no `.env`, `research/`, `targets.txt` or
`disclosure.jsonl`. The one credential-shaped string in the whole history is
a fake mongodb URI in a test fixture. This `PLAN.md` went public along with
it, pricing ladder and all — a deliberate build-in-public choice.

Vercel now deploys psychosecurity.io from this repository, so there is one
copy of everything and one place to change it.

**v0.52 — corpus collection (done).** `scripts/collect_targets.py` builds
the sample for the writeup. Eight searches, each a different fingerprint
these tools leave behind — the dev dependency Lovable injects, the README
lines Bolt and v0 write — because no single signal finds everything.

The filtering is the part that decides whether the headline number means
anything. Forks, archived repos, vendor repos and anything self-describing as
a template, starter, boilerplate, demo or tutorial are excluded, and the
exclusion counts are printed so the writeup can state what the sample
actually is. Without that, one insecure starter copied a thousand times reads
as a thousand insecure apps, and the whole post is worthless.

**Rule precision over rule coverage.** v0.2 above lists rules to add. The
corpus argues for sharpening the ones that exist first. `innerhtml-assignment`
fired on 82% of 189 repos, which is close to "this app is written in
JavaScript" — a number that large stops being a finding and becomes a fact
about the language, and it sat at the top of the writeup's list of problems
where it could not be defended.

It is now two rules. If the line names a source an attacker chooses — the URL,
a form field, a request, browser storage — that is a demonstrated path from
stranger to page and it stays a finding, retitled to say so. If the value's
origin isn't visible, it is still reported, at low, titled "HTML built from a
variable", which is what the scanner actually knows. Demoted rather than
dropped: a real hole it can't prove is still worth a look, and the same
argument that kept placeholder detection to exact matches applies here.

The split is on evidence rather than a guess about what a variable might
hold, which is why the untrusted-source list is short. Widening it trades
away the precision the split was for.

The writeup's list now carries each finding's severity, because a low at 79%
and a high at 19% mean very different things and an unlabelled list invites
the reader to weigh them the same.

The rescan then showed the split had left the post making an unshowable
claim: the caveat compares the escalated variant to the vague one, and only
the vague one ranks in the top five, so the second half of the comparison
appeared nowhere. Every rule is now addressable by its id —
`{{RULE_INNERHTML_UNTRUSTED_INPUT_PCT}}` — so prose can cite one that didn't
rank. A rule that fired nowhere is 0, because zero is a real answer; a name
that isn't a rule gets no value at all, so a typo fails the run rather than
quietly reading as 0%.

**v0.6 — auto-fix PRs.** Pro-gated: the action opens a branch applying the
mechanical fixes (`.gitignore` entries, moving a key to an env var reference)
and leaves the judgement calls as review comments.

## Launch channels (in order)

1. **Show HN / r/SideProject / r/nocode** with the free CLI + a writeup:
   "I scanned 100 vibe-coded apps; here's what leaked." (Do the scan of
   public repos for real — responsibly, reporting privately first — it's the
   single best content asset possible here.)
   The draft lives at `content/scanned-vibe-coded-apps.md` with every figure
   as a `{{PLACEHOLDER}}`, and `scripts/fill_writeup.py` substitutes them from
   `research/aggregate.json`. Hand-typing eleven numbers out of a JSON file is
   how a transposed digit gets into the one document where a transposed digit
   is the whole problem. The filler refuses to write a post with an unfilled
   placeholder in it, and refuses to write anywhere but the gitignored
   `research/` directory, because the disclosure window may still be open.
   What it can't check is whether anyone was actually contacted — that stays a
   human step, and the header it stamps on the output says so.

   The first real run caught two things the post would otherwise have claimed.
   Supabase anon keys were the fifth most common finding at 17.7% — and an
   anon key is not a finding: it's public by design, and the guide at
   `/guides/supabase-service-role-key-exposed` spends a section telling people
   to stop worrying about it. Listing it under "the most common problems"
   would have contradicted our own advice on our own domain. The filler now
   drops info-severity rules from that list and prints what it dropped, since
   a list that quietly lost an entry reads as the whole picture. Second, the
   top entry is `innerhtml-assignment` at 81.8%, which is a pattern match
   rather than a confirmed hole — the post now says so in its own paragraph
   rather than leaving a reader to point it out.

   Both needed a severity lookup covering every rule the scanner can emit,
   including the three built programmatically. Those lived in a second list
   that only the manifest generator knew about, so `vibecheck/rules.py` now
   exports `ALL_RULES` and both callers read it.

   The next run caught two more, both in the paragraph the ethics of the whole
   project rests on. The post said the high-severity repos "aren't live keys" —
   ten of the sixteen high rules are hardcoded credentials, and the post's own
   fifth-place finding was a Postgres connection string with the password in
   it, three lines above the sentence denying it. And it said "a further 69",
   implying 80 affected projects, when `repos_with_severity` counts a repo once
   per severity it contains: nine repos hold both a critical and a high, so the
   real union is the 71 the disclosure run reported. The sum invents nine
   projects and overstates how many people went uncontacted.

   Both are now stated correctly, and the real reason for the contact
   boundary — eleven done carefully beats seventy-one done badly, which
   `find_contacts.py` already argued in its own docstring — replaces a claim
   that wasn't true. `anonymise()` records `repos_at_or_above_high` so the
   union never has to be derived by addition again, and the filler reads it
   from the scan or counts `disclosure.jsonl`, never by adding.

   `scripts/mark_reported.py` closes the last loop. Private vulnerability
   reporting reached zero of seventy-one repositories, so the contacting
   happens by email, outside any tool — and `prepare_disclosures.py` only
   writes `reported` for advisories it filed through the API. Nothing on disk
   knew the emails had gone out, so `find_contacts.py` would hand back the
   same people, and "did everyone get told?" had no answer except a sent-mail
   folder. It names repositories explicitly rather than offering a
   mark-them-all, because marking a repo reported when nobody was told leaves
   a row that looks finished and ends with a live credential never disclosed.
   A typo aborts the run rather than marking the rest. An already-reported
   repo keeps its first date, since that is when the window started. It ends
   by counting the criticals still unreported and saying, in as many words,
   that the post's claim to have contacted them isn't true yet.

   First real use found a flaw in it immediately: `--from -` spends stdin on
   the repo list, so the confirmation prompt hit EOF and the run refused with
   "nothing written" — safe, unusable, and phrased as though the operator had
   declined. It now asks the terminal directly when stdin is spent, and when
   there is genuinely nobody to ask it says so and names the two ways out
   instead of pretending someone said no.

   `--note` came out of the first replies. Template 4 allows one follow-up
   after a week on a critical with no response, and forbids a third message;
   acting on that needs a record of who answered, which `reported` alone
   doesn't carry. A note lands on an already-reported row without touching
   `reported_on` — restarting a fourteen-day window because somebody said
   thanks would be both absurd and silent — and the day-seven list becomes a
   filter on the tracker rather than a trawl through a sent folder.

   Recording the first replies then exposed a worse bug in the same tool. The
   publication date was `--on + window`, and on an annotate-only run `--on`
   means "when they replied" — so logging an acknowledgement printed a date
   *earlier* than the real one, straight after a run that had printed the
   right one. Two contradicting dates, the wrong one last, on the number the
   whole disclosure window rests on. It now comes from the latest
   `reported_on` in the tracker, which is the actual answer in every mode and
   cannot be made to contradict itself, and the line names the date it
   counted from so the arithmetic is checkable rather than trusted.

   Drafting the one remaining disclosure email exposed a precision problem
   worth more than the email. The URI credential rules match any
   `user:pass@host`, which is also exactly how database documentation writes
   a connection string, and `looks_like_placeholder` only ever tested the
   matched text for substrings like "example" or "your_". In one repository
   that produced twenty-five hits out of README files, deployment guides and
   a `.env.production.example` — one of them inside a `SECRET_PREVENTION.md`,
   a document about not committing secrets — against six from code that runs.
   That rule is the writeup's fifth most common finding at 8.3%, so the
   inflation reached the post as well as the reports.

   The fix tests the password itself, not the path. Path-based demotion was
   considered and rejected once already: the most serious finding in the
   whole corpus was a live Stripe key in a `DEPLOYMENT_SUCCESS.md`, and
   demoting secrets in markdown would have buried it. A value test cuts the
   right way in both directions — `user:password` is an illustration wherever
   it appears, and a real credential in prose still fires.

   Matched whole, never as a substring. "password" is a placeholder;
   "MyPassword2024!" is somebody's credential, and a substring check throws
   the second away — the one error here nobody ever notices.
2. **SEO pages per platform** (done): the seven platform/topic guides plus
   three per-provider "my key is exposed" pages, each ending with the hosted
   scanner.
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
