<!--
DRAFT — NOT PUBLISHABLE YET.

Every {{PLACEHOLDER}} below must be replaced with real output from
scripts/research_scan.py before this goes anywhere. Do not estimate,
guess, or "round to a nice number". The entire credibility of the piece
rests on the numbers being real, and a security post with invented
statistics is worse than no post.

Order of operations:
  1. build a target list of public AI-built repos
  2. python3 scripts/research_scan.py targets.txt --out research/
  3. fill the placeholders from research/aggregate.json
  4. contact everyone in research/disclosure.jsonl — templates and the
     process notes are in content/disclosure-templates.md — and leave at
     least 14 days for people to rotate
  5. publish
-->

# i scanned {{N_REPOS}} vibe-coded apps. here's what leaked.

a few weeks ago i watched someone ship a working saas app in an afternoon. no
code written by hand, just prompting. it was genuinely impressive. then i opened
devtools and their Stripe key was sitting in the page source.

i wanted to know how common that was, so i built a scanner and pointed it at
{{N_REPOS}} public repos built with Lovable, Bolt, v0, Cursor and Claude Code.

## what i found

{{PCT_ANY_CRITICAL}}% had at least one critical problem — a live credential,
mostly. {{PCT_ANY_HIGH}}% had at least one high-severity one. the median score
was {{MEDIAN_SCORE}} out of 100, and {{PCT_CLEAN}}% were completely clean.

the most common problems, by share of apps affected:

- {{RULE_1_PCT}}% — {{RULE_1_NAME}}
- {{RULE_2_PCT}}% — {{RULE_2_NAME}}
- {{RULE_3_PCT}}% — {{RULE_3_NAME}}
- {{RULE_4_PCT}}% — {{RULE_4_NAME}}
- {{RULE_5_PCT}}% — {{RULE_5_NAME}}

a caveat on that list, because the top of it is the number people will push
back on: these are pattern matches, not confirmed exploits. the scanner can see
that HTML is being built out of a variable. it cannot see whether that variable
ever holds someone else's input, and in plenty of these apps it won't. the
credential figures above are the ones i'd defend one at a time. this list is
prevalence, which is the weaker claim.

i also left something out of it on purpose. Supabase anon keys turned up in a
lot of these apps, and that is not a finding — the anon key is meant to be
public, it's in the page source of every Supabase app by design, and the only
thing it tells you is that Row Level Security is now load-bearing. the scanner
grades it as information rather than a problem. putting it in a list titled
"the most common problems" would have inflated the numbers with something i
spend a whole page telling people not to panic about.

<!--
Optional: one anonymised example here. Be careful. A specific enough
story identifies the repo even without naming it — if the detail is
unusual, cut it or blur it. Never quote code. Never show a key, even
partially redacted.
-->

## why it happens

none of this is because the people building these apps are careless. it's
structural.

an AI builder optimises for the thing you asked for, which is an app that works.
nobody prompts "and make sure the Supabase service_role key isn't in the client
bundle", because if you knew to ask that, you'd have known not to do it. the
model gives you working code. working and safe are different targets.

the second thing is that a lot of these mistakes look identical to correct code
until you know one specific fact. `dangerouslyAllowBrowser: true` makes the error
message go away, and the app starts working, and the flag is doing exactly what
it says on the tin — shipping your API key to every visitor. the name is a
warning that only means something if you already understand it.

underneath most of what i found are two ideas:

browser code cannot keep a secret. anything in the frontend — hardcoded, or in a
`NEXT_PUBLIC_` variable, or inside an SDK running client-side — is public. not
"probably fine", not "obscure enough". public.

and deleting a leaked key doesn't un-leak it. it's in your git history, someone's
cache, a scraper's database. the only fix is rotating it.

## what i did about the ones i found

i didn't test a single credential. finding a key in public code is reading; using
it to check whether it works is unauthorised access, and the fact that someone
left the door open isn't an invitation.

{{N_ANY_CRITICAL}} repos had something critical: a committed private key, a
Supabase service_role key, an LLM key being shipped to the browser, or — in one
case — a live Stripe key. those are the ones where the worst case is someone
else's money or someone else's entire database. i contacted those maintainers privately and gave them
time to rotate before publishing this.

{{N_ANY_HIGH}} had at least one high-severity finding, and i want to be straight
about what that covers: plenty of them are live credentials too — database
connection strings with the password in them, API keys for paid services. it
isn't a tier of harmless stuff. i didn't contact those maintainers individually,
and the reason isn't that it doesn't matter. it's that {{N_ANY_CRITICAL}} of these
done properly is an evening's work, and {{N_DISCLOSED}} done properly doesn't
happen at all — you get a rushed job or no job. i'd rather do the smaller
number carefully.
that's a judgement call about where one person's time goes, and you're welcome
to think it's the wrong one.

(those two figures overlap, by the way — a repo can have both, and some do. it
isn't {{N_ANY_CRITICAL}} plus {{N_ANY_HIGH}} separate projects.)

the numbers above are aggregates — no repo names, no owners, no file paths, no
code. people published their code, not their consent to be made an example of.

if you'd rather not be in a future version of this post, the scanner is below.

## the tool

it's called vibecheck. you point it at a folder or a URL and it tells you what's
wrong in plain english, then gives you a prompt to paste back into whatever AI
tool you're using, so the thing that made the mess can clean it up.

free, no signup: [psychosecurity.io](https://psychosecurity.io)

there's a CLI too if you'd rather nothing left your machine — same scanner, runs
offline, no dependencies.

```
python3 -m vibecheck .
python3 -m vibecheck --url https://myapp.com
```

## caveats, because this is a security post

the scanner looks for known patterns. a clean score means it didn't find those
patterns, not that your app is secure — it doesn't understand your auth logic or
your database rules, and it never will.

i started from {{N_ATTEMPTED}} candidate repos and scanned {{N_REPOS}} of them.
{{N_EXCLUDED}} were dropped for having no application code in them at all —
prompt collections and link lists, mostly, which score perfectly and mean
nothing. a further {{N_FAILED}} couldn't be cloned. that second number is a
hole rather than a filter: those were probably real apps and i have no idea
what was in them.

the sample is public repos, which is a biased slice. people who commit their app
to a public GitHub repo are probably not identical to people who ship on Lovable
and never export the code. i'd guess the real numbers are worse, since a public
repo is at least somewhat considered, but i can't prove that.

and i'm not neutral here. i built the tool that produced these numbers, and the
numbers are an advert for it. the code is open, the rules are readable, and the
method's above — check it if you like.

---

*i'm Joel. i build small tools, mostly in the evenings. this one came out of
watching a friend nearly ship their Stripe key to production.*
