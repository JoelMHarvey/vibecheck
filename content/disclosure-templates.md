# Disclosure templates

For contacting maintainers in `research/disclosure.jsonl` before publishing
anything. Send these, wait, *then* publish.

## The problem these templates are solving

An unsolicited email saying "your Stripe key is exposed" is, from the
recipient's side, indistinguishable from a scam. Attackers send exactly
this to farm panic clicks. So every template below is built around three
rules:

1. **Verifiable without trusting you.** Give the file path and line so
   they can look in their own repo and confirm it themselves. A scammer
   can't do that, and it's the fastest way to be believed.
2. **No link they must click, no attachment, no login, no deadline
   pressure.** Those are the phishing tells.
3. **No ask.** No reply requested, no "check out my tool", no link-back.
   The moment there's an ask it reads as marketing wearing a safety vest,
   and people discount the warning.

**Never put the credential in the email**, not even partially redacted.
It puts the secret in one more unencrypted mailbox, and a message
containing someone's key reads as a threat no matter how it's worded.

A note on register: these are in sentence case rather than Joel's usual
lowercase. Cold contact with a stranger about a security problem is the
one place where looking slightly formal buys you credibility. Lowercase
them if you'd rather.

---

## 1. Leaked credential in a public repo

**Subject:** Exposed API key in `{{REPO_NAME}}`

> Hi {{NAME}},
>
> I think there's a live {{PROVIDER}} key committed in {{REPO_NAME}}, at
> `{{PATH}}` line {{LINE}}. You can check that file yourself rather than
> take my word for it — I'm a stranger emailing you about a security
> problem, which is also what a scam looks like.
>
> If it is a real key, rotate it at {{PROVIDER}} before anything else.
> Deleting it from the file isn't enough on its own, because it stays in
> the git history and it's likely already been scraped — public repos get
> crawled for keys within minutes.
>
> I found it running a scanner over public repos built with AI coding
> tools, to see how often this happens. I'm writing up the results as
> aggregate numbers only: no repo names, no owners, no paths, no code.
> You won't be identifiable, and I'm not publishing anything before
> {{DATE}}.
>
> Nothing needed from me and no reply necessary — I just didn't want to
> know about this and say nothing.
>
> Joel

---

## 2. Live site serving `.env` or `.git`

More urgent than the above: it needs no git history archaeology, anyone
who requests the path gets the file.

**Subject:** {{DOMAIN}} is serving its .env file publicly

> Hi {{NAME}},
>
> {{DOMAIN}}/.env currently returns your environment file to anyone who
> requests it. You can confirm it in a browser in about five seconds.
>
> Every credential in that file should be treated as compromised and
> rotated — it's been publicly readable for at least as long as the site
> has been up, and paths like that get scanned constantly.
>
> For the fix itself: the file needs to come out of whatever directory
> your host serves as public, and the host configured to refuse dotfiles.
>
> I found it running a scanner over sites built with AI coding tools, for
> a writeup that reports aggregate numbers only — you're not named in it,
> and nothing goes out before {{DATE}}.
>
> No reply needed.
>
> Joel

---

## 3. No email address findable

Use GitHub's private vulnerability reporting — Security tab → "Report a
vulnerability" — if the repo has it enabled. Same content as template 1.

If it isn't enabled, open a **public issue that contains no details**:

> **Title:** Security: please check your email / enable private reporting
>
> I've found what looks like a committed credential in this repo. I'm not
> posting the details publicly, for obvious reasons.
>
> Could you either enable private vulnerability reporting on this repo
> (Settings → Security) or let me know a contact address? Happy to send
> specifics wherever you'd like.

Never put the finding in a public issue. That's not disclosure, that's
publication with extra steps.

---

## 4. One follow-up, then stop

Only if there's been no response after a week and the finding is critical.

**Subject:** Re: Exposed API key in `{{REPO_NAME}}`

> Hi {{NAME}}, just making sure this didn't land in spam — the key at
> `{{PATH}}` in {{REPO_NAME}} was still in the repo last time I looked.
> Worth rotating whenever you get a moment.
>
> That's the last you'll hear from me either way.
>
> Joel

"Still looks live" would be a lie: we never test the credential, so we
cannot know whether it still works — only that it is still in the file.
Say the thing you actually checked.

Then stop. Two messages is diligence; three is harassment. Non-response
isn't consent to publish their details either — the aggregate stats go
out regardless, and they were never going to be named.

---

## 5. The message bounced

A bounce is not a non-response, and it must not be treated as one. Nobody
was told, so the disclosure window has not started for that repo and the
writeup cannot claim they were contacted.

Record it, so the tracker stops saying otherwise and `find_contacts.py`
hands the repo back:

```
python3 scripts/mark_reported.py owner/repo --bounced --on YYYY-MM-DD
```

Then find another route, in the same order as always: GitHub private
vulnerability reporting, a different address in `SECURITY.md`, the
profile email, the commit author email. If nothing works, template 3's
detail-free public issue is the last resort — it asks for a channel
without publishing the finding.

Only when every route has failed is it defensible to publish the
aggregate numbers without having reached that maintainer, and the
sentence claiming everyone was contacted has to come out of the post.

---

## Process notes

**Finding contact details.** In order: `SECURITY.md`, a security address
on the org's site, the GitHub profile email, then the commit author email
from `git log`. Commit emails are published by the person, so using one
for this is reasonable — but don't add anyone to any list, ever.

**Timing.** Send everything, then leave at least 14 days before
publishing. Rotating credentials means finding every deployment that
uses them, which is a weekend job for someone with a life.

**If someone replies angrily.** Some people react badly to being told
this, usually because it's frightening. Answer once, plainly, offer to
answer questions, don't argue, don't get defensive about the tool. Then
leave it.

**If someone asks you to delete what you have.** Do it, and say you have.
`disclosure.jsonl` is a local file; remove their row.

**What never happens.** You do not test the credential. Not to confirm
it's live, not to gauge severity, not once. Reading public code is fine;
using a key found in it is unauthorised access, and "I was checking
whether it worked" is not a defence anywhere.
