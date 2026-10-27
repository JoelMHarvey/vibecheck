# Badges: design note

Plan §0.6. A badge is only worth having if it can be checked. Each rule from
the plan, and where it lives.

| Rule | How |
| --- | --- |
| Every badge links to its report | `badge.badge_markdown`: the image links to `/report#r=<signed report>`. `/report` is the verify page. |
| Signed | Ed25519. `core/ed25519.py` is a standard-library implementation checked against RFC 8032's vectors and byte for byte against `cryptography`; the server signs with `cryptography` (constant-time, in `requirements.txt`) and the CLI never signs. The public key is at `/.well-known/vibecheck-key`, derived from the signing key so the two can't drift. Browsers verify with WebCrypto, falling back to `/api/verify`. |
| Dated and expiring | Claims carry `scanned_at` and `expires_at` (30 days). The badge endpoint goes grey ("expired · rescan") from then; the report page says the badge has expired. |
| Pinned to what was scanned | URL checks record the address the home page ended up at after redirects; repo checks record the commit (read from `.git`, walking up from a subfolder) and the badge says "commit abc1234". An upload has neither, so it gets a signed report and no badge. |
| Earned by thresholds | `scoring.badge_level`: gold 85+ with no critical or high open, silver 70+ with no critical, bronze 50+ with no critical. |
| Self-scan is labelled | Only scans run on psychosecurity.io are signed. `vibecheck --badge` from a laptop gives "self-reported"; inside GitHub Actions it gives "CI run" and the report links to the run. An unsigned claim that says our server ran it shows "unsigned". |
| Storing nothing | The badge URL carries its signed claim (`/badge/<check>.svg?r=`), the report link carries the signed report in the fragment. Nothing is written anywhere. Badges can't be revoked early; they expire. |
| Combined badge | `/api/vibechecked` takes the signed reports, checks they're ours, for the same site (www and bare count as one), every check that applies, none expired, each bronze or above, and signs a "vibechecked" badge at the lowest of their levels. `/check` offers it when it qualifies. |

## What's signed

```
envelope = {"p": <canonical JSON claim>, "sig": <base64url Ed25519>, "kid": <key id>}
signature over:  "vibecheck/report/1\n" + p     (a report)
                 "vibecheck/badge/1\n"  + p     (a badge)
```

The prefixes stop a report signature passing as a badge one. Canonical JSON
is sorted keys, no spaces, ASCII only, and verifiers check the bytes of `p` as
received before parsing it, so there's no re-serialisation for the two sides
to disagree on.

A report claim is the result's facts: check and version, target, times,
total, category scores, level, meta, provenance, and each finding as
`[id, severity, path, line, evidence]`. The words (why it matters, the fix
prompt) are rebuilt from the check's manifest, which is the same for everyone,
so signing the facts covers what a reader relies on. A badge claim is the
summary plus the SHA-256 of the report it was issued with.

## Links

- Report: `/report#r=z<base64url(gzip({"v":3,"e":[envelope, ...]}))>`. v1 and v2
  links (unsigned, from before) still open, without a "verified" line.
- Badge: `/badge/<security|visibility|vibechecked>.svg?r=<base64url(envelope)>`,
  about 600 characters.
- The old `/api/badge?score=94` keeps working, drawn exactly as before.

## Before this goes live

1. `python3 scripts/make_signing_key.py`, then set `VIBECHECK_SIGNING_KEY`
   in Vercel (Production, sensitive). Without it everything still works and
   says "unsigned"; `/api/vibechecked` answers 503.
2. Check `/.well-known/vibecheck-key` shows the key, and that
   `/badge/visibility.svg?r=...` from a fresh scan renders.
3. To rotate later: put the old public key in `VIBECHECK_OLD_PUBLIC_KEYS`
   so reports signed with it still verify, then set the new secret.

## Left open

A CI badge says which run produced it, and the run's log is public, but we
don't sign it: the runner has no key of ours. GitHub Actions can prove a run
to a server with an OIDC token; an `/api/attest` that checks the token and
signs the run's result would make CI badges verifiable the way server ones
are. Not built yet.
