# Runbook: psychosecurity.io

For whoever has to fix the site. Written 21 November 2026 from this repo, the
family's infra kit (JoelMHarvey/projects, `infra/`) and the readiness audit of
the same day. Nothing here was checked on the server itself; where a fact can
only be known there, it says "not verified".

## What runs where

| Thing | Where |
|---|---|
| The site | one container on apps-01 (Hetzner), since 7 November 2026: `server/app.py` under gunicorn, two workers, built by the Flask kit (`infra/apps/_flask` in projects, row `psychosecurity` of `apps.tsv`). Not on Vercel |
| Compose project | `/srv/psychosecurity` on the server: the kit's `docker-compose.yml` and a `.env` holding `APP_REF`, the commit that is running |
| Settings and secrets | `/etc/psychosecurity/app.env`, mode 600. The only copy of the signing key outside the backups |
| Front door | the server's one Caddy, `/srv/edge`. It holds the certificate and passes requests to `psychosecurity:8000`. The site file's name, expected to be `sites/psychosecurity.caddy`: not verified |
| Deploys | `.github/workflows/deploy.yml`, on a push to `main` that changes anything other than Markdown or `docs/`. It runs on GitHub's runners and sends the commit's files to `deploy-app` on the server |
| Logs | the container's own (`docker compose logs`), kept to five files of 10 MB; deploys also in `/var/log/deploy.log` |
| Health path | `/api/health/live`. It answers 200 before anything else runs, so it says the process is up and nothing more. It does not check the signing key |
| Database | none. Nothing is stored |
| DNS | GoDaddy, `psychosecurity.io` and `www` |

Nobody is told when the site is down: it is on no watch and has no error
tracker (audit, 21 November 2026). A crashed function prints a traceback to
the container log and nothing else.

## It is down

Check in this order.

1. **From outside.** `curl -sI https://www.psychosecurity.io/` and
   `curl -s https://www.psychosecurity.io/api/health/live`. A healthy site
   answers 200 with `via: 1.1 Caddy`, and the health path answers
   `{"ok":true}`. The bare domain answers 308 to `www`.
   - No answer at all, or a certificate error: the server or Caddy (steps 2
     and 5).
   - 502 from Caddy: the container (steps 3 and 4).
   - Pages load but reports say "unsigned", or `/api/vibechecked` answers
     503: the signing key is missing ("Restore `/etc/psychosecurity`" below).
2. **Was it a deploy?** GitHub, Actions, "deploy": the last run and its
   summary. A deploy that does not come up healthy within three minutes puts
   the previous version back by itself and the job fails, so a red run
   usually means the old version is still serving.
3. **The container.** On the server, as `ops`:

   ```bash
   cd /srv/psychosecurity
   sudo docker compose ps                         # app should be "running (healthy)"
   sudo docker compose logs --tail 200 app        # tracebacks, and the start-up warnings
   sudo tail -n 30 /var/log/deploy.log
   ```

   At start the app prints `psychosecurity: VIBECHECK_SIGNING_KEY is not set`
   or `psychosecurity: no KV store` when those settings are absent. It
   refuses to start at all if `VIBECHECK_RATE_LIMIT_OFF` is set beside
   `VIBECHECK_DEPLOYED=1`, or if `vercel.json` has gained a setting
   `server/app.py` does not implement.
4. **Ask it directly, past Caddy.** The app listens on the host's loopback,
   port 8000 unless `APP_LOOPBACK` in `/srv/psychosecurity/.env` says
   otherwise (which port it has: not verified):

   ```bash
   curl -s http://127.0.0.1:8000/api/health/live
   ```

   200 here and nothing from outside means Caddy or DNS, not the app.
5. **Caddy.** `cd /srv/edge && sudo docker compose ps` and
   `sudo docker compose logs --tail 100 caddy`. Caddy renews the certificate
   by itself; the one seen on 21 November 2026 runs to 5 February 2027.
6. **Restart it.** `cd /srv/psychosecurity && sudo docker compose up -d --wait app`.
   Nothing is lost by a restart: there is no database. Without a KV store the
   rate-limit counters and the daily spending caps start again from zero.
7. **Redeploy.** GitHub, Actions, "deploy", "Run workflow" on `main`. If the
   server already runs that commit it says so and changes nothing.

If only the visibility check is failing, look at the Anthropic and Serper
accounts first: a key over its spending limit or revoked shows as errors in
the container log while the rest of the site works. The exact wording of
those errors: not verified.

## Roll back a deploy

A failed deploy rolls itself back (step 2 above). To go back from a deploy
that came up healthy but is wrong, either:

- **On GitHub:** revert the commit on `main`. The revert is a push to `main`,
  so it deploys. This is the usual way, and it keeps `main` and the server
  the same.
- **On the server,** when it cannot wait for a build:

  ```bash
  cd /srv/psychosecurity
  sudo docker images psychosecurity-app          # the newest three are kept
  sudo grep '^APP_REF=' .env                     # what runs now
  # set APP_REF in .env to the earlier tag (12 characters of the commit), then:
  sudo docker compose up -d --wait app
  ```

  The next push to `main` deploys `main` again, so revert the commit there
  as well or the fault comes back.

There are no migrations and no stored data, so a rollback has nothing to undo
beyond the code.

## Restore `/etc/psychosecurity`

There is no database to restore. What has to survive is
`/etc/psychosecurity/app.env`: lose the signing key in it and every report
and badge already issued stops verifying. The folder is in the server's
nightly settings backup (`etc/psychosecurity` in
`infra/apps/_postgres/settings.list`): one encrypted tar at 02:55 UTC to the
backup bucket at Hetzner, copied to Cloudflare R2 at 04:30 UTC. It opens with
`BACKUP_CIPHER_PASS`, which is in the password manager. A dated test restore
of this folder: none on record (audit, 21 November 2026).

**The file is lost or damaged, the server is fine.** Fetch the backup to a
scratch folder and take only this app's folder out of it. Do not run
`settings-restore apply` on a live server: it unpacks every app's settings
over the current ones.

```bash
cd /srv/db
sudo bin/settings-restore list                       # what is in the bucket
sudo bin/settings-restore fetch /root/settings       # newest; add a name for an older one
sudo tar -C / --numeric-owner -xpzf /root/settings/settings.tar.gz etc/psychosecurity
sudo shred -u /root/settings/settings.tar.gz
cd /srv/psychosecurity && sudo docker compose up -d --force-recreate --wait app
```

`fetch` lists the tar's paths with owners and modes and prints no file's
contents. That the paths inside the tar begin `etc/psychosecurity/` follows
from `settings-backup`, which tars the paths in `settings.list` relative to
`/`; check it against what `fetch` lists before unpacking.

**The whole server is gone.** `infra/PROVIDER-EXIT.md` in projects, which
restores every app's settings with `settings-restore apply` on the new
server, then builds each app.

**Afterwards, check the key came back.** `curl -s
https://www.psychosecurity.io/.well-known/vibecheck-key` should list a key
with `"status": "current"` and the same `kid` as before (`PjQttDIDJCQIAcXo`
on 21 November 2026; a key id is public). Then open a badge or report issued
before the loss: it should say "verified". A different `kid` means a
different key is in the file, and older badges and reports will show as
signed with a key the site does not publish ("unknown key" below).

**If no backup holds the key,** it cannot be rebuilt. Make a new one
("Rotate the signing key", without the old public key unless it can still be
read from a saved copy of `/.well-known/vibecheck-key` or from the "x"
printed when the key was made). With the old public key in
`VIBECHECK_OLD_PUBLIC_KEYS`, old badges go on verifying. Without it, every
badge and report issued before then reads "unknown key" until its owner
scans again.

## Rotate each key

Every setting lives in `/etc/psychosecurity/app.env` on apps-01 unless it
says otherwise. Two rules for all of them:

- The container reads the file only when it is created, so after an edit run
  `cd /srv/psychosecurity && sudo docker compose up -d --force-recreate --wait app`.
  A plain `restart` keeps the old values.
- Then send the changed file to the backup at once:
  `sudo systemctl start db-backup-settings`.

Nothing here signs anyone out: the site has no accounts and no sessions.
Which of these settings are present on the server today: not verified (the
audit could not read the file).

### `VIBECHECK_SIGNING_KEY` (the Ed25519 key that signs reports and badges)

Issued by nobody: made with `scripts/make_signing_key.py`. It has no expiry.
Rotate it if it may have been read by someone else, not on a schedule.

1. Note the current public key: `curl -s
   https://www.psychosecurity.io/.well-known/vibecheck-key`, the `x` of the
   key with `"status": "current"`.
2. On a laptop, in a checkout of this repo: `python3
   scripts/make_signing_key.py`. It prints the new secret line, the new
   public key and its key id. Do not paste the secret anywhere but the
   server's file.
3. In `app.env`: add the old `x` to `VIBECHECK_OLD_PUBLIC_KEYS`
   (comma-separated if there is one there already), and replace
   `VIBECHECK_SIGNING_KEY` with the new line.
4. Recreate the container and start the settings backup (the two rules
   above).
5. Check: `/.well-known/vibecheck-key` lists the new key as `current` and the
   old one as `retired`; a fresh scan on the site is signed with the new
   `kid` and says "verified"; a badge from before the rotation still says
   "verified".

What it breaks:

- Done as above, nothing. Reports and badges signed with the old key verify
  for as long as its public key stays in `VIBECHECK_OLD_PUBLIC_KEYS`. Badges
  expire 30 days after their scan, so keep the old key there at least 30
  days.
- Leave the old public key out, and every report and badge issued before the
  rotation reads "unknown key". That is the right choice only when the old
  secret has leaked and badges forged with it must stop verifying. It cannot
  be done for some badges and not others: there is no revocation list.
- `/.well-known/vibecheck-key` is served with a one-hour cache
  (`api/key.py`), so a browser that fetched the list just before the
  rotation may not know the new key for up to an hour. Whether the report
  page then falls back to `/api/verify` in that case: not verified.
- With the setting empty or absent the site still works, but everything goes
  out unsigned and `/api/vibechecked` answers 503.

### `VIBECHECK_OLD_PUBLIC_KEYS`

Not a secret: retired public keys, comma-separated. Remove one only when
nothing signed with it should verify any more.

### `ANTHROPIC_API_KEY`

Pays for the positioning review and the AI-answer probe on
`/api/visibility`. Issued in the Anthropic Console (API keys). Which account
or workspace the current key belongs to, and whether it has an expiry: not
verified.

1. Create a new key in the console.
2. Replace the line in `app.env`, recreate the container, start the settings
   backup.
3. Run a visibility check on the site with a product name, and see the
   positioning review come back.
4. Only then delete the old key in the console.

What it breaks: nothing if done in that order. With the key absent the site
skips the review and the probe and the rest of the visibility check still
runs (`api/visibility.py`). A key revoked before the new one is in place
makes those calls fail until step 2; how the page words that: not verified.
The daily caps (`PROBE_DAILY_CAP`, `POSITIONING_DAILY_CAP`) are counted per
worker and start again when the container is recreated, unless a KV store is
set.

### `SERPER_API_KEY`

Pays for the plain Google searches behind the off-site footprint. Issued in
the Serper dashboard (serper.dev). Which account: not verified.

Same four steps as the Anthropic key. With the key absent the footprint is
done by two more Claude calls instead (`api/visibility.py`), so the check
still works and costs a little more.

### `KV_REST_API_TOKEN` or `UPSTASH_REDIS_REST_TOKEN` (with their `_URL`)

The token for the shared rate-limit store and 24-hour cache, an Upstash Redis
REST store. Whether either is set on apps-01: not verified, and it is an open
question for Joel (it also decides what the privacy page may say). If it is
set: issue a new token in the Upstash console, replace the line, recreate the
container, start the settings backup. During a gap, or with a wrong token,
the ordinary limits fail open (requests are let through uncounted); the two
daily spending caps fail closed, so the paid checks stop until the store
answers again (`api/visibility.py`).

### `DEPLOY_SSH_KEY` (not read by the app)

A secret of this GitHub repository, set 7 November 2026, no expiry. It is the
private half of a key whose line in `ops`'s `authorized_keys` on apps-01 may
run `deploy-app` for `psychosecurity` and nothing else. To rotate: make a new
key pair on the Mac, add its public half to `authorized_keys` with the same
restricted command, set the secret with `gh secret set DEPLOY_SSH_KEY`,
delete the key files, remove the old line on the server, and run "deploy" by
hand to prove it. The exact line is in projects,
`infra/deploy/README.md` ("One-time setup" and "Other repos"). It breaks
nothing that is running; a wrong key only makes the next deploy fail.

### Not secrets

`VIBECHECK_DEPLOYED=1` (must stay), `VIBECHECK_PROBE_MODEL`,
`PROBE_DAILY_CAP`, `POSITIONING_DAILY_CAP`. `VIBECHECK_RATE_LIMIT_OFF` must
never be set on the server: the app refuses to start with it.

## Dates to know

| What | When |
|---|---|
| TLS certificate | 5 February 2027; Caddy renews it |
| Domain at GoDaddy | 9 August 2027 |
| Signed badges | 30 days after each scan |
| Signing key, `DEPLOY_SSH_KEY` | no expiry |
| Anthropic and Serper keys | not verified |
