# Releasing vibecheck

One repository ships three things, and they are released differently.

| What | How people get it | When a change reaches them |
|---|---|---|
| The hosted site, psychosecurity.io | they visit it | on every merge to `main` that changes anything other than Markdown or `docs/` (see [`RUNBOOK.md`](RUNBOOK.md)) |
| The GitHub Action | `uses: JoelMHarvey/vibecheck@v1` in their workflow | only when the `v1` tag is moved |
| The scanner as a package | `pip install git+https://github.com/JoelMHarvey/vibecheck@<ref>` | when the ref they pinned moves: a tag, or `main` if they follow it |

So merging to `main` releases the site and nothing else. The Action and the
package reach people only through tags, and a tag moves only when someone
moves it by hand. Nothing in CI cuts a release.

## Where things stand

The list of releases is on the repository's
[releases page](https://github.com/JoelMHarvey/vibecheck/releases); this
file does not repeat it, so it cannot fall behind.

- `v1` points at the newest `v1.x.y`. The first release, `v1.0.0`, was
  16 August 2026; `v1` then stood still until 22 November 2026, through a
  security fix, which is why the checks below exist.
- The version in the code matches the newest tag: `pyproject.toml` and
  `vibecheck/__init__.py`. `--version` and reports print it with the
  commit, for example `1.2.0+0111204`, and the hosted site's reports and
  its `/api/health` do the same.
- Two weekly jobs in `ci.yml` watch the tag: `published-tag` runs the
  Action from `v1`, and `tag-drift` fails when `v1` is behind `main` for
  the scanner or the Action.

## The tags

- `vMAJOR.MINOR.PATCH` (for example `v1.1.0`) names one commit and never
  moves. Pin this for a result that can be reproduced.
- `v1` is the moving tag the README tells people to use. It always points at
  the newest `v1.x.y`. Moving it changes what runs in other people's
  pipelines on their next job, with no action on their part. Treat it as a
  deploy to every user.

## When to release

- **A security fix in the Action or the scanner: the same day.** A fix that
  sits on `main` protects nobody who runs `@v1`. Cut a patch release and move
  `v1`.
- **A new or changed rule, a changed score, a new input or output:** a minor
  release, when the change is one users should have. A rule that changes
  scores can turn a passing pipeline red, so say so in the release notes.
- **Site-only changes** (pages, guides, `api/`, `server/`): no release. The
  merge is the release.
- **A breaking change** (an input removed or renamed, an output that changes
  meaning, a higher minimum Python): a new major. Tag `v2.0.0`, create `v2`,
  and leave `v1` where it is.

## How to release

Only the maintainer does this. Tags are pushed from a clean checkout of
`main`.

1. **Check `main` is green.** The `ci` workflow must have passed on the commit
   you are about to tag: the tests on three operating systems, the run with
   Chromium, and the self-scan.

   ```bash
   git checkout main && git pull
   python3 -m unittest discover -s tests
   python3 -m vibecheck .
   ```

2. **Set the version** to the one you are about to tag, in both places, in a
   pull request of its own:

   - `pyproject.toml`: `version = "1.1.0"`
   - `vibecheck/__init__.py`: `__version__ = "1.1.0"`

   Merge it and wait for `ci`. This merge also deploys the site, which then
   prints the new version in its reports.

3. **Tag that commit** and push the tag:

   ```bash
   git pull
   git tag -a v1.1.0 -m "v1.1.0"
   git push origin v1.1.0
   ```

4. **Try the tag before moving `v1`.** In a scratch repository, run the Action
   at the exact tag (`uses: JoelMHarvey/vibecheck@v1.1.0`) on a pull request,
   and install the package from it:

   ```bash
   pip install "git+https://github.com/JoelMHarvey/vibecheck@v1.1.0"
   vibecheck --version
   ```

   CI tests the Action from the working tree (`uses: ./`), never from a tag,
   so this is the only test of what users will run.

5. **Move `v1`:**

   ```bash
   git tag -f -a v1 -m "v1 -> v1.1.0" 'v1.1.0^{}'
   git push --force origin v1
   ```

   The `^{}` makes `v1` point at the commit. Without it `v1` would be a
   tag of a tag.

   This is the one forced push the repository allows. Never force any other
   tag.

6. **Publish a GitHub release** for `v1.1.0` with notes: what changed for
   users, any rule whose findings or scores change, and any security fix by
   name. Do not describe how to exploit a fixed flaw.

7. **Tell whoever pins a ref.** Anyone following `@v1` has the change already.
   Anyone pinned to an exact tag or commit has not: the release notes are how
   they find out. If you maintain other projects that install the scanner,
   move their pins in the same sitting, so that scores in different places
   come from the same scanner.

## Taking a release back

If a release breaks people's pipelines, move `v1` back to the last good tag.
That is step 5 with the older version:

```bash
git tag -f -a v1 -m "v1 -> v1.0.0" 'v1.0.0^{}'
git push --force origin v1
```

Leave the bad `v1.x.y` tag in place, mark its GitHub release as a
pre-release with a line saying why, and fix forward with the next patch.
Deleting a tag people have pinned breaks their builds a second time.

## What is not in place

- The drift check runs weekly, so `v1` can be behind `main` for up to a
  week before a job goes red, and a red scheduled job is the only notice.
