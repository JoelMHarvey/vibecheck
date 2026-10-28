"""The integrity check: how well a codebase is built and looked after.

Repo-based (a live URL alone can't show tests or code quality): observability,
alerting, how it was built, tests, code quality and tech debt, each a set of
deterministic signals with the same finding model and fix prompts as the
other checks. Given a URL as well, it also checks that the health route
answers and a status page is linked.

It runs where the code is: the CLI and the GitHub Action. The code is never
uploaded for it, so its reports are self-reported or CI-attested, never
signed by psychosecurity.io, and the combined badge doesn't require it
(``hosted = False``). See docs/integrity-design.md.
"""

from __future__ import annotations

from ...core.models import CheckResult, Context, Target, iso
from ...core.scoring import category_scores, weighted_total
from ...core.models import SEVERITY_ORDER
from . import repo as repo_mod
from . import signals
from .rules import CATEGORIES

URL_FETCH = dict(user_agent="vibecheck-integrity/1.0 (+https://psychosecurity.io)",
                 timeout=6.0, max_bytes=600_000, max_redirects=3)


class IntegrityCheck:
    id = "integrity"
    version = "1.0.0"
    title = "Integrity"
    inputs = {"repo"}
    hosted = False
    categories = CATEGORIES
    blurbs = {
        "A": "Well built and well looked after. Keep it that way.",
        "B": "Solid, with a few gaps. Work through the list and it's ready for real users.",
        "C": "It works, but you'd hear about problems late and fix them slowly. Start at the top.",
        "D": "Fragile: little to catch a broken change or tell you something's down.",
        "F": "Nothing is watching this code. Start with tests and error tracking.",
        "–": "We couldn't read the project.",
    }
    not_run = "needs your code"
    footer = ("Scores reward what's wired up (tests that CI runs, errors that reach a tracker), "
              "not how much there is.")

    def run(self, target: Target, ctx: Context) -> CheckResult:
        if target.files is not None:
            repo = repo_mod.from_files(target.files, label=target.label or "uploaded project")
        elif target.repo:
            repo = repo_mod.from_folder(target.repo, exclude=ctx.exclude)
        else:
            raise ValueError("the integrity check needs a repository")

        c = signals.Collector()
        server = signals.has_server(repo)
        signals.observability(repo, c, server)
        signals.alerting(repo, c, server)
        signals.build(repo, c)
        signals.tests(repo, c)
        signals.quality(repo, c)
        signals.debt(repo, c)
        if target.url:
            signals.live(target.url, ctx.fetcher(**URL_FETCH), c)

        findings = sorted(c.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.category, f.id))
        ran = {cat.id for cat in CATEGORIES}
        if not repo.paths:
            ran = set()
        scores = category_scores(findings, CATEGORIES, ran)
        return CheckResult(
            check_id=self.id,
            check_version=self.version,
            target=target,
            scanned_at=iso(ctx.timestamp()),
            category_scores=scores,
            total=weighted_total(scores, CATEGORIES),
            findings=findings,
            meta={"files_scanned": len(repo.paths), "server_code": server},
        )


CHECK = IntegrityCheck()
