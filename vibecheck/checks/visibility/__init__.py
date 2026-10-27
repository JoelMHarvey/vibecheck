"""The visibility check: "Is anyone finding it?"

How a live site looks to search engines and AI crawlers, with the same
plain-English findings and fix prompts as the security check. See
docs/visibility-design.md.
"""

from __future__ import annotations

from ...core.models import CheckResult, Context, Target
from . import config


class VisibilityCheck:
    id = "visibility"
    version = "1.0.0"
    title = "Visibility"
    inputs = {"url"}
    categories = config.CATEGORIES
    blurbs = {
        "A": "Easy to find. Fix anything below and keep it that way.",
        "B": "Mostly findable. A few fixes will help search engines and AI read you right.",
        "C": "Findable, with gaps. Work through the list, top first.",
        "D": "Hard to find. Fix the high and medium items before anything else.",
        "F": "Close to invisible. Start with the first finding.",
        "–": "We couldn't check this site.",
    }
    not_run = "deeper check coming soon"
    footer = ("Rankings, keywords and backlinks aren't in this scan: Google Search Console "
              "shows those for your own site, free.")

    def run(self, target: Target, ctx: Context) -> CheckResult:
        fetch = ctx.fetcher(user_agent=config.USER_AGENT, timeout=config.TIMEOUT,
                            max_bytes=config.MAX_BYTES, max_redirects=config.MAX_REDIRECTS)
        result = scan_visibility(target.url, fetch, now=ctx.timestamp(),
                                 budget=ctx.budget or config.BUDGET)
        result.target.commit = target.commit
        return result


CHECK = VisibilityCheck()

from .scan import scan_visibility  # noqa: E402  (after CHECK: scan.py reads it)
