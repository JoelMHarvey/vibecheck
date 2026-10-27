"""Render a visibility result for the terminal, Markdown and JSON.

Same shape as the security report (score, findings by severity, fix
prompts), plus the six category scores and what passed.
"""

from __future__ import annotations

import json
import textwrap

from .. import __version__
from ..report import ANSI, SEVERITY_LABELS
from ..rules import SEVERITY_ORDER
from . import config
from .rules import RULES
from .scan import VisibilityResult

SITE = "https://psychosecurity.io"
DEEPER = "deeper check coming soon"

GRADE_BLURB = {
    "A": "Easy to find. Fix anything below and keep it that way.",
    "B": "Mostly findable. A few fixes will help search engines and AI read you right.",
    "C": "Findable, with gaps. Work through the list, top first.",
    "D": "Hard to find. Fix the high and medium items before anything else.",
    "F": "Close to invisible. Start with the first finding.",
    "–": "We couldn't check this site.",
}

FOOTER = ("Rankings, keywords and backlinks aren't in this scan: Google Search Console "
          "shows those for your own site, free.")


def _wrap(text: str, indent: str = "     ") -> str:
    return textwrap.fill(text, width=96, initial_indent=indent, subsequent_indent=indent)


def category_rows(result: VisibilityResult):
    scores = result.categories
    return [(key, label, scores[key]) for key, label in config.CATEGORIES]


def basis(result: VisibilityResult) -> str:
    n = result.categories_scored
    return f"based on {n} of {len(config.CATEGORIES)} categories"


def render_terminal(result: VisibilityResult, use_color: bool = True) -> str:
    def c(code: str, s: str) -> str:
        return f"{ANSI[code]}{s}{ANSI['reset']}" if use_color else s

    lines = ["", c("bold", f"  vibecheck v{__version__} visibility — {result.root}"),
             c("dim", f"  {result.pages_crawled} page{'s' if result.pages_crawled != 1 else ''} crawled · {result.scanned_at}"), ""]
    score = result.score
    if score is None:
        lines.append("  " + c("bold", "VISIBILITY: ") + c("critical", "not checked"))
    else:
        color = "green" if score >= 90 else ("medium" if score >= 60 else "critical")
        lines.append("  " + c("bold", "VISIBILITY: ") + c(color, f"{score}/100 (grade {result.grade})")
                     + c("dim", f"   {basis(result)}"))
    lines.append(c("dim", f"  {GRADE_BLURB[result.grade]}"))
    lines.append("")
    for _key, label, s in category_rows(result):
        bar = "·" * 10 if s is None else "█" * s + "░" * (10 - s)
        value = c("dim", DEEPER) if s is None else f"{s}/10"
        lines.append(f"  {label:<20} {bar}  {value}")
    lines.append("")

    current = None
    for f in result.findings:
        if f.severity != current:
            current = f.severity
            lines.append(c(f.severity, f"  {SEVERITY_LABELS[f.severity]} " + "─" * (60 - len(f.severity))))
            lines.append("")
        rule = RULES[f.rule_id]
        lines.append("  " + c(f.severity, "✗ ") + c("bold", f.title) + c("dim", f"   {f.path}"))
        lines.append(_wrap(f.excerpt))
        lines.append(_wrap(c("dim", "Why it matters: ") + f.description))
        if f.fix_prompt:
            lines.append(c("dim", "     Fix prompt (paste into your AI coding tool):"))
            lines.append(_wrap(f'"{f.fix_prompt}"', indent="       "))
        if rule.verify:
            lines.append(_wrap(c("dim", "Check it worked: ") + rule.verify))
        lines.append("")

    if result.passes:
        lines.append(c("green", "  WORKING " + "─" * 53))
        lines.append("")
        for p in result.passes:
            lines.append("  " + c("green", "✓ ") + p.title + c("dim", f"   {p.evidence}"))
        lines.append("")
    lines.append(c("dim", "  " + FOOTER))
    lines.append("")
    return "\n".join(lines)


def render_markdown(result: VisibilityResult) -> str:
    lines = ["# vibecheck visibility report", "",
             f"**Site:** {result.root} ({result.pages_crawled} pages crawled, {result.scanned_at})", ""]
    if result.score is None:
        lines += ["## Visibility: not checked", ""]
    else:
        lines += [f"## Visibility: {result.score}/100 (grade {result.grade})", "",
                  f"{GRADE_BLURB[result.grade]} Score {basis(result)}.", ""]
    lines += ["| Category | Score |", "|---|---|"]
    for _key, label, s in category_rows(result):
        lines.append(f"| {label} | {'_' + DEEPER + '_' if s is None else f'{s}/10'} |")
    lines.append("")

    current = None
    for f in result.findings:
        if f.severity != current:
            current = f.severity
            lines += [f"## {SEVERITY_LABELS[f.severity]}", ""]
        rule = RULES[f.rule_id]
        lines += [f"### {f.title}", "", f"`{f.path}`", "", f"> {f.excerpt}", "",
                  f"**Why it matters:** {f.description}", ""]
        if f.fix_prompt:
            lines += ["**Fix prompt** — paste this into Cursor / Claude Code / Lovable / Bolt:", "",
                      "```text", f.fix_prompt, "```", ""]
        if rule.verify:
            lines += [f"**Check it worked:** {rule.verify}", ""]
        if rule.guide:
            lines += [f"More: [{SITE}{rule.guide}]({SITE}{rule.guide})", ""]

    if result.passes:
        lines += ["## Working", ""]
        for p in result.passes:
            lines.append(f"- ✓ **{p.title}** — {p.evidence}")
        lines.append("")
    lines += ["---", "", f"_{FOOTER}_"]
    return "\n".join(lines) + "\n"


def to_json_dict(result: VisibilityResult) -> dict:
    return {
        "kind": "visibility",
        "root": result.root,
        "scanned_at": result.scanned_at,
        "pages_crawled": result.pages_crawled,
        "score": result.score,
        "grade": result.grade,
        "categories_scored": result.categories_scored,
        "categories": [{"key": k, "label": label, "score": s} for k, label, s in category_rows(result)],
        "counts": result.counts,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "category": RULES[f.rule_id].category,
                "path": f.path,
                "excerpt": f.excerpt,
                "description": f.description,
                "fix_prompt": f.fix_prompt,
                "verify": RULES[f.rule_id].verify,
                "guide": RULES[f.rule_id].guide,
            }
            for f in result.findings
        ],
        "passes": [{"check_id": p.check_id, "title": p.title, "evidence": p.evidence} for p in result.passes],
    }


def render_json(result: VisibilityResult) -> str:
    return json.dumps(to_json_dict(result), indent=2, ensure_ascii=False) + "\n"


def fails(result: VisibilityResult, threshold: str = "high") -> bool:
    limit = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[f.severity] <= limit for f in result.findings)
