"""Render any CheckResult, or several side by side, for the terminal,
Markdown or JSON. Checks supply only their wording (grade blurbs, a footer);
the layout is the same for all of them."""

from __future__ import annotations

import json
import textwrap
from typing import Optional, Sequence

from .. import __version__
from .models import SEVERITY_ORDER, CheckResult
from .scoring import badge_level

ANSI = {
    "critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m",
    "info": "\033[90m", "pass": "\033[92m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
}
LABELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO", "pass": "WORKING"}
NOT_RUN = "not checked"  # a check's own not_run wording wins
DEFAULT_BLURB = {
    "A": "Looking good. Fix anything below and keep it that way.",
    "B": "Nearly there. A few things need attention.",
    "C": "Some real gaps. Work through the list, top first.",
    "D": "Serious problems. Fix the critical and high items first.",
    "F": "Start with the first finding.",
    "–": "Nothing could be checked.",
}


def _check(check_id: str):
    from .registry import get
    return get(check_id)


def blurb(result: CheckResult) -> str:
    return getattr(_check(result.check_id), "blurbs", DEFAULT_BLURB).get(result.grade, "")


def basis(result: CheckResult) -> str:
    total = len(result.category_scores)
    ran = sum(1 for s in result.category_scores.values() if s is not None)
    return f"based on {ran} of {total} categories" if ran < total else ""


def describe_target(result: CheckResult) -> str:
    t = result.target.to_dict()
    parts = [t.get("repo"), t.get("url")]
    label = " + ".join(p for p in parts if p)
    if t.get("commit"):
        label += f" (commit {t['commit'][:7]})"
    return label


def meta_line(result: CheckResult) -> str:
    bits = []
    if "files_scanned" in result.meta:
        bits.append(f"{result.meta['files_scanned']} files scanned")
    if "pages_crawled" in result.meta:
        n = result.meta["pages_crawled"]
        bits.append(f"{n} page{'s' if n != 1 else ''} crawled")
    if result.meta.get("positioning"):
        bits.append(f"positioning review: {result.meta['positioning']}")
    if result.meta.get("architecture"):
        bits.append(f"architecture read: {result.meta['architecture']}")
    probe = result.meta.get("probe")
    if isinstance(probe, dict) and str(probe.get("status", "")).startswith("not run"):
        bits.append(f"AI answers: {probe['status']}")
    bits.append(result.scanned_at)
    return " · ".join(bits)


def level(result: CheckResult) -> Optional[str]:
    return badge_level(result.total, (f.severity for f in result.problems))


def _wrap(text: str, indent: str = "     ") -> str:
    return textwrap.fill(text, width=96, initial_indent=indent, subsequent_indent=indent)


SNAPSHOT_NOTE = ("A snapshot: AI answers vary from run to run, so read these as a sample, "
                 "not a ranking.")


def probe_answers(result: CheckResult) -> list:
    probe = result.meta.get("probe")
    return probe.get("answers") or [] if isinstance(probe, dict) else []


def render_terminal(result: CheckResult, use_color: bool = True) -> str:
    def c(code: str, s: str) -> str:
        return f"{ANSI[code]}{s}{ANSI['reset']}" if use_color else s

    check = _check(result.check_id)
    lines = ["", c("bold", f"  vibecheck v{__version__} · {check.title} — {describe_target(result)}"),
             c("dim", f"  {meta_line(result)}"), ""]
    if result.total is None:
        lines.append("  " + c("bold", f"{check.title.upper()}: ") + c("critical", "not checked"))
    else:
        color = "pass" if result.total >= 90 else ("medium" if result.total >= 60 else "critical")
        tail = basis(result)
        lines.append("  " + c("bold", f"{check.title.upper()}: ") + c(color, f"{result.total}/100 (grade {result.grade})")
                     + (c("dim", f"   {tail}") if tail else ""))
    lines.append(c("dim", f"  {blurb(result)}"))
    lines.append("")
    not_run = getattr(check, "not_run", NOT_RUN)
    for cat in check.categories:
        s = result.category_scores.get(cat.id)
        bar = "·" * 10 if s is None else "█" * s + "░" * (10 - s)
        lines.append(f"  {cat.label:<20} {bar}  {c('dim', not_run) if s is None else f'{s}/10'}")
    lines.append("")

    current = None
    for f in result.problems:
        if f.severity != current:
            current = f.severity
            lines += [c(f.severity, f"  {LABELS[f.severity]} " + "─" * (60 - len(f.severity))), ""]
        lines.append("  " + c(f.severity, "✗ ") + c("bold", f.title) + c("dim", f"   {f.location}"))
        if f.evidence:
            lines.append(_wrap(f.evidence))
        if f.why_it_matters:
            lines.append(_wrap("Why it matters: " + f.why_it_matters))
        if f.fix_prompt:
            lines.append(c("dim", "     Fix prompt (paste into your AI coding tool):"))
            lines.append(_wrap(f'"{f.fix_prompt}"', indent="       "))
        if f.verify_hint:
            lines.append(_wrap("Check it worked: " + f.verify_hint))
        lines.append("")
    if result.passes:
        lines += [c("pass", "  WORKING " + "─" * 53), ""]
        for f in result.passes:
            lines.append("  " + c("pass", "✓ ") + f.title + c("dim", f"   {f.evidence}"))
        lines.append("")
    answers = probe_answers(result)
    if answers:
        lines += [c("bold", "  WHAT THE AI SAID " + "─" * 44), c("dim", _wrap(SNAPSHOT_NOTE, indent="  ")), ""]
        for a in answers:
            mark = c("pass", "✓ named") if a.get("mentioned") else c("medium", "✗ not named")
            cited = c("pass", ", cited") if a.get("cited") else ""
            lines.append(f"  {mark}{cited}   " + c("bold", a.get("q", "")))
            if a.get("competitors"):
                lines.append(_wrap("Also named: " + ", ".join(a["competitors"])))
            if a.get("snippet"):
                lines.append(c("dim", _wrap(a["snippet"])))
            lines.append("")
    footer = getattr(check, "footer", "")
    if footer:
        lines += [c("dim", _wrap(footer, indent="  ")), ""]
    return "\n".join(lines)


def render_markdown(result: CheckResult, heading_level: int = 1) -> str:
    check = _check(result.check_id)
    h = "#" * heading_level
    lines = [f"{h} vibecheck {check.title.lower()} report", "",
             f"**Target:** {describe_target(result)} · {meta_line(result)}", ""]
    if result.total is None:
        lines += [f"{h}# {check.title}: not checked", ""]
    else:
        tail = basis(result)
        lines += [f"{h}# {check.title}: {result.total}/100 (grade {result.grade})", "",
                  blurb(result) + (f" Score {tail}." if tail else ""), ""]
    lines += ["| Category | Score |", "|---|---|"]
    not_run = getattr(check, "not_run", NOT_RUN)
    for cat in check.categories:
        s = result.category_scores.get(cat.id)
        lines.append(f"| {cat.label} | {'_' + not_run + '_' if s is None else f'{s}/10'} |")
    lines.append("")
    current = None
    for f in result.problems:
        if f.severity != current:
            current = f.severity
            lines += [f"{h}# {LABELS[f.severity]}", ""]
        lines += [f"{h}## {f.title}", "", f"`{f.location}`", ""]
        if f.evidence:
            lines += [f"> {f.evidence}", ""]
        if f.why_it_matters:
            lines += [f"**Why it matters:** {f.why_it_matters}", ""]
        if f.fix_prompt:
            lines += ["**Fix prompt** — paste this into Cursor / Claude Code / Lovable / Bolt:", "",
                      "```text", f.fix_prompt, "```", ""]
        if f.verify_hint:
            lines += [f"**Check it worked:** {f.verify_hint}", ""]
        if f.guide_url:
            lines += [f"More: https://www.psychosecurity.io{f.guide_url}", ""]
    if result.passes:
        lines += [f"{h}# Working", ""]
        lines += [f"- ✓ **{f.title}** — {f.evidence}" for f in result.passes]
        lines.append("")
    answers = probe_answers(result)
    if answers:
        lines += [f"{h}# What the AI said", "", f"_{SNAPSHOT_NOTE}_", ""]
        for a in answers:
            mark = ("✓ named" if a.get("mentioned") else "✗ not named") + (", cited" if a.get("cited") else "")
            lines += [f"**{a.get('q', '')}** ({mark})", ""]
            if a.get("competitors"):
                lines += [f"Also named: {', '.join(a['competitors'])}", ""]
            if a.get("snippet"):
                lines += [f"> {a['snippet']}", ""]
    footer = getattr(check, "footer", "")
    if footer:
        lines += ["---", "", f"_{footer}_"]
    return "\n".join(lines) + "\n"


def summary_table(results: Sequence[CheckResult]) -> str:
    rows = ["| Check | Score | Grade | Badge | Critical | High |", "|---|---|---|---|---|---|"]
    for r in results:
        counts = r.counts
        rows.append(f"| {_check(r.check_id).title} | {'–' if r.total is None else f'{r.total}/100'} | {r.grade} "
                    f"| {level(r) or 'none'} | {counts['critical']} | {counts['high']} |")
    return "\n".join(rows)


def render_combined_markdown(results: Sequence[CheckResult]) -> str:
    if len(results) == 1:
        return render_markdown(results[0])
    out = ["# vibecheck report", "", f"**Target:** {describe_target(results[0])}", "", summary_table(results), ""]
    for r in results:
        out.append(render_markdown(r, heading_level=2))
    return "\n".join(out)


def render_combined_terminal(results: Sequence[CheckResult], use_color: bool = True) -> str:
    return "\n".join(render_terminal(r, use_color) for r in results)


def to_json(results: Sequence[CheckResult]) -> dict:
    if len(results) == 1:
        return results[0].to_dict()
    return {"target": results[0].target.to_dict(), "results": [r.to_dict() for r in results]}


def render_json(results: Sequence[CheckResult]) -> str:
    return json.dumps(to_json(results), indent=2, ensure_ascii=False) + "\n"


def fails(results: Sequence[CheckResult], threshold: str = "high") -> bool:
    """Any problem at or above ``threshold`` in any result."""
    limit = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[f.severity] <= limit for r in results for f in r.problems)


__all__ = ["render_terminal", "render_markdown", "render_combined_markdown", "render_combined_terminal",
           "render_json", "to_json", "fails", "level", "summary_table"]
