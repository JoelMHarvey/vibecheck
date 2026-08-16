"""Render scan results for the terminal, Markdown, and JSON."""

from __future__ import annotations

import json
import textwrap

from . import __version__
from .rules import SEVERITY_ORDER
from .scanner import ScanResult

ANSI = {
    "critical": "\033[1;91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[92m",
    "reset": "\033[0m",
}

SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

GRADE_BLURB = {
    "A": "Looking good. Fix anything below and ship it.",
    "B": "Nearly there — a few things need attention before launch.",
    "C": "Some real risks here. Work through the list before sharing your app.",
    "D": "Serious problems. Fix the critical/high items before anything else.",
    "F": "Stop — do not launch this yet. Fix the critical items first.",
}


def _wrap(text: str, indent: str = "     ") -> str:
    return textwrap.fill(text, width=96, initial_indent=indent, subsequent_indent=indent)


def _loc(finding) -> str:
    """Location label: 'path:line' for code findings, just 'path' for
    deployed-site findings (which have no line number)."""
    if finding.line and finding.line > 0:
        return f"{finding.path}:{finding.line}"
    return finding.path


def render_terminal(result: ScanResult, use_color: bool = True) -> str:
    def c(code: str, s: str) -> str:
        if not use_color:
            return s
        return f"{ANSI[code]}{s}{ANSI['reset']}"

    lines = []
    lines.append("")
    lines.append(c("bold", f"  vibecheck v{__version__} — {result.root}"))
    lines.append(c("dim", f"  {result.files_scanned} files scanned"))
    lines.append("")

    counts = result.counts
    summary = ", ".join(
        f"{counts[sev]} {sev}" for sev in SEVERITY_ORDER if counts.get(sev)
    ) or "no findings"
    score_color = "green" if result.score >= 90 else ("medium" if result.score >= 60 else "critical")
    lines.append(
        "  " + c("bold", "VIBE SCORE: ") + c(score_color, f"{result.score}/100 (grade {result.grade})")
        + c("dim", f"   — {summary}")
    )
    lines.append(c("dim", f"  {GRADE_BLURB[result.grade]}"))
    lines.append("")

    if not result.findings:
        lines.append(c("green", "  ✓ Nothing found. Nice."))
        lines.append("")
        return "\n".join(lines)

    current_severity = None
    for f in result.findings:
        if f.severity != current_severity:
            current_severity = f.severity
            lines.append(c(f.severity, f"  {SEVERITY_LABELS[f.severity]} " + "─" * (60 - len(f.severity))))
            lines.append("")
        lines.append("  " + c(f.severity, "✗ ") + c("bold", f.title) + c("dim", f"   {_loc(f)}"))
        lines.append(c("dim", f"     {f.excerpt}"))
        lines.append(_wrap(f.description))
        if f.fix_prompt:
            lines.append(c("dim", "     Fix prompt (paste into your AI coding tool):"))
            lines.append(_wrap(f'"{f.fix_prompt}"', indent="       "))
        lines.append("")

    lines.append(c("dim", "  Tip: re-run vibecheck after applying fixes. Rotate any exposed key — deleting"))
    lines.append(c("dim", "  it from the code does not un-leak it."))
    lines.append("")
    return "\n".join(lines)


def render_markdown(result: ScanResult) -> str:
    counts = result.counts
    lines = []
    lines.append("# vibecheck security report")
    lines.append("")
    lines.append(f"**Scanned:** `{result.root}` ({result.files_scanned} files)")
    lines.append("")
    lines.append(f"## Vibe Score: {result.score}/100 (grade {result.grade})")
    lines.append("")
    lines.append(GRADE_BLURB[result.grade])
    lines.append("")
    summary_cells = " | ".join(str(counts.get(sev, 0)) for sev in SEVERITY_ORDER)
    lines.append("| Critical | High | Medium | Low | Info |")
    lines.append("|---|---|---|---|---|")
    lines.append(f"| {summary_cells} |")
    lines.append("")

    if not result.findings:
        lines.append("No findings. 🎉")
        return "\n".join(lines) + "\n"

    current_severity = None
    for f in result.findings:
        if f.severity != current_severity:
            current_severity = f.severity
            lines.append(f"## {SEVERITY_LABELS[f.severity]}")
            lines.append("")
        lines.append(f"### {f.title}")
        lines.append("")
        lines.append(f"`{_loc(f)}`")
        lines.append("")
        lines.append(f"> {f.excerpt}")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        if f.fix_prompt:
            lines.append("**Fix prompt** — paste this into Cursor / Claude Code / Lovable / Bolt:")
            lines.append("")
            lines.append("```text")
            lines.append(f.fix_prompt)
            lines.append("```")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Remember: deleting a key from your code does **not** un-leak it. "
        "Rotate every exposed credential at its provider._"
    )
    return "\n".join(lines) + "\n"


SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

# Marker used to find and update our own pull request comment instead of
# posting a new one on every push.
CI_COMMENT_MARKER = "<!-- vibecheck-report -->"


def render_ci_markdown(
    result: ScanResult,
    limit: int = 30,
    footer_link: str = "https://psychosecurity.io",
    path_prefix: str = "",
) -> str:
    """A compact report for a job summary or a pull request comment.

    Differs from render_markdown in shape rather than content: findings go in
    one scannable table with the fix prompts folded away underneath, because a
    comment that takes ten screens to scroll gets ignored.

    ``path_prefix`` makes locations repository-relative when a subdirectory was
    scanned, so they match the paths in the pull request diff.
    """
    prefix = path_prefix.replace("\\", "/").strip("/")
    prefix = prefix + "/" if prefix else ""

    def loc(f) -> str:
        return prefix + _loc(f)

    counts = result.counts
    lines = [CI_COMMENT_MARKER, ""]
    lines.append(f"## 🔒 vibecheck — Vibe Score {result.score}/100 (grade {result.grade})")
    lines.append("")
    lines.append(GRADE_BLURB[result.grade])
    lines.append("")

    if not result.findings:
        lines.append("**No findings.** Nothing exposed, nothing to fix. 🎉")
        lines.append("")
        lines.append(f"<sub>{result.files_scanned} files scanned · [vibecheck]({footer_link})</sub>")
        return "\n".join(lines) + "\n"

    present = [sev for sev in SEVERITY_ORDER if counts.get(sev)]
    lines.append("| " + " | ".join(SEVERITY_LABELS[s].title() for s in present) + " |")
    lines.append("|" + "---|" * len(present))
    lines.append("| " + " | ".join(str(counts[s]) for s in present) + " |")
    lines.append("")

    shown = result.findings[:limit]
    lines.append("| Severity | Finding | Location |")
    lines.append("|---|---|---|")
    for f in shown:
        lines.append(f"| {SEVERITY_EMOJI[f.severity]} {f.severity} | {f.title} | `{loc(f)}` |")
    if len(result.findings) > limit:
        remaining = len(result.findings) - limit
        lines.append(f"| | _…and {remaining} more_ | |")
    lines.append("")

    with_prompts = [f for f in shown if f.fix_prompt]
    if with_prompts:
        lines.append("<details>")
        lines.append("<summary><b>Fix prompts</b> — paste into Cursor, Claude Code, Lovable, Bolt or v0</summary>")
        lines.append("")
        for f in with_prompts:
            lines.append(f"**`{loc(f)}` — {f.title}**")
            lines.append("")
            lines.append("```text")
            lines.append(f.fix_prompt)
            lines.append("```")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append(
        "<sub>Deleting a key from your code does not un-leak it — rotate every exposed "
        f"credential at its provider. {result.files_scanned} files scanned · "
        f"[vibecheck]({footer_link})</sub>"
    )
    return "\n".join(lines) + "\n"


def to_json_dict(result: ScanResult) -> dict:
    return {
        "root": result.root,
        "files_scanned": result.files_scanned,
        "score": result.score,
        "grade": result.grade,
        "counts": result.counts,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "path": f.path,
                "line": f.line,
                "excerpt": f.excerpt,
                "description": f.description,
                "fix_prompt": f.fix_prompt,
            }
            for f in result.findings
        ],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(to_json_dict(result), indent=2) + "\n"
