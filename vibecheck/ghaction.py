"""The runner half of the vibecheck GitHub Action.

action.yml maps its inputs into INPUT_* environment variables and runs this
module. Everything here is stdlib, so the action needs no setup step and no
install step — it scans and reports in about a second.

Findings are surfaced four ways, because each reaches a different person:

- workflow annotations, which land inline on the diff and cost nothing;
- a job summary, which is the report someone reads after a red build;
- a pull request comment, updated in place rather than re-posted;
- SARIF, for repositories with code scanning enabled.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .report import (
    CI_COMMENT_MARKER,
    render_ci_markdown,
    render_json,
    render_terminal,
)
from .rules import SEVERITY_ORDER
from .sarif import render_sarif
from .scanner import scan

# GitHub rejects issue comments over 65536 characters.
MAX_COMMENT_CHARS = 65_000
ANNOTATION_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "notice",
    "info": "notice",
}


def _flag(env, name: str, default: bool = False) -> bool:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _escape_annotation(text: str) -> str:
    """Workflow commands are newline-delimited and use % as an escape lead."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _emit_annotations(result, path_prefix: str, out) -> None:
    prefix = path_prefix.strip("/")
    prefix = prefix + "/" if prefix else ""
    for f in result.findings:
        level = ANNOTATION_LEVEL[f.severity]
        title = _escape_annotation(f"vibecheck: {f.title}")
        message = _escape_annotation(f.description)
        line = max(1, f.line)
        print(
            f"::{level} file={prefix}{f.path},line={line},title={title}::{message}",
            file=out,
        )


def _write_outputs(result, sarif_path: str, env) -> None:
    target = env.get("GITHUB_OUTPUT")
    if not target:
        return
    counts = result.counts
    pairs = {
        "score": result.score,
        "grade": result.grade,
        "findings": len(result.findings),
        "sarif-file": sarif_path,
        **{sev: counts.get(sev, 0) for sev in SEVERITY_ORDER},
    }
    with open(target, "a", encoding="utf-8") as fh:
        for key, value in pairs.items():
            fh.write(f"{key}={value}\n")


def _path_prefix(scan_path: str, env) -> str:
    """How far the scanned directory sits below the repository root.

    Findings are relative to what was scanned, but GitHub resolves annotation
    and SARIF paths from the repository root. Deriving this by resolving both
    sides rather than reusing the input string keeps absolute paths, './web'
    and trailing slashes from producing a prefix that points nowhere.
    """
    base = Path(env.get("GITHUB_WORKSPACE") or ".").resolve()
    try:
        rel = Path(scan_path).resolve().relative_to(base)
    except ValueError:
        # Scanning outside the workspace entirely; no prefix can be right.
        return ""
    return "" if str(rel) == "." else rel.as_posix()


def _pull_request_number(env) -> int | None:
    event_path = env.get("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).exists():
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    number = (event.get("pull_request") or {}).get("number")
    return number if isinstance(number, int) else None


def _api(url: str, token: str, method: str = "GET", payload: dict | None = None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("User-Agent", f"vibecheck/{__version__}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else None


def post_pr_comment(body: str, env, out, opener=_api) -> bool:
    """Create or update the sticky comment. Returns True if it was posted.

    Never fatal: a pull request from a fork gets a read-only token, and a
    failed comment is not a reason to fail someone's build.
    """
    token = env.get("INPUT_TOKEN") or ""
    repo = env.get("GITHUB_REPOSITORY") or ""
    api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    number = _pull_request_number(env)

    if not number:
        return False
    if not token or not repo:
        print("::warning::vibecheck: no token or repository available, skipping the PR comment", file=out)
        return False

    if len(body) > MAX_COMMENT_CHARS:
        body = body[:MAX_COMMENT_CHARS] + "\n\n_Report truncated._\n"

    try:
        existing = opener(f"{api}/repos/{repo}/issues/{number}/comments?per_page=100", token) or []
        mine = next((c for c in existing if CI_COMMENT_MARKER in (c.get("body") or "")), None)
        if mine:
            opener(f"{api}/repos/{repo}/issues/comments/{mine['id']}", token, "PATCH", {"body": body})
        else:
            opener(f"{api}/repos/{repo}/issues/{number}/comments", token, "POST", {"body": body})
        return True
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        # Most often a fork's read-only token. Say so and carry on.
        print(f"::warning::vibecheck: could not post the PR comment ({exc})", file=out)
        return False


def main(argv=None, env=None, out=None) -> int:
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out

    scan_path = (env.get("INPUT_PATH") or ".").strip() or "."
    fail_on = (env.get("INPUT_FAIL_ON") or "high").strip()
    min_severity = (env.get("INPUT_MIN_SEVERITY") or "info").strip()
    sarif_file = (env.get("INPUT_SARIF_FILE") or "").strip()

    for name, value in (("fail-on", fail_on), ("min-severity", min_severity)):
        allowed = list(SEVERITY_ORDER) + (["never"] if name == "fail-on" else [])
        if value not in allowed:
            print(f"::error::vibecheck: {name} must be one of {', '.join(allowed)} (got '{value}')", file=out)
            return 2

    target = Path(scan_path)
    if not target.exists():
        print(f"::error::vibecheck: path does not exist: {scan_path}", file=out)
        return 2

    # One pattern per line or comma-separated, so both YAML spellings work.
    raw_exclude = (env.get("INPUT_EXCLUDE") or "").replace(",", "\n")
    exclude = [line.strip() for line in raw_exclude.splitlines() if line.strip()]

    result = scan(str(target), exclude=exclude)
    threshold = SEVERITY_ORDER[min_severity]
    result.findings = [f for f in result.findings if SEVERITY_ORDER[f.severity] <= threshold]

    prefix = _path_prefix(scan_path, env)

    # Actions renders ANSI, so the log gets the same coloured report as a terminal.
    print(render_terminal(result, use_color=not _flag(env, "NO_COLOR")), file=out)
    _emit_annotations(result, prefix, out)

    ci_markdown = render_ci_markdown(result, path_prefix=prefix)

    if _flag(env, "INPUT_SUMMARY", default=True):
        summary_path = env.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(ci_markdown)

    if sarif_file:
        Path(sarif_file).parent.mkdir(parents=True, exist_ok=True)
        Path(sarif_file).write_text(render_sarif(result, __version__, prefix), encoding="utf-8")
        print(f"  SARIF written to {sarif_file}", file=out)

    json_file = (env.get("INPUT_JSON_FILE") or "").strip()
    if json_file:
        Path(json_file).parent.mkdir(parents=True, exist_ok=True)
        Path(json_file).write_text(render_json(result), encoding="utf-8")
        print(f"  JSON report written to {json_file}", file=out)

    _write_outputs(result, sarif_file, env)

    if _flag(env, "INPUT_COMMENT", default=True):
        post_pr_comment(ci_markdown, env, out)

    if fail_on != "never":
        limit = SEVERITY_ORDER[fail_on]
        blocking = [f for f in result.findings if SEVERITY_ORDER[f.severity] <= limit]
        if blocking:
            print(
                f"::error::vibecheck: {len(blocking)} finding(s) at or above '{fail_on}' "
                f"— Vibe Score {result.score}/100 (grade {result.grade})",
                file=out,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
