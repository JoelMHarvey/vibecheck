"""Applies the detection rules to a project directory or in-memory files.

Two entry points:
- scan(path)        — walk a directory on disk (used by the CLI)
- scan_files(pairs) — scan (relative_path, text) pairs already in memory
                      (used by the hosted API, where nothing touches disk)
"""

from __future__ import annotations

import base64
import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional, Tuple

from .rules import (
    ENV_NOT_IGNORED,
    JWT_RULE_ID,
    RULES,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    SUPABASE_ANON_INFO,
    SUPABASE_SERVICE_ROLE,
    Rule,
    looks_like_placeholder,
)

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "out",
    "coverage",
    ".turbo",
    ".cache",
    "vendor",
    "site-packages",
    ".idea",
    ".vscode",
}

SKIP_FILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
}

SKIP_FILE_SUFFIXES = (".min.js", ".min.css", ".map", ".lock")

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".7z",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ogg",
    ".pyc", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".sqlite", ".db", ".pkl", ".npy", ".parquet",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

FRONTEND_EXTS = {".html", ".jsx", ".tsx", ".vue", ".svelte"}
FRONTEND_DIR_HINTS = {"public", "static", "frontend", "client", "www"}

MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 1_000  # longer lines are almost always bundled/minified output
MAX_FINDINGS_PER_RULE_PER_FILE = 20

_SEVERITY_BUMP = {"info": "low", "low": "medium", "medium": "high", "high": "critical", "critical": "critical"}

IGNORE_FILE = ".vibecheckignore"

# Inline suppression, spelled the way eslint does it so nobody has to look it
# up: `vibecheck-ignore` silences the line it sits on, `-next-line` the line
# below. An optional comma-separated rule list narrows it to those rules;
# bare, it silences every rule on that line.
#
#     const q = `SELECT ...`;  // vibecheck-ignore: sql-string-building
#     // vibecheck-ignore-next-line
#     verify: false
_IGNORE_RE = re.compile(
    r"vibecheck-ignore(?P<next>-next-line)?\s*(?::\s*(?P<rules>[A-Za-z0-9_.\-]+(?:\s*,\s*[A-Za-z0-9_.\-]+)*))?"
)


def _ignored_rules(line: str, want_next_line: bool):
    """What this line suppresses, or None if it suppresses nothing.

    Returns a set of rule ids, or an empty set meaning "every rule".
    """
    for match in _IGNORE_RE.finditer(line):
        if bool(match.group("next")) != want_next_line:
            continue
        raw = match.group("rules")
        return {r.strip() for r in raw.split(",")} if raw else set()
    return None


def _suppressed(rule_id: str, line: str, previous: str) -> bool:
    for text, want_next in ((line, False), (previous, True)):
        rules = _ignored_rules(text, want_next)
        if rules is not None and (not rules or rule_id in rules):
            return True
    return False


class PathFilter:
    """Glob-based path exclusion, from `.vibecheckignore` and --exclude.

    Deliberately more forgiving than gitignore: a pattern matches if it
    matches the whole relative path, that path under a directory prefix, or
    any single path segment. Someone writing `tests` to mean "not my tests"
    should not have to discover that it needed to be `tests/**`.
    """

    def __init__(self, patterns: Optional[Iterable[str]] = None):
        self.patterns = [p.strip() for p in (patterns or []) if p.strip() and not p.strip().startswith("#")]

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def matches(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/").lstrip("/")
        segments = rel.split("/")
        for raw in self.patterns:
            pattern = raw.rstrip("/")
            if fnmatch.fnmatch(rel, pattern):
                return True
            if fnmatch.fnmatch(rel, pattern + "/*"):
                return True
            if any(fnmatch.fnmatch(seg, pattern) for seg in segments[:-1]):
                return True
            if fnmatch.fnmatch(segments[-1], pattern):
                return True
        return False


def _read_ignore_file(root: Path) -> List[str]:
    target = root / IGNORE_FILE
    try:
        return target.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str  # posix-style, relative to the scanned root
    line: int
    excerpt: str
    description: str
    fix_prompt: str

    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity, 99), self.path, self.line)


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def counts(self):
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def score(self) -> int:
        penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"


def is_frontend_path(rel_path: PurePosixPath) -> bool:
    if rel_path.suffix.lower() in FRONTEND_EXTS:
        return True
    return any(part.lower() in FRONTEND_DIR_HINTS for part in rel_path.parts[:-1])


def _is_env_file(name: str) -> bool:
    if not name.startswith(".env"):
        return False
    lowered = name.lower()
    return not any(hint in lowered for hint in ("example", "sample", "template", "test"))


def _should_skip_name(name: str, ext: str) -> bool:
    if name in SKIP_FILE_NAMES:
        return True
    if name.endswith(SKIP_FILE_SUFFIXES):
        return True
    if ext in BINARY_EXTS:
        return True
    return False


def _decode_jwt_role(token: str) -> Optional[str]:
    """Return the 'role' claim of a JWT payload, or None if undecodable."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        role = payload.get("role")
        return role if isinstance(role, str) else None
    except Exception:
        return None


def _redact(line: str, match: "re.Match[str]") -> str:
    matched = match.group(0)
    keep = min(6, max(0, len(matched) - 4))
    redacted = matched[:keep] + "…[redacted]"
    return (line[: match.start()] + redacted + line[match.end():]).strip()


_SECRET_PATTERNS = [r.pattern for r in RULES if r.is_secret]


def _sanitize_excerpt(line: str) -> str:
    """Redact any secret-shaped value in an excerpt, no matter which rule
    produced the finding — a non-secret rule can match a line that also
    contains a key."""
    for pattern in _SECRET_PATTERNS:
        line = pattern.sub(lambda m: m.group(0)[:6] + "…[redacted]", line)
    return line.strip()


def _make_finding(rule: Rule, rel_path: str, line_no: int, excerpt: str, severity: Optional[str] = None) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity or rule.severity,
        path=rel_path,
        line=line_no,
        excerpt=excerpt[:200],
        description=rule.description,
        fix_prompt=rule.fix_prompt.format(path=rel_path, line=line_no),
    )


def scan_text(rel_path: str, text: str) -> List[Finding]:
    """Run every applicable rule over one file's content.

    ``rel_path`` is a posix-style path relative to the project root; it
    drives extension gating, frontend detection, and .env handling.
    """
    rel = PurePosixPath(rel_path)
    ext = rel.suffix.lower()
    frontend = is_frontend_path(rel)
    in_env_file = _is_env_file(rel.name)

    if "\x00" in text[:1024]:
        return []

    findings: List[Finding] = []
    per_rule_counts: dict = {}
    previous_line = ""

    applicable = []
    for rule in RULES:
        if rule.extensions is not None and ext not in rule.extensions:
            continue
        if rule.frontend_only and not frontend:
            continue
        # Inside a real .env file, secret VALUES are expected — that's the
        # right place for them. The repo-level gitignore check covers the risk.
        if in_env_file and rule.is_secret:
            continue
        applicable.append(rule)
    if not applicable:
        return []

    for line_no, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_CHARS:
            previous_line = line
            continue
        for rule in applicable:
            if _suppressed(rule.id, line, previous_line):
                continue
            if per_rule_counts.get(rule.id, 0) >= MAX_FINDINGS_PER_RULE_PER_FILE:
                continue
            for match in rule.pattern.finditer(line):
                if rule.is_secret and looks_like_placeholder(match.group(0)):
                    continue

                effective_rule = rule
                severity = rule.severity

                if rule.id == JWT_RULE_ID:
                    role = _decode_jwt_role(match.group(0))
                    if role == "service_role":
                        effective_rule = SUPABASE_SERVICE_ROLE
                        severity = SUPABASE_SERVICE_ROLE.severity
                    elif role == "anon":
                        effective_rule = SUPABASE_ANON_INFO
                        severity = SUPABASE_ANON_INFO.severity

                # A JWT resolves to a different rule than the one that matched,
                # so honour a suppression naming either id.
                if effective_rule is not rule and _suppressed(effective_rule.id, line, previous_line):
                    continue

                if effective_rule.frontend_boost and frontend:
                    severity = _SEVERITY_BUMP[severity]

                excerpt = _redact(line, match) if effective_rule.is_secret else _sanitize_excerpt(line)[:200]
                findings.append(_make_finding(effective_rule, rel_path, line_no, excerpt, severity))
                per_rule_counts[rule.id] = per_rule_counts.get(rule.id, 0) + 1

        previous_line = line

    return findings


def scan_file(path: Path, root: Path) -> List[Finding]:
    rel_str = path.relative_to(root).as_posix()
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_text(rel_str, text)


def _gitignore_lines_cover(lines: List[str], filename: str) -> bool:
    for raw in lines:
        pattern = raw.strip().rstrip("/")
        if not pattern or pattern.startswith("#"):
            continue
        pattern = pattern.lstrip("/")
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


def _gitignore_covers(root: Path, filename: str) -> bool:
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return False
    try:
        lines = gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False
    return _gitignore_lines_cover(lines, filename)


def _env_finding(rel: str) -> Finding:
    return Finding(
        rule_id=ENV_NOT_IGNORED.id,
        title=ENV_NOT_IGNORED.title,
        severity=ENV_NOT_IGNORED.severity,
        path=rel,
        line=1,
        excerpt="(file-level finding)",
        description=ENV_NOT_IGNORED.description,
        fix_prompt=ENV_NOT_IGNORED.fix_prompt.format(path=rel, line=1),
    )


def _finalize(result: ScanResult) -> ScanResult:
    # Deduplicate (same rule, same location can be hit via overlapping patterns).
    seen = set()
    unique: List[Finding] = []
    for f in result.findings:
        key = (f.rule_id, f.path, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    result.findings = sorted(unique, key=Finding.sort_key)
    return result


def scan(root_path: str, exclude: Optional[Iterable[str]] = None) -> ScanResult:
    """Walk a directory on disk.

    ``exclude`` is combined with any patterns in the root ``.vibecheckignore``.
    """
    root = Path(root_path).resolve()
    result = ScanResult(root=str(root))

    if root.is_file():
        result.findings.extend(scan_file(root, root.parent))
        result.files_scanned = 1
        return _finalize(result)

    ignored = PathFilter(_read_ignore_file(root) + list(exclude or []))
    env_files: List[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIP_DIRS and not ignored.matches(entry.relative_to(root).as_posix()):
                    stack.append(entry)
                continue
            if not entry.is_file():
                continue
            rel = entry.relative_to(root).as_posix()
            if ignored.matches(rel):
                continue
            if _is_env_file(entry.name):
                env_files.append(entry)
            if _should_skip_name(entry.name, entry.suffix.lower()):
                continue
            result.files_scanned += 1
            result.findings.extend(scan_file(entry, root))

    for env_file in env_files:
        if not _gitignore_covers(root, env_file.name):
            result.findings.append(_env_finding(env_file.relative_to(root).as_posix()))

    return _finalize(result)


def scan_files(
    files: Iterable[Tuple[str, str]],
    root_label: str = "(uploaded files)",
    exclude: Optional[Iterable[str]] = None,
) -> ScanResult:
    """Scan (relative_path, text) pairs without touching the filesystem.

    Applies the same directory/file skip rules as the disk walker, so a
    caller can pass a whole project verbatim. The .env/.gitignore check
    uses the root .gitignore from the supplied files, if present, and a
    supplied .vibecheckignore is honoured the same way.
    """
    result = ScanResult(root=root_label)
    gitignore_lines: List[str] = []
    env_names: List[str] = []
    pending: List[Tuple[str, str]] = []

    # Two passes: an uploaded .vibecheckignore has to be read before it can be
    # applied, and the caller supplies files in whatever order they arrive.
    materialised = list(files)
    ignore_lines: List[str] = []
    for raw_path, content in materialised:
        if raw_path.replace("\\", "/").strip("/") == IGNORE_FILE:
            ignore_lines = content.splitlines()
            break
    ignored = PathFilter(ignore_lines + list(exclude or []))

    for raw_path, content in materialised:
        norm = raw_path.replace("\\", "/").strip("/")
        if not norm:
            continue
        parts = norm.split("/")
        if any(part in SKIP_DIRS for part in parts[:-1]):
            continue
        if ignored.matches(norm):
            continue
        name = parts[-1]
        if norm == ".gitignore":
            gitignore_lines = content.splitlines()
        if _is_env_file(name) and len(parts) == 1:
            env_names.append(name)
        ext = PurePosixPath(name).suffix.lower()
        if _should_skip_name(name, ext):
            continue
        if len(content.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
            continue
        pending.append((norm, content))

    for norm, content in pending:
        result.files_scanned += 1
        result.findings.extend(scan_text(norm, content))

    for name in env_names:
        if not _gitignore_lines_cover(gitignore_lines, name):
            result.findings.append(_env_finding(name))

    return _finalize(result)
