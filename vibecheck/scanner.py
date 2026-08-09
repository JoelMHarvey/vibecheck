"""Walks a project directory and applies the detection rules."""

from __future__ import annotations

import base64
import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

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


def is_frontend_path(rel_path: Path) -> bool:
    if rel_path.suffix.lower() in FRONTEND_EXTS:
        return True
    return any(part.lower() in FRONTEND_DIR_HINTS for part in rel_path.parts[:-1])


def _is_env_file(name: str) -> bool:
    if not name.startswith(".env"):
        return False
    lowered = name.lower()
    return not any(hint in lowered for hint in ("example", "sample", "template", "test"))


def _should_skip_file(path: Path) -> bool:
    name = path.name
    if name in SKIP_FILE_NAMES:
        return True
    if name.endswith(SKIP_FILE_SUFFIXES):
        return True
    if path.suffix.lower() in BINARY_EXTS:
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


def scan_file(path: Path, root: Path) -> List[Finding]:
    rel = path.relative_to(root)
    rel_str = rel.as_posix()
    ext = path.suffix.lower()
    frontend = is_frontend_path(rel)
    in_env_file = _is_env_file(path.name)

    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if "\x00" in text[:1024]:
        return []

    findings: List[Finding] = []
    per_rule_counts: dict = {}

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
            continue
        for rule in applicable:
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

                if effective_rule.frontend_boost and frontend:
                    severity = _SEVERITY_BUMP[severity]

                excerpt = _redact(line, match) if effective_rule.is_secret else _sanitize_excerpt(line)[:200]
                findings.append(_make_finding(effective_rule, rel_str, line_no, excerpt, severity))
                per_rule_counts[rule.id] = per_rule_counts.get(rule.id, 0) + 1

    return findings


def _gitignore_covers(root: Path, filename: str) -> bool:
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return False
    try:
        lines = gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False
    for raw in lines:
        pattern = raw.strip().rstrip("/")
        if not pattern or pattern.startswith("#"):
            continue
        pattern = pattern.lstrip("/")
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


def scan(root_path: str) -> ScanResult:
    root = Path(root_path).resolve()
    result = ScanResult(root=str(root))
    env_files: List[Path] = []

    if root.is_file():
        result.findings.extend(scan_file(root, root.parent))
        result.files_scanned = 1
        result.findings.sort(key=Finding.sort_key)
        return result

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
                if entry.name not in SKIP_DIRS:
                    stack.append(entry)
                continue
            if not entry.is_file():
                continue
            if _is_env_file(entry.name):
                env_files.append(entry)
            if _should_skip_file(entry):
                continue
            result.files_scanned += 1
            result.findings.extend(scan_file(entry, root))

    for env_file in env_files:
        if not _gitignore_covers(root, env_file.name):
            rel = env_file.relative_to(root).as_posix()
            result.findings.append(
                Finding(
                    rule_id=ENV_NOT_IGNORED.id,
                    title=ENV_NOT_IGNORED.title,
                    severity=ENV_NOT_IGNORED.severity,
                    path=rel,
                    line=1,
                    excerpt="(file-level finding)",
                    description=ENV_NOT_IGNORED.description,
                    fix_prompt=ENV_NOT_IGNORED.fix_prompt.format(path=rel, line=1),
                )
            )

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
