"""Walk a project folder the same way for every check.

Skips dependency and build folders, lockfiles, minified bundles, binaries and
anything a .vibecheckignore or --exclude names; never follows symlinks.
``redact`` is the one way a check puts a secret-shaped value into a report.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

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
    "vendored",
    "third_party",
    "bower_components",
    ".yarn",
    "Pods",
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

MAX_FILE_BYTES = 1_000_000

IGNORE_FILE = ".vibecheckignore"


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


def _should_skip_name(name: str, ext: str) -> bool:
    if name in SKIP_FILE_NAMES:
        return True
    if name.endswith(SKIP_FILE_SUFFIXES):
        return True
    if ext in BINARY_EXTS:
        return True
    return False



@dataclass
class Entry:
    path: Path
    rel: str          # posix-style, relative to the root
    skipped: bool     # a lockfile, bundle or binary: listed, not read


def walk(root: Path, exclude: Optional[Iterable[str]] = None) -> Iterator[Entry]:
    """Every file under ``root`` that isn't excluded, depth-first and in
    sorted order. Skippable files are yielded with ``skipped=True`` because
    some checks still care that they exist (a committed .env, a lockfile)."""
    ignored = PathFilter(_read_ignore_file(root) + list(exclude or []))
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
            yield Entry(entry, rel, _should_skip_name(entry.name, entry.suffix.lower()))


def read_text(path: Path) -> Optional[str]:
    """A file's text, or None when it's too big or unreadable."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def redact(value: str, keep: int = 6) -> str:
    """The first few characters of a secret, then a marker. Enough to tell
    which key it was; not enough to use it."""
    return value[:keep] + "…[redacted]"


def redact_patterns(line: str, patterns: Iterable["re.Pattern[str]"]) -> str:
    for pattern in patterns:
        line = pattern.sub(lambda m: redact(m.group(0)), line)
    return line


def git_commit(root: Path) -> Optional[str]:
    """The commit SHA a working tree is at, read from .git without running
    git, looking upward from ``root`` the way git does. None when it isn't in
    a repository or the ref can't be found."""
    root = Path(root).resolve()
    for candidate in (root, *root.parents):  # a subfolder pins to its checkout
        if (candidate / ".git").exists():
            root = candidate
            break
    git = root / ".git"
    try:
        if git.is_file():  # a worktree or submodule: "gitdir: <path>"
            pointer = git.read_text(encoding="utf-8").strip()
            if pointer.startswith("gitdir:"):
                git = (root / pointer.split(":", 1)[1].strip()).resolve()
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return head if re.fullmatch(r"[0-9a-f]{40}", head) else None
        ref = head.split(":", 1)[1].strip()
        loose = git / ref
        if loose.is_file():
            return loose.read_text(encoding="utf-8").strip() or None
        packed = git / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0]
    except OSError:
        return None
    return None
