"""Which build of vibecheck is this?

The version (``__version__``) names a release. It cannot tell a copy
installed from the release tag from one installed from ``main`` a month
later, and scores are only comparable when they come from the same scanner.
So reports also carry the commit, when it can be found.

Three ways a copy reaches someone, and where each one's commit is read:

- a git checkout (``python -m vibecheck`` in a clone): ``.git`` next to the
  package;
- an archive of the repository, which is how GitHub hands an action to a
  runner: ``_ARCHIVE_COMMIT`` below, filled in by ``git archive`` because
  ``.gitattributes`` marks this file ``export-subst``;
- ``pip install git+https://...``: the ``direct_url.json`` pip writes beside
  the installed package.

Standard library only, and it never raises: a copy whose commit cannot be
found reports the version alone.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from . import __version__

# `git archive` replaces the placeholder with the full commit hash. In a
# checkout it stays as written, which is how the two are told apart.
_ARCHIVE_COMMIT = "$Format:%H$"

_HEX = re.compile(r"^[0-9a-f]{7,64}$")
_PACKAGE_DIR = Path(__file__).resolve().parent

_cached: Optional[str] = None
_looked = False


def _clean(value: object) -> Optional[str]:
    text = str(value or "").strip().lower()
    return text if _HEX.match(text) else None


def _from_checkout(package_dir: Path) -> Optional[str]:
    """HEAD of the git checkout this package sits in, read without running git."""
    git = package_dir.parent / ".git"
    try:
        if git.is_file():  # a worktree or submodule: "gitdir: <path>"
            pointer = git.read_text(encoding="utf-8").strip()
            if not pointer.startswith("gitdir:"):
                return None
            git = (git.parent / pointer[len("gitdir:"):].strip()).resolve()
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return _clean(head)
        ref = head[len("ref:"):].strip()
        # A worktree keeps HEAD in its own folder and the refs in the main one.
        common = git
        commondir = git / "commondir"
        if commondir.is_file():
            common = (git / commondir.read_text(encoding="utf-8").strip()).resolve()
        for base in (git, common):
            loose = base / ref
            if loose.is_file():
                return _clean(loose.read_text(encoding="utf-8"))
        packed = common / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                parts = line.split(" ", 1)
                if len(parts) == 2 and parts[1].strip() == ref:
                    return _clean(parts[0])
    except (OSError, ValueError):
        return None
    return None


def _from_archive(value: str = _ARCHIVE_COMMIT) -> Optional[str]:
    return None if value.startswith("$Format") else _clean(value)


def _from_pip(package_dir: Path) -> Optional[str]:
    """The commit pip recorded, but only if that install is this copy."""
    try:
        from importlib import metadata

        dist = metadata.distribution("vibecheck-scanner")
        if Path(str(dist.locate_file("vibecheck"))).resolve() != package_dir:
            return None
        raw = dist.read_text("direct_url.json")
        if not raw:
            return None
        return _clean((json.loads(raw).get("vcs_info") or {}).get("commit_id"))
    except Exception:  # noqa: BLE001 - a version string must never break a scan
        return None


def commit() -> Optional[str]:
    """The full commit hash this copy was built from, or None if unknown."""
    global _cached, _looked
    if not _looked:
        _cached = (_from_checkout(_PACKAGE_DIR) or _from_archive()
                   or _from_pip(_PACKAGE_DIR))
        _looked = True
    return _cached


def full_version() -> str:
    """``1.1.0+3a83b0d`` when the commit is known, else ``1.1.0``."""
    sha = commit()
    return f"{__version__}+{sha[:7]}" if sha else __version__


def scanner_info() -> dict:
    """What a machine-readable report says about the scanner that made it."""
    return {"name": "vibecheck", "version": __version__, "commit": commit()}
