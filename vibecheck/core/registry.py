"""Every check vibecheck knows about, in the order reports show them."""

from __future__ import annotations

from typing import Dict, List

from .models import Check, Target


def checks() -> Dict[str, Check]:
    from ..checks.integrity import CHECK as integrity
    from ..checks.security import CHECK as security
    from ..checks.visibility import CHECK as visibility

    return {c.id: c for c in (security, visibility, integrity)}


def get(check_id: str) -> Check:
    try:
        return checks()[check_id]
    except KeyError:
        raise KeyError(f"unknown check '{check_id}' (known: {', '.join(checks())})") from None


def available_for(target: Target) -> List[Check]:
    """The checks this target can satisfy: a check needs any one of its inputs."""
    have = target.inputs
    return [c for c in checks().values() if c.inputs & have]


def hosted_for(target: Target) -> List[Check]:
    """The checks psychosecurity.io itself runs (and signs) for this target.
    Integrity runs only where the code is, so it's never one of them."""
    return [c for c in available_for(target) if getattr(c, "hosted", True)]
