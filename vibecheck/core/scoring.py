"""Scores, grades and badge levels, the same way for every check."""

from __future__ import annotations

from typing import Dict, Iterable, Optional, Sequence

from .models import Category, Finding

# Points a category (out of 10) loses per finding in it.
CATEGORY_PENALTY = {"critical": 10, "high": 4, "medium": 2, "low": 1, "info": 0, "pass": 0}

GRADES = ((90, "A"), (75, "B"), (60, "C"), (40, "D"))

# Badge levels: a total AND a ceiling on what may still be open (plan §0.6).
LEVELS = (
    ("gold", 85, ("critical", "high")),
    ("silver", 70, ("critical",)),
    ("bronze", 50, ("critical",)),
)


def category_scores(findings: Iterable[Finding], categories: Sequence[Category],
                    ran: Iterable[str]) -> Dict[str, Optional[int]]:
    """Each category that ran starts at 10 and loses CATEGORY_PENALTY per
    finding in it, floored at 0. One that didn't run is None, not 0."""
    ran = set(ran)
    findings = list(findings)
    scores: Dict[str, Optional[int]] = {}
    for cat in categories:
        if cat.id not in ran:
            scores[cat.id] = None
            continue
        penalty = sum(CATEGORY_PENALTY.get(f.severity, 0) for f in findings if f.category == cat.id)
        scores[cat.id] = max(0, 10 - penalty)
    return scores


def weighted_total(scores: Dict[str, Optional[int]], categories: Sequence[Category]) -> Optional[int]:
    """Weighted mean of the categories that ran, scaled to 0-100."""
    scored = [(c.weight, scores[c.id]) for c in categories if scores.get(c.id) is not None]
    weight = sum(w for w, _ in scored)
    if not scored or weight <= 0:
        return None
    return round(sum(w * s for w, s in scored) / weight * 10)


def grade_for(total: Optional[int]) -> str:
    if total is None:
        return "–"
    for threshold, letter in GRADES:
        if total >= threshold:
            return letter
    return "F"


def badge_level(total: Optional[int], severities: Iterable[str]) -> Optional[str]:
    """gold / silver / bronze, or None. Open findings cap the level whatever
    the total says."""
    if total is None:
        return None
    open_ = set(severities)
    for level, minimum, blocked_by in LEVELS:
        if total >= minimum and not (open_ & set(blocked_by)):
            return level
    return None
