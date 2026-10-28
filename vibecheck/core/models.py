"""The shapes every check shares: what it scans, what it finds, what it returns.

A check is a plugin (see ``Check``). It takes a ``Target`` and a
``Context`` and returns a ``CheckResult`` made of ``Finding``s. The report
renderers, the CLI, the web page and the badges only ever see these types,
so a new check is a new folder under ``vibecheck/checks/``, not a rewrite.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

try:  # typing.Protocol is 3.8+; runtime_checkable keeps isinstance() honest.
    from typing import Protocol, runtime_checkable
except ImportError:  # pragma: no cover
    Protocol = object  # type: ignore

    def runtime_checkable(cls):  # type: ignore
        return cls

# "pass" is a finding too: a check that went right. "info" is reported and
# never scored (security's informational notes, visibility's AI-crawler list).
SEVERITIES = ("critical", "high", "medium", "low", "info", "pass")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
PROBLEM_SEVERITIES = SEVERITIES[:5]


@dataclass(frozen=True)
class Category:
    id: str
    label: str
    weight: float = 1.0


@dataclass
class Target:
    """What a check runs against: a URL, a repository, or both.

    ``repo`` is a local folder (the CLI), an uploaded folder (the web page,
    files held in memory as ``files``) or a GitHub clone. ``commit`` is the
    SHA the repository was at, when there is one.
    """

    url: Optional[str] = None
    repo: Optional[str] = None
    commit: Optional[str] = None
    files: Optional[Sequence[tuple]] = None   # (path, text) pairs for an upload
    label: Optional[str] = None               # how to name an upload in a report

    @property
    def inputs(self) -> set:
        got = set()
        if self.url:
            got.add("url")
        if self.repo or self.files is not None:
            got.add("repo")
        return got

    def to_dict(self) -> dict:
        out: Dict[str, Any] = {}
        if self.url:
            out["url"] = self.url
        if self.repo or self.files is not None:
            out["repo"] = self.label or self.repo or "uploaded files"
        if self.commit:
            out["commit"] = self.commit
        return out


@dataclass
class Finding:
    """One thing a check found, good or bad.

    ``evidence`` is a redacted excerpt or a URL; ``path``/``line`` say where
    (a file and line for code, a page path for a site, line 0 when there's
    no line).
    """

    id: str
    check_id: str
    category: str
    severity: str
    title: str
    why_it_matters: str = ""
    evidence: str = ""
    fix_prompt: str = ""
    verify_hint: str = ""
    guide_url: Optional[str] = None
    path: str = ""
    line: int = 0

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path

    @property
    def is_problem(self) -> bool:
        return self.severity not in ("pass",)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "check_id": self.check_id, "category": self.category,
            "severity": self.severity, "title": self.title, "why_it_matters": self.why_it_matters,
            "evidence": self.evidence, "fix_prompt": self.fix_prompt, "verify_hint": self.verify_hint,
            "guide_url": self.guide_url, "path": self.path, "line": self.line,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**{k: d.get(k, v) for k, v in _FINDING_DEFAULTS.items()})


_FINDING_DEFAULTS = {
    "id": "", "check_id": "", "category": "", "severity": "info", "title": "", "why_it_matters": "",
    "evidence": "", "fix_prompt": "", "verify_hint": "", "guide_url": None, "path": "", "line": 0,
}


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def iso(ts: _dt.datetime) -> str:
    return ts.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class CheckResult:
    check_id: str
    check_version: str
    target: Target
    scanned_at: str                                   # UTC, ISO 8601, second precision
    category_scores: Dict[str, Optional[int]] = field(default_factory=dict)  # None: didn't run
    total: Optional[int] = None                       # 0-100; None when nothing could be checked
    findings: List[Finding] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)  # e.g. files scanned, pages crawled

    @property
    def problems(self) -> List[Finding]:
        return [f for f in self.findings if f.severity != "pass"]

    @property
    def passes(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "pass"]

    @property
    def counts(self) -> Dict[str, int]:
        counts = {s: 0 for s in PROBLEM_SEVERITIES}
        for f in self.problems:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def grade(self) -> str:
        from .scoring import grade_for
        return grade_for(self.total)

    def has_severity(self, *severities: str) -> bool:
        return any(f.severity in severities for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "check_version": self.check_version,
            "target": self.target.to_dict(),
            "scanned_at": self.scanned_at,
            "category_scores": dict(self.category_scores),
            "total": self.total,
            "grade": self.grade,
            "counts": self.counts,
            "meta": dict(self.meta),
            "findings": [f.to_dict() for f in self.findings],
        }


@runtime_checkable
class Check(Protocol):
    """The plugin contract. One instance per check, registered in
    ``vibecheck.core.registry``."""

    id: str                      # "security" | "visibility" | "integrity"
    version: str                 # semver; bump when scoring changes
    inputs: set                  # subset of {"url", "repo"}: any one is enough
    categories: List[Category]
    title: str                   # shown in reports and the CLI

    def run(self, target: Target, ctx: "Context") -> CheckResult: ...


Fetcher = Callable[..., Any]


@dataclass
class Context:
    """What a check may use, so no check reaches for the network or the disk
    on its own terms.

    ``fetcher(**options)`` returns a fetch function: guarded and pinned when
    ``guard`` is on (anything hosted), plain urllib for the CLI. Tests set
    ``fetch_override`` to a fake site. ``walker`` walks a folder with the
    shared skip rules. ``llm`` is an optional model client, for checks that
    use one (visibility's positioning review takes a reviewer here; the caller
    owns its budget and cache).
    """

    guard: bool = True
    now: Optional[_dt.datetime] = None
    fetch_override: Optional[Fetcher] = None
    exclude: Sequence[str] = ()
    llm: Any = None
    budget: Optional[float] = None
    options: Dict[str, Any] = field(default_factory=dict)   # per-check extras, e.g. visibility's "probe"
    provenance: str = "self"     # "server" | "ci" | "self": who ran the scan

    def fetcher(self, **options) -> Fetcher:
        if self.fetch_override is not None:
            return self.fetch_override
        from .fetcher import build_fetcher
        return build_fetcher(guard=self.guard, **options)

    @property
    def walker(self):
        from . import walker
        return walker

    def timestamp(self) -> _dt.datetime:
        return (self.now or utc_now()).astimezone(_dt.timezone.utc).replace(microsecond=0)
