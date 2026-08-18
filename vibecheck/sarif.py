"""Render scan results as SARIF 2.1.0.

SARIF is what GitHub code scanning consumes, so this is how findings become
annotations on the pull request diff and entries in the repository's Security
tab — rather than something a developer only sees if they open the job log.

The interesting part is `help.markdown`: GitHub renders it on the alert page,
so each alert carries its own paste-ready fix prompt.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List

from .scanner import ScanResult

TOOL_NAME = "vibecheck"
TOOL_URI = "https://psychosecurity.io"

# SARIF has three levels; we have five severities.
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub reads `security-severity` (a CVSS-like number) to decide which
# severity badge an alert gets, and repositories can require a minimum before
# a check fails. These are chosen to land in GitHub's own bands:
# 9.0+ critical, 7.0+ high, 4.0+ medium, 0.1+ low.
SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.0",
    "info": "0.5",
}

# Severity ordering, most severe first — local so this module stays
# independent of the rules table.
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _fingerprint(rule_id: str, path: str, excerpt: str) -> str:
    """Stable id so GitHub tracks one alert across commits rather than
    closing and reopening it every push."""
    digest = hashlib.sha256(f"{rule_id}\n{path}\n{excerpt}".encode("utf-8"))
    return digest.hexdigest()[:16]


def _help_markdown(finding) -> str:
    body = finding.description
    if finding.fix_prompt:
        body += (
            "\n\n**Fix prompt** — paste this into Cursor, Claude Code, Lovable, "
            "Bolt or v0:\n\n```text\n" + finding.fix_prompt + "\n```"
        )
    body += f"\n\n[Scan your whole project with vibecheck]({TOOL_URI})"
    return body


def to_sarif_dict(result: ScanResult, version: str, path_prefix: str = "") -> dict:
    """Build the SARIF document.

    ``path_prefix`` is prepended to every finding path. Findings are relative
    to the scanned directory, but code scanning resolves URIs against the
    repository root — so scanning a subdirectory needs the prefix to make the
    annotations land on the right lines.
    """
    prefix = path_prefix.replace("\\", "/").strip("/")
    if prefix:
        prefix += "/"

    # One SARIF rule per rule_id, described by the first finding that used it.
    # A rule's severity can be escalated per-finding (a key in frontend code is
    # worse than the same key in a server file), so the rule-level number takes
    # the most severe occurrence in this run while each result keeps its own
    # accurate level.
    # Informational findings are left out of SARIF entirely.
    #
    # Code scanning is an alert queue, and GitHub turns its alerts into inline
    # review comments on the pull request. A finding worth zero points — a
    # credential in a test fixture, say — becomes a comment telling the author
    # to rotate a key that was never real. That is the same cry-wolf failure
    # that gets scanners switched off, arriving through a different door.
    #
    # They are not lost: the job summary, the PR comment and the JSON report
    # all still carry them. Only the alert queue is kept for things that are
    # actually alerts.
    reportable = [f for f in result.findings if f.severity != "info"]

    rules: List[dict] = []
    rule_index: Dict[str, int] = {}
    rule_worst: Dict[str, str] = {}

    for f in reportable:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rule_worst[f.rule_id] = f.severity
            rules.append(
                {
                    "id": f.rule_id,
                    "name": f.rule_id.replace(".", "_"),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "help": {"text": f.description, "markdown": _help_markdown(f)},
                    "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
                    "properties": {
                        "tags": ["security", "vibecheck"],
                        "security-severity": SECURITY_SEVERITY[f.severity],
                    },
                }
            )
        elif _RANK[f.severity] < _RANK[rule_worst[f.rule_id]]:
            rule_worst[f.rule_id] = f.severity
            rule = rules[rule_index[f.rule_id]]
            rule["defaultConfiguration"]["level"] = SARIF_LEVEL[f.severity]
            rule["properties"]["security-severity"] = SECURITY_SEVERITY[f.severity]

    results = []
    for f in reportable:
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title} — {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": prefix + f.path},
                            # Code scanning rejects a region with startLine 0.
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "partialFingerprints": {
                    "vibecheckFingerprint/v1": _fingerprint(f.rule_id, prefix + f.path, f.excerpt)
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "version": version,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(result: ScanResult, version: str, path_prefix: str = "") -> str:
    return json.dumps(to_sarif_dict(result, version, path_prefix), indent=2) + "\n"
