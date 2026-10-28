"""Badges that can be checked (plan §0.6).

- Every badge links to its report; the report is the claim, the image isn't.
- Server scans are signed (see signing.py). The report page verifies and says
  "verified" or "tampered".
- Badges show the scan date and turn grey 30 days after it.
- URL checks pin the final URL after redirects; repo checks pin the commit.
- Levels need a total AND no open criticals (scoring.badge_level).
- Who ran the scan is on the badge: our server (signed), a GitHub Actions run
  (unsigned, with the run's URL) or someone's own machine ("self-reported").

Nothing is stored. A badge URL carries its signed claim
(/badge/<check>.svg?r=...), a report link carries the signed report in its
fragment (/report#r=...). The cost: a badge can't be revoked early, only
expire.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import html
import json
import re
from typing import Dict, List, Optional, Sequence, Tuple

from . import signing
from .models import CheckResult
from .report import level as result_level

SITE = "https://www.psychosecurity.io"
EXPIRY_DAYS = 30
LEVEL_ORDER = ["bronze", "silver", "gold"]
RUN_URL_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/actions/runs/\d+(/attempts/\d+)?$")
CHECK_IDS = {"security", "visibility", "vibechecked"}
MAX_PARAM = 4000

COLORS = {"gold": "#c9a227", "silver": "#8f98a6", "bronze": "#b0703a", "grey": "#9f9f9f"}
SCORE_COLORS = [(90, "#3fb950"), (75, "#9acd32"), (60, "#d29922"), (40, "#db8a34"), (0, "#f85149")]


# ---- time ----------------------------------------------------------------

def parse_ts(text: str) -> _dt.datetime:
    return _dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)


def fmt_ts(ts: _dt.datetime) -> str:
    return ts.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def expires(scanned_at: str) -> str:
    return fmt_ts(parse_ts(scanned_at) + _dt.timedelta(days=EXPIRY_DAYS))


def is_expired(claim: dict, now: _dt.datetime) -> bool:
    try:
        return now >= parse_ts(claim["expires_at"])
    except (KeyError, ValueError, TypeError):
        return True


# ---- provenance ----------------------------------------------------------

def provenance(by: str, run: Optional[str] = None) -> dict:
    if by == "ci" and run and RUN_URL_RE.match(run):
        return {"by": "ci", "run": run}
    return {"by": "server"} if by == "server" else {"by": "self"}


def ci_provenance(env) -> dict:
    """A GitHub Actions run names itself; anywhere else is self-reported."""
    if env.get("GITHUB_ACTIONS") == "true" and env.get("GITHUB_RUN_ID") and env.get("GITHUB_REPOSITORY"):
        server = env.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
        return provenance("ci", f"{server}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}")
    return provenance("self")


# ---- claims ----------------------------------------------------------------

def report_claim(result: CheckResult, prov: dict) -> dict:
    return {
        "v": 1,
        "check": result.check_id,
        "check_version": result.check_version,
        "target": result.target.to_dict(),
        "scanned_at": result.scanned_at,
        "expires_at": expires(result.scanned_at),
        "total": result.total,
        "category_scores": dict(result.category_scores),
        "level": result_level(result),
        "meta": dict(result.meta),
        "provenance": prov,
        "findings": [[f.id, f.severity, f.path, f.line, f.evidence] for f in result.findings],
    }


def badge_claim(report_envelope: dict) -> dict:
    claim = json.loads(report_envelope["p"])
    return {
        "v": 1,
        "check": claim["check"],
        "target": claim["target"],
        "scanned_at": claim["scanned_at"],
        "expires_at": claim["expires_at"],
        "total": claim["total"],
        "level": claim["level"],
        "provenance": claim["provenance"],
        "report": signing.digest(report_envelope["p"]),
    }


def sign_result(result: CheckResult, signer: Optional[signing.Signer], prov: dict) -> Dict[str, dict]:
    """The signed report and badge for a result. Without a signer (no key
    configured, or the CLI) both are unsigned and say who ran the scan."""
    rc = report_claim(result, prov)
    if signer is None:
        report = signing.unsigned_envelope(rc)
        return {"report": report, "badge": signing.unsigned_envelope(badge_claim(report))}
    report = signer.envelope(signing.REPORT, rc)
    return {"report": report, "badge": signer.envelope(signing.BADGE, badge_claim(report))}


def same_target(a: dict, b: dict) -> bool:
    def norm(t):
        url = (t.get("url") or "").lower()
        host = re.sub(r"^https?://", "", url).split("/")[0]
        host = host[4:] if host.startswith("www.") else host
        return (host, t.get("repo"), t.get("commit"))
    return norm(a) == norm(b)


def combined_claim(report_envelopes: Sequence[dict], keys: List[dict], now: _dt.datetime,
                   required: Sequence[str]) -> Tuple[Optional[dict], str]:
    """The "vibechecked" badge: every available check, same target, all
    signed by us, none expired, each at bronze or above. Returns (claim,
    reason it was refused)."""
    claims = []
    for env in report_envelopes:
        status = signing.verify_envelope(env, signing.REPORT, keys)
        if status != signing.VERIFIED:
            return None, f"a report is {status}; only reports signed by psychosecurity.io count"
        claims.append(json.loads(env["p"]))
    have = {c["check"] for c in claims}
    missing = [c for c in required if c not in have]
    if missing:
        return None, "needs every check for this target; missing " + ", ".join(missing)
    if len(claims) != len(have):
        return None, "one report per check"
    if not all(same_target(claims[0]["target"], c["target"]) for c in claims):
        return None, "the reports are for different targets"
    if any(is_expired(c, now) for c in claims):
        return None, "a report is more than 30 days old; rescan"
    if any(c.get("level") not in LEVEL_ORDER for c in claims):
        weak = [c["check"] for c in claims if c.get("level") not in LEVEL_ORDER]
        return None, "every check needs bronze or above; not yet: " + ", ".join(weak)
    oldest = min(claims, key=lambda c: c["scanned_at"])
    lowest = min((c["level"] for c in claims), key=LEVEL_ORDER.index)
    return {
        "v": 1,
        "check": "vibechecked",
        "target": oldest["target"],
        "scanned_at": oldest["scanned_at"],
        "expires_at": oldest["expires_at"],
        "total": None,
        "level": lowest,
        "checks": {c["check"]: c["level"] for c in sorted(claims, key=lambda c: c["check"])},
        "provenance": {"by": "server"},
        "report": [signing.digest(e["p"]) for e in report_envelopes],
    }, ""


# ---- links ------------------------------------------------------------------

def encode_report_link(envelopes: Sequence[dict]) -> str:
    """The #r= value of a /report link: v3, gzip + base64url, as report.js reads it."""
    raw = json.dumps({"v": 3, "e": list(envelopes)}, separators=(",", ":")).encode("utf-8")
    return "z" + signing.b64url(gzip.compress(raw, mtime=0))


def decode_report_link(value: str) -> List[dict]:
    data = signing.unb64url(value[1:])
    if value[0] == "z":
        data = gzip.decompress(data)
    payload = json.loads(data)
    if payload.get("v") != 3:
        raise ValueError("not a signed report link")
    return payload["e"]


def encode_badge_param(envelope: dict) -> str:
    return signing.b64url(signing.canonical(envelope).encode("utf-8"))


def decode_badge_param(value: str) -> dict:
    if len(value) > MAX_PARAM:
        raise ValueError("badge parameter too long")
    env = json.loads(signing.unb64url(value))
    if not isinstance(env, dict) or not isinstance(env.get("p"), str):
        raise ValueError("not a badge")
    return env


def badge_markdown(check_id: str, badge_env: dict, report_envs: Sequence[dict], site: str = SITE) -> str:
    claim = json.loads(badge_env["p"])
    alt = f"vibecheck {check_id}: {claim.get('level') or 'no badge yet'}"
    return (f"[![{alt}]({site}/badge/{check_id}.svg?r={encode_badge_param(badge_env)})]"
            f"({site}/report#r={encode_report_link(report_envs)})")


# ---- the image ----------------------------------------------------------------

def _score_color(score: int) -> str:
    return next(c for t, c in SCORE_COLORS if score >= t)


def svg(label: str, value: str, color: str) -> str:
    label, value = html.escape(label), html.escape(value)
    lw = 7 * len(label) + 12
    vw = 7 * len(value) + 14
    total = lw + vw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" '
        f'aria-label="{label}: {value}"><title>{label}: {value}</title>'
        f'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/><rect width="{total}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>'
        f'<text x="{lw / 2}" y="14">{label}</text>'
        f'<text x="{lw + vw / 2}" y="15" fill="#010101" fill-opacity=".3">{value}</text>'
        f'<text x="{lw + vw / 2}" y="14">{value}</text></g></svg>'
    )


def badge_view(check_id: str, envelope: Optional[dict], keys: List[dict],
               now: _dt.datetime) -> Tuple[str, str, str]:
    """(label, value, color) for a badge. Every string here is built from
    parsed, whitelisted values; nothing from the URL reaches the image as is."""
    check = check_id if check_id in CHECK_IDS else "vibecheck"
    label = "vibechecked" if check == "vibechecked" else f"vibecheck {check}"
    if envelope is None:
        return label, "unverified", COLORS["grey"]
    status = signing.verify_envelope(envelope, signing.BADGE, keys)
    try:
        claim = json.loads(envelope["p"])
    except (ValueError, TypeError):
        return label, "unverified", COLORS["grey"]
    if claim.get("check") != check_id:
        return label, "unverified", COLORS["grey"]
    prov = claim.get("provenance") or {}
    signed = status == signing.VERIFIED and prov.get("by") == "server"
    if status in (signing.TAMPERED, signing.UNKNOWN_KEY) or (status == signing.VERIFIED and not signed):
        return label, "unverified", COLORS["grey"]
    if is_expired(claim, now):
        return label, "expired · rescan", COLORS["grey"]

    level = claim.get("level") if claim.get("level") in LEVEL_ORDER else None
    total = claim.get("total")
    parts = []
    if level:
        parts.append(level)
    elif isinstance(total, int) and 0 <= total <= 100:
        parts.append(f"{total}/100")
    else:
        parts.append("no level")
    commit = (claim.get("target") or {}).get("commit") or ""
    if re.fullmatch(r"[0-9a-f]{7,40}", commit):
        parts.append(f"commit {commit[:7]}")
    try:
        when = parse_ts(claim["scanned_at"])
        parts.append(f"{when.day} {when.strftime('%b %Y')}")
    except (KeyError, ValueError, TypeError):
        return label, "unverified", COLORS["grey"]
    if not signed:
        parts.append({"ci": "CI run", "self": "self-reported"}.get(prov.get("by"), "unsigned"))
    color = COLORS[level] if level else (_score_color(total) if isinstance(total, int) else COLORS["grey"])
    return label, " · ".join(parts), color


def render(check_id: str, param: Optional[str], keys: List[dict], now: _dt.datetime) -> str:
    try:
        envelope = decode_badge_param(param) if param else None
    except (ValueError, TypeError):
        envelope = None
    return svg(*badge_view(check_id, envelope, keys, now))
