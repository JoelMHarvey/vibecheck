"""Vercel serverless function: POST /api/vibechecked

{"reports": [signed report envelopes]} -> the "vibechecked" badge, when
every check available for the target passed at bronze or above, all signed
by us, for the same target, within the last 30 days.

Stateless: the reports come in with the request, are verified against our
own key, and the combined badge goes back signed. Nothing is stored.
"""

import datetime as dt
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibecheck.core import badge, registry, signing  # noqa: E402
from vibecheck.core.models import Target  # noqa: E402
from vibecheck.core.ratelimit import RateLimiter, client_ip  # noqa: E402

MAX_BODY_BYTES = 300_000
LIMITER = RateLimiter("vibechecked", [(30, 60)])


def required_checks(report_envelopes):
    """Every check we could have signed for the target: a URL target needs
    every hosted URL check, a repo target every hosted repo check. Integrity
    never runs here, so it can't be required."""
    try:
        target = json.loads(report_envelopes[0]["p"])["target"]
    except (ValueError, KeyError, TypeError, IndexError):
        return []
    t = Target(url=target.get("url"), repo=target.get("repo"), commit=target.get("commit"))
    return [c.id for c in registry.hosted_for(t)]


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        decision = LIMITER.check(client_ip(self.headers))
        if not decision.allowed:
            return self._json(429, {"error": decision.message}, {"Retry-After": str(decision.retry_after)})
        signer = signing.load_signer()
        if signer is None:
            return self._json(503, {"error": "Badges aren't being signed on this server yet."})
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._json(400, {"error": "Invalid request."})
        try:
            reports = json.loads(self.rfile.read(length))["reports"]
            if not isinstance(reports, list) or not 1 <= len(reports) <= 5 or \
                    not all(isinstance(r, dict) for r in reports):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self._json(400, {"error": "Send the signed reports to combine."})

        claim, reason = badge.combined_claim(reports, signing.public_keys(signer=signer),
                                             dt.datetime.now(dt.timezone.utc), required_checks(reports))
        if claim is None:
            return self._json(400, {"error": "No vibechecked badge yet: " + reason + "."})
        envelope = signer.envelope(signing.BADGE, claim)
        return self._json(200, {"badge": envelope,
                                "markdown": badge.badge_markdown("vibechecked", envelope, reports)})

    def _json(self, code, payload, extra_headers=None):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass
