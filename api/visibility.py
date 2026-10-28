"""Vercel serverless function: POST /api/visibility

Accepts {"url": "https://example.com", "fresh": false} and checks how the
site looks to search engines and AI crawlers: rendering, robots.txt,
sitemap, llms.txt, structured data, titles, link previews, hosts.

With "probe": {"brand", "category", "country", "competitors": [...]} it also
runs phases 3 and 4 (the AI-answer probe and the off-site footprint): five
questions to Claude with web search (VIBECHECK_PROBE_MODEL, default Claude
Haiku 5.5), and seven plain Google searches through Serper when
SERPER_API_KEY is set (else two more Claude calls), all in parallel. Those
cost real money, so they need ANTHROPIC_API_KEY, are limited to PROBE_DAILY_CAP runs a day across
everyone and two a day per visitor, and are cached for 24 hours by URL and
inputs. Over the cap, the report says "back tomorrow" for those categories.

The crawl runs here, server-side, never in the browser. Every request and
every redirect hop goes through the SSRF guard, and connects to the address
the guard vetted. Results are cached for 24 hours by URL; "fresh" skips the
cache (for checking a fix) but not the per-site limit.

When ANTHROPIC_API_KEY is set, the scan also runs the positioning review: one
capped call to Claude about the home page's copy, cached for a week by a hash
of that copy and limited to POSITIONING_DAILY_CAP reviews a day across all
visitors. Over the cap, the Positioning category says so and the rest of the
report is unchanged.
"""

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibecheck.checks.visibility import CHECK  # noqa: E402
from vibecheck.checks.visibility.probe import ProbeInput  # noqa: E402
from vibecheck.checks.visibility.serper import SerperSearch  # noqa: E402
from vibecheck.checks.visibility.websearch import MODEL as PROBE_MODEL, ClaudeSearch  # noqa: E402
from vibecheck.checks.visibility.positioning import (  # noqa: E402
    CACHE_SECONDS as POSITIONING_CACHE_SECONDS,
    CachingReviewer,
    ClaudeReviewer,
)
from vibecheck.checks.visibility.scan import normalise_input  # noqa: E402
from vibecheck.core.cache import ResultCache  # noqa: E402
from vibecheck.core.models import Context, Target  # noqa: E402
from vibecheck.core.netguard import check_url  # noqa: E402
from vibecheck.core.ratelimit import RateLimiter, client_ip  # noqa: E402
from vibecheck.core.signed import with_signatures  # noqa: E402

MAX_BODY_BYTES = 4_000

# A scan is up to ~40 requests at a site the caller chose.
LIMITER = RateLimiter("visibility", [(10, 3600)])
# One scan a minute per target, whoever asks, so we never hammer a site.
HOST_LIMITER = RateLimiter("visibility-host", [(1, 60)])
# A ceiling on all outbound crawling.
GLOBAL_LIMITER = RateLimiter("visibility-global", [(200, 3600)])

CACHE = ResultCache(namespace="vis")

# Claude calls a day, across everyone. A review is a few thousand tokens on
# Claude Haiku, so the default caps the spend at a pound or two a day.
try:
    POSITIONING_DAILY_CAP = int(os.environ.get("POSITIONING_DAILY_CAP", "1000"))
except ValueError:
    POSITIONING_DAILY_CAP = 1000
# A spending cap, so the local-development off switch doesn't lift it.
POSITIONING_LIMITER = RateLimiter("positioning-day", [(POSITIONING_DAILY_CAP, 86400)], disabled=False)
POSITIONING_CACHE = ResultCache(namespace="pos", ttl=POSITIONING_CACHE_SECONDS)


try:
    PROBE_DAILY_CAP = int(os.environ.get("PROBE_DAILY_CAP", "40"))
except ValueError:
    PROBE_DAILY_CAP = 40
# Five web-searching questions a run, plus the footprint's searches: about
# ten pence on Haiku with Serper, so a tighter cap than the copy review.
PROBE_LIMITER = RateLimiter("probe-day", [(PROBE_DAILY_CAP, 86400)], disabled=False)
PROBE_IP_LIMITER = RateLimiter("probe-ip", [(2, 86400)])
MAX_FIELD = 80


def probe_input(raw, url):
    """The probe's inputs from the request, or None. Raises ValueError on junk."""
    if not raw:
        return None
    if not isinstance(raw, dict):
        raise ValueError
    brand, category = raw.get("brand"), raw.get("category")
    comps = raw.get("competitors") or []
    if not isinstance(brand, str) or not isinstance(category, str) or not isinstance(comps, list):
        raise ValueError
    if not brand.strip() or not category.strip() or len(brand) > MAX_FIELD or len(category) > 2 * MAX_FIELD:
        raise ValueError
    if len(comps) > 3 or not all(isinstance(c, str) and len(c) <= 40 for c in comps):
        raise ValueError
    country = raw.get("country") or "GB"
    if not isinstance(country, str) or not country.isalpha() or len(country) != 2:
        raise ValueError
    host = (urlsplit(url).hostname or "").lower()
    return ProbeInput(brand, host, category, country.upper(), comps).clean()


def probe_model():
    """VIBECHECK_PROBE_MODEL when it looks like a Claude model id, else Haiku."""
    model = os.environ.get("VIBECHECK_PROBE_MODEL", "").strip()
    return model if re.fullmatch(r"claude-[a-z0-9-]{1,40}", model) else PROBE_MODEL


def prober():
    if not os.environ.get("ANTHROPIC_API_KEY") or PROBE_DAILY_CAP <= 0:
        return None
    return ClaudeSearch(model=probe_model(), limiter=PROBE_LIMITER)


def finder():
    """Plain search for the footprint, or None to let Claude do it."""
    key = os.environ.get("SERPER_API_KEY", "").strip()
    return SerperSearch(key) if key else None


def reviewer():
    """The positioning reviewer, or None when no key is configured."""
    if not os.environ.get("ANTHROPIC_API_KEY") or POSITIONING_DAILY_CAP <= 0:
        return None
    return CachingReviewer(ClaudeReviewer(limiter=POSITIONING_LIMITER), POSITIONING_CACHE)


def scan(target, probe=None):
    """Separate so tests can swap the network out."""
    options = {}
    if probe is not None:
        search = prober()
        if search is not None:
            options["probe"] = (search, probe)
            plain = finder()
            if plain is not None:
                options["footprint"] = plain
    return CHECK.run(Target(url=target), Context(guard=True, provenance="server", llm=reviewer(),
                                                 options=options))


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        decision = LIMITER.check(client_ip(self.headers))
        if not decision.allowed:
            return self._json(429, {"error": decision.message.replace("scans", "visibility scans")},
                              extra_headers={"Retry-After": str(decision.retry_after)})

        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._json(400, {"error": "Invalid request."})
        try:
            body = json.loads(self.rfile.read(length))
            target = body.get("url")
            if not isinstance(target, str) or not target.strip():
                raise ValueError
            fresh = bool(body.get("fresh"))
        except (ValueError, AttributeError, json.JSONDecodeError):
            return self._json(400, {"error": "Please provide a URL to check."})
        try:
            probe = probe_input(body.get("probe"), normalise_input(target))
        except ValueError:
            return self._json(400, {"error": "The AI check needs a brand (80 characters at most), a category, "
                                             "a two-letter country and up to three competitors."})

        target = normalise_input(target)
        ok, reason = check_url(target)
        if not ok:
            return self._json(400, {"error": reason})

        parts = urlsplit(target)
        cache_url = f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path or '/'}"
        if probe is not None:
            cache_url += "#probe=" + json.dumps([probe.brand, probe.category, probe.country, probe.competitors,
                                                 probe_model()])
        if not fresh:
            cached = CACHE.get(cache_url)
            if cached:
                cached["cached"] = True
                return self._json(200, cached)

        host = (parts.hostname or "").lower()
        host = host[4:] if host.startswith("www.") else host
        decision = HOST_LIMITER.check(host)
        if decision.allowed:
            decision = GLOBAL_LIMITER.check("all")
        if not decision.allowed:
            return self._json(429, {"error": f"That site was checked moments ago. Try again in {decision.retry_after}s."},
                              extra_headers={"Retry-After": str(decision.retry_after)})
        if probe is not None:
            per_ip = PROBE_IP_LIMITER.check(client_ip(self.headers))
            if not per_ip.allowed:
                return self._json(429, {"error": "That's your two AI checks for today. The rest of the check "
                                                 "still works without the brand fields."},
                                  extra_headers={"Retry-After": str(per_ip.retry_after)})

        payload = with_signatures(scan(target, probe) if probe is not None else scan(target))
        payload["cached"] = False
        CACHE.set(cache_url, payload)
        return self._json(200, payload)

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

    def log_message(self, *args):  # never log scanned URLs
        pass
