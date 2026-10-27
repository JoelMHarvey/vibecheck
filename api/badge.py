"""Vercel serverless function: the badges.

GET /badge/<check>.svg?r=<signed claim>   (rewritten to /api/badge?check=<check>&r=...)
    A badge for a security, visibility or vibechecked result. The claim in
    the URL is verified against our key, the level and date come from it,
    and it turns grey 30 days after the scan. Nothing is stored and nothing
    from the URL reaches the SVG unchecked.

GET /api/badge?score=94[&label=visibility]
    The original score-only badge, kept so existing READMEs don't break.
"""

import datetime as dt
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibecheck.core import badge  # noqa: E402
from vibecheck.core.signing import public_keys  # noqa: E402

COLORS = [(90, "#3fb950"), (75, "#9acd32"), (60, "#d29922"), (40, "#db8a34"), (0, "#f85149")]
LABEL = "vibe score"
LABELS = {"vibe": "vibe score", "visibility": "visibility"}


def grade_for(score: int) -> str:
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= threshold:
            return letter
    return "F"


def color_for(score: int) -> str:
    for threshold, color in COLORS:
        if score >= threshold:
            return color
    return COLORS[-1][1]


def render_badge(score: int, label: str = LABEL) -> str:
    """The score-only badge, drawn exactly as it always was. Score clamped to
    an int 0-100, label from a fixed list."""
    score = max(0, min(100, int(score)))
    value = f"{score}/100 {grade_for(score)}"
    text = label if label in LABELS.values() else LABELS["vibe"]
    label_w = 7 * len(text) + 4
    value_w = 8 * len(value) + 16
    total = label_w + value_w
    color = color_for(score)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{text}: {value}">'
        f'<title>{text}: {value}</title>'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{label_w}" height="20" fill="#555"/>'
        f'<rect x="{label_w}" width="{value_w}" height="20" fill="{color}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{label_w / 2}" y="15" fill="#010101" fill-opacity=".3">{text}</text>'
        f'<text x="{label_w / 2}" y="14">{text}</text>'
        f'<text x="{label_w + value_w / 2}" y="15" fill="#010101" fill-opacity=".3">{value}</text>'
        f'<text x="{label_w + value_w / 2}" y="14">{value}</text>'
        f"</g></svg>"
    )


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        check = (params.get("check") or [""])[0]
        if check or "r" in params:
            svg = badge.render(check, (params.get("r") or [""])[0], public_keys(),
                               dt.datetime.now(dt.timezone.utc))
            # Short cache: the badge must go grey on time.
            cache = "public, max-age=3600"
        else:
            raw = (params.get("score") or ["0"])[0]
            try:
                score = int(float(raw))
            except (TypeError, ValueError):
                score = 0
            label = LABELS.get((params.get("label") or ["vibe"])[0], LABEL)
            svg = render_badge(score, label)
            cache = "public, max-age=3600"

        data = svg.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass
