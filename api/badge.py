"""Vercel serverless function: GET /api/badge?score=94

Returns an SVG "Vibe Score" badge for READMEs. Inputs are clamped to an
integer 0-100 and the grade is derived server-side, so nothing
caller-controlled is ever interpolated into the SVG.
"""

import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

COLORS = [(90, "#3fb950"), (75, "#9acd32"), (60, "#d29922"), (40, "#db8a34"), (0, "#f85149")]
LABEL = "vibe score"


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


def render_badge(score: int) -> str:
    score = max(0, min(100, int(score)))
    value = f"{score}/100 {grade_for(score)}"
    label_w = 74
    value_w = 8 * len(value) + 16
    total = label_w + value_w
    color = color_for(score)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{LABEL}: {value}">'
        f'<title>{LABEL}: {value}</title>'
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
        f'<text x="{label_w / 2}" y="15" fill="#010101" fill-opacity=".3">{LABEL}</text>'
        f'<text x="{label_w / 2}" y="14">{LABEL}</text>'
        f'<text x="{label_w + value_w / 2}" y="15" fill="#010101" fill-opacity=".3">{value}</text>'
        f'<text x="{label_w + value_w / 2}" y="14">{value}</text>'
        f"</g></svg>"
    )


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        raw = (params.get("score") or ["0"])[0]
        try:
            score = int(float(raw))
        except (TypeError, ValueError):
            score = 0

        svg = render_badge(score).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(len(svg)))
        self.end_headers()
        self.wfile.write(svg)

    def log_message(self, *args):
        pass
