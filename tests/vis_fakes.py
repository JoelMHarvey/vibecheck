"""Fake websites for the visibility tests: a dictionary of URL -> response.

Anything not listed fails like a dead host, so a test only has to describe
the requests it cares about.
"""

from __future__ import annotations

import datetime as dt

from vibecheck.core.fetcher import Fetched

NOW = dt.datetime(2026, 10, 27, 12, 0, tzinfo=dt.timezone.utc)

HEAD_OK = """
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Booking and invoicing software for dog groomers in the UK, with one flat price and no commission.">
<meta property="og:title" content="Groomly">
<meta property="og:description" content="Booking software for dog groomers.">
<meta property="og:image" content="https://groomly.test/og.png">
<meta property="og:url" content="https://groomly.test/">
<meta name="twitter:card" content="summary_large_image">
"""

BODY_TEXT = ("<p>Groomly takes bookings, sends reminders and invoices your clients. "
             "It costs £12 a month, flat, with no commission on anything you earn. "
             "Built for independent dog groomers who are tired of paying per booking.</p>")


def html(url, body, status=200, chain=None, ctype="text/html; charset=utf-8", headers=None):
    h = {"content-type": ctype}
    h.update(headers or {})
    return Fetched(url=url, status=status, headers=h, body=body.encode("utf-8"), chain=list(chain or []))


def text(url, body, ctype="text/plain"):
    return html(url, body, ctype=ctype)


def redirect(src, dst, status=308):
    """A response that arrived at dst after one redirect from src."""
    return src, dst, status


def png(width, height):
    import struct
    return (b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR"
            + struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00")


def good_home(url="https://groomly.test/", extra_body="", extra_head=""):
    return f"""<!doctype html><html lang="en-GB"><head>
<title>Groomly · booking software for dog groomers</title>
<link rel="canonical" href="{url}">
{HEAD_OK}{extra_head}
<script type="application/ld+json">{{"@context":"https://schema.org","@graph":[
 {{"@type":"Organization","name":"Groomly Ltd","url":"https://groomly.test/","logo":"https://groomly.test/logo.png","sameAs":["https://x.com/groomly"]}},
 {{"@type":"SoftwareApplication","name":"Groomly","offers":{{"@type":"Offer","price":"12","priceCurrency":"GBP"}}}}]}}</script>
</head><body>
<nav><a href="/pricing">Pricing</a> <a href="/features">Features</a> <a href="/about">About</a> <a href="mailto:hi@groomly.test">Contact</a></nav>
<h1>Booking software for dog groomers</h1>
{BODY_TEXT}
<h2>What it does</h2><p>Bookings and invoices.</p>
<img src="/team.jpg" alt="The team">
<footer><a href="/privacy">Privacy</a> Groomly Ltd, registered in England.</footer>
{extra_body}
</body></html>"""


def sub_page(url, title, extra=""):
    return f"""<!doctype html><html lang="en-GB"><head><title>{title} · Groomly</title>
<link rel="canonical" href="{url}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="{title} for Groomly, the booking and invoicing software for independent dog groomers in the UK.">
<meta property="og:title" content="{title}"><meta property="og:description" content="{title}">
<meta property="og:image" content="https://groomly.test/og.png"><meta property="og:url" content="{url}">
<meta name="twitter:card" content="summary_large_image">
</head><body><a href="/">Home</a><h1>{title}</h1>{BODY_TEXT}{extra}</body></html>"""


SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://groomly.test/</loc><lastmod>2026-10-20</lastmod></url>
<url><loc>https://groomly.test/pricing</loc></url>
<url><loc>https://groomly.test/features</loc></url>
<url><loc>https://groomly.test/about</loc></url>
<url><loc>https://groomly.test/privacy</loc></url>
</urlset>"""

ROBOTS = "User-agent: *\nAllow: /\n\nSitemap: https://groomly.test/sitemap.xml\n"

LLMS = """# Groomly

> Booking and invoicing software for independent dog groomers in the UK. £12 a month, flat.

## Pages

- [Pricing](https://groomly.test/pricing): one plan, £12 a month
- [Features](https://groomly.test/features): bookings, reminders, invoices
- Plans as data: https://groomly.test/plans.json
"""


class FakeSite:
    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.requests = []

    def add(self, key, resp):
        self.responses[key] = resp
        return self

    def fetch(self, url, method="GET"):
        self.requests.append((method, url))
        return self.responses.get(f"{method} {url}", self.responses.get(url) if method == "GET" else None)


def healthy_site() -> FakeSite:
    """A site that should pass nearly everything."""
    base = "https://groomly.test"
    site = FakeSite({
        f"{base}/robots.txt": text(f"{base}/robots.txt", ROBOTS),
        f"{base}/sitemap.xml": text(f"{base}/sitemap.xml", SITEMAP, ctype="application/xml"),
        f"{base}/llms.txt": text(f"{base}/llms.txt", LLMS),
        f"{base}/": html(f"{base}/", good_home()),
        f"{base}/og.png": Fetched(url=f"{base}/og.png", status=200, headers={"content-type": "image/png"}, body=png(1200, 630)),
        "https://www.groomly.test/": html(f"{base}/", good_home(), chain=[("https://www.groomly.test/", 308)]),
        "http://groomly.test/": html(f"{base}/", good_home(), chain=[("http://groomly.test/", 308)]),
        f"HEAD {base}/team.jpg": Fetched(url=f"{base}/team.jpg", status=200, headers={"content-type": "image/jpeg", "content-length": "48000"}),
    })
    for path, title in (("/pricing", "Pricing"), ("/features", "Features"), ("/about", "About"), ("/privacy", "Privacy")):
        site.add(f"{base}{path}", html(f"{base}{path}", sub_page(f"{base}{path}", title)))
    return site
