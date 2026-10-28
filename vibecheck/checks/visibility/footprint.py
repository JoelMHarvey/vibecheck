"""Visibility phase 4: the off-site footprint.

Searches the web for the brand, and for it on the directories buyers and AI
assistants lean on, then counts what came back: pages about you that aren't
on your own site, and which directories have a listing. The searches' result
URLs are the evidence. With a Serper key the searches are plain Google
searches (serper.py, seven a run); without one, two Claude calls with web
search, whose summaries aren't used either.

What it can't do is list you: the output is a checklist with each
directory's sign-up page and a description to paste, taken from your own
llms.txt or meta description.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlsplit

from .websearch import SearchUnavailable


@dataclass(frozen=True)
class Directory:
    name: str
    host: str
    how: str     # where to list, as the site itself describes it (checked October 2026)


DIRECTORIES = [
    Directory("Product Hunt", "producthunt.com",
              "https://www.producthunt.com/launch: log in with a personal account, then Submit, New Product"),
    Directory("AlternativeTo", "alternativeto.net",
              "https://alternativeto.net: sign up, then the user icon, Suggest new application (free)"),
    Directory("G2", "g2.com", "https://sell.g2.com/create-free-profile (free; business software only)"),
    Directory("Capterra", "capterra.com",
              "https://digital-markets.gartner.com/capterra-vendor-signup (free Launch plan; may send you to G2)"),
    Directory("Crunchbase", "crunchbase.com", "https://www.crunchbase.com/add-new (needs an account)"),
    Directory("Reddit", "reddit.com",
              "no form: answer questions in the subreddits your buyers use, within each one's self-promotion rules"),
]
FEW_MENTIONS = 5


def _host(url: str) -> str:
    h = (urlsplit(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _slug(brand: str) -> str:
    return re.sub(r"[^a-z0-9]", "", brand.lower())


def about_brand(url: str, title: str, brand: str) -> bool:
    """A directory result is a listing for the brand when its address or title
    names it, not just when it's on the directory (a category page isn't)."""
    slug = _slug(brand)
    return bool(slug) and (slug in re.sub(r"[^a-z0-9]", "", url.lower())
                           or slug in re.sub(r"[^a-z0-9]", "", (title or "").lower()))


def describe(scan) -> str:
    """The one-line description to paste into a listing form."""
    text = getattr(scan, "llms_text", None) or ""
    m = re.search(r"^>\s*(.+)$", text, re.M)
    if m:
        return m.group(1).strip()[:300]
    home = getattr(scan, "home", None)
    return ((home.description if home is not None else "") or "").strip()[:300]


def _with_claude(search, brand: str):
    """Two Claude calls: one general search, one across the directories."""
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=2) as pool:
        general_f = pool.submit(search.ask, f'Search the web for "{brand}" and list what you find about it.',
                                max_uses=2, system="Search, then list the pages you found in one line each.")
        listed_f = pool.submit(search.ask, f'Search each of these sites for "{brand}": '
                               + ", ".join(d.host for d in DIRECTORIES) + ".",
                               allowed_domains=[d.host for d in DIRECTORIES], max_uses=len(DIRECTORIES),
                               system="Run one search per site. Then list the pages you found in one line each.")
        return general_f.result().results, listed_f.result().results


def _with_serper(finder, brand: str):
    """Seven plain searches: the brand, then the brand on each directory."""
    from concurrent.futures import ThreadPoolExecutor

    queries = [f'"{brand}"'] + [f'site:{d.host} "{brand}"' for d in DIRECTORIES]
    with ThreadPoolExecutor(max_workers=len(queries)) as pool:
        found = list(pool.map(lambda q: finder.results(q, num=20 if q.startswith('"') else 5), queries))
    return found[0], [r for rs in found[1:] for r in rs]


def run_footprint(scan, search, brand: str, domain: str, finder=None) -> str:
    """Add the off-site findings to the scan. Returns a status line. Uses
    ``finder`` (a SerperSearch) when given, else Claude through ``search``."""
    brand = re.sub(r"\s+", " ", brand or "").strip()[:80]
    domain = (domain or "").lower()
    domain = domain[4:] if domain.startswith("www.") else domain
    if not brand:
        return "not run: needs a brand name"
    try:
        general, listed = _with_serper(finder, brand) if finder is not None else _with_claude(search, brand)
    except SearchUnavailable as e:
        return f"not run: {e}"

    elsewhere = sorted({_host(r["url"]) for r in general
                        if _host(r["url"]) and _host(r["url"]) != domain and not _host(r["url"]).endswith("." + domain)
                        and about_brand(r["url"], r["title"], brand)})
    if not elsewhere:
        scan.add("offsite-no-mentions", "/", f'a web search for "{brand}" found no pages about it beyond your own site')
    elif len(elsewhere) < FEW_MENTIONS:
        scan.add("offsite-few-mentions", "/", f"{len(elsewhere)} other sites mention it: " + ", ".join(elsewhere[:5]))
    else:
        scan.ok("offsite-mentions", f"{len(elsewhere)} other sites mention it, including " + ", ".join(elsewhere[:4]))

    found, missing = [], []
    for d in DIRECTORIES:
        hit = next((r for r in listed + general
                    if (_host(r["url"]) == d.host or _host(r["url"]).endswith("." + d.host))
                    and about_brand(r["url"], r["title"], brand)), None)
        (found if hit else missing).append((d, hit))
    if found:
        scan.ok("offsite-listed", "; ".join(f"{d.name} ({h['url']})" for d, h in found))
    if missing:
        blurb = describe(scan) or f"{brand}: say what it is, who it's for and what it costs, in one sentence."
        checklist = " | ".join(f"{d.name}: {d.how}" for d, _ in missing)
        scan.add("offsite-missing-listings", "/",
                 f"not found on {', '.join(d.name for d, _ in missing)}. Where to list: {checklist}. "
                 f"Description to paste: “{blurb}”")
    scan.ran.add("offsite")
    scan.footprint = {"brand": brand, "elsewhere": elsewhere[:20],
                      "listed": [d.name for d, _ in found], "missing": [d.name for d, _ in missing]}
    return "searched" if finder is None else "searched (Google, through Serper)"
