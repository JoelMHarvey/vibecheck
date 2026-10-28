"""Visibility phase 3: the AI-answer probe.

Asks Claude, with web search on, the questions a buyer would ask about your
category ("best practice software for therapists in the UK", "alternatives
to Cliniko") and records, for each answer: is the brand mentioned, is its
site cited, where does it come among the named competitors, and which pages
were cited. From those: mention rate, citation rate and share of voice
against the competitors you name. The answers are kept as snippets so you can
read what the AI actually said.

It's a snapshot. The same question asked twice gets different answers, which
the report says beside the numbers. Every figure comes from parsing the
response (websearch.py), not from asking the model how it did.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from .websearch import Answer, SearchUnavailable

QUESTIONS = 5
SNIPPET = 320
COUNTRY_NAMES = {"GB": "the UK", "UK": "the UK", "US": "the US", "JP": "Japan", "IE": "Ireland",
                 "AU": "Australia", "NZ": "New Zealand", "CA": "Canada", "DE": "Germany", "FR": "France"}
SYSTEM = ("Answer as you would for someone choosing a product: name specific products, say briefly why, "
          "and keep it under 200 words.")


@dataclass
class ProbeInput:
    brand: str
    domain: str
    category: str
    country: str = "GB"
    competitors: List[str] = field(default_factory=list)

    def clean(self) -> "ProbeInput":
        def tidy(s: str, n: int = 80) -> str:
            return re.sub(r"\s+", " ", str(s or "")).strip()[:n]
        comps = [tidy(c, 40) for c in (self.competitors or []) if tidy(c, 40)][:3]
        country = tidy(self.country, 2).upper() or "GB"
        domain = tidy(self.domain, 120).lower()
        domain = urlsplit(domain if "://" in domain else "https://" + domain).hostname or domain
        domain = domain[4:] if domain.startswith("www.") else domain
        return ProbeInput(tidy(self.brand), domain, tidy(self.category, 120), country, comps)


def questions(inp: ProbeInput) -> List[str]:
    """Five buyer-style questions about the category, never naming the brand:
    the point is whether the AI brings it up unprompted."""
    where = COUNTRY_NAMES.get(inp.country, inp.country)
    cat, comps = inp.category, inp.competitors
    qs = [
        f"What's the best {cat} in {where}?",
        f"I'm looking for {cat} in {where}. What would you recommend, and roughly what does each cost?",
        f"What are good alternatives to {comps[0]} for {cat}?" if comps
        else f"What's the cheapest {cat} in {where} that's still good?",
        f"{comps[0]} or {comps[1]}: which is better, and is there anything better than both?" if len(comps) >= 2
        else f"Which {cat} do small businesses in {where} actually use?",
        f"Is there a {cat} with a flat price and no commission?",
    ]
    return qs[:QUESTIONS]


def _name_rx(name: str) -> "re.Pattern[str]":
    return re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", re.I)


def _host(url: str) -> str:
    h = (urlsplit(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


@dataclass
class Reading:
    question: str
    mentioned: bool
    cited: bool
    position: Optional[int]          # 1 = named first among the brand and competitors
    competitors: List[str]
    cited_pages: List[str]
    snippet: str


def read(answer: Answer, inp: ProbeInput) -> Reading:
    text = answer.text
    names = [inp.brand] + inp.competitors
    firsts: Dict[str, int] = {}
    for n in names:
        m = _name_rx(n).search(text)
        if m:
            firsts[n] = m.start()
    # The brand's own domain written out counts as a mention.
    if inp.brand not in firsts and inp.domain and inp.domain in text.lower():
        firsts[inp.brand] = text.lower().index(inp.domain)
    order = sorted(firsts, key=firsts.get)
    mentioned = inp.brand in firsts
    cited = any(_host(u) == inp.domain or _host(u).endswith("." + inp.domain) for u in answer.cited)
    snippet = text
    if mentioned:
        start = max(0, firsts[inp.brand] - 120)
        snippet = ("…" if start else "") + text[start:]
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if len(snippet) > SNIPPET:
        snippet = snippet[:SNIPPET - 1].rstrip() + "…"
    return Reading(answer.question, mentioned, cited, order.index(inp.brand) + 1 if mentioned else None,
                   [n for n in order if n != inp.brand], answer.cited[:5], snippet)


def summarise(readings: List[Reading], inp: ProbeInput) -> Dict[str, object]:
    n = len(readings) or 1
    brand_mentions = sum(r.mentioned for r in readings)
    comp_mentions = {c: sum(c in r.competitors for r in readings) for c in inp.competitors}
    total = brand_mentions + sum(comp_mentions.values())
    return {
        "brand": inp.brand, "category": inp.category, "country": inp.country,
        "competitors": inp.competitors,
        "mention_rate": round(brand_mentions / n, 2),
        "citation_rate": round(sum(r.cited for r in readings) / n, 2),
        "share_of_voice": round(brand_mentions / total, 2) if total else None,
        "competitor_mentions": comp_mentions,
        "answers": [{"q": r.question, "mentioned": r.mentioned, "cited": r.cited, "position": r.position,
                     "competitors": r.competitors, "pages": r.cited_pages, "snippet": r.snippet}
                    for r in readings],
    }


def run_probe(scan, search, inp: ProbeInput) -> str:
    """Ask the questions, add findings to the scan, keep the snapshot in
    scan.probe. Returns a one-line status for the report's meta."""
    inp = inp.clean()
    if not (inp.brand and inp.category):
        return "not run: needs a brand name and a category"
    from concurrent.futures import ThreadPoolExecutor

    try:
        with ThreadPoolExecutor(max_workers=QUESTIONS) as pool:
            answers = list(pool.map(lambda q: search.ask(q, country=inp.country, system=SYSTEM), questions(inp)))
    except SearchUnavailable as e:
        return f"not run: {e}"
    readings = [read(a, inp) for a in answers]
    snap = summarise(readings, inp)
    scan.probe = snap
    asked = len(readings)
    mentioned = sum(r.mentioned for r in readings)
    cited = sum(r.cited for r in readings)
    named = ", ".join(f"{c} ({k})" for c, k in sorted(snap["competitor_mentions"].items(), key=lambda x: -x[1]) if k)
    if mentioned == 0:
        scan.add("probe-not-mentioned", "/", f"named in 0 of {asked} answers"
                 + (f"; competitors named: {named}" if named else ""))
    elif mentioned / asked < 0.4:
        scan.add("probe-rarely-mentioned", "/", f"named in {mentioned} of {asked} answers"
                 + (f"; competitors named: {named}" if named else ""))
    else:
        scan.ok("probe-mentioned", f"named in {mentioned} of {asked} answers")
    if mentioned and not cited:
        scan.add("probe-not-cited", "/", f"named in {mentioned} answers, your site cited in none")
    elif cited:
        scan.ok("probe-cited", f"your site cited in {cited} of {asked} answers")
    sov = snap["share_of_voice"]
    leader = max(snap["competitor_mentions"].items(), key=lambda x: x[1], default=(None, 0))
    if inp.competitors and mentioned and leader[1] > mentioned:
        scan.add("probe-behind-competitors", "/",
                 f"{leader[0]} named in {leader[1]} answers to your {mentioned}; share of voice {int((sov or 0) * 100)}%")
    elif inp.competitors and mentioned:
        scan.ok("probe-share-ok", f"share of voice {int((sov or 0) * 100)}% against {', '.join(inp.competitors)}")
    scan.ran.add("brand")
    return "asked"
