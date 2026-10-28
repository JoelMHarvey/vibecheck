"""The visibility scan: crawl a site the way a search or AI crawler would and
check what it finds.

``scan_visibility(url, fetch)`` is the whole entry point. ``fetch`` is
injected (see fetch.py), so every check runs offline in tests against
recorded responses.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import json
import re
import time
import urllib.robotparser
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

from ...core.fetcher import PERMANENT_CODES, Fetched
from ...core.models import SEVERITY_ORDER, CheckResult, Finding, Target, iso
from ...core.scoring import category_scores, weighted_total
from . import config
from .page import Page, fingerprint, parse_page
from .rules import PASSES, RULES

SKIP_EXTS = (
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".css", ".js",
    ".mjs", ".json", ".xml", ".txt", ".md", ".csv", ".zip", ".gz", ".mp4", ".mp3", ".webm",
    ".woff", ".woff2", ".ttf", ".rss", ".atom", ".doc", ".docx", ".xls", ".xlsx",
)
SKIP_FRAGMENTS = {"top", "main", "content", "main-content", "maincontent", "skip", "skip-link", "page"}
STOPWORDS = {
    "the", "and", "for", "with", "your", "you", "our", "from", "that", "this", "are", "who",
    "what", "into", "more", "than", "every", "free", "best", "just", "make", "made", "about",
    "have", "will", "their", "they", "them", "its", "it's", "one", "all", "any", "get",
}
MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july", "august",
     "september", "october", "november", "december"], start=1)}
FREE_PRICE_RE = re.compile(
    r"\b(?:is|it's|it’s|it is|always|completely|entirely)\s+free\b"
    r"|\bfree (?:to use|forever|for everyone)\b|\bno paid (?:tiers?|plans?)\b", re.I)
ORG_TYPES = {"organization", "corporation", "localbusiness", "onlinebusiness", "onlinestore",
             "ngo", "educationalorganization", "professionalservice", "store", "softwarecompany"}
PRODUCT_TYPES = {"softwareapplication", "webapplication", "mobileapplication", "product"}


# ---- small helpers -------------------------------------------------------------

def normalise_input(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    return url


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{(p.netloc or '').lower()}"


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def other_host_form(host: str) -> str:
    return host[4:] if host.startswith("www.") else "www." + host


def strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def page_key(url: str) -> str:
    """Comparison key for 'same page': host, path without trailing slash, no
    fragment or query."""
    p = urlsplit(url)
    path = p.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return f"{(p.hostname or '').lower()}{path}"


def display_path(url: str, origin_host: str) -> str:
    p = urlsplit(url)
    path = p.path or "/"
    if (p.hostname or "").lower() != origin_host:
        return f"{p.hostname}{path}"
    return path


def summarise(items: Sequence[str], limit: int = 6) -> str:
    items = list(dict.fromkeys(items))
    shown = "; ".join(items[:limit])
    if len(items) > limit:
        shown += f"; and {len(items) - limit} more"
    return shown


def looks_like_real_file(resp: Optional[Fetched]) -> bool:
    """An SPA host answers every path with index.html. An HTML answer to
    /robots.txt or /llms.txt is the app, not the file."""
    if resp is None or not resp.ok or not resp.body.strip():
        return False
    if resp.is_html and b"<html" in resp.body[:3000].lower():
        return False
    return True


def _words(text: str) -> Set[str]:
    out = set()
    for w in re.findall(r"[a-z][a-z'-]+", text.lower()):
        for part in w.split("-"):
            part = part.strip("'")
            if len(part) < 4 or part in STOPWORDS:
                continue
            out.add(part[:-1] if part.endswith("s") else part)
    return out


_DATE_PATTERNS = [
    (re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"), "ymd"),
    (re.compile(r"\b(\d{1,2}) (January|February|March|April|May|June|July|August|September|October|November|December) (\d{4})\b", re.I), "dmy"),
    (re.compile(r"\b(January|February|March|April|May|June|July|August|September|October|November|December) (\d{1,2}),? (\d{4})\b", re.I), "mdy"),
]


def urls_in(text: str) -> List[str]:
    """Bare and Markdown URLs in plain text, without trailing punctuation."""
    return [u.rstrip(".,;:!?") for u in re.findall(r"https?://[^\s)>\]\"'<]+", text)]


def parse_date(value: str) -> Optional[_dt.date]:
    value = (value or "").strip()
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", value)
    if m:
        try:
            return _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    return None


def dates_in_text(text: str) -> List[_dt.date]:
    found = []
    for pattern, kind in _DATE_PATTERNS:
        for m in pattern.finditer(text):
            try:
                if kind == "ymd":
                    d = _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                elif kind == "dmy":
                    d = _dt.date(int(m.group(3)), MONTHS[m.group(2).lower()], int(m.group(1)))
                else:
                    d = _dt.date(int(m.group(3)), MONTHS[m.group(1).lower()], int(m.group(2)))
            except ValueError:
                continue
            found.append(d)
    return found


def image_size(data: bytes) -> Optional[Tuple[int, int]]:
    """Width and height from a PNG, GIF, JPEG or WebP header."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        return int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little")
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP" and len(data) >= 30:
        chunk = data[12:16]
        if chunk == b"VP8X":
            return 1 + int.from_bytes(data[24:27], "little"), 1 + int.from_bytes(data[27:30], "little")
        if chunk == b"VP8 ":
            return int.from_bytes(data[26:28], "little") & 0x3FFF, int.from_bytes(data[28:30], "little") & 0x3FFF
        if chunk == b"VP8L" and len(data) >= 25:
            bits = int.from_bytes(data[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if data[:2] == b"\xff\xd8":
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            length = int.from_bytes(data[i + 2:i + 4], "big")
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                return int.from_bytes(data[i + 7:i + 9], "big"), int.from_bytes(data[i + 5:i + 7], "big")
            i += 2 + length
    return None


def jsonld_nodes(value) -> Iterable[dict]:
    """Every dict in a JSON-LD document, however deeply it's nested."""
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from jsonld_nodes(v)
    elif isinstance(value, list):
        for v in value:
            yield from jsonld_nodes(v)


def node_types(node: dict) -> Set[str]:
    t = node.get("@type")
    if isinstance(t, str):
        return {t.lower()}
    if isinstance(t, list):
        return {x.lower() for x in t if isinstance(x, str)}
    return set()


def has_price(node: dict) -> bool:
    offers = node.get("offers")
    for offer in jsonld_nodes(offers) if offers is not None else []:
        if ("price" in offer or "lowPrice" in offer) and "priceCurrency" in offer:
            return True
    return False


def parse_sitemap(body: bytes) -> Tuple[str, List[Tuple[str, Optional[str]]]]:
    """('urlset' | 'index', [(loc, lastmod)]). Raises ValueError if it isn't
    a sitemap."""
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)[: config.MAX_BYTES]
    head = body[:4000].lower()
    # The standard library's XML parser expands entities; a sitemap never
    # needs a DOCTYPE, so refuse one rather than risk an entity bomb.
    if b"<!doctype" in head or b"<!entity" in body.lower():
        raise ValueError("has a DOCTYPE or entity declarations")
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        raise ValueError(f"not valid XML: {e}") from None
    tag = root.tag.rsplit("}", 1)[-1].lower()
    if tag not in ("urlset", "sitemapindex"):
        raise ValueError(f"root element is <{tag}>, not <urlset>")
    entries = []
    for item in root:
        loc = lastmod = None
        for child in item:
            name = child.tag.rsplit("}", 1)[-1].lower()
            if name == "loc":
                loc = (child.text or "").strip()
            elif name == "lastmod":
                lastmod = (child.text or "").strip()
        if loc:
            entries.append((loc, lastmod))
    return ("index" if tag == "sitemapindex" else "urlset"), entries


# ---- the scan ------------------------------------------------------------------

class _Scan:
    def __init__(self, url: str, fetch: Callable[..., Optional[Fetched]],
                 now: Optional[_dt.datetime], budget: float):
        self.input_url = normalise_input(url)
        self.fetch = fetch
        self.now = now or _dt.datetime.now(_dt.timezone.utc)
        self.deadline = time.monotonic() + budget
        self.origin = origin_of(self.input_url)
        self.host = host_of(self.input_url)
        self.findings: List[Finding] = []
        self.ran: Set[str] = set()       # categories whose checks ran
        self.reachable = True
        self.robots: Optional[urllib.robotparser.RobotFileParser] = None
        self.robots_resp: Optional[Fetched] = None
        self.sitemap_entries: List[Tuple[str, Optional[str]]] = []
        self.sitemap_found = False
        self.llms_text: Optional[str] = None
        self.fetched: Dict[str, Optional[Fetched]] = {}   # requested URL -> response
        self.pages: Dict[str, Tuple[Fetched, Page]] = {}  # page_key -> (response, parsed)
        self.home: Optional[Page] = None
        self.csr_pages: Set[str] = set()

    # -- recording --
    def add(self, rule_id: str, path: str, excerpt: str) -> None:
        rule = RULES[rule_id]
        fill = {"path": path, "excerpt": excerpt, "line": 0}
        self.findings.append(Finding(
            id=rule_id, check_id="visibility", category=rule.category, severity=rule.severity,
            title=rule.title, why_it_matters=rule.description.format(**fill), evidence=excerpt,
            fix_prompt=rule.fix_prompt.format(**fill), verify_hint=rule.verify, guide_url=rule.guide,
            path=path,
        ))

    def add_pages(self, rule_id: str, items: List[Tuple[str, str]]) -> None:
        """One finding for a rule that fired on several pages."""
        if not items:
            return
        paths = list(dict.fromkeys(p for p, _ in items))
        path = paths[0] + (f" (+{len(paths) - 1} more)" if len(paths) > 1 else "")
        excerpt = summarise([f"{p}: {d}" if d else p for p, d in items])
        self.add(rule_id, path, excerpt)

    def ok(self, check_id: str, evidence: str) -> None:
        title, category = PASSES[check_id]
        self.findings.append(Finding(id=check_id, check_id="visibility", category=category,
                                     severity="pass", title=title, evidence=evidence))

    # -- fetching --
    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def get_many(self, urls: Sequence[str], method: str = "GET") -> Dict[str, Optional[Fetched]]:
        urls = [u for u in dict.fromkeys(urls) if (u, method) not in self._seen]
        out: Dict[str, Optional[Fetched]] = {}
        if not urls or self.remaining() <= 0:
            return out
        pool = ThreadPoolExecutor(max_workers=config.WORKERS)
        try:
            futures = {(pool.submit(self.fetch, u) if method == "GET" else pool.submit(self.fetch, u, method)): u
                       for u in urls}
            done, _pending = wait(futures, timeout=max(0.1, self.remaining()))
            for fut in done:
                u = futures[fut]
                try:
                    out[u] = fut.result()
                except Exception:
                    out[u] = None
                self._seen.add((u, method))
        finally:
            # Don't wait for stragglers past the budget; each has its own timeout.
            pool.shutdown(wait=False, cancel_futures=True)
        if method == "GET":
            self.fetched.update(out)
        return out

    _seen: Set[Tuple[str, str]]

    def get(self, url: str) -> Optional[Fetched]:
        return self.get_many([url]).get(url)

    def internal(self, url: str) -> bool:
        return host_of(url) == self.host and urlsplit(url).scheme in ("http", "https")

    def crawlable(self, url: str) -> bool:
        if self.robots is None:
            return True
        return self.robots.can_fetch(config.ROBOTS_AGENT, url)

    # -- main --
    def run(self) -> None:
        self._seen = set()
        self.robots_step()
        if not self.reachable:
            return
        if self.robots is not None and not self.crawlable(self.origin + "/"):
            self.add("robots-blocks-us", "/robots.txt",
                     "robots.txt disallows the vibecheck-visibility user agent from /")
            self.side_files()
            self.ran.update({"technical", "ai"})
            return

        home_url = self.origin + "/"
        start = urlsplit(self.input_url)
        extra = [] if (start.path or "/") == "/" else [urlunsplit((start.scheme, start.netloc, start.path, "", ""))]
        got = self.get_many([home_url] + extra)
        home = got.get(home_url)
        if home is None or not home.ok or not home.is_html:
            self.reachable = False
            why = "no response" if home is None else (
                f"home page returned {home.status}" if not home.ok else "home page isn't HTML")
            self.add("site-unreachable", "/", why)
            return
        # Follow the home page wherever it redirected (www <-> bare, http -> https).
        self.origin = origin_of(home.url)
        self.host = host_of(home.url)
        self.input_chain = home.chain
        self.home = parse_page(home.url, home.text)
        self.pages[page_key(home.url)] = (home, self.home)
        for u in extra:
            r = got.get(u)
            if r is not None and r.ok and r.is_html and self.internal(r.url):
                self.pages[page_key(r.url)] = (r, parse_page(r.url, r.text))

        self.side_files()
        self.crawl()
        self.ran.update({"technical", "ai", "content"})

        self.check_rendering()
        self.check_head()
        self.check_social()
        self.check_structure()
        self.check_architecture()
        self.check_sitemap_against_crawl()
        self.check_structured_data()
        self.check_trust()
        self.check_hosts_and_media()
        return

    # -- robots, sitemap, llms -----------------------------------------------
    def robots_step(self) -> None:
        resp = self.get(self.origin + "/robots.txt")
        self.robots_resp = resp
        if resp is not None and resp.url and host_of(resp.url) and host_of(resp.url) != self.host:
            # The site redirects to another host form; that's where its files are.
            self.origin, self.host = origin_of(resp.url), host_of(resp.url)
        if resp is None:
            # Could be just robots.txt timing out; the home page decides.
            return
        if not looks_like_real_file(resp):
            self.robots_present = False
            return
        self.robots_present = True
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(resp.text.splitlines())
        self.robots = rp
        home = self.origin + "/"
        blocked_search = [a for a in config.SEARCH_CRAWLERS if not rp.can_fetch(a, home)]
        if blocked_search:
            self.add("robots-blocks-search", "/robots.txt", f"{', '.join(blocked_search)} disallowed from /")
        else:
            self.ok("robots-ok", "Googlebot and Bingbot may crawl /")

    robots_present = False

    def side_files(self) -> None:
        """Sitemap(s) and llms.txt, plus the AI-crawler report."""
        # AI crawler access: reported, never scored.
        if self.robots is not None:
            home = self.origin + "/"
            def split(names):
                out = [a for a in names if not self.robots.can_fetch(a, home)]
                return out, [a for a in names if a not in out]

            blocked, allowed = split(config.AI_TRAINING_CRAWLERS)
            if blocked:
                self.add("ai-crawlers-blocked", "/robots.txt",
                         f"Blocked: {', '.join(blocked)}" + (f". Allowed: {', '.join(allowed)}" if allowed else ""))
            search_blocked, search_allowed = split(config.AI_SEARCH_CRAWLERS)
            if search_blocked:
                self.add("ai-search-blocked", "/robots.txt",
                         f"Blocked: {', '.join(search_blocked)}"
                         + (f". Allowed: {', '.join(search_allowed)}" if search_allowed else ""))
            if not blocked and not search_blocked:
                self.ok("ai-crawlers-allowed", "robots.txt allows " + ", ".join(config.AI_CRAWLERS))
        else:
            self.ok("ai-crawlers-allowed", "no robots.txt, so nothing is blocked")
            if self.robots_resp is not None or self.reachable:
                self.add("robots-missing", "/robots.txt", "GET /robots.txt didn't return a robots file")

        listed = list(self.robots.site_maps() or []) if self.robots is not None else []
        sitemap_urls = listed or [self.origin + "/sitemap.xml"]
        got = self.get_many(sitemap_urls[:config.MAX_SITEMAPS] + [self.origin + "/llms.txt"])

        llms = got.get(self.origin + "/llms.txt")
        self.llms_text = llms.text if looks_like_real_file(llms) else None

        problems = []
        for sm_url in sitemap_urls[:config.MAX_SITEMAPS]:
            resp = got.get(sm_url)
            if not looks_like_real_file(resp):
                continue
            try:
                kind, entries = parse_sitemap(resp.body)
            except (ValueError, OSError, EOFError) as e:
                problems.append(f"{display_path(sm_url, self.host)} {e}")
                continue
            self.sitemap_found = True
            if kind == "index":
                children = [loc for loc, _ in entries][:config.MAX_SITEMAPS]
                for child_url, child in self.get_many(children).items():
                    if not looks_like_real_file(child):
                        continue
                    try:
                        _k, child_entries = parse_sitemap(child.body)
                        self.sitemap_entries.extend(child_entries)
                    except (ValueError, OSError, EOFError) as e:
                        problems.append(f"{display_path(child_url, self.host)} {e}")
            else:
                self.sitemap_entries.extend(entries)

        if problems:
            self.add("sitemap-invalid", "/sitemap.xml", summarise(problems))
        elif not self.sitemap_found:
            self.add("sitemap-missing", "/sitemap.xml",
                     "GET " + ", ".join(display_path(u, self.host) for u in sitemap_urls[:config.MAX_SITEMAPS])
                     + " didn't return a sitemap")
        else:
            self.ok("sitemap-ok", f"{len(self.sitemap_entries)} URL{'s' if len(self.sitemap_entries) != 1 else ''} listed")
            if self.robots is not None and not listed:
                self.add("sitemap-not-in-robots", "/robots.txt", "robots.txt has no Sitemap: line")

        self.check_llms()

    def check_llms(self) -> None:
        text = self.llms_text
        if text is None:
            self.add("llms-missing", "/llms.txt", "GET /llms.txt didn't return a text file")
            self.data_files([])
            return
        lines = [ln.strip() for ln in text.splitlines()]
        has_h1 = any(ln.startswith("# ") for ln in lines)
        summary = next((ln[1:].strip() for ln in lines if ln.startswith(">")), "")
        links = re.findall(r"\[[^\]]+\]\(([^)\s]+)\)", text)
        missing = []
        if not has_h1:
            missing.append("a '# ' title")
        if not summary:
            missing.append("a '> ' summary line")
        if not links:
            missing.append("Markdown links to key pages")
        if missing:
            self.add("llms-incomplete", "/llms.txt", ", ".join(missing))
        else:
            short = summary if len(summary) <= 90 else summary[:87].rstrip() + "..."
            self.ok("llms-ok", f"{len(links)} links; summary: \"{short}\"")
        self.data_files(urls_in(text))

    def data_files(self, urls_in_llms: List[str]) -> None:
        self._llms_urls = urls_in_llms

    _llms_urls: List[str] = []

    # -- crawl -------------------------------------------------------------------
    def candidate(self, url: str) -> Optional[str]:
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or (p.hostname or "").lower() != self.host:
            return None
        if p.query or p.path.lower().endswith(SKIP_EXTS):
            return None
        clean = urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))
        return clean if self.crawlable(clean) else None

    def crawl(self) -> None:
        queued: List[str] = []
        seen = set(self.pages)

        def push(urls: Iterable[str]) -> None:
            for u in urls:
                c = self.candidate(u)
                if c and page_key(c) not in seen:
                    seen.add(page_key(c))
                    queued.append(c)

        push(loc for loc, _ in self.sitemap_entries)       # sitemap first
        for _resp, page in list(self.pages.values()):
            push(l.href for l in page.links)

        budget = config.MAX_PAGES
        for _wave in range(2):
            batch, queued = queued[:budget], queued[budget:]
            if not batch or self.remaining() <= 0:
                break
            new_links: List[str] = []
            for url, resp in self.get_many(batch).items():
                if resp is None or not resp.ok or not resp.is_html or not self.internal(resp.url):
                    continue
                key = page_key(resp.url)
                if key in self.pages:
                    continue
                page = parse_page(resp.url, resp.text)
                self.pages[key] = (resp, page)
                new_links.extend(l.href for l in page.links)
            budget -= len(batch)
            if budget <= 0:
                break
            push(new_links)

    # -- checks ----------------------------------------------------------------------
    def path(self, url: str) -> str:
        return display_path(url, self.host)

    def body_pages(self) -> List[Tuple[str, Page]]:
        """Pages whose body is server-rendered; client-rendered ones are
        reported once by the rendering check rather than by every body check."""
        return [(self.path(r.url), p) for r, p in self.pages.values() if page_key(r.url) not in self.csr_pages]

    def check_rendering(self) -> None:
        family, label = fingerprint(self.home)
        blank = []
        for resp, page in self.pages.values():
            n = len(page.text)
            if n < config.MIN_BODY_TEXT or page.empty_root:
                self.csr_pages.add(page_key(resp.url))
                detail = f"{n} characters of text in the raw HTML"
                if page.empty_root:
                    detail += f", <div id=\"{page.empty_root}\"> is empty"
                blank.append((self.path(resp.url), detail))
        if blank:
            fam = {"vite": "csr-vite", "next": "csr-next"}.get(family, "csr-generic")
            items = blank
            if label:
                items = [(p, f"{label}: {d}") if i == 0 else (p, d) for i, (p, d) in enumerate(blank)]
            self.add_pages(fam, items)
        else:
            self.ok("server-rendered", f"home page has {len(self.home.text):,} characters of text in the raw HTML")

    def check_head(self) -> None:
        missing_title, long_title, missing_desc, bad_desc = [], [], [], []
        no_canon, elsewhere, no_lang, no_viewport = [], [], [], []
        titles: Dict[str, List[str]] = {}
        descs: Dict[str, List[str]] = {}
        for resp, page in self.pages.values():
            path = self.path(resp.url)
            t = page.title
            if not t:
                missing_title.append((path, ""))
            else:
                titles.setdefault(t, []).append(path)
                if len(t) > config.TITLE_MAX:
                    long_title.append((path, f"{len(t)} characters: \"{t}\""))
            d = page.description
            if not d:
                missing_desc.append((path, ""))
            else:
                descs.setdefault(d, []).append(path)
                if not (config.DESCRIPTION_MIN <= len(d) <= config.DESCRIPTION_MAX):
                    bad_desc.append((path, f"{len(d)} characters"))
            if not page.canonical:
                no_canon.append((path, ""))
            elif page_key(page.canonical) != page_key(resp.url):
                elsewhere.append((path, f"canonical is {page.canonical}"))
            if not page.html_lang:
                no_lang.append((path, ""))
            if "viewport" not in page.meta:
                no_viewport.append((path, ""))

        self.add_pages("title-missing", missing_title)
        self.add_pages("title-long", long_title)
        dup_titles = [(paths[0], f"\"{t}\" on {', '.join(paths)}") for t, paths in titles.items() if len(paths) > 1]
        self.add_pages("title-duplicate", dup_titles)
        if not (missing_title or long_title or dup_titles):
            self.ok("titles-ok", f"{len(self.pages)} page{'s' if len(self.pages) != 1 else ''}, each with its own title")

        self.add_pages("description-missing", missing_desc)
        self.add_pages("description-length", bad_desc)
        dup_desc = [(paths[0], f"same description on {', '.join(paths)}") for paths in descs.values() if len(paths) > 1]
        self.add_pages("description-duplicate", dup_desc)
        if not (missing_desc or bad_desc or dup_desc):
            self.ok("descriptions-ok", f"{len(self.pages)} page{'s' if len(self.pages) != 1 else ''}, 70 to 160 characters each")

        self.add_pages("canonical-missing", no_canon)
        self.add_pages("canonical-elsewhere", elsewhere)
        if not (no_canon or elsewhere):
            self.ok("canonical-ok", "every page's canonical is its own URL")
        self.add_pages("lang-missing", no_lang)
        self.add_pages("viewport-missing", no_viewport)

    def check_social(self) -> None:
        wanted = ("og:title", "og:description", "og:image", "og:url", "twitter:card")
        missing = []
        for resp, page in self.pages.values():
            gone = [t for t in wanted if not page.meta.get(t)]
            if gone:
                missing.append((self.path(resp.url), ", ".join(gone)))
        self.add_pages("og-incomplete", missing)

        image = self.home.meta.get("og:image")
        self._og_image = image if image and urlsplit(image).scheme in ("http", "https") else None
        self._og_home_complete = all(self.home.meta.get(t) for t in wanted)

    def finish_og_image(self, resp: Optional[Fetched]) -> None:
        image = self._og_image
        if not image:
            return
        if resp is None or not resp.ok or not resp.content_type.startswith("image/"):
            why = "no response" if resp is None else (
                f"returned {resp.status}" if not resp.ok else f"served as {resp.content_type or 'unknown type'}")
            self.add("og-image-broken", "/", f"{image} {why}")
            return
        size = image_size(resp.body)
        if size:
            w, h = size
            if h == 0 or abs(w / h - 1200 / 630) > 0.06 or w < 600:
                self.add("og-image-size", "/", f"{w}x{h}, not 1200x630")
                return
        if self._og_home_complete:
            dims = f" ({size[0]}x{size[1]})" if size else ""
            self.ok("og-complete", f"og:title, og:description, og:image{dims}, og:url and twitter:card on the home page")

    def check_structure(self) -> None:
        none, many, skips = [], [], []
        for path, page in self.body_pages():
            h1s = page.h1s
            if not h1s:
                none.append((path, ""))
            elif len(h1s) > 1:
                many.append((path, f"{len(h1s)} H1s"))
            prev = 0
            for level, text in page.headings:
                if prev and level > prev + 1:
                    skips.append((path, f"H{prev} then H{level} (\"{text[:40]}\")"))
                    break
                prev = level
        self.add_pages("h1-missing", none)
        self.add_pages("h1-multiple", many)
        self.add_pages("heading-skip", skips)
        if not (none or many) and self.body_pages():
            self.ok("h1-ok", f"one H1 on each of {len(self.body_pages())} page{'s' if len(self.body_pages()) != 1 else ''}")

        home_key = page_key(self.home.url)
        if home_key not in self.csr_pages and self.home.h1s:
            topic = _words((self.home.title or "") + " " + (self.home.description or ""))
            h1 = self.home.h1s[0]
            if topic and not (_words(h1) & topic):
                self.add("h1-off-topic", "/", f"\"{h1}\"")

        # Alt text, across every server-rendered page.
        total = missing = 0
        examples = []
        for path, page in self.body_pages():
            for img in page.images:
                total += 1
                if img.alt is None:
                    missing += 1
                    examples.append(self.path(img.src) if img.src else f"an image on {path}")
        if total:
            if missing and (total - missing) / total < config.ALT_COVERAGE_MIN:
                self.add("img-alt-missing", "/", f"{missing} of {total} images have no alt attribute: " + summarise(examples, 4))
            elif not missing:
                self.ok("alt-ok", f"all {total} images have an alt attribute")

    def check_architecture(self) -> None:
        home_key = page_key(self.home.url)
        if home_key in self.csr_pages:
            return
        frags: List[str] = []
        routes: Set[str] = set()
        for link in self.home.links:
            raw = link.raw.strip()
            if raw.startswith("#"):
                # Whether the target is an anchor or a view a script swaps in
                # (#/pricing, #myapp), search engines see one URL either way.
                frag = raw[1:].lstrip("/!")
                if frag and frag.lower() not in SKIP_FRAGMENTS:
                    frags.append(frag)
                continue
            c = self.candidate(link.href)
            if c and page_key(c) != home_key:
                routes.add(page_key(c))
        frags = list(dict.fromkeys(frags))
        if len(frags) >= config.FRAGMENT_SECTIONS_MIN and len(frags) > len(routes):
            shown = ", ".join("#" + f for f in frags[:6]) + (", ..." if len(frags) > 6 else "")
            self.add("fragment-sections", "/",
                     f"{len(frags)} sections at #fragments of the home page ({shown}), "
                     f"against {len(routes)} other page{'s' if len(routes) != 1 else ''} with an address of their own")
        elif len(routes) < 3:
            self.add("few-internal-links", "/", f"{len(routes)} other page{'s' if len(routes) != 1 else ''}")

        # Links to our own pages that redirect, or use the other host form.
        other = other_host_form(self.host)
        redirecting, other_form = [], []
        for _resp, page in self.pages.values():
            for link in page.links:
                h = host_of(link.href)
                if h == other:
                    other_form.append(link.href.split("#")[0])
                if h != self.host:
                    continue
                target = link.href.split("#")[0]
                r = self.fetched.get(urlunsplit(urlsplit(target)._replace(query="", fragment="")))
                if r is not None and r.chain and self.internal(r.url):
                    redirecting.append(f"{self.path(target)} -> {self.path(r.url)}")
        if redirecting:
            self.add("internal-link-redirects", "/", summarise(redirecting))
        if other_form:
            self.add("internal-links-other-host", "/", summarise(other_form))

    def check_sitemap_against_crawl(self) -> None:
        if not self.sitemap_found:
            return
        listed = {page_key(loc): (loc, lastmod) for loc, lastmod in self.sitemap_entries}
        same_host = {k: v for k, v in listed.items() if k.split("/", 1)[0] == self.host}

        # Pages the site links to that the sitemap leaves out.
        crawled = {page_key(r.url): self.path(r.url) for r, _p in self.pages.values()}
        not_listed = [path for key, path in crawled.items() if key not in listed]
        if not_listed:
            self.add("sitemap-incomplete", "/sitemap.xml",
                     f"sitemap lists {len(listed)} URL{'s' if len(listed) != 1 else ''}; the crawl found "
                     f"{len(crawled)} page{'s' if len(crawled) != 1 else ''}. Not listed: {summarise(not_listed)}")

        # Sitemap URLs that don't load cleanly.
        broken = []
        for key, (loc, _lm) in same_host.items():
            r = self.fetched.get(loc)
            if loc not in self.fetched:
                continue
            if r is None:
                broken.append(f"{self.path(loc)} (no response)")
            elif r.chain:
                broken.append(f"{self.path(loc)} (redirects to {self.path(r.url)})")
            elif not r.ok:
                broken.append(f"{self.path(loc)} ({r.status})")
        if broken:
            self.add("sitemap-broken-urls", "/sitemap.xml", summarise(broken))

        # Orphans: only claim this when the crawl saw every page.
        if len(self.pages) <= config.MAX_PAGES:
            linked = {page_key(l.href) for _r, p in self.pages.values() for l in p.links}
            home_key = page_key(self.home.url)
            orphans = [self.path(loc) for key, (loc, _lm) in same_host.items()
                       if key not in linked and key != home_key and key in crawled]
            if orphans:
                self.add("sitemap-orphans", "/sitemap.xml", summarise(orphans))

        # lastmod against dates the page itself shows.
        today = self.now.date()
        stale = []
        for resp, page in self.pages.values():
            entry = listed.get(page_key(resp.url))
            if not entry or not entry[1]:
                continue
            lastmod = parse_date(entry[1])
            if not lastmod:
                continue
            newest, source = self.content_date(page, today)
            if newest and (newest - lastmod).days > config.LASTMOD_SLACK_DAYS:
                stale.append((self.path(resp.url), f"lastmod {lastmod.isoformat()}, but the page {source} "
                                                   f"{newest.day} {newest.strftime('%B %Y')}"))
        if stale:
            self.add_pages("sitemap-lastmod-stale", stale)

    def content_date(self, page: Page, today: _dt.date) -> Tuple[Optional[_dt.date], str]:
        """The newest date the page gives for its own content, never in the
        future. Dates written in the page beat server headers: a static
        host's Last-Modified is the deploy time, not the edit."""
        best: Optional[_dt.date] = None
        source = ""
        for block in page.jsonld:
            try:
                data = json.loads(block)
            except ValueError:
                continue
            for node in jsonld_nodes(data):
                for key in ("dateModified", "datePublished"):
                    d = parse_date(str(node.get(key, "")))
                    if d and d <= today and (best is None or d > best):
                        best, source = d, f"says {key}"
        d = parse_date(page.meta.get("article:modified_time", ""))
        if d and d <= today and (best is None or d > best):
            best, source = d, "says article:modified_time"
        for d in dates_in_text(page.text):
            if d <= today and (best is None or d > best):
                best, source = d, "mentions"
        return best, source

    def check_structured_data(self) -> None:
        nodes: List[dict] = []
        invalid = []
        pages_with = 0
        blocks = 0
        for resp, page in self.pages.values():
            if page.jsonld:
                pages_with += 1
            for block in page.jsonld:
                blocks += 1
                try:
                    nodes.extend(jsonld_nodes(json.loads(block)))
                except ValueError as e:
                    invalid.append((self.path(resp.url), str(e).split(":")[0]))
        if invalid:
            self.add_pages("jsonld-invalid", invalid)
        if not blocks:
            self.add("jsonld-missing", "/", "no <script type=\"application/ld+json\"> on any page crawled")
        elif not invalid:
            self.ok("jsonld-ok", f"{blocks} JSON-LD block{'s' if blocks != 1 else ''} on {pages_with} page{'s' if pages_with != 1 else ''}")

        types = [node_types(n) for n in nodes]
        if blocks:
            orgs = [n for n, t in zip(nodes, types)
                    if t & ORG_TYPES or any(x.endswith("organization") for x in t)]
            if not orgs:
                self.add("org-missing", "/", "no Organization (or LocalBusiness) node")
            else:
                org = max(orgs, key=lambda n: sum(1 for k in ("name", "url", "logo", "sameAs") if n.get(k)))
                gaps = [k for k in ("name", "url", "logo", "sameAs") if not org.get(k)]
                if gaps:
                    self.add("org-incomplete", "/", ", ".join(gaps))
                else:
                    self.ok("org-ok", f"{org.get('name')}: name, url, logo and sameAs set")

        products = [n for n, t in zip(nodes, types) if t & PRODUCT_TYPES]
        unpriced = list(dict.fromkeys(str(n.get("name") or "unnamed") for n in products if not has_price(n)))
        if unpriced:
            self.add("offer-missing", "/", summarise(unpriced, 8))
        elif blocks and not products and self.home_has_prices():
            self.add("product-schema-missing", "/", "prices on the page, no SoftwareApplication or Product")

        has_faq = any("faqpage" in t for t in types)
        if not has_faq:
            faq_pages = [(path, f"{p.questions} questions") for path, p in self.body_pages() if p.questions >= 3]
            if faq_pages:
                self.add_pages("faq-schema-missing", faq_pages)

        # Machine-readable data: a data file linked from llms.txt or a page.
        data_urls = [u for u in self._llms_urls if re.search(r"\.(json|csv|md|txt|xml)(\?|$)", u)
                     and not re.search(r"/(llms|robots)\.txt$|sitemap[^/]*\.xml$", u)]
        for _r, page in self.pages.values():
            data_urls += [h for t, h in page.alternates if "json" in t]
        if data_urls:
            self.ok("data-files-ok", summarise([u.rsplit("/", 1)[-1] or u for u in data_urls], 4))
        else:
            self.add("data-files-missing", "/llms.txt", "no JSON, CSV or Markdown data linked")

    def home_has_prices(self) -> bool:
        text = self.home.text
        if re.search(r"[£$€¥]\s?\d", text) or re.search(r"\b\d+(\.\d+)?\s?(USD|GBP|EUR|JPY)\b", text):
            return True
        if re.search(r"\b(per|a) month\b|/mo(nth)?\b", text, re.I):
            return True
        # A free product saying so plainly has stated its price. "Free" alone
        # doesn't count: "free trial" and "free scan" are everywhere.
        return bool(FREE_PRICE_RE.search(text))

    def check_trust(self) -> None:
        home_key = page_key(self.home.url)
        if home_key in self.csr_pages:
            return
        hrefs = " ".join((l.raw + " " + l.text).lower() for l in self.home.links)
        text = self.home.text
        found = {
            "a contact link or email": "mailto:" in hrefs or "contact" in hrefs or "support" in hrefs,
            "a privacy policy link": "privacy" in hrefs,
            "company details": bool(re.search(
                r"\b(Ltd|Limited|LLC|L\.L\.C\.|Inc\.?|GmbH|PLC|Pty|B\.V\.|S\.A\.S?|K\.K\.)(?=\W|$)|株式会社|company (number|no)|registered in",
                text)) or self.org_has_legal(),
            "prices or a pricing link": self.home_has_prices() or "pricing" in hrefs or "/plans" in hrefs,
        }
        missing = [k for k, v in found.items() if not v]
        if missing:
            self.add("trust-missing", "/", ", ".join(missing))
        else:
            self.ok("trust-ok", "contact, privacy policy, company details and prices on the home page")

    def org_has_legal(self) -> bool:
        for block in self.home.jsonld:
            try:
                for node in jsonld_nodes(json.loads(block)):
                    if node.get("legalName") or node.get("address"):
                        return True
            except ValueError:
                continue
        return False

    def check_hosts_and_media(self) -> None:
        other = other_host_form(self.host)
        scheme = urlsplit(self.origin).scheme
        other_url = f"https://{other}/"
        http_url = f"http://{self.host}/"

        # Images to size: unique, http(s), up to MAX_IMAGES.
        images = []
        for _path, page in self.body_pages():
            for img in page.images:
                if img.src.startswith(("http://", "https://")) and img.src not in images:
                    images.append(img.src)
        images = images[: config.MAX_IMAGES]

        # External hosts linked both with and without www.
        sources: Dict[str, Dict[str, Set[str]]] = {}   # bare host -> form -> {source}

        def note(url: str, source: str) -> None:
            h = host_of(url)
            if not h or strip_www(h) == strip_www(self.host):
                return
            sources.setdefault(strip_www(h), {}).setdefault(h, set()).add(source)

        for _r, page in self.pages.values():
            for link in page.links:
                note(link.href, "page links")
            for block in page.jsonld:
                try:
                    data = json.loads(block)
                except ValueError:
                    continue
                for node in jsonld_nodes(data):
                    for key in ("url", "sameAs", "@id"):
                        vals = node.get(key)
                        for v in (vals if isinstance(vals, list) else [vals]):
                            if isinstance(v, str) and v.startswith("http"):
                                note(v, "structured data")
        if self.llms_text:
            for u in urls_in(self.llms_text):
                note(u, "llms.txt")
        mixed = {bare: forms for bare, forms in sources.items() if len(forms) > 1}
        mixed_probe = [f"https://{bare}/" for bare in list(mixed)[:5]]

        side = [other_url, http_url] + ([self._og_image] if self._og_image else []) + mixed_probe
        got = self.get_many(side)
        heads = self.get_many(images, method="HEAD")

        chains = []
        if len(getattr(self, "input_chain", [])) > 1:
            chains.append(self.chain_text(self.input_chain, self.origin + "/"))

        # www vs bare.
        r = got.get(other_url)
        if other_url in got:
            if r is None:
                self.add("host-unreachable", "/", other)
            elif host_of(r.url) == self.host and r.chain:
                first = r.chain[0][1]
                if first in PERMANENT_CODES:
                    self.ok("host-ok", f"{other} redirects to {self.host} ({first})")
                else:
                    self.add("host-redirect-temporary", "/", f"{other} -> {self.host} with a {first}")
                if len(r.chain) > 1:
                    chains.append(self.chain_text(r.chain, r.url))
            elif host_of(r.url) == other and r.ok and not r.chain:
                self.add("host-duplicate", "/", f"{self.host} and {other}")

        # HTTP -> HTTPS.
        r = got.get(http_url)
        if scheme == "http":
            self.add("http-not-redirected", "/", f"{self.origin}/ is served over HTTP")
        elif http_url in got and r is not None:
            if not r.chain and r.ok:
                self.add("http-not-redirected", "/", f"{http_url} answers {r.status} without redirecting")
            elif r.chain and r.url.startswith("https://"):
                self.ok("https-ok", f"{http_url} redirects to {r.url.split('/')[2]} over HTTPS ({r.chain[0][1]})")
                if len(r.chain) > 1:
                    chains.append(self.chain_text(r.chain, r.url))
        if chains:
            self.add("redirect-chain", "/", summarise(chains))

        if self._og_image:
            self.finish_og_image(got.get(self._og_image))

        if mixed:
            parts = []
            for bare, forms in mixed.items():
                served = got.get(f"https://{bare}/")
                served_host = host_of(served.url) if served is not None and served.ok else ""
                desc = "; ".join(f"{form} in {' and '.join(sorted(srcs))}"
                                 for form, srcs in sorted(forms.items()))
                if served_host in forms:
                    desc += f" (the site serves {served_host})"
                parts.append(f"{bare}: {desc}")
            self.add("external-host-mixed", "/", summarise(parts))

        big = []
        for url, resp in heads.items():
            if resp is None or not resp.ok:
                continue
            try:
                size = int(resp.headers.get("content-length", "0"))
            except ValueError:
                continue
            if size > config.IMAGE_MAX_BYTES:
                big.append((size, f"{self.path(url)} ({size // 1000} KB)"))
        if big:
            self.add("img-oversized", "/", summarise([t for _s, t in sorted(big, reverse=True)]))

    def chain_text(self, chain: List[Tuple[str, int]], final: str) -> str:
        hops = " -> ".join(u for u, _s in chain) + " -> " + final
        return f"{hops} ({len(chain)} hops)"


def scan_visibility(url: str, fetch: Callable[..., Optional[Fetched]],
                    now: Optional[_dt.datetime] = None, budget: float = config.BUDGET,
                    target: Optional[Target] = None, reviewer=None) -> CheckResult:
    """Run every phase-1 check against ``url``, then the positioning review
    when a ``reviewer`` is given (phase 2, see positioning.py)."""
    from . import CHECK
    from .positioning import review_positioning

    scan = _Scan(url, fetch, now, budget)
    scan.run()
    positioning = review_positioning(scan, reviewer)
    findings = sorted(scan.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.id, f.path))
    ran = scan.ran if scan.reachable else set()
    scores = category_scores(findings, config.CATEGORIES, ran)
    return CheckResult(
        check_id=CHECK.id,
        check_version=CHECK.version,
        target=target or Target(url=scan.origin),
        scanned_at=iso(scan.now),
        category_scores=scores,
        total=weighted_total(scores, config.CATEGORIES),
        findings=findings,
        meta={"pages_crawled": len(scan.pages), "final_url": scan.origin + "/",
              **({"positioning": positioning} if reviewer is not None else {})},
    )
