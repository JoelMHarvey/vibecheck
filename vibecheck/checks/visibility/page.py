"""Pull what the checks need out of a page's raw HTML.

Raw HTML on purpose: it is what a crawler that doesn't run JavaScript sees,
and that includes most AI crawlers. Standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

# Text inside these never reaches a reader of the raw HTML. noscript is
# included: "Please enable JavaScript" is not content.
_HIDDEN = {"script", "style", "template", "noscript", "svg", "head", "title"}
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
         "param", "source", "track", "wbr"}

EMPTY_ROOT_RE = re.compile(
    r"<div\b[^>]*\bid\s*=\s*[\"'](root|app|__next|__nuxt|___gatsby|svelte)[\"'][^>]*>\s*</div>",
    re.I,
)


@dataclass
class Link:
    href: str          # absolute URL (fragment kept)
    raw: str           # as written
    text: str


@dataclass
class Image:
    src: str           # absolute URL ("" if none)
    alt: Optional[str]  # None when the attribute is absent


@dataclass
class Page:
    url: str
    html_lang: Optional[str] = None
    titles: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)  # name/property (lower) -> content, first wins
    canonical: Optional[str] = None
    headings: List[Tuple[int, str]] = field(default_factory=list)
    links: List[Link] = field(default_factory=list)
    images: List[Image] = field(default_factory=list)
    jsonld: List[str] = field(default_factory=list)
    alternates: List[Tuple[str, str]] = field(default_factory=list)  # (type, href)
    script_srcs: List[str] = field(default_factory=list)
    ids: Set[str] = field(default_factory=set)
    text: str = ""
    questions: int = 0     # headings / summaries / dts that end in "?"
    empty_root: Optional[str] = None
    raw: str = ""

    @property
    def title(self) -> Optional[str]:
        return self.titles[0] if self.titles else None

    @property
    def description(self) -> Optional[str]:
        return self.meta.get("description")

    @property
    def h1s(self) -> List[str]:
        return [t for level, t in self.headings if level == 1]


def is_noindex(page: "Page", headers: Optional[Dict[str, str]] = None) -> bool:
    """The page asks search engines not to index it: <meta name="robots"> (or
    googlebot) or an X-Robots-Tag header saying noindex or none."""
    values = [page.meta.get("robots", ""), page.meta.get("googlebot", "")]
    if headers:
        values.append(headers.get("x-robots-tag", ""))
    for v in values:
        # X-Robots-Tag may name a bot first: "googlebot: noindex".
        tokens = {t.strip().split(":")[-1].strip() for t in v.lower().split(",")}
        if "noindex" in tokens or "none" in tokens:
            return True
    return False


def _collapse(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


class _Parser(HTMLParser):
    def __init__(self, page: Page):
        super().__init__(convert_charrefs=True)
        self.page = page
        self.hidden_depth = 0
        self.stack: List[str] = []
        self.text_parts: List[str] = []
        self.capture: Optional[List[str]] = None  # title / heading / link text
        self.capture_tag: Optional[str] = None
        self.link_href: Optional[str] = None
        self.link_parts: List[str] = []
        self.in_jsonld = False
        self.jsonld_parts: List[str] = []
        self.in_title = False
        self.title_parts: List[str] = []
        self.q_tag: Optional[str] = None
        self.q_parts: List[str] = []

    def _abs(self, href: str) -> str:
        try:
            return urljoin(self.page.url, href.strip())
        except ValueError:
            return ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if a.get("id"):
            self.page.ids.add(a["id"])
        if tag == "html" and "lang" in a:
            self.page.html_lang = a["lang"].strip()
        elif tag == "title" and not self.in_title:
            self.in_title = True
            self.title_parts = []
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or "").strip().lower()
            if key and key not in self.page.meta:
                self.page.meta[key] = _collapse(a.get("content", ""))
        elif tag == "link":
            rel = a.get("rel", "").lower().split()
            if "canonical" in rel and self.page.canonical is None:
                self.page.canonical = self._abs(a.get("href", ""))
            if "alternate" in rel and a.get("href"):
                self.page.alternates.append((a.get("type", "").lower(), self._abs(a["href"])))
        elif tag == "script":
            if a.get("type", "").lower() == "application/ld+json":
                self.in_jsonld = True
                self.jsonld_parts = []
            if a.get("src"):
                self.page.script_srcs.append(self._abs(a["src"]))
        elif tag == "img":
            src = a.get("src") or (a.get("srcset", "").split(",")[0].split(" ")[0])
            self.page.images.append(Image(self._abs(src) if src else "", a.get("alt") if "alt" in a else None))
        elif tag == "a" and "href" in a:
            self.link_href = a["href"]
            self.link_parts = []
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self.capture_tag = tag
            self.capture = []
        if tag in ("summary", "dt") or (tag in ("h2", "h3", "h4")):
            self.q_tag = tag
            self.q_parts = []

        if tag not in _VOID:
            self.stack.append(tag)
            if tag in _HIDDEN:
                self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag == "title" and self.in_title:
            self.in_title = False
            self.page.titles.append(_collapse("".join(self.title_parts)))
        if tag == "script" and self.in_jsonld:
            self.in_jsonld = False
            self.page.jsonld.append("".join(self.jsonld_parts))
        if tag == "a" and self.link_href is not None:
            raw = self.link_href
            self.page.links.append(Link(self._abs(raw), raw, _collapse("".join(self.link_parts))))
            self.link_href = None
        if self.capture is not None and tag == self.capture_tag:
            self.page.headings.append((int(tag[1]), _collapse("".join(self.capture))))
            self.capture = None
            self.capture_tag = None
        if self.q_tag == tag:
            if _collapse("".join(self.q_parts)).endswith("?"):
                self.page.questions += 1
            self.q_tag = None

        if tag in _VOID:
            return
        # Pop to the matching open tag, tolerating sloppy nesting.
        if tag in self.stack:
            while self.stack:
                top = self.stack.pop()
                if top in _HIDDEN:
                    self.hidden_depth = max(0, self.hidden_depth - 1)
                if top == tag:
                    break

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)
            return
        if self.in_jsonld:
            self.jsonld_parts.append(data)
            return
        if self.hidden_depth:
            return
        self.text_parts.append(data)
        if self.capture is not None:
            self.capture.append(data)
        if self.link_href is not None:
            self.link_parts.append(data)
        if self.q_tag is not None:
            self.q_parts.append(data)


def parse_page(url: str, html: str) -> Page:
    page = Page(url=url, raw=html)
    parser = _Parser(page)
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass  # a half-parsed page is still worth checking
    page.text = _collapse(" ".join(parser.text_parts))
    m = EMPTY_ROOT_RE.search(html)
    if m:
        page.empty_root = m.group(1)
    return page


def same_site_path(url: str) -> str:
    """The path (and query) of a URL, for display."""
    parts = urlsplit(url)
    path = parts.path or "/"
    return path + (f"?{parts.query}" if parts.query else "")


# ---- framework fingerprints -------------------------------------------------

def fingerprint(page: Page) -> Tuple[str, str]:
    """(family, label): family picks the fix prompt (vite / next / generic),
    label names the builder for the reader."""
    raw = page.raw.lower()
    gen = page.meta.get("generator", "").lower()
    author = page.meta.get("author", "").lower()
    srcs = " ".join(page.script_srcs).lower()
    if "lovable" in author or "lovable" in gen or "gptengineer" in raw or "lovable.dev" in raw or "lovable-tagger" in raw:
        return "vite", "Lovable (Vite + React)"
    if "bolt" in gen or "bolt.new" in raw or "stackblitz" in raw:
        return "vite", "Bolt (Vite)"
    if "v0.dev" in raw or "v0.app" in raw or gen.startswith("v0"):
        return "next", "v0 (Next.js)"
    if "__next_data__" in raw or "/_next/static" in raw or "self.__next_f" in raw:
        return "next", "Next.js"
    if "/@vite/client" in raw or re.search(r"/assets/index-[\w-]+\.js", srcs) or 'type="module" crossorigin' in raw:
        return "vite", "Vite"
    if "/static/js/main." in srcs:
        return "generic", "Create React App"
    return "generic", ""
