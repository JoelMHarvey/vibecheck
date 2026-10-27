"""HTTP for every check that reads a live site.

A fetch returns a ``Fetched`` (with the redirect chain it followed) or None
when the request failed, timed out or was refused by the SSRF guard. The
checks only ever see this interface, so tests swap in a dictionary of
recorded responses.

Two transports:

- guarded (the hosted API): every hop is vetted by ``netguard.vet_url`` and
  the connection goes to the address that was vetted, not to a fresh DNS
  answer, so a name can't pass the check and then resolve somewhere private.
- unguarded (the CLI): plain urllib, which honours HTTPS_PROXY. Pointing the
  CLI at your own staging box is a fair use of a tool on your own machine.

Redirects are always followed by hand, up to MAX_REDIRECTS, so the chain is
visible to the checks and each hop can be vetted.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin, urlsplit

# Defaults; a check asks for its own (the security scan keeps its older,
# tighter limits, the visibility crawl uses these).
USER_AGENT = "vibecheck/0.1 (+https://psychosecurity.io)"
TIMEOUT = 10.0
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5

REDIRECT_CODES = (301, 302, 303, 307, 308)
PERMANENT_CODES = (301, 308)


@dataclass
class Fetched:
    url: str                      # where the chain ended
    status: int
    headers: Dict[str, str]       # keys lower-cased
    body: bytes = b""
    chain: List[Tuple[str, int]] = field(default_factory=list)  # (url, status) per redirect hop
    truncated: bool = False

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip().strip('"') or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        if self.content_type in ("text/html", "application/xhtml+xml"):
            return True
        if not self.content_type:
            return b"<html" in self.body[:2000].lower()
        return False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


Fetcher = Callable[..., Optional[Fetched]]


def _safe_url(url: str) -> str:
    """Percent-encode anything in the path or query that isn't legal on the
    wire (spaces, non-ASCII), leaving existing escapes alone."""
    parts = urlsplit(url)
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/%:@!$&'()*+,;=-._~?")
    return f"{parts.scheme}://{parts.netloc}{path}" + (f"?{query}" if query else "")


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # SNI and certificate checks use the hostname; only the address is pinned.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _read_capped(stream, max_bytes: int, deadline: float) -> Tuple[bytes, bool]:
    chunks, size = [], 0
    while size <= max_bytes:
        if time.monotonic() > deadline:
            return b"".join(chunks), True
        chunk = stream.read(min(65536, max_bytes + 1 - size))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)[:max_bytes], True


def _pinned_request(url, ip, method, headers, timeout, max_bytes):
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if parts.scheme == "https":
        conn = _PinnedHTTPS(parts.hostname, ip, port=port, timeout=timeout,
                            context=ssl.create_default_context())
    else:
        conn = _PinnedHTTP(parts.hostname, ip, port=port, timeout=timeout)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    try:
        conn.request(method, target, headers=headers)
        resp = conn.getresponse()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        body, truncated = (b"", False)
        if method != "HEAD" and resp.status not in REDIRECT_CODES:
            body, truncated = _read_capped(resp, max_bytes, time.monotonic() + timeout * 2)
        return resp.status, hdrs, body, truncated
    finally:
        conn.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urllib_request(url, method, headers, timeout, max_bytes):
    req = urllib.request.Request(url, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:  # noqa: S310 (user-chosen URL, CLI only)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            body, truncated = (b"", False)
            if method != "HEAD":
                body, truncated = _read_capped(r, max_bytes, time.monotonic() + timeout * 2)
            return r.status, hdrs, body, truncated
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        body = b""
        if e.code not in REDIRECT_CODES and method != "HEAD":
            try:
                body = e.read(max_bytes)
            except Exception:
                body = b""
        return e.code, hdrs, body, False


def build_fetcher(guard: bool = True, *, timeout: float = TIMEOUT,
                  max_bytes: int = MAX_BYTES, max_redirects: int = MAX_REDIRECTS,
                  user_agent: str = USER_AGENT, resolver=None) -> Fetcher:
    """The real network fetcher. ``guard=True`` for anything hosted."""
    from . import netguard

    resolve = resolver or netguard.resolve_host
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
    }

    def fetch(url: str, method: str = "GET") -> Optional[Fetched]:
        chain: List[Tuple[str, int]] = []
        current = _safe_url(url)
        for _ in range(max_redirects + 1):
            try:
                if guard:
                    ok, _reason, ip = netguard.vet_url(current, resolve)
                    if not ok:
                        return None
                    status, hdrs, body, truncated = _pinned_request(
                        current, ip, method, headers, timeout, max_bytes)
                else:
                    status, hdrs, body, truncated = _urllib_request(
                        current, method, headers, timeout, max_bytes)
            except Exception:
                return None
            if status in REDIRECT_CODES and hdrs.get("location"):
                chain.append((current, status))
                current = _safe_url(urljoin(current, hdrs["location"]))
                continue
            return Fetched(url=current, status=status, headers=hdrs, body=body,
                           chain=chain, truncated=truncated)
        return None  # too many redirects

    return fetch
