"""Scan a *deployed* site for security mistakes — no source code needed.

This is the zero-friction check: give it a URL and it looks for the things
that leak from a live vibe-coded app regardless of how it was built —
an exposed .env, published source maps, missing security headers, CORS
open to everyone, and admin paths advertised in robots.txt.

The HTTP layer is injected (``fetch``) so the checks are fully testable
without a network. A fetch returns a ``Response`` or None (connection
failed / timed out).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .scanner import Finding, ScanResult, _finalize

# Paths that should never be readable on a deployed site. Each maps to a
# (rule_id, title, severity, description, fix_prompt) tuple.
SENSITIVE_PATHS = {
    "/.env": (
        "exposed-env-file",
        "Live .env file is publicly readable",
        "critical",
        "Your deployed site serves its .env file to anyone who asks for "
        "/.env. Every secret in it — API keys, database passwords, signing "
        "secrets — is being handed to the public right now.",
        "My deployed site serves its .env file at the public URL /.env. Make the "
        "server refuse to serve dotfiles, move .env out of the web root / public "
        "directory, and confirm the deploy no longer includes it. Then remind me "
        "to rotate EVERY credential in that file because it has been exposed.",
    ),
    "/.git/config": (
        "exposed-git-dir",
        "Live .git directory is publicly readable",
        "critical",
        "Your .git directory is being served publicly. Anyone can download "
        "your entire source history — including any secrets ever committed "
        "and later 'removed' — by cloning it straight off your site.",
        "My deployed site exposes its .git directory (/.git/config is readable). "
        "Stop the server from serving the .git folder, remove it from the deployed "
        "output, and remind me to rotate any secret that was ever committed to this "
        "repo's history because the full history is downloadable.",
    ),
    "/.env.local": (
        "exposed-env-file",
        "Live .env.local file is publicly readable",
        "critical",
        "Your deployed site serves .env.local publicly. Every secret in it "
        "is readable by anyone.",
        "My deployed site serves /.env.local publicly. Stop serving dotfiles, keep "
        "env files out of the web root, and remind me to rotate every credential "
        "inside it.",
    ),
    "/config.json": (
        "exposed-config",
        "config.json is publicly readable",
        "medium",
        "A config.json is served publicly. That's fine if it only holds "
        "public settings, but config files often accidentally contain API "
        "keys or internal URLs.",
        "My deployed site serves /config.json publicly. Check it for anything that "
        "shouldn't be public (API keys, secrets, internal endpoints); if it has "
        "them, move those to server-side environment variables and rotate them.",
    ),
    "/.aws/credentials": (
        "exposed-aws-credentials",
        "AWS credentials file publicly readable",
        "critical",
        "An AWS credentials file is being served publicly. Anyone can take "
        "your AWS keys and use your account.",
        "My deployed site serves an AWS credentials file publicly at "
        "/.aws/credentials. Remove it from the deploy, never include credential "
        "files in the web root, and remind me to deactivate those AWS keys "
        "immediately.",
    ),
}

# Security response headers we expect on an HTML page, with the fix guidance.
SECURITY_HEADERS = {
    "strict-transport-security": (
        "missing-hsts",
        "Missing HSTS header",
        "low",
        "Your site doesn't send Strict-Transport-Security, so a visitor's "
        "first request can be downgraded to plain HTTP and intercepted.",
        "My deployed site is missing the Strict-Transport-Security header. Add "
        "'Strict-Transport-Security: max-age=63072000; includeSubDomains' to my "
        "site's response headers (in vercel.json, netlify.toml, or my server config).",
    ),
    "x-content-type-options": (
        "missing-xcto",
        "Missing X-Content-Type-Options header",
        "low",
        "Without X-Content-Type-Options: nosniff, browsers may guess the "
        "type of a response and execute a file you didn't intend to be a "
        "script.",
        "My deployed site is missing the X-Content-Type-Options header. Add "
        "'X-Content-Type-Options: nosniff' to my site's response headers.",
    ),
    "content-security-policy": (
        "missing-csp",
        "No Content-Security-Policy",
        "low",
        "There's no Content-Security-Policy header. A CSP is the strongest "
        "defence against cross-site scripting (XSS) — without it, an injected "
        "script runs with no restrictions.",
        "My deployed site has no Content-Security-Policy header. Add a CSP that "
        "restricts scripts to my own domain and any services I actually use, then "
        "test it doesn't break the app. Start in report-only mode if unsure.",
    ),
    "x-frame-options": (
        "missing-xfo",
        "Missing X-Frame-Options / frame-ancestors",
        "low",
        "Nothing stops your site being embedded in an <iframe> on another "
        "site, which enables clickjacking (tricking your users into clicking "
        "things they can't see).",
        "My deployed site can be framed by any other site. Add 'X-Frame-Options: "
        "DENY' (or a Content-Security-Policy with frame-ancestors 'self') to my "
        "response headers.",
    ),
}


@dataclass
class Response:
    status: int
    headers: Dict[str, str]  # keys l-cased by the fetcher
    text: str
    url: str


Fetcher = Callable[[str], Optional[Response]]


def _norm_base(url: str) -> str:
    if not urlparse(url).scheme:
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _finding(rule_id, title, severity, path, description, fix_prompt, excerpt) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        path=path,
        line=0,
        excerpt=excerpt,
        description=description,
        fix_prompt=fix_prompt,
    )


def _looks_like_real_file(resp: Response) -> bool:
    """A 200 that's actually an SPA's index.html (catch-all routing) is not a
    real exposed file. Treat HTML responses to dotfile paths as false hits."""
    ctype = resp.headers.get("content-type", "")
    if "text/html" in ctype and "<html" in resp.text.lower()[:2000]:
        return False
    return bool(resp.text.strip())


def _check_sensitive_paths(base: str, fetch: Fetcher) -> List[Finding]:
    findings = []
    for path, (rule_id, title, severity, desc, fix) in SENSITIVE_PATHS.items():
        resp = fetch(urljoin(base, path))
        if resp is None or resp.status != 200:
            continue
        if not _looks_like_real_file(resp):
            continue
        # For .env-style files, confirm it smells like key=value, not a page.
        if path.endswith((".env", ".env.local", "credentials")):
            if "=" not in resp.text[:500]:
                continue
        findings.append(_finding(rule_id, title, severity, path, desc, fix,
                                 f"GET {path} returned 200 with file-like content"))
    return findings


def _check_source_maps(base: str, home: Response, fetch: Fetcher) -> List[Finding]:
    """If the homepage references a bundle, see whether its .map is public."""
    findings = []
    import re

    scripts = re.findall(r'src=[\"\']([^\"\']+\.js)[\"\']', home.text)[:5]
    checked = set()
    for src in scripts:
        map_url = urljoin(base, src if src.startswith("http") else urljoin(base, src)) + ".map"
        if map_url in checked:
            continue
        checked.add(map_url)
        resp = fetch(map_url)
        if resp and resp.status == 200 and '"sources"' in resp.text[:2000]:
            findings.append(_finding(
                "exposed-source-map",
                "Source maps are published",
                "medium",
                urlparse(map_url).path,
                "Your JavaScript source maps are publicly served. They let "
                "anyone reconstruct your original, unminified source code — "
                "including comments and any secrets or logic you assumed were "
                "hidden in the bundle.",
                "My deployed site publishes JavaScript source maps (.map files are "
                "publicly readable). Turn off source map generation for production "
                "builds, or stop the server from serving .map files. Check the "
                "reconstructed source didn't expose any secrets.",
                f"GET {urlparse(map_url).path} returned a valid source map",
            ))
            break  # one is enough to make the point
    return findings


def _check_headers(base: str, home: Response) -> List[Finding]:
    findings = []
    present = home.headers
    for header, (rule_id, title, severity, desc, fix) in SECURITY_HEADERS.items():
        if header not in present:
            findings.append(_finding(rule_id, title, severity, "(response headers)",
                                     desc, fix, f"'{header}' header not sent"))
    # CORS wide open
    acao = present.get("access-control-allow-origin")
    if acao == "*":
        findings.append(_finding(
            "cors-wildcard-live",
            "Live site sends CORS: allow all origins",
            "medium",
            "(response headers)",
            "Your site responds with Access-Control-Allow-Origin: *, letting "
            "any website read responses from it. Combined with cookie auth "
            "this can expose logged-in users' data to malicious sites.",
            "My deployed site returns 'Access-Control-Allow-Origin: *'. Restrict it "
            "to only the origins that actually need cross-origin access, and never "
            "combine a wildcard with credentialed (cookie) requests.",
            "Access-Control-Allow-Origin: *",
        ))
    return findings


def _check_robots(base: str, fetch: Fetcher) -> List[Finding]:
    resp = fetch(urljoin(base, "/robots.txt"))
    if not resp or resp.status != 200:
        return []
    findings = []
    suspicious = ("admin", "secret", "private", "internal", "staging", "backup", "dashboard")
    for raw in resp.text.splitlines():
        line = raw.strip()
        if not line.lower().startswith("disallow:"):
            continue
        path = line.split(":", 1)[1].strip()
        if path and path != "/" and any(word in path.lower() for word in suspicious):
            findings.append(_finding(
                "robots-leaks-paths",
                "robots.txt advertises sensitive paths",
                "low",
                "/robots.txt",
                "Your robots.txt lists a sensitive-looking path in a Disallow "
                "rule. robots.txt is public, so this is a signpost pointing "
                "attackers straight at the pages you most want hidden — it "
                "does not protect them.",
                "My robots.txt lists sensitive paths (like {p}) in Disallow rules, "
                "which just advertises them. Protect those routes with real "
                "authentication instead of relying on robots.txt, and remove the "
                "revealing entries.".format(p=path),
                f"Disallow: {path}",
            ))
    return findings


def scan_url(url: str, fetch: Fetcher, root_label: Optional[str] = None) -> ScanResult:
    """Run all deployed-site checks against ``url`` using ``fetch``."""
    base = _norm_base(url)
    result = ScanResult(root=root_label or base)

    home = fetch(base + "/")
    if home is None:
        result.findings.append(_finding(
            "site-unreachable",
            "Site could not be reached",
            "info",
            base,
            "vibecheck couldn't connect to this URL, so no deployed-site "
            "checks ran. Check the address is correct and the site is up.",
            "",
            "connection failed",
        ))
        return _finalize(result)

    result.files_scanned = 1
    if home.url.startswith("http://"):
        result.findings.append(_finding(
            "no-https",
            "Site served over plain HTTP",
            "high",
            base,
            "Your site is served over HTTP, not HTTPS. Everything between your "
            "users and the site — including passwords and session cookies — "
            "travels unencrypted and can be read or altered in transit.",
            "My deployed site is served over plain HTTP. Enable HTTPS (most hosts "
            "like Vercel/Netlify do this automatically once a domain is added) and "
            "redirect all HTTP traffic to HTTPS.",
            home.url,
        ))

    result.findings.extend(_check_sensitive_paths(base, fetch))
    result.findings.extend(_check_source_maps(base, home, fetch))
    result.findings.extend(_check_headers(base, home))
    result.findings.extend(_check_robots(base, fetch))
    return _finalize(result)


def build_default_fetcher(timeout: float = 8.0) -> Fetcher:
    """A urllib-based fetcher for the CLI. Kept out of scan_url so tests
    never touch the network."""
    import urllib.request

    def fetch(target: str) -> Optional[Response]:
        req = urllib.request.Request(target, headers={"User-Agent": "vibecheck/0.1 (+https://psychosecurity.io)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (URL is user-supplied by design)
                raw = r.read(1_000_000)
                headers = {k.lower(): v for k, v in r.headers.items()}
                text = raw.decode("utf-8", errors="replace")
                return Response(status=r.status, headers=headers, text=text, url=r.geturl())
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            return Response(status=e.code, headers=headers, text="", url=target)
        except Exception:
            return None

    return fetch
