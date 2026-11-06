"""psychosecurity.io as one WSGI app, so the site can run on a server of its
own instead of Vercel. Standard library only, like the scanner.

    gunicorn server.app:app        # what the Docker image runs

It does what Vercel does with this repository, driven by the same files:

- the static site, with vercel.json's cleanUrls: /check serves check.html,
  /check.html answers 308 to /check, / is index.html;
- nothing .vercelignore or .gitignore leaves out of a deployment, no dotfile,
  and none of the files only a server needs (server/, the Dockerfile);
- vercel.json's rewrites and headers, read from vercel.json itself;
- every api/<name>.py function at /api/<name>, run by its own handler class,
  unchanged: the request is handed to the class as BaseHTTPRequestHandler
  would hand it, and whatever it writes goes back as the response.

Plus GET /api/health/live, which touches nothing, for the container's
health check. Off Vercel nobody vouches for X-Vercel-Forwarded-For, so it is
dropped; the rate limits read X-Real-IP, which the server's Caddy sets.
"""

from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import io
import json
import mimetypes
import os
import re
import sys
import traceback
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from types import ModuleType
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HEALTH_PATH = "/api/health/live"

# Vercel refuses a function request body over 4.5 MB before the function
# runs; api/scan.py is written to that limit.
MAX_BODY_BYTES = 4_500_000

# Files a Vercel deployment of this repository never serves although no
# ignore file names them (checked against the live site). The files that
# exist only for this server are in .vercelignore, so neither serves them.
NEVER_SERVED = {"README.md", "vercel.json"}

# Content types as Vercel sends them for the files this site has; anything
# else falls back to the mimetypes table, then to a download.
TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
    ".yml": "text/yaml; charset=utf-8",
    ".yaml": "text/yaml; charset=utf-8",
    ".xml": "application/xml",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".py": "application/octet-stream",
}

# Vercel's own headers on static files.
STATIC_CACHE = "public, max-age=0, must-revalidate"
HSTS = "max-age=63072000"

Response = Tuple[int, List[Tuple[str, str]], bytes]


# ---------------------------------------------------------------------------
# vercel.json and the ignore files

def load_config(root: Path = ROOT) -> dict:
    with open(root / "vercel.json", encoding="utf-8") as f:
        return json.load(f)


def source_regex(source: str) -> "re.Pattern[str]":
    """A vercel.json source (path-to-regexp) as a regex, for the forms this
    repository uses: literal text, :name segments and (.*) groups."""
    out, i = "", 0
    while i < len(source):
        if source.startswith("(.*)", i):
            out += "(.*)"
            i += 4
            continue
        m = re.match(r":([A-Za-z_][A-Za-z0-9_]*)", source[i:])
        if m:
            out += f"(?P<{m.group(1)}>[^/]+?)"
            i += len(m.group(0))
            continue
        out += re.escape(source[i])
        i += 1
    return re.compile("^" + out + "$")


def ignore_patterns(root: Path = ROOT) -> List[str]:
    """.vercelignore and .gitignore lines: what a deployment never contains."""
    patterns: List[str] = []
    for name in (".vercelignore", ".gitignore"):
        try:
            content = (root / name).read_text(encoding="utf-8")
        except OSError:
            continue
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("!"):
                patterns.append(line)
    return patterns


def ignored(rel: str, patterns: Iterable[str]) -> bool:
    """Whether a repository-relative path is left out by gitignore-style
    patterns: "dir/" covers everything under any directory of that name (or
    that anchored path), "a/*/b" is anchored, a bare name matches any part."""
    parts = rel.split("/")
    for pattern in patterns:
        directory = pattern.endswith("/")
        pat = pattern.strip("/")
        anchored = "/" in pat
        if anchored:
            # Compared with the path's first segments: a directory pattern
            # covers what is under it, a file pattern the path itself too.
            depth = pat.count("/") + 1
            if len(parts) >= depth and fnmatch.fnmatchcase("/".join(parts[:depth]), pat) and \
                    (len(parts) > depth or not directory):
                return True
        else:
            names = parts[:-1] if directory else parts
            if any(fnmatch.fnmatchcase(p, pat) for p in names):
                return True
    return False


def public_files(root: Path = ROOT) -> Dict[str, Path]:
    """Every file the site serves, by URL path ("/check.html"). Built once
    from a walk of the tree, so a request can only ever name one of these:
    no path from a URL ever reaches the filesystem."""
    patterns = ignore_patterns(root)
    files: Dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in dirnames:
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if d.startswith(".") or d == "__pycache__" or (not rel_dir and d in ("api", *NEVER_SERVED)):
                continue
            if ignored(rel + "/x", patterns):
                continue
            keep.append(d)
        dirnames[:] = sorted(keep)
        for name in filenames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if name.startswith(".") or name.endswith(".pyc"):
                continue
            if not rel_dir and name in NEVER_SERVED:
                continue
            if ignored(rel, patterns):
                continue
            path = Path(dirpath) / name
            if path.is_file() and not path.is_symlink():
                files["/" + rel] = path
    return files


# ---------------------------------------------------------------------------
# The Vercel functions

class _Captured:
    """What a handler writes: status, headers, then the body to wfile."""

    def __init__(self) -> None:
        self.status = 200
        self.headers: List[Tuple[str, str]] = []


def load_functions(root: Path = ROOT) -> Dict[str, ModuleType]:
    """Each api/<name>.py, loaded, by its URL, as Vercel mounts them."""
    out: Dict[str, ModuleType] = {}
    for path in sorted((root / "api").glob("*.py")):
        if path.name.startswith("_"):
            continue
        module_name = "psychosecurity_api_" + re.sub(r"\W", "_", path.stem)
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        out["/api/" + path.stem] = module
    return out


def request_headers(environ: dict) -> Message:
    """The request's headers as the handler classes expect them (they call
    self.headers.get, which is case-insensitive on this type)."""
    headers = Message()
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").title()
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            name = key.replace("_", "-").title()
        else:
            continue
        if value != "" and name.lower() != "x-vercel-forwarded-for":
            headers[name] = value
    # Caddy sets X-Real-IP. Reached any other way (the host's loopback), the
    # connection's own address is the best there is.
    if headers.get("x-real-ip") is None and headers.get("x-forwarded-for") is None:
        remote = environ.get("REMOTE_ADDR")
        if remote:
            headers["X-Real-IP"] = remote
    return headers


def run_function(handler_cls: type, method: str, path: str, environ: dict, body: bytes) -> Response:
    """Run one Vercel handler class against this request, the way
    BaseHTTPRequestHandler would, without a socket."""
    do = getattr(handler_cls, "do_" + method, None)
    if do is None:
        return text(501, f"Unsupported method ('{method}')")
    captured = _Captured()
    bound = handler_cls.__new__(handler_cls)
    bound.command = method
    bound.path = path
    bound.request_version = "HTTP/1.1"
    bound.requestline = f"{method} {path} HTTP/1.1"
    bound.client_address = (environ.get("REMOTE_ADDR", ""), 0)
    bound.headers = request_headers(environ)
    bound.rfile = io.BytesIO(body)
    bound.wfile = io.BytesIO()
    bound.close_connection = True

    def send_response(code, message=None):
        captured.status = int(code)

    def send_header(name, value):
        captured.headers.append((str(name), str(value)))

    bound.send_response = send_response
    bound.send_response_only = send_response
    bound.send_header = send_header
    bound.end_headers = lambda: None
    do(bound)
    return captured.status, captured.headers, bound.wfile.getvalue()


# ---------------------------------------------------------------------------
# Responses

def text(status: int, message: str, extra: Optional[List[Tuple[str, str]]] = None) -> Response:
    data = (message + "\n").encode("utf-8")
    return status, [("Content-Type", "text/plain; charset=utf-8"), *(extra or [])], data


def redirect(location: str) -> Response:
    return text(308, f"Redirecting to {location} (308)", [("Location", location)])


def content_type(path: Path) -> str:
    known = TYPES.get(path.suffix.lower())
    if known:
        return known
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def status_line(status: int) -> str:
    try:
        return f"{status} {HTTPStatus(status).phrase}"
    except ValueError:
        return f"{status} Unknown"


class Site:
    """The whole site as a WSGI callable."""

    def __init__(self, root: Path = ROOT) -> None:
        self.root = root
        config = load_config(root)
        self.understood(config)
        self.files = public_files(root)
        # The modules stay reachable so tests can swap their limiters.
        self.modules = load_functions(root)
        self.functions = {url: module.handler for url, module in self.modules.items()}
        self.rewrites = [(source_regex(r["source"]), r["destination"]) for r in config.get("rewrites", [])]
        self.header_rules = [(source_regex(r["source"]), [(h["key"], h["value"]) for h in r["headers"]])
                             for r in config.get("headers", [])]
        self.clean_urls = bool(config.get("cleanUrls"))
        self._etags: Dict[str, str] = {}

    @staticmethod
    def understood(config: dict) -> None:
        """vercel.json may only say what this server does. A new setting there
        (redirects, trailingSlash, crons...) should fail here, loudly, rather
        than be ignored on the server while working on Vercel."""
        known = {"$schema", "cleanUrls", "functions", "rewrites", "headers"}
        unknown = set(config) - known
        if unknown:
            raise RuntimeError("server/app.py doesn't implement vercel.json's " + ", ".join(sorted(unknown)))

    # -- WSGI ---------------------------------------------------------------

    def __call__(self, environ: dict, start_response: Callable) -> List[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO") or "/"
        query = environ.get("QUERY_STRING", "")
        try:
            status, headers, body = self.respond(method, path, query, environ)
        except Exception:  # a handler crashed: say so, as Vercel would, and log where
            traceback.print_exc(file=sys.stderr)
            status, headers, body = text(500, "A server error has occurred")
        names = {k.lower() for k, _ in headers}
        for pattern, rule in self.header_rules:
            if pattern.match(path):
                headers.extend((k, v) for k, v in rule if k.lower() not in names)
        if "strict-transport-security" not in names:
            headers.append(("Strict-Transport-Security", HSTS))
        if "content-length" not in names and status != 304:
            headers.append(("Content-Length", str(len(body))))
        start_response(status_line(status), headers)
        return [b""] if method == "HEAD" else [body]

    def read_body(self, environ: dict) -> Tuple[Optional[bytes], int]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            return None, length
        stream = environ.get("wsgi.input")
        return (stream.read(length) if stream is not None and length > 0 else b""), length

    def respond(self, method: str, path: str, query: str, environ: dict) -> Response:
        if path == HEALTH_PATH:
            return 200, [("Content-Type", "application/json"), ("Cache-Control", "no-store")], b'{"ok":true}\n'

        # Static files first, as on Vercel; then cleanUrls; then the rewrites.
        static = self.static(method, path, query, environ)
        if static is not None:
            return static

        for pattern, destination in self.rewrites:
            m = pattern.match(path)
            if m:
                for name, value in m.groupdict().items():
                    destination = destination.replace(":" + name, quote(value, safe=""))
                path, _, dest_query = destination.partition("?")
                query = "&".join(q for q in (dest_query, query) if q)
                break

        handler_cls = self.functions.get(path)
        if handler_cls is not None:
            body, length = self.read_body(environ)
            if body is None:
                return text(413, "Request Entity Too Large")
            return run_function(handler_cls, method, path + ("?" + query if query else ""), environ, body)
        # The function's source file is not the function.
        if path.startswith("/api/") and path.endswith(".py") and path[:-3] in self.functions:
            return redirect(path[:-3] + ("?" + query if query else ""))
        return text(404, "The page could not be found")

    # -- static files ---------------------------------------------------------

    def static(self, method: str, path: str, query: str, environ: dict) -> Optional[Response]:
        suffix = "?" + query if query else ""
        if self.clean_urls and path.endswith(".html"):
            # Every .html address redirects to its clean form, file or not.
            clean = path[: -len(".html")]
            if clean.endswith("/index") or clean == "/index":
                clean = clean[: -len("index")]
            return redirect((clean or "/") + suffix)
        if self.clean_urls and (path.endswith("/index") or path == "/index") and \
                ("/" + path.strip("/") + ".html") in self.files:
            return redirect(path[: -len("index")] + suffix)
        found = self.resolve(path)
        if found is None:
            return None
        if method not in ("GET", "HEAD"):
            return text(405, "Method Not Allowed", [("Allow", "GET, HEAD")])
        url_path, file_path = found
        etag = self.etag(url_path, file_path)
        headers = [("Content-Type", content_type(file_path)), ("Cache-Control", STATIC_CACHE),
                   ("ETag", etag), ("Access-Control-Allow-Origin", "*")]  # vibecheck-ignore: cors-allow-all
        if etag in (environ.get("HTTP_IF_NONE_MATCH") or ""):
            return 304, headers, b""
        return 200, headers, file_path.read_bytes()

    def resolve(self, path: str) -> Optional[Tuple[str, Path]]:
        """The file a URL path names, or None. /x is x, else x.html, else
        x/index.html; a trailing slash is tolerated on a page, as on Vercel."""
        bare = path.rstrip("/") or "/"
        candidates = []
        if not path.endswith("/") and path in self.files:
            candidates.append(path)
        if self.clean_urls:
            if bare == "/":
                candidates.append("/index.html")
            else:
                candidates += [bare + ".html", bare + "/index.html"]
        for candidate in candidates:
            if candidate in self.files:
                return candidate, self.files[candidate]
        return None

    def etag(self, url_path: str, file_path: Path) -> str:
        tag = self._etags.get(url_path)
        if tag is None:
            tag = '"' + hashlib.sha256(file_path.read_bytes()).hexdigest()[:32] + '"'
            self._etags[url_path] = tag
        return tag


def check_deployed_settings(env=None) -> List[str]:
    """Refuse a deployed server whose limits are switched off; warn about
    what it will lack. VIBECHECK_DEPLOYED=1 stands in for Vercel's VERCEL=1."""
    env = os.environ if env is None else env
    if (env.get("VIBECHECK_DEPLOYED") or "").strip() not in ("1", "true", "yes"):
        return []
    if (env.get("VIBECHECK_RATE_LIMIT_OFF") or "").strip().lower() in ("1", "true", "yes"):
        raise RuntimeError("VIBECHECK_RATE_LIMIT_OFF is set on a deployed server; unset it")
    warnings = []
    if not (env.get("VIBECHECK_SIGNING_KEY") or "").strip():
        warnings.append("VIBECHECK_SIGNING_KEY is not set: reports and badges will go out unsigned")
    if not (env.get("KV_REST_API_URL") or env.get("UPSTASH_REDIS_REST_URL")):
        warnings.append("no KV store: rate limits and the cache are per worker process")
    return warnings


for _warning in check_deployed_settings():
    print("psychosecurity: " + _warning, file=sys.stderr)

app = Site()
