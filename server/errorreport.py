"""Send unhandled errors to GlitchTip (Sentry-compatible), with personal data removed.

Standard library only. Does nothing at all unless SENTRY_DSN is set in the
environment, so tests, local runs and a server without the setting send
nothing. The DSN is a secret of the server's env file; it is never in the repo.

What leaves the app, and nothing else: the exception's class name, its message
after scrub() (first and last line only; quoted text, numbers, emails, links, IPs and tokens removed), and
the stack as file, function and line. No request body, query string, cookie,
header, user, IP address or local variable is ever read, so none can be sent.
The route is sent as its pattern ("/item/<int:id>"), never the address asked for.

Use:
    import errorreport
    errorreport.init_flask(app, "myapp")        # unhandled errors in requests
    errorreport.install_excepthook("myapp")     # scripts and workers
    errorreport.capture_exception(exc, where="cron:digest")   # a job that catches its own errors
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid

MAX_MESSAGE = 200
MAX_FRAMES = 40
MAX_EVENTS_PER_MINUTE = 20
TIMEOUT_SECONDS = 3

_APP = {"name": ""}
_sent: list[float] = []
_lock = threading.Lock()

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s'\"<>)]+", re.I)
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_PG_VALUE = re.compile(r"=\s*\([^)]*\)")
_QUOTED = re.compile(r"\"[^\"\n]*\"|'[^'\n]*'")
_BACKTICK = re.compile(r"`([^`\n]*)`")
_CODE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,60}(?:\(\))?$")
_TOKEN = re.compile(r"\b[A-Za-z0-9_\-]{24,}\b")
_NUMBER = re.compile(r"\d[\d.,:/\-]*")
_ERROR_CODE = re.compile(r"^[A-Z0-9_]{2,24}$")


def scrub(text: object) -> str:
    """Remove personal data from an exception message. Order matters.

    Strict on purpose: a message can quote what a person typed, or print the
    whole query it was given. So only the first and last lines are kept (the
    middle of a long message is where arguments are dumped), everything in
    single or double quotes goes, every number goes, and so do emails, links,
    IP addresses and long tokens. Code names in backticks stay. What cannot be
    caught is free text with no quotes round it inside those two lines.
    """
    s = str(text) if text is not None else ""
    lines = [ln.strip() for ln in s.splitlines() if ln.strip()]
    if len(lines) > 2:
        lines = [lines[0], lines[-1]]
    s = " | ".join(lines)
    s = _EMAIL.sub("[email]", s)
    s = _URL.sub("[url]", s)
    s = _PG_VALUE.sub("=([value])", s)
    s = _QUOTED.sub("[text]", s)
    s = _BACKTICK.sub(lambda m: m.group(0) if _CODE.match(m.group(1)) else "[text]", s)
    s = _IPV6.sub("[ip]", s)
    s = _TOKEN.sub("[token]", s)
    s = _NUMBER.sub("[n]", s)
    s = " ".join(s.split())
    return s[:MAX_MESSAGE]


def error_code(exc: BaseException) -> str:
    """A machine code for the error (Postgres SQLSTATE, errno name), never text."""
    for attr in ("sqlstate", "pgcode", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, str) and _ERROR_CODE.match(value):
            return value
    return ""


def parse_dsn(dsn: str | None):
    """(store URL, public key) for a DSN, or None when it is missing or malformed."""
    if not dsn:
        return None
    try:
        u = urllib.parse.urlsplit(dsn.strip())
        project = u.path.strip("/").split("/")[-1]
        if u.scheme not in ("https", "http") or not u.username or not u.hostname or not project.isdigit():
            return None
        host = u.hostname + (f":{u.port}" if u.port else "")
        prefix = "/".join(u.path.strip("/").split("/")[:-1])
        base = f"{u.scheme}://{host}" + (f"/{prefix}" if prefix else "")
        return f"{base}/api/{project}/store/", u.username
    except Exception:
        return None


def _frames(tb) -> list[dict]:
    root = os.getcwd().rstrip("/") + "/"
    out = []
    for f in traceback.extract_tb(tb)[-MAX_FRAMES:]:
        name = f.filename or ""
        if name.startswith(root):
            name = name[len(root):]
        elif "site-packages/" in name:
            name = name.split("site-packages/", 1)[1]
        else:
            name = os.path.basename(name)  # no home directory or user name
        out.append({"filename": name, "function": f.name, "lineno": f.lineno,
                    "in_app": "site-packages" not in (f.filename or "")})
    return out


def build_event(exc: BaseException, where: str = "", route: str = "", app: str = "") -> dict:
    """The whole of what is sent. Built from the exception alone."""
    tags = {"app": app or _APP["name"] or "app"}
    if where:
        tags["where"] = scrub(where)[:80]
    code = error_code(exc)
    if code:
        tags["code"] = code
    event = {
        "event_id": uuid.uuid4().hex,
        "timestamp": time.time(),
        "platform": "python",
        "level": "error",
        "logger": "errorreport",
        "environment": os.environ.get("APP_ENV") or "production",
        "tags": tags,
        "exception": {"values": [{
            "type": type(exc).__name__,
            "value": scrub(exc),
            "stacktrace": {"frames": _frames(exc.__traceback__)},
        }]},
    }
    if route:
        event["transaction"] = route[:200]
    return event


def _allowed() -> bool:
    now = time.time()
    with _lock:
        _sent[:] = [t for t in _sent if now - t < 60]
        if len(_sent) >= MAX_EVENTS_PER_MINUTE:
            return False
        _sent.append(now)
        return True


def _post(url: str, key: str, event: dict) -> None:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(event).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": "errorreport/1",
                     "X-Sentry-Auth": f"Sentry sentry_version=7, sentry_client=errorreport/1, sentry_key={key}"})
        urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS).close()
    except Exception:
        pass  # reporting must never break the app, or report itself


def capture_exception(exc: BaseException, where: str = "", route: str = "", wait: bool = False) -> bool:
    """Send one error. Returns False (and does nothing) when no DSN is set."""
    try:
        target = parse_dsn(os.environ.get("SENTRY_DSN"))
        if not target or not _allowed():
            return False
        event = build_event(exc, where=where, route=route)
        t = threading.Thread(target=_post, args=(target[0], target[1], event), daemon=True)
        t.start()
        if wait:
            t.join(TIMEOUT_SECONDS + 1)
        return True
    except Exception:
        return False


def init_flask(app, name: str) -> None:
    """Report unhandled errors in requests. Reads the route pattern only."""
    _APP["name"] = name
    from flask import got_request_exception, request

    def _on_error(sender, exception=None, **_):
        route = ""
        try:
            rule = request.url_rule
            route = f"{request.method} {rule.rule}" if rule is not None else ""
        except Exception:
            pass
        if exception is not None:
            capture_exception(exception, where="request", route=route)

    got_request_exception.connect(_on_error, app, weak=False)


def install_excepthook(name: str) -> None:
    """Report an error that ends a script, a worker or a thread. Waits for the send."""
    _APP["name"] = name
    previous = sys.excepthook

    def _hook(exc_type, exc, tb):
        if exc is not None and not issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            capture_exception(exc, where="process", wait=True)
        previous(exc_type, exc, tb)

    sys.excepthook = _hook
    previous_thread = threading.excepthook

    def _thread_hook(args):
        if args.exc_value is not None and not issubclass(args.exc_type, SystemExit):
            capture_exception(args.exc_value, where="thread", wait=True)
        previous_thread(args)

    threading.excepthook = _thread_hook
