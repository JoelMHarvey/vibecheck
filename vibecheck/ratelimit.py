"""Rate limiting for the hosted API.

Both endpoints cost money on every call — /api/scan runs Python over an
upload, and /api/scan-url makes roughly eight outbound requests from our
servers to a URL a stranger chose. Unlimited, that's an amplifier pointed
at third parties with our name on the traffic.

Fixed-window counters, one or more windows per endpoint (e.g. "3 a minute
AND 10 an hour"). Two backends:

- MemoryBackend (default): per-instance counters. Serverless spreads
  requests over several warm instances, so the real ceiling is roughly
  limit × instances — best-effort, not exact. It still stops the case
  that matters (one client hammering one endpoint) with zero setup.
- KVBackend: durable, exact across instances. Activates automatically if
  Vercel KV / Upstash env vars are present. Uses the REST API over
  urllib, so there's still no dependency to install.

Never let a limiter failure take the API down: if the KV call errors, we
fail open and serve the request.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# (max_requests, window_seconds)
Window = Tuple[int, int]


@dataclass
class Decision:
    allowed: bool
    retry_after: int = 0  # seconds until the offending window resets
    limit: int = 0
    window: int = 0

    @property
    def message(self) -> str:
        if self.allowed:
            return ""
        unit = "minute" if self.window <= 60 else ("hour" if self.window <= 3600 else "day")
        return (
            f"Rate limit reached ({self.limit} scans per {unit}). "
            f"Try again in {self.retry_after}s — or run the CLI locally, "
            f"which has no limits and never uploads your code."
        )


class MemoryBackend:
    """Per-process fixed-window counters with bounded memory."""

    def __init__(self, max_keys: int = 20_000):
        self._counts: Dict[str, int] = {}
        self._max_keys = max_keys
        self._lock = threading.Lock()

    def incr(self, key: str, window_seconds: int) -> int:
        with self._lock:
            # Keys embed their window index, so old ones are simply dead
            # weight. Clear wholesale when we hit the cap; the alternative
            # (tracking expiries) costs more than it saves at this size.
            if len(self._counts) >= self._max_keys:
                self._counts.clear()
            count = self._counts.get(key, 0) + 1
            self._counts[key] = count
            return count


class KVBackend:
    """Vercel KV / Upstash Redis over the REST API (no client library).

    ``post`` is injectable so tests never touch the network.
    """

    def __init__(self, url: str, token: str, post: Optional[Callable[[str, dict, list], list]] = None):
        self._url = url.rstrip("/")
        self._token = token
        self._post = post or self._http_post

    def _http_post(self, url: str, headers: dict, commands: list) -> list:
        body = json.dumps(commands).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return json.loads(resp.read())

    def incr(self, key: str, window_seconds: int) -> int:
        # Pipeline: INCR then EXPIRE-if-no-TTL, so the window can't be
        # extended by later hits inside it.
        commands = [["INCR", key], ["EXPIRE", key, str(window_seconds), "NX"]]
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        result = self._post(f"{self._url}/pipeline", headers, commands)
        return int(result[0]["result"])


class RateLimiter:
    def __init__(self, name: str, windows: Sequence[Window], backend=None,
                 clock: Callable[[], float] = time.time, disabled: Optional[bool] = None):
        if not windows:
            raise ValueError("a rate limiter needs at least one window")
        self.name = name
        self.windows: List[Window] = list(windows)
        self.backend = backend or default_backend()
        self._clock = clock
        # Off switch for local development and UI tests, where every request
        # arrives from the same address and would share one bucket. Never set
        # this in production.
        self.disabled = limiting_disabled() if disabled is None else disabled

    def check(self, identity: str) -> Decision:
        if self.disabled:
            return Decision(allowed=True)
        now = self._clock()
        # Check the tightest window first so the retry hint is the shortest
        # honest wait rather than "come back in an hour".
        for limit, window in sorted(self.windows, key=lambda w: w[1]):
            bucket = int(now // window)
            key = f"rl:{self.name}:{identity}:{window}:{bucket}"
            try:
                count = self.backend.incr(key, window)
            except Exception:
                # Fail open: a broken limiter must not break the product.
                continue
            if count > limit:
                reset_at = (bucket + 1) * window
                return Decision(
                    allowed=False,
                    retry_after=max(1, int(reset_at - now)),
                    limit=limit,
                    window=window,
                )
        return Decision(allowed=True)


def limiting_disabled() -> bool:
    return os.environ.get("VIBECHECK_RATE_LIMIT_OFF", "").strip().lower() in ("1", "true", "yes")


def default_backend():
    """Use KV when the platform provides it, memory otherwise."""
    url = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if url and token:
        return KVBackend(url, token)
    return MemoryBackend()


def client_ip(headers) -> str:
    """Best-effort client IP from proxy headers.

    A client can send its own X-Forwarded-For, and proxies *append* rather
    than replace — so the first entry is attacker-controlled and the last
    is the one our proxy vouches for. Prefer the single-value headers the
    platform sets, and fall back to the last XFF entry, never the first.
    """
    for header in ("x-real-ip", "x-vercel-forwarded-for"):
        value = headers.get(header)
        if value:
            return value.strip()
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return "unknown"
