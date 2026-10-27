"""A 24-hour cache of check results, keyed by check and URL.

What's cached is the report on a public site, built from what any crawler
can read. Nothing a visitor sends is kept beyond the URL they asked about.

Two backends, chosen the same way as the rate limiter's: Vercel KV /
Upstash over REST when its env vars are set (shared across instances),
per-instance memory otherwise. Any cache failure is a miss, never an error.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.request
from typing import Callable, Dict, Optional, Tuple

CACHE_SECONDS = 24 * 3600


def cache_key(url: str, namespace: str = "vis") -> str:
    return f"{namespace}:" + hashlib.sha256(url.strip().lower().encode("utf-8")).hexdigest()[:32]


class MemoryCache:
    def __init__(self, max_items: int = 500, clock: Callable[[], float] = time.time):
        self._items: Dict[str, Tuple[float, str]] = {}
        self._max = max_items
        self._clock = clock
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            item = self._items.get(key)
            if not item:
                return None
            expires, value = item
            if expires < self._clock():
                del self._items[key]
                return None
            return value

    def set(self, key: str, value: str, ttl: int) -> None:
        with self._lock:
            if len(self._items) >= self._max:
                self._items.clear()
            self._items[key] = (self._clock() + ttl, value)


class KVCache:
    def __init__(self, url: str, token: str, post: Optional[Callable[[str, dict, list], list]] = None):
        self._url = url.rstrip("/")
        self._token = token
        self._post = post or self._http_post

    def _http_post(self, url: str, headers: dict, commands: list) -> list:
        req = urllib.request.Request(url, data=json.dumps(commands).encode("utf-8"),
                                     headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return json.loads(resp.read())

    def _run(self, commands: list) -> list:
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        return self._post(f"{self._url}/pipeline", headers, commands)

    def get(self, key: str) -> Optional[str]:
        return self._run([["GET", key]])[0].get("result")

    def set(self, key: str, value: str, ttl: int) -> None:
        self._run([["SET", key, value, "EX", str(ttl)]])


def default_cache():
    url = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if url and token:
        return KVCache(url, token)
    return MemoryCache()


class ResultCache:
    """JSON payloads in, JSON payloads out; failures are misses."""

    def __init__(self, backend=None, ttl: int = CACHE_SECONDS, namespace: str = "vis"):
        self.backend = backend or default_cache()
        self.ttl = ttl
        self.namespace = namespace

    def get(self, url: str) -> Optional[dict]:
        try:
            raw = self.backend.get(cache_key(url, self.namespace))
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def set(self, url: str, payload: dict) -> None:
        try:
            self.backend.set(cache_key(url, self.namespace), json.dumps(payload), self.ttl)
        except Exception:
            pass
