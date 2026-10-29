"""Plain web search for the off-site footprint (phase 4), through Serper.

The footprint only needs to know which pages a search for the brand turns
up, and whether each directory has a page about it. That's a lookup, not a
question for a model, so when SERPER_API_KEY is set it runs as seven Google
searches through Serper (google.serper.dev, about a tenth of a penny each)
instead of two Claude calls with web search. Without a key, the footprint
falls back to Claude (websearch.py).

Only the brand name and the directories' hostnames are sent. The address is
fixed, so the SSRF guard has nothing to vet.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional

from .websearch import SearchUnavailable

URL = "https://google.serper.dev/search"
TIMEOUT = 15
MAX_RESULTS = 20


def _post(url: str, body: bytes, headers: Dict[str, str], timeout: float) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 (fixed https address)
        return resp.read(1_000_000)


class SerperSearch:
    def __init__(self, key: str, post: Optional[Callable[..., bytes]] = None, timeout: float = TIMEOUT):
        self.key = key
        self.post = post or _post
        self.timeout = timeout
        self.searches = 0
        self._lock = threading.Lock()

    def results(self, query: str, num: int = 10) -> List[dict]:
        """[{"url", "title"}] for one Google search, or SearchUnavailable."""
        body = json.dumps({"q": query, "num": max(1, min(num, MAX_RESULTS))}).encode("utf-8")
        headers = {"X-API-KEY": self.key, "Content-Type": "application/json"}
        with self._lock:
            self.searches += 1
        try:
            data = json.loads(self.post(URL, body, headers, self.timeout))
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SearchUnavailable(f"the search service didn't answer ({type(e).__name__})") from e
        out: List[dict] = []
        for r in (data.get("organic") or []) if isinstance(data, dict) else []:
            url = r.get("link") if isinstance(r, dict) else None
            if isinstance(url, str) and url.startswith(("https://", "http://")) and url not in [x["url"] for x in out]:
                out.append({"url": url, "title": str(r.get("title") or "")[:300]})
        return out
