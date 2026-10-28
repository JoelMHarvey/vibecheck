"""One question to Claude with web search, and what came back.

Used by the AI-answer probe (phase 3) and the off-site footprint (phase 4).
Everything the checks score comes from parsing the response here: the
answer's text, the pages its sentences cite, and the URLs the searches
returned. Nothing is taken from the model's own account of what it found.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence

MODEL = "claude-opus-5-5"
MAX_TOKENS = 4000
MAX_CONTINUATIONS = 3
# Server-side fallback: if a request is declined by a safety classifier, the
# API retries it on a model that routes by refusal category.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class SearchUnavailable(Exception):
    """No key, over budget, refused, or the API failed."""


@dataclass
class Answer:
    question: str
    text: str = ""
    cited: List[str] = field(default_factory=list)     # URLs the answer's sentences cite
    results: List[dict] = field(default_factory=list)  # {"url", "title"} the searches returned
    stop_reason: str = ""


def _get(obj: Any, name: str, default=None):
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def parse(question: str, content: Sequence[Any], stop_reason: str = "") -> Answer:
    ans = Answer(question=question, stop_reason=stop_reason)
    texts = []
    for block in content or []:
        kind = _get(block, "type", "")
        if kind == "text":
            texts.append(_get(block, "text", "") or "")
            for c in _get(block, "citations", None) or []:
                url = _get(c, "url")
                if url and url not in ans.cited:
                    ans.cited.append(url)
        elif kind == "web_search_tool_result":
            results = _get(block, "content")
            if isinstance(results, list):   # an error comes back as an object, not a list
                for r in results:
                    url = _get(r, "url")
                    if url and url not in [x["url"] for x in ans.results]:
                        ans.results.append({"url": url, "title": _get(r, "title", "") or ""})
    ans.text = "".join(texts).strip()
    return ans


class ClaudeSearch:
    """Asks Claude a question with the web search tool on. The client is made
    on first use, so importing this needs neither the SDK nor a key."""

    def __init__(self, client=None, model: str = MODEL, limiter=None):
        self._client = client
        self.model = model
        self.limiter = limiter      # one check per probe, before the first call
        self.calls = 0

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as e:
                raise SearchUnavailable("the anthropic package isn't installed") from e
            self._client = anthropic.Anthropic()
        return self._client

    def spend(self) -> None:
        """Take one unit from the daily budget, or say why not."""
        if self.limiter is not None and not self.limiter.check("all").allowed:
            raise SearchUnavailable("today's AI checks are used up; back tomorrow")

    def ask(self, question: str, *, country: Optional[str] = None, allowed_domains: Optional[List[str]] = None,
            max_uses: int = 3, system: Optional[str] = None) -> Answer:
        client = self._get_client()
        tool = {"type": "web_search_20260209", "name": "web_search", "max_uses": max_uses}
        if country:
            tool["user_location"] = {"type": "approximate", "country": country}
        if allowed_domains:
            tool["allowed_domains"] = list(allowed_domains)
        messages = [{"role": "user", "content": question}]
        kwargs = dict(model=self.model, max_tokens=MAX_TOKENS, tools=[tool], messages=messages,
                      output_config={"effort": "low"}, betas=[FALLBACK_BETA], fallbacks="default")
        if system:
            kwargs["system"] = system
        content: List[Any] = []
        seen: List[Any] = []       # every block across resumed turns
        stop = ""
        for _ in range(MAX_CONTINUATIONS + 1):
            try:
                self.calls += 1
                response = client.beta.messages.create(**kwargs)
            except Exception as e:   # anthropic.APIError and friends: never fail the scan
                raise SearchUnavailable(f"the AI service didn't answer ({type(e).__name__})") from e
            stop = _get(response, "stop_reason", "")
            content = list(_get(response, "content", []) or [])
            seen.extend(content)
            if stop != "pause_turn":
                break
            # A long server-side search paused: send it back and it resumes.
            kwargs["messages"] = messages + [{"role": "assistant", "content": content}]
        if stop == "refusal":
            raise SearchUnavailable("the AI service declined the question")
        return parse(question, seen, stop)
