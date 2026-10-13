"""Local model through Ollama's HTTP API -- the lab-mode fixer.

Security decisions:

* **Loopback only.** Source context must never leave the machine because of a
  configuration typo. A hosted model would be a separate provider class that
  someone chooses explicitly.
* **No proxies, no redirects** (``trust_env=False``, ``follow_redirects=False``):
  an ``HTTPS_PROXY`` in the environment must not silently route code elsewhere.
* **Redact again before sending.** Context is already redacted when extracted;
  doing it once more at the boundary costs nothing.
* **Bounded response.** The body is streamed and abandoned past a size cap, so
  a misbehaving server cannot exhaust memory.
* **Every failure is a ProviderError** -- a timeout or a bad reply is recorded
  as an error, never mistaken for an answer.

Reproducibility: temperature 0, fixed ``top_p`` and ``seed``; the model name,
these parameters and the token counts the server reports are returned with
every completion so each result row can record them.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

import httpx

from app.ai.providers.base import ChatMessage, Completion, LLMProvider, ProviderError
from app.core.config import Settings, get_settings
from app.core.redaction import redact


def loopback_base_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ProviderError(f"invalid model server URL: {url!r}")
    host = parts.hostname
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ProviderError("the model server must be on this machine (loopback address)")
        except ValueError as exc:
            raise ProviderError("the model server must be given as localhost or a loopback IP") from exc
    if parts.path not in {"", "/"} or parts.query or parts.fragment or parts.username or parts.password:
        raise ProviderError("the model server URL must be a bare scheme://host:port")
    return f"{parts.scheme}://{parts.netloc}"


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, settings: Settings | None = None, transport: httpx.BaseTransport | None = None) -> None:
        s = settings or get_settings()
        self.base_url = loopback_base_url(s.ollama_url)
        self.model = s.ollama_model
        self.timeout = s.llm_timeout_seconds
        self.max_bytes = s.max_llm_response_bytes
        self.options = {"temperature": 0.0, "top_p": 1.0, "seed": s.llm_seed, "num_ctx": s.llm_num_ctx}
        self._transport = transport

    def _client(self, timeout: float) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, timeout=timeout, transport=self._transport,
                            trust_env=False, follow_redirects=False)

    def describe(self) -> dict[str, object]:
        return {"provider": self.name, "model": self.model, "options": dict(self.options)}

    def complete(self, messages: Sequence[ChatMessage], *,
                 json_schema: Mapping[str, object] | None = None) -> Completion:
        payload: dict[str, object] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": redact(m.content)} for m in messages],
            "stream": False,
            "options": self.options,
        }
        if json_schema is not None:
            payload["format"] = dict(json_schema)
        try:
            with self._client(self.timeout) as client, client.stream("POST", "/api/chat", json=payload) as resp:
                if resp.status_code != 200:
                    raise ProviderError(f"model server answered HTTP {resp.status_code}")
                body = bytearray()
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > self.max_bytes:
                        raise ProviderError("model response exceeded the size limit")
        except httpx.TimeoutException as exc:
            raise ProviderError("model server timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(f"model server unreachable ({type(exc).__name__})") from exc
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise ProviderError("model server returned a non-JSON body") from exc
        message = data.get("message") if isinstance(data, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ProviderError("model server reply has no message content")

        def _count(key: str) -> int | None:
            value = data.get(key)
            return value if isinstance(value, int) and value >= 0 else None

        return Completion(text=content, model=str(data.get("model") or self.model),
                          prompt_tokens=_count("prompt_eval_count"), completion_tokens=_count("eval_count"),
                          params=dict(self.options))

    def available(self) -> tuple[bool, str]:
        """(usable, reason): is the server up and the configured model pulled?"""
        try:
            with self._client(5.0) as client:
                resp = client.get("/api/tags")
            names = {m.get("name") for m in resp.json().get("models", []) if isinstance(m, dict)}
        except (httpx.HTTPError, ValueError, AttributeError):
            return False, f"no Ollama server at {self.base_url}"
        if self.model not in names and f"{self.model}:latest" not in names:
            return False, f"model {self.model} not pulled (ollama pull {self.model})"
        return True, "ok"
