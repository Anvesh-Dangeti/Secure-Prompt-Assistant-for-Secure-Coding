"""A provider that replays pre-written answers -- for tests and offline demos.

It lets the whole lab-mode path (conversation, schema validation, and later the
verification gates) be exercised deterministically with known-good and
known-bad fixes, without a model server.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from app.ai.providers.base import ChatMessage, Completion, LLMProvider, ProviderError
from app.ai.tokens import estimate_tokens


class ScriptedProvider(LLMProvider):
    name = "scripted"

    def __init__(self, responses: Iterable[str]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[list[ChatMessage], Mapping[str, object] | None]] = []

    def complete(self, messages: Sequence[ChatMessage], *,
                 json_schema: Mapping[str, object] | None = None) -> Completion:
        self.calls.append((list(messages), json_schema))
        if not self._responses:
            raise ProviderError("scripted provider has no responses left")
        text = self._responses.pop(0)
        prompt = sum(estimate_tokens(m.content) for m in messages)
        return Completion(text=text, model="scripted", prompt_tokens=prompt,
                          completion_tokens=estimate_tokens(text), params={"scripted": True})
