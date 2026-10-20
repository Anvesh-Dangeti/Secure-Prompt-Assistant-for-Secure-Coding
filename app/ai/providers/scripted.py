"""A provider that replays pre-written answers -- for tests and offline demos.

It lets the whole lab-mode path (conversation, schema validation, and later the
verification gates) be exercised deterministically with known-good and
known-bad fixes, without a model server.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

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


class ReplayProvider(LLMProvider):
    """A recorded answer to any strategy: free-text replies for the critique turns, one final fix.

    File format (``evaluation/replays/*.json``)::

        {"note": "...", "turns": ["...", "..."], "final": {"code": ..., "imports": [...], "summary": ...}}

    The final answer is returned on the turn that asks for the fix schema, so
    the same file works for single-turn strategies and for RCI. The file is
    untrusted input like any model reply: size-capped here, schema-validated by
    the conversation.
    """

    name = "replay"
    MAX_BYTES = 256 * 1024
    FILLER = "No further problems found."

    def __init__(self, turns: Iterable[str], final: str, source: str = "replay") -> None:
        self._turns = list(turns)
        self._final = final
        self._source = source

    @classmethod
    def from_file(cls, path: Path) -> ReplayProvider:
        raw = path.read_bytes()
        if len(raw) > cls.MAX_BYTES:
            raise ProviderError("replay file too large")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProviderError("replay file is not JSON") from exc
        if not isinstance(data, dict) or "final" not in data:
            raise ProviderError("replay file needs a 'final' answer")
        final = data["final"] if isinstance(data["final"], str) else json.dumps(data["final"])
        return cls([str(t) for t in data.get("turns", [])], final, path.name)

    def complete(self, messages: Sequence[ChatMessage], *,
                 json_schema: Mapping[str, object] | None = None) -> Completion:
        if json_schema is not None:
            text = self._final
        else:
            text = self._turns.pop(0) if self._turns else self.FILLER
        prompt = sum(estimate_tokens(m.content) for m in messages)
        return Completion(text=text, model=f"replay:{self._source}", prompt_tokens=prompt,
                          completion_tokens=estimate_tokens(text), params={"replay": self._source})

    def describe(self) -> dict[str, object]:
        return {"provider": self.name, "file": self._source}
