"""The provider-agnostic LLM interface.

Everything above this layer talks to ``LLMProvider``; swapping the model, or
the vendor, is a new subclass and nothing else changes. A provider only
transports messages: it never sees a finding, never applies a change, and its
answer is untrusted text until a caller validates it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field


class ProviderError(RuntimeError):
    """The model could not produce an answer. The result is an error -- never a fix."""


@dataclass(frozen=True)
class ChatMessage:
    role: str        # "system" | "user" | "assistant"
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    params: Mapping[str, object] = field(default_factory=dict)


class LLMProvider(ABC):
    name: str = "abstract"
    #: False for providers that cannot generate text at all (the template provider).
    generates: bool = True

    @abstractmethod
    def complete(self, messages: Sequence[ChatMessage], *,
                 json_schema: Mapping[str, object] | None = None) -> Completion:
        """Return the model's reply to ``messages``.

        ``json_schema``, when given, asks the server to constrain the reply to
        that schema. The caller must still validate the reply: a constraint
        requested is not a constraint guaranteed.
        """

    def describe(self) -> dict[str, object]:
        """What to record next to every result produced with this provider."""
        return {"provider": self.name}
