"""The developer-mode default: no model at all.

In developer mode the fix is written by the developer's own coding assistant;
this tool explains the finding from templates and builds the prompt. Asking
this provider to *generate* fails closed rather than inventing an answer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from app.ai.providers.base import ChatMessage, Completion, LLMProvider, ProviderError


class TemplateProvider(LLMProvider):
    name = "template"
    generates = False

    def complete(self, messages: Sequence[ChatMessage], *,
                 json_schema: Mapping[str, object] | None = None) -> Completion:
        raise ProviderError(
            "the template provider does not generate text: in developer mode the prompt goes to the "
            "developer's own assistant; use the ollama provider for lab-mode experiments")
