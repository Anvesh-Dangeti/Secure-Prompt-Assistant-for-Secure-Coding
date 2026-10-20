"""LLM providers behind one interface (``base.LLMProvider``)."""

from __future__ import annotations

from app.ai.providers.base import ChatMessage, Completion, LLMProvider, ProviderError
from app.ai.providers.ollama import OllamaProvider
from app.ai.providers.scripted import ReplayProvider, ScriptedProvider
from app.ai.providers.template import TemplateProvider
from app.core.config import get_settings

__all__ = ["ChatMessage", "Completion", "LLMProvider", "OllamaProvider", "ProviderError", "ReplayProvider",
           "ScriptedProvider", "TemplateProvider", "get_provider"]


def get_provider(name: str | None = None) -> LLMProvider:
    """The provider named, or the configured default (``SPA_LLM_PROVIDER``)."""
    chosen = (name or get_settings().llm_provider).strip().lower()
    if chosen == "template":
        return TemplateProvider()
    if chosen == "ollama":
        return OllamaProvider()
    raise ProviderError(f"unknown provider {chosen!r} (choose template or ollama)")
