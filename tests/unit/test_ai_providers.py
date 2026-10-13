"""LLM providers: loopback-only, reproducible parameters, and every failure is an error."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from app.ai.providers import (ChatMessage, OllamaProvider, ProviderError, ScriptedProvider, TemplateProvider,
                              get_provider)
from app.ai.providers.ollama import loopback_base_url
from app.core.config import Settings, get_settings


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434",
                                 "http://127.0.0.2:8080/"])
def test_loopback_urls_are_accepted(url: str) -> None:
    assert loopback_base_url(url).startswith("http")


@pytest.mark.parametrize("url", ["http://10.0.0.5:11434", "http://example.com:11434", "http://169.254.169.254",
                                 "file:///etc/passwd", "http://127.0.0.1:11434/api", "http://u:p@127.0.0.1:11434",
                                 "http://127.0.0.1.nip.io:11434"])
def test_anything_else_is_refused(url: str) -> None:
    with pytest.raises(ProviderError):
        loopback_base_url(url)


def test_unknown_provider_is_a_configuration_error() -> None:
    with pytest.raises(ValidationError):
        Settings(llm_provider="gpt")
    with pytest.raises(ProviderError):
        get_provider("gpt")
    assert isinstance(get_provider(), TemplateProvider)


def test_template_provider_never_invents_an_answer() -> None:
    with pytest.raises(ProviderError, match="does not generate"):
        TemplateProvider().complete([ChatMessage("user", "hi")])


def test_scripted_provider_replays_then_fails() -> None:
    p = ScriptedProvider(["a", "b"])
    assert [p.complete([ChatMessage("user", "x")]).text for _ in range(2)] == ["a", "b"]
    with pytest.raises(ProviderError):
        p.complete([ChatMessage("user", "x")])


def _ollama(handler) -> OllamaProvider:  # noqa: ANN001
    return OllamaProvider(get_settings(), transport=httpx.MockTransport(handler))


def _reply(content: str = '{"code": "x"}', **extra) -> httpx.Response:  # noqa: ANN003
    return httpx.Response(200, json={"model": "qwen2.5-coder:7b-instruct", "message": {"content": content},
                                     "prompt_eval_count": 120, "eval_count": 30, **extra})


def test_request_is_reproducible_redacted_and_schema_constrained() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return _reply()

    completion = _ollama(handler).complete([ChatMessage("user", 'password = "hunter2"')],
                                           json_schema={"type": "object"})
    body = seen["body"]
    assert seen["url"] == "http://127.0.0.1:11434/api/chat"
    assert body["options"]["temperature"] == 0.0 and body["options"]["seed"] == 42 and body["stream"] is False
    assert body["format"] == {"type": "object"}
    assert "hunter2" not in body["messages"][0]["content"]
    assert (completion.prompt_tokens, completion.completion_tokens) == (120, 30)
    assert completion.params["temperature"] == 0.0


@pytest.mark.parametrize("handler, message", [
    (lambda r: httpx.Response(500), "HTTP 500"),
    (lambda r: httpx.Response(200, content=b"not json"), "non-JSON"),
    (lambda r: httpx.Response(200, json={"message": {}}), "no message content"),
])
def test_bad_replies_are_errors(handler, message: str) -> None:  # noqa: ANN001
    with pytest.raises(ProviderError, match=message):
        _ollama(handler).complete([ChatMessage("user", "x")])


@pytest.mark.parametrize("exc, message", [
    (httpx.ReadTimeout("slow"), "timed out"),
    (httpx.ConnectError("down"), "unreachable"),
])
def test_transport_failures_are_errors(exc: Exception, message: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc
    with pytest.raises(ProviderError, match=message):
        _ollama(handler).complete([ChatMessage("user", "x")])


def test_oversized_reply_is_abandoned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_MAX_LLM_RESPONSE_BYTES", "2048")
    get_settings.cache_clear()
    with pytest.raises(ProviderError, match="size limit"):
        _ollama(lambda r: _reply("x" * 5000)).complete([ChatMessage("user", "x")])


def test_proxy_settings_are_ignored() -> None:
    assert _ollama(lambda r: _reply())._client(1.0).trust_env is False


def test_non_loopback_configuration_refuses_to_construct(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_OLLAMA_URL", "http://203.0.113.7:11434")
    get_settings.cache_clear()
    with pytest.raises(ProviderError, match="loopback"):
        OllamaProvider()


def test_availability_check() -> None:
    def tags(models):  # noqa: ANN001, ANN202
        return lambda r: httpx.Response(200, json={"models": [{"name": m} for m in models]})
    assert _ollama(tags(["qwen2.5-coder:7b-instruct"])).available() == (True, "ok")
    ok, reason = _ollama(tags(["llama3:8b"])).available()
    assert not ok and "ollama pull" in reason
    ok, reason = _ollama(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))).available()
    assert not ok and "no Ollama server" in reason
