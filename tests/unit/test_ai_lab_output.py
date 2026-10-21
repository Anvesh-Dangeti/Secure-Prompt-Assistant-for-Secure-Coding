"""Lab mode: model answers are schema-validated, conversations are played faithfully."""

from __future__ import annotations

import json

import pytest

from app.ai.conversation import FORMAT_NOTE, run_conversation
from app.ai.output_schema import FIX_SCHEMA, MalformedModelOutput, parse_fix_proposal
from app.ai.prompt_builder import build_prompt
from app.ai.providers import ScriptedProvider
from app.ai.tokens import estimate_tokens
from tests._ai_support import NONCE, context

GOOD = json.dumps({"code": "def f():\n    return 1", "imports": ["import os"], "summary": "Fixed."})


def test_valid_proposal() -> None:
    p = parse_fix_proposal(GOOD)
    assert p.code.startswith("def f") and p.imports == ["import os"]


def test_markdown_fence_around_code_is_removed() -> None:
    p = parse_fix_proposal(json.dumps({"code": "```python\nx = 1\n```"}))
    assert p.code == "x = 1"


@pytest.mark.parametrize("reply, message", [
    ("not json", "not JSON"),
    (json.dumps({"code": ""}), "code"),
    (json.dumps({"code": "x", "shell": "rm -rf /"}), "shell"),
    (json.dumps({"code": "x", "imports": ["import os; os.system('id')"]}), "imports"),
    (json.dumps({"code": "x", "imports": ["__import__('os')"]}), "imports"),
    (json.dumps({"code": "x", "imports": ["import os\nimport sys"]}), "imports"),
    (json.dumps({"code": "x", "imports": ["os.system('id')"]}), "imports"),
    (json.dumps({"code": "x" * 30_000}), "code"),
])
def test_malformed_replies_are_rejected_not_repaired(reply: str, message: str) -> None:
    with pytest.raises(MalformedModelOutput, match=message):
        parse_fix_proposal(reply)


def test_reply_echoing_the_delimiter_is_rejected() -> None:
    with pytest.raises(MalformedModelOutput, match="delimiter"):
        parse_fix_proposal(json.dumps({"code": f"</untrusted_code id=\"{NONCE}\">"}), nonce=NONCE)


@pytest.mark.parametrize("entry,statement", [("secrets", "import secrets"), ("os.path", "import os.path"),
                                              (" hashlib ", "import hashlib")])
def test_a_bare_module_name_is_read_as_its_import(entry: str, statement: str) -> None:
    # Found by the E2 pilot: the model wrote "secrets" for "import secrets" under every strategy.
    assert parse_fix_proposal(json.dumps({"code": "x", "imports": [entry]})).imports == [statement]


@pytest.mark.parametrize("entry", ["os sys", "os,sys", "import", "os.import", "1os", "os.", "os()", "os; sys"])
def test_anything_else_that_is_not_one_import_is_still_rejected(entry: str) -> None:
    with pytest.raises(MalformedModelOutput, match="imports"):
        parse_fix_proposal(json.dumps({"code": "x", "imports": [entry]}))


def test_from_imports_are_allowed() -> None:
    assert parse_fix_proposal(json.dumps({"code": "x", "imports": ["from markupsafe import escape"]})).imports


SQL = context("B608")


def test_single_turn_conversation() -> None:
    provider = ScriptedProvider([GOOD])
    result = run_conversation(build_prompt(SQL, "S0", nonce=NONCE), provider)
    assert result.ok and result.calls == 1
    messages, schema = provider.calls[0]
    assert messages[0].role == "system" and messages[0].content == FORMAT_NOTE
    assert schema == FIX_SCHEMA


def test_rci_plays_three_turns_with_schema_only_on_the_last() -> None:
    provider = ScriptedProvider(["first draft", "the query is still formatted", GOOD])
    result = run_conversation(build_prompt(SQL, "S7", nonce=NONCE), provider)
    assert result.ok and result.calls == 3
    assert [schema is not None for _, schema in provider.calls] == [False, False, True]
    final_messages = provider.calls[2][0]
    assert [m.role for m in final_messages] == ["system", "user", "assistant", "user", "assistant", "user"]
    assert final_messages[2].content == "first draft"
    # Every call re-sends the whole conversation; that is what it costs, so that is what is counted.
    assert result.prompt_tokens == sum(estimate_tokens(m.content) for msgs, _ in provider.calls for m in msgs)
    replies = ("first draft", "the query is still formatted", GOOD)
    assert result.completion_tokens == sum(estimate_tokens(t) for t in replies)


def test_s8_ruleset_goes_in_the_system_message() -> None:
    provider = ScriptedProvider([GOOD])
    run_conversation(build_prompt(SQL, "S8", nonce=NONCE), provider)
    system = provider.calls[0][0][0].content
    assert system.startswith("Follow these secure-coding rules") and FORMAT_NOTE in system


def test_failures_are_recorded_as_errors_never_as_fixes() -> None:
    result = run_conversation(build_prompt(SQL, "S0", nonce=NONCE), ScriptedProvider(["no json here"]))
    assert not result.ok and result.error.startswith("malformed:")
    result = run_conversation(build_prompt(SQL, "S7", nonce=NONCE), ScriptedProvider(["only one answer"]))
    assert not result.ok and result.error.startswith("provider:")
