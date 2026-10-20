"""Recorded model answers for offline lab runs: the final answer goes to the schema turn; files are untrusted."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ai.providers import ChatMessage, ProviderError, ReplayProvider

FINAL = {"code": "x = 1", "imports": [], "summary": "s"}


def _file(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "r.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def test_final_answer_is_returned_on_the_schema_turn(tmp_path: Path) -> None:
    provider = ReplayProvider.from_file(_file(tmp_path, {"turns": ["first"], "final": FINAL}))
    msgs = [ChatMessage("user", "hello")]
    assert provider.complete(msgs).text == "first"
    assert provider.complete(msgs).text == ReplayProvider.FILLER          # turns ran out: neutral filler
    final = provider.complete(msgs, json_schema={"type": "object"})
    assert json.loads(final.text) == FINAL and final.model == "replay:r.json"
    assert provider.describe() == {"provider": "replay", "file": "r.json"}


@pytest.mark.parametrize("content, message", [
    ("not json", "not JSON"),
    ({"turns": []}, "final"),
    (["a list"], "final"),
    ({"final": "x" * (ReplayProvider.MAX_BYTES + 1)}, "too large"),
])
def test_bad_replay_files_are_refused(tmp_path: Path, content: object, message: str) -> None:
    with pytest.raises(ProviderError, match=message):
        ReplayProvider.from_file(_file(tmp_path, content))


def test_shipped_replays_are_valid() -> None:
    for path in (Path(__file__).resolve().parents[2] / "evaluation" / "replays").glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["note"] and set(data["final"]) == {"code", "imports", "summary"}, path.name
