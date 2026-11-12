"""The command line: exit codes for CI, the input cap, JSON output and --fix."""

from __future__ import annotations

import io
import json
import sys

import pytest

from secure_prompt_lint.cli import EXIT_FAIL, EXIT_PASS, EXIT_USAGE, main

ONE_LINER = ('Fix the command injection in ping_host in app.py.\n\n```python\ndef ping_host():\n'
             '    host = request.args.get("host")\n    return subprocess.check_output("ping " + host, shell=True)\n```\n')
BOUND = ["--cwe", "CWE-78", "--entity", "host", "--entity", "subprocess.check_output", "--location", "app.py",
         "--location", "ping_host"]


@pytest.fixture
def prompt_file(tmp_path):  # noqa: ANN001, ANN201
    path = tmp_path / "prompt.txt"
    path.write_text(ONE_LINER, encoding="utf-8")
    return path


def test_a_failing_prompt_exits_1(prompt_file, capsys) -> None:  # noqa: ANN001
    assert main([str(prompt_file), *BOUND]) == EXIT_FAIL
    out = capsys.readouterr().out
    assert out.startswith("FAIL") and "A2" in out and "A3" in out


def test_fix_repairs_it_and_the_result_passes(prompt_file, tmp_path, capsys) -> None:  # noqa: ANN001
    assert main([str(prompt_file), *BOUND, "--fix"]) == EXIT_PASS
    fixed = tmp_path / "fixed.txt"
    fixed.write_text(capsys.readouterr().out, encoding="utf-8")
    assert main([str(fixed), *BOUND]) == EXIT_PASS


def test_json_output(prompt_file, capsys) -> None:  # noqa: ANN001
    main([str(prompt_file), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["passed"] is False and data["bound"] is False


def test_stdin(monkeypatch, capsys) -> None:  # noqa: ANN001
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(ONE_LINER.encode())))
    assert main(["-"]) == EXIT_FAIL


def test_oversized_input_is_refused(tmp_path, capsys) -> None:  # noqa: ANN001
    big = tmp_path / "big.txt"
    big.write_text("x" * 2048, encoding="utf-8")
    assert main([str(big), "--max-bytes", "1024"]) == EXIT_USAGE
    assert "larger than" in capsys.readouterr().err


def test_binary_and_missing_input_are_usage_errors(tmp_path, capsys) -> None:  # noqa: ANN001
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\xff\xfe\x00bad")
    assert main([str(blob)]) == EXIT_USAGE
    assert main([str(tmp_path / "nope.txt")]) == EXIT_USAGE
    assert main([]) == EXIT_USAGE


def test_rules_listing(capsys) -> None:  # noqa: ANN001
    assert main(["--rules"]) == EXIT_PASS
    out = capsys.readouterr().out
    assert all(rule in out for rule in ("A1", "A7", "B1", "B5", "C1"))
