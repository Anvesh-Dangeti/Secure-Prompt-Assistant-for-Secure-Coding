"""Dashboard security: scanned content is never rendered as Markdown/HTML, and the server stays locked down.

A repository under scan controls its file names, and its code shapes scanner
messages and rule matches. If any of that reached a Markdown-rendering element,
``![x](https://attacker.example/pixel)`` would make the viewer's browser fetch
a remote URL, and ``[docs](javascript:...)`` would become a link.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

from app import pipeline
from app.db.session import init_db
from dashboard import actions, auth
from tests._dashboard_support import all_text, page, signed_in
from tests._verify_support import PatternScanner

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = "![pixel](https://attacker.example/p.png) <img src=x onerror=alert(1)> [docs](javascript:alert(1))"
MARKERS = ("attacker.example", "onerror", "javascript:", "![pixel]", "![file]")
EVIL_FILE = "![file](evil).py"


def _payload_scanners() -> list[PatternScanner]:
    rule = f"B666 {PAYLOAD}"
    return [PatternScanner("bandit", {rule: (r"os\.system\(", "CWE-78", "HIGH")})]


def _rendered_as_markdown(at) -> str:  # noqa: ANN001
    kinds = ("markdown", "caption", "error", "warning", "success", "info", "title", "header", "subheader")
    return "\n".join(all_text(getattr(at, kind)) for kind in kinds)


def _rendered_literally(at) -> str:  # noqa: ANN001
    return "\n".join((all_text(at.text), all_text(at.code), all_text(at.dataframe)))


def test_scanned_content_never_reaches_markdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "FAILURE_DELAY_S", 0.0)
    monkeypatch.setattr(pipeline, "all_scanners", _payload_scanners)
    init_db()
    code = tmp_path / "code"
    code.mkdir()
    (code / EVIL_FILE).write_text(f'"""{PAYLOAD}"""\nimport os\n\n\ndef handler(name):\n'
                                  f'    os.system("echo " + name)  # {PAYLOAD}\n', encoding="utf-8")
    actions.scan_checkout("evil", str(code))                 # the rule id and message carry the payload too

    at = signed_in()
    seen_literally = []
    for name in ("Overview", "Findings", "Prompt & lint", "Verification", "Scan history"):
        page(at, name)
        if name == "Prompt & lint":
            at.text_input(key="spa_checkout_path_input").input(str(code))
            at.selectbox(key="prompt_strategy").set_value("S0")      # S0 quotes the raw scanner message
            at.button(key="build_prompt").click().run()
        if name == "Verification":
            (code / EVIL_FILE).write_text("import os\n\n\ndef handler(name):\n    return name\n", encoding="utf-8")
            at.button(key="rescan_verify").click().run()            # a verification card full of payload labels
            assert "Verification #1" in all_text(at.success)
        assert not at.exception, [e.value for e in at.exception]
        markdown = _rendered_as_markdown(at)
        for marker in MARKERS:
            assert marker not in markdown, (name, marker)
        seen_literally.append(_rendered_literally(at))
    shown = "\n".join(seen_literally)
    assert f"B666 {PAYLOAD}" in shown and EVIL_FILE in shown            # it is displayed -- as literal text
    assert PAYLOAD in seen_literally[2]                                    # quoted inside the S0 prompt


def test_no_raw_html_or_markdown_writers_in_the_dashboard() -> None:
    for path in (ROOT / "dashboard").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword):
                assert node.arg != "unsafe_allow_html", path.name
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "st":
                assert node.func.attr not in {"write", "markdown", "html"}, f"{path.name}: st.{node.func.attr}"


def test_server_configuration_is_locked_down() -> None:
    config = tomllib.loads((ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    assert config["server"]["address"] == "127.0.0.1"
    assert config["server"]["enableXsrfProtection"] is True and config["server"]["enableCORS"] is True
    assert config["server"]["enableStaticServing"] is False and config["server"]["fileWatcherType"] == "none"
    assert config["browser"]["gatherUsageStats"] is False
    assert config["client"]["showErrorDetails"] == "none"
    assert config["runner"]["magicEnabled"] is False


def test_key_comparison_is_constant_time_and_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import get_settings

    assert auth.check_key("test-key-0123456789abcdef") and not auth.check_key("test-key")
    monkeypatch.setenv("SPA_API_KEY", "")
    get_settings.cache_clear()
    assert not auth.check_key("") and not auth.key_configured()
    assert "compare_digest" in (ROOT / "dashboard" / "auth.py").read_text(encoding="utf-8")
