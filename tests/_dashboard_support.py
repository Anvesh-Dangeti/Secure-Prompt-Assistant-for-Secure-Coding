"""Drive the Streamlit dashboard headlessly (``streamlit.testing.v1.AppTest``) in tests."""

from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

from tests._support import TEST_API_KEY

APP = str(Path(__file__).resolve().parents[1] / "dashboard" / "streamlit_app.py")
PAGES = ("Overview", "Findings", "Prompt & lint", "Verification", "Scan history")


def started() -> AppTest:
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    return at


def signed_in() -> AppTest:
    at = started()
    at.text_input(key="spa_key_input").input(TEST_API_KEY)
    at.button(key="spa_sign_in").click().run()
    assert not at.exception, at.exception
    return at


def page(at: AppTest, name: str) -> AppTest:
    at.radio(key="spa_page").set_value(name).run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def button(at: AppTest, label: str):  # noqa: ANN201
    return next(b for b in at.button if b.label == label)


def all_text(elements) -> str:  # noqa: ANN001
    return "\n".join(str(e.value) for e in elements)
