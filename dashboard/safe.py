"""The only way text from a scanned repository reaches the page.

Scanned code, file names, rule ids, scanner messages, gate details and model
summaries are attacker-controllable. Streamlit renders Markdown in
``st.markdown``, ``st.write``, captions, headings and alert boxes, so a finding
message such as ``![x](https://attacker.example/pixel)`` would make the browser
fetch a remote image, and ``[docs](https://attacker.example)`` would become a
link. These helpers use only elements that display text literally
(``st.text``, ``st.code``, ``st.dataframe``); Markdown calls elsewhere in the
dashboard carry only our own literals and numbers, and ``unsafe_allow_html`` is
never used.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

import pandas as pd
import streamlit as st


def text(value: object) -> None:
    """Untrusted value, shown literally."""
    st.text("-" if value is None or value == "" else str(value))


def field(label: str, value: object) -> None:
    """A trusted label (our own literal) above an untrusted value."""
    st.caption(label)
    text(value)


def code(value: str | None, language: str | None = None) -> None:
    """Untrusted code or a prompt, shown literally, with Streamlit's copy button."""
    st.code(value or "", language=language)


def table(rows: Iterable[Mapping[str, object]], **kwargs: object):  # noqa: ANN201
    """Rows of untrusted values as a grid; cells are plain text (no link or Markdown columns)."""
    frame = pd.DataFrame(list(rows))
    return st.dataframe(frame, hide_index=True, width="stretch", **kwargs)


def error(title: str, detail: object) -> None:
    """A trusted headline in an alert box; the (possibly path-bearing) detail as literal text."""
    st.error(title)
    text(detail)
