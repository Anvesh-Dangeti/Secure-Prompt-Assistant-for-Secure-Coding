"""Secure Prompt Assistant -- the local dashboard (developer mode).

    python -m streamlit run dashboard/streamlit_app.py        # from the project root

It serves http://127.0.0.1:8501 only (.streamlit/config.toml) and refuses to
show anything if bound wider. Every page is behind SPA_API_KEY. It calls the
same services as the CLI -- scan a checkout, read findings, build and lint a
prompt, rescan and verify -- and never runs a model or the scanned code.
"""

from __future__ import annotations

import sys
from pathlib import Path

# `streamlit run` puts dashboard/ first on sys.path; the project root is needed
# for `app` and `dashboard`. (This file is not called app.py so that it can
# never shadow the `app` package.)
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from app.db.session import init_db  # noqa: E402
from dashboard import auth, data  # noqa: E402
from dashboard.views import findings, history, overview, prompt, verification  # noqa: E402

PAGES = {
    "Overview": overview.render,
    "Findings": findings.render,
    "Prompt & lint": prompt.render,
    "Verification": verification.render,
    "Scan history": history.render,
}


def main() -> None:
    st.set_page_config(page_title="Secure Prompt Assistant", layout="wide")
    if not auth.loopback_only():
        st.error("Refusing to serve: the dashboard must be bound to 127.0.0.1. Run it from the project root "
                 "(which loads .streamlit/config.toml) or pass --server.address 127.0.0.1.")
        st.stop()
    if not auth.gate():
        st.stop()
    init_db()
    projects = data.projects()
    with st.sidebar:
        st.title("Secure Prompt Assistant")
        st.caption("Developer mode - your own assistant writes the fix; scanners verify it.")
        project = st.selectbox("Project", projects, format_func=lambda p: f"{p.name} ({p.scans} scans)",
                               key="spa_project") if projects else None
        page = st.radio("Page", list(PAGES), key="spa_page")
        if st.button("Sign out", key="spa_sign_out"):
            auth.logout()
            st.rerun()
    PAGES[page](project.id if project else None)


main()
