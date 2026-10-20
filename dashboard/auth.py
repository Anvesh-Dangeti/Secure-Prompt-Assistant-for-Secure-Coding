"""The dashboard's access gate -- the same key and the same fail-closed rule as the API.

* **Loopback only.** Streamlit listens on every interface unless told
  otherwise, so the app checks its own configured address and serves nothing
  (not even the login form) unless it is bound to loopback.
* **Key required.** Every page is behind ``SPA_API_KEY``. If no key is
  configured the dashboard refuses to open -- it never falls back to "open".
* **Constant-time comparison**, a one-second delay after each wrong key, and a
  lockout after five failures in a session, so the gate cannot be brute-forced
  quickly from the page.
"""

from __future__ import annotations

import secrets
import time

import streamlit as st

from app.core.config import get_settings

LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
MAX_FAILURES = 5
FAILURE_DELAY_S = 1.0
_AUTHED, _FAILURES = "spa_authenticated", "spa_failed_attempts"


def loopback_only() -> bool:
    return (st.get_option("server.address") or "").strip().lower() in LOOPBACK


def key_configured() -> bool:
    key = get_settings().api_key
    return key is not None and bool(key.get_secret_value())


def check_key(entered: str) -> bool:
    key = get_settings().api_key
    if key is None or not key.get_secret_value():
        return False
    return secrets.compare_digest(entered.encode("utf-8"), key.get_secret_value().encode("utf-8"))


def logout() -> None:
    st.session_state[_AUTHED] = False


def gate() -> bool:
    """Render the sign-in form unless this session is already signed in. True when access is granted."""
    if st.session_state.get(_AUTHED):
        return True
    st.title("Secure Prompt Assistant")
    if not key_configured():
        st.error("SPA_API_KEY is not set, so the dashboard is disabled. Set it in .env and restart.")
        return False
    if st.session_state.get(_FAILURES, 0) >= MAX_FAILURES:
        st.error("Too many wrong keys in this session. Restart the dashboard to try again.")
        return False
    entered = st.text_input("API key", type="password", key="spa_key_input")
    if st.button("Sign in", key="spa_sign_in"):
        if check_key(entered or ""):
            st.session_state[_AUTHED] = True
            st.session_state[_FAILURES] = 0
            st.rerun()
        st.session_state[_FAILURES] = st.session_state.get(_FAILURES, 0) + 1
        time.sleep(FAILURE_DELAY_S)
        if st.session_state[_FAILURES] >= MAX_FAILURES:
            st.session_state.pop("spa_key_input", None)
            st.rerun()          # the next run shows only the lockout message
        st.error("Wrong key.")
    return False
