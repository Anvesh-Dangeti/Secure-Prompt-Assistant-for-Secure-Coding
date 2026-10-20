"""Prompt & lint: build the remediation prompt for your own assistant, then lint whatever you edit."""

from __future__ import annotations

import streamlit as st

from app.ai.strategies import DEFAULT_STRATEGY, STRATEGIES
from app.cli_ai import MAX_PROMPT_INPUT
from dashboard import actions, data, safe, widgets
from dashboard.actions import ActionError

_VIEW = "spa_prompt_view"


def render(project_id: int | None) -> None:
    st.header("Prompt & lint")
    st.caption("Build the prompt, copy it into your own coding assistant (Copilot, Cursor, Codex...), and lint any "
               "edits before sending. No model runs here and no tokens are spent.")
    if project_id is None:
        st.info("No project yet - scan a checkout on the Overview page.")
        return
    rows = data.tracked(project_id, states=["NEW", "STILL_OPEN", "REGRESSION"])
    if not rows:
        st.success("No open findings.")
        return
    row = widgets.pick_finding(rows, key="prompt_pick")
    path = widgets.checkout_input()
    ids = list(STRATEGIES)
    strategy = st.selectbox("Strategy", ids, index=ids.index(DEFAULT_STRATEGY), key="prompt_strategy",
                            format_func=lambda s: f"{s} - {STRATEGIES[s].name}")

    if st.button("Build prompt", key="build_prompt"):
        try:
            st.session_state[_VIEW] = (row.id, actions.prompt_for(row.id, path, strategy))
        except ActionError as exc:
            st.session_state.pop(_VIEW, None)
            safe.error("No prompt was built.", exc)
    stored = st.session_state.get(_VIEW)
    if stored and stored[0] == row.id:
        view = stored[1]
        if view.warning:
            st.warning("The code in this checkout differs from the scanned version; rescan for exact context.")
        st.subheader(f"Prompt ({view.strategy}) - copy with the button at the top right")
        safe.code(view.rendered)
        st.caption(f"~{view.tokens} tokens; explanation from the {view.explanation_source}")
        widgets.lint_report(view.report, "Lint of this prompt")

    st.divider()
    st.subheader("Lint your edited prompt")
    st.caption("Shortened or reworded prompts often lose the security constituents. Paste yours to check it.")
    edited = st.text_area("Edited prompt", height=220, max_chars=MAX_PROMPT_INPUT, key="edited_prompt")
    bound = st.toggle("Check against the selected finding (exact entity and shortening checks)", value=True,
                      key="lint_bound")
    c1, c2 = st.columns(2)
    run_lint, run_fix = c1.button("Lint", key="lint"), c2.button("Apply fix-its", key="fix")
    if run_lint or run_fix:
        try:
            result = actions.lint_text(edited, row.id if bound else None, path if bound else None, fix=run_fix)
        except ActionError as exc:
            safe.error("Not linted.", exc)
            return
        widgets.lint_report(result.report, "Lint of your prompt")
        if result.fixed is not None:
            st.subheader("With fix-its applied")
            safe.code(result.fixed)
            widgets.lint_report(result.fixed_report, "Lint after fix-its")
