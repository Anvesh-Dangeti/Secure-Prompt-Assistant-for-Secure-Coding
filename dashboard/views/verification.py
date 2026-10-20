"""Verification: rescan the fixed code and let the gates decide -- never the model, never this page."""

from __future__ import annotations

import streamlit as st

from dashboard import actions, data, safe, widgets
from dashboard.actions import ActionError


def render(project_id: int | None) -> None:
    st.header("Verification")
    st.caption("A fix counts only when a fresh scan says so. Gate 1: the weakness is gone for every scanner. "
               "Gate 2: nothing new at its severity or above. Gate 3a: the function is still intact. "
               "Nothing on this page runs your code.")
    if project_id is None:
        st.info("No project yet - scan a checkout on the Overview page.")
        return
    project = data.project(project_id)
    rows = data.tracked(project_id)
    if project is None or not rows:
        st.info("This project has no findings.")
        return
    row = widgets.pick_finding(rows, key="verify_pick")

    left, right = st.columns(2)
    with left:
        st.subheader("Rescan and verify")
        path = widgets.checkout_input() if project.source_type == "zip" else None
        if project.source_type != "zip":
            st.caption("This project tracks a git repository: push your fix; the rescan re-clones it.")
        if st.button("Rescan checkout & verify", key="rescan_verify"):
            try:
                with st.spinner("Rescanning..."):
                    summary, result = actions.rescan_and_verify(row.id, path)
                st.success(f"Scan #{summary.scan_id} ({summary.status}) -> verdict {result.verdict}")
            except ActionError as exc:
                safe.error("Not verified.", exc)
    with right:
        st.subheader("Judge the latest scan")
        st.caption("Use this after scanning from the CLI or the API.")
        if st.button("Verify against latest scan", key="verify_latest"):
            try:
                result = actions.verify_against(row.id)
                st.success(f"Verdict {result.verdict}")
            except ActionError as exc:
                safe.error("Not verified.", exc)

    st.subheader("History")
    history = data.verifications(row.id)
    if not history:
        st.caption("No verifications for this finding yet.")
    for v in history:
        widgets.verification_card(v)
