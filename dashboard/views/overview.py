"""Overview: what is open, how severe, how it has moved, and what the last scan could see."""

from __future__ import annotations

import streamlit as st

from dashboard import actions, charts, data, safe
from dashboard.actions import ActionError

OPEN_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def scan_form(project: data.ProjectRow | None) -> None:
    """Scan a local checkout: into a new project, or again into the selected one."""
    with st.form("scan_form"):
        if project is None or project.source_type == "zip":
            name = st.text_input("Project name", value=project.name if project else "",
                                 disabled=project is not None)
            path = st.text_input("Checkout to scan (absolute path)", key="scan_path")
        else:
            name, path = project.name, None
            st.caption("This project tracks a git repository: the scan re-clones it.")
        label = st.text_input("Label (optional)", max_chars=120)
        submitted = st.form_submit_button("Scan")
    if submitted:
        try:
            with st.spinner("Scanning with Semgrep, Bandit, Gitleaks and pip-audit..."):
                summary = (actions.rescan(project.id, path, label) if project else
                           actions.scan_checkout(name, path, label))
        except ActionError as exc:
            safe.error("The scan did not run.", exc)
            return
        st.success(f"Scan #{summary.scan_id} finished: {summary.status}, {summary.findings} findings.")
        st.rerun()


def render(project_id: int | None) -> None:
    st.header("Overview")
    if project_id is None:
        st.info("No project yet. Scan a checkout to start.")
        scan_form(None)
        return
    o = data.overview(project_id)
    if o is None:
        st.warning("Project not found.")
        return

    st.subheader("Open findings by severity")
    for col, sev in zip(st.columns(len(OPEN_SEVERITIES)), OPEN_SEVERITIES):
        col.metric(sev, o.open_by_severity.get(sev, 0))
    st.subheader("Lifecycle")
    for col, state in zip(st.columns(len(o.states)), o.states):
        col.metric(state, o.states[state])
    st.subheader("Latest verification verdict per finding")
    for col, verdict in zip(st.columns(len(o.verdicts)), o.verdicts):
        col.metric(verdict, o.verdicts[verdict])

    left, right = st.columns(2)
    with left:
        st.subheader("Open findings by OWASP category")
        if o.open_by_owasp:
            st.altair_chart(charts.open_by_category(o.open_by_owasp), width="stretch")
        else:
            st.caption("Nothing open.")
    with right:
        st.subheader("Findings reported per scan")
        scans = data.scan_history(project_id)
        st.altair_chart(charts.findings_per_scan(
            [{"scan": f"#{s.id}", "label": s.label or "-", "status": s.status, "findings": s.findings} for s in scans]),
            width="stretch")

    if o.latest:
        st.subheader(f"Scan #{o.latest.id} - {o.latest.status}")
        safe.table(o.scanner_runs)
    with st.expander("Scan again"):
        scan_form(o.project)
