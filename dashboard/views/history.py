"""Scan and commit history: every scan of the project, what it changed, and what each scanner could see."""

from __future__ import annotations

import streamlit as st

from dashboard import charts, data, safe


def render(project_id: int | None) -> None:
    st.header("Scan history")
    if project_id is None:
        st.info("No project yet - scan a checkout on the Overview page.")
        return
    scans = data.scan_history(project_id)
    if not scans:
        st.caption("No scans yet.")
        return
    st.caption("Source is the commit SHA for git projects and the SHA-256 of the archive for uploads.")
    safe.table([{"scan": s.id, "label": s.label or "-", "status": s.status, "source": (s.source_ref or "-")[:12],
                 "started": s.started_at.strftime("%Y-%m-%d %H:%M"), "findings": s.findings, **s.transitions,
                 "scanner problems": ", ".join(f"{k}={v}" for k, v in s.scanners.items() if v != "OK") or "-"}
                for s in scans])
    st.subheader("Findings reported per scan")
    st.altair_chart(charts.findings_per_scan(
        [{"scan": f"#{s.id}", "label": s.label or "-", "status": s.status, "findings": s.findings} for s in scans]),
        width="stretch")
    st.subheader("Scanner runs")
    chosen = st.selectbox("Scan", [s.id for s in reversed(scans)], format_func=lambda i: f"#{i}", key="history_scan")
    safe.table(data.scanner_runs(chosen))
