"""Findings: filter the tracked findings, then inspect one -- evidence, lifecycle, verdicts, suppression."""

from __future__ import annotations

import streamlit as st

from app.normalization.finding import SEVERITIES
from dashboard import actions, data, safe, widgets
from dashboard.actions import ActionError

OPEN = ["NEW", "STILL_OPEN", "REGRESSION"]


def _detail(row: data.TrackedRow) -> None:
    detail = data.finding_detail(row.id)
    if detail is None:
        st.warning("Finding not found.")
        return
    ev = detail.evidence
    left, right = st.columns(2)
    with left:
        st.subheader("Scanner evidence")
        if ev is None:
            st.caption("No stored evidence.")
        else:
            safe.field("Rule", f"{ev.tool} {ev.rule_id}")
            safe.field("Message", ev.message)
            safe.field("Location", f"{ev.file_path}:{ev.start_line or '-'}")
            safe.field("Classification",
                       f"{ev.cwe or '-'} (reported {ev.cwe_reported or '-'}), OWASP {ev.owasp or '-'}")
            if ev.package:
                safe.field("Package", f"{ev.package} {ev.package_version or ''}; CVEs {', '.join(ev.cve_ids) or '-'}; "
                                      f"fixed in {', '.join(ev.fix_versions) or '-'}")
            st.caption("Snippet (redacted)")
            safe.code(ev.snippet)
    with right:
        st.subheader("Lifecycle")
        safe.table([{"scan": e.scan_id if e.scan_id is not None else "manual", "from": e.from_status or "-",
                     "to": e.to_status, "unverified": e.unverified, "note": e.note or ""} for e in detail.events])
        st.subheader("Verifications")
        if detail.verifications:
            safe.table([{"id": v.id, "mode": v.mode, "verdict": v.verdict, "reason": v.reason or ""}
                        for v in detail.verifications])
        else:
            st.caption("Not verified yet - see the Verification page.")

    st.subheader("False positive?")
    if row.status == "SUPPRESSED":
        safe.field("Suppressed because", detail.suppressed_reason)
        if st.button("Withdraw suppression", key="unsuppress"):
            try:
                actions.unsuppress_finding(row.id)
                st.rerun()
            except ActionError as exc:
                safe.error("Could not withdraw the suppression.", exc)
    else:
        reason = st.text_input("Reason (kept on record; the finding is never deleted)", key="suppress_reason",
                               max_chars=500)
        if st.button("Suppress as false positive", key="suppress"):
            try:
                actions.suppress_finding(row.id, reason)
                st.rerun()
            except ActionError as exc:
                safe.error("Not suppressed.", exc)


def render(project_id: int | None) -> None:
    st.header("Findings")
    if project_id is None:
        st.info("No project yet - scan a checkout on the Overview page.")
        return
    everything = data.tracked(project_id)
    c1, c2, c3 = st.columns(3)
    states = c1.multiselect("State", list(data.STATES), default=OPEN, key="filter_states")
    severities = c2.multiselect("Severity", list(SEVERITIES), key="filter_severities")
    tools = c3.multiselect("Scanner", sorted({r.tool for r in everything}), key="filter_tools")
    rows = data.tracked(project_id, states, severities, tools)
    st.caption(f"{len(rows)} of {len(everything)} tracked findings")
    if not rows:
        st.info("No findings match these filters.")
        return
    safe.table([{"id": r.id, "state": r.status, "severity": r.severity, "scanner": r.tool, "rule": r.rule,
                 "CWE": r.cwe or "-", "OWASP": r.owasp or "-", "location": f"{r.file_path}:{r.line or '-'}",
                 "first scan": r.first_seen, "last scan": r.last_seen, "regressions": r.regressions,
                 "latest verdict": r.verdict or "-"} for r in rows])
    _detail(widgets.pick_finding(rows, "Details for", key="findings_pick"))
