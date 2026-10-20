"""Widgets shared by several pages: finding picker, checkout path, lint report, verification card."""

from __future__ import annotations

import streamlit as st

from app.ai.linter import RULES
from dashboard import safe
from dashboard.data import TrackedRow, VerificationRow

SELECTED = "spa_tracked_id"     # the finding the user is working on, shared across pages
CHECKOUT = "spa_checkout_path"  # the developer's checkout, shared across pages

_BADGE = {"VERIFIED_RESOLVED": st.success, "FIX_REJECTED": st.error, "UNVERIFIED": st.warning, "ERROR": st.warning}


def pick_finding(rows: list[TrackedRow], label: str = "Finding", key: str = "pick") -> TrackedRow:
    """A selectbox over findings (option text is shown literally), remembering the choice across pages."""
    ids = [r.id for r in rows]
    current = st.session_state.get(SELECTED)
    index = ids.index(current) if current in ids else 0
    row = st.selectbox(label, rows, index=index, format_func=lambda r: r.label, key=key)
    st.session_state[SELECTED] = row.id
    return row


def checkout_input() -> str:
    value = st.text_input("Your checkout (absolute path)", value=st.session_state.get(CHECKOUT, ""),
                          key=f"{CHECKOUT}_input", help="The local copy of the scanned code you are fixing.")
    st.session_state[CHECKOUT] = value
    return value


def lint_report(report: dict, title: str = "Lint") -> None:
    passed = report["passed"]
    (st.success if passed else st.error)(
        f"{title}: {'PASS' if passed else 'FAIL'} - constituents {report['constituent_score']:.0%}, "
        f"~{report['tokens']} tokens ({'bound to the finding' if report['bound'] else 'unbound'})")
    marks = {True: "ok", False: "MISSING", None: "n/a"}
    safe.table([{"rule": rule, "result": marks[present], "checks": RULES[rule]}
                for rule, present in report["constituents"].items()])
    if report["issues"]:
        safe.table([{"rule": i["rule"], "severity": i["severity"], "problem": i["message"], "fix-it": i["fix"] or ""}
                    for i in report["issues"]])


def verification_card(v: VerificationRow) -> None:
    with st.container(border=True):
        _BADGE.get(v.verdict, st.warning)(f"Verification #{v.id}: {v.verdict}")
        if v.mode == "developer":
            st.caption(f"developer mode - scan #{v.before_scan_id} compared with scan #{v.after_scan_id}")
        else:
            st.caption(f"lab mode - strategy {v.strategy or '-'}, {v.calls} model call(s), "
                       f"{v.prompt_tokens or 0} prompt + {v.completion_tokens or 0} completion tokens")
            safe.field("Model", v.model)
        if v.reason:
            safe.field("Reason", v.reason)
        safe.table([{"gate": g["gate"], "check": g["title"], "status": g["status"], "detail": g["detail"]}
                    for g in v.gates])
        with st.expander("Findings in this weakness, and gate details"):
            safe.text("\n".join(v.target))
            for g in v.gates:
                if g.get("items"):
                    st.caption(f"Gate {g['gate']}")
                    safe.text("\n".join(g["items"]))
