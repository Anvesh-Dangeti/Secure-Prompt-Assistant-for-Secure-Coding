"""The dashboard's two charts, built with Altair (bundled with Streamlit).

Both are single-series, so there is no categorical palette and no legend: the
title names the series. The mark rules follow the project's chart guidance:
thin bars with a 4 px rounded data end anchored to the baseline, a 2 px line
with >= 8 px markers, selective direct labels, a recessive grid, and a hover
tooltip on every mark. The colour is categorical slot 1 (blue), which reads on
both the light and the dark Streamlit theme; text keeps the theme's ink.
Every chart has the same numbers in a table on the same page.
"""

from __future__ import annotations

import altair as alt
import pandas as pd

SERIES_1 = "#2a78d6"


def open_by_category(counts: dict[str, int]) -> alt.LayerChart:
    """Horizontal bars: open findings per OWASP category, largest first, value labelled at the bar end."""
    frame = pd.DataFrame({"category": list(counts), "open": list(counts.values())})
    base = alt.Chart(frame).encode(
        y=alt.Y("category:N", sort="-x", title=None, axis=alt.Axis(labelLimit=320, ticks=False)),
        x=alt.X("open:Q", title="Open findings", axis=alt.Axis(tickMinStep=1, gridOpacity=0.35)),
    )
    bars = base.mark_bar(color=SERIES_1, size=14, cornerRadiusEnd=4).encode(
        tooltip=[alt.Tooltip("category:N", title="OWASP category"), alt.Tooltip("open:Q", title="Open")])
    labels = base.mark_text(align="left", dx=4).encode(text="open:Q")
    return (bars + labels).properties(height=max(120, 30 * len(frame)))


def findings_per_scan(rows: list[dict]) -> alt.Chart:
    """A line over scans in order: how many findings each scan reported."""
    frame = pd.DataFrame(rows)
    return alt.Chart(frame).mark_line(
        color=SERIES_1, strokeWidth=2, point=alt.OverlayMarkDef(color=SERIES_1, filled=True, size=72),
    ).encode(
        x=alt.X("scan:N", sort=None, title="Scan", axis=alt.Axis(labelAngle=0)),
        y=alt.Y("findings:Q", title="Findings reported", scale=alt.Scale(zero=True),
                axis=alt.Axis(tickMinStep=1, gridOpacity=0.35)),
        tooltip=[alt.Tooltip("scan:N", title="Scan"), alt.Tooltip("label:N", title="Label"),
                 alt.Tooltip("status:N", title="Status"), alt.Tooltip("findings:Q", title="Findings")],
    ).properties(height=220)
