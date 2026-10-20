"""The dashboard's charts: every category is labelled, and the mark rules hold."""

from __future__ import annotations

from dashboard import charts

CATEGORIES = {f"A0{i}:2021 Category {i}": 7 - i for i in range(1, 7)}


def test_every_category_name_is_drawn() -> None:
    spec = charts.open_by_category(CATEGORIES).to_dict()
    bars, labels = spec["layer"]
    assert bars["encoding"]["y"]["axis"]["labelOverlap"] is False
    assert labels["mark"]["type"] == "text"                     # value at the bar end
    assert spec["height"] >= 30 * len(CATEGORIES)


def test_single_series_marks() -> None:
    bars = charts.open_by_category(CATEGORIES).to_dict()["layer"][0]["mark"]
    assert bars["color"] == charts.SERIES_1 and bars["cornerRadiusEnd"] == 4
    line = charts.findings_per_scan([{"scan": "#1", "label": "v1", "status": "COMPLETED", "findings": 3}]).to_dict()
    assert line["mark"]["strokeWidth"] == 2 and line["mark"]["color"] == charts.SERIES_1
