"""Web interface parts without a server: chart geometry, the Host parser, the sign-in throttle."""

from __future__ import annotations

import pytest

from dashboard.web import security, svg


def test_a_bar_is_square_at_the_baseline_and_rounded_at_the_data_end() -> None:
    path = svg.bar_path(0, 10, 100, 14)
    assert path.startswith("M0.0,10.0H96.0A4,4 0 0 1 100.0,14.0") and path.endswith("H0.0Z")
    assert svg.bar_path(0, 10, 0, 14) == ""                       # zero draws no mark
    assert "A2,2" in svg.bar_path(0, 10, 2, 14)                    # radius never exceeds the bar


def test_hbars_scale_to_the_largest_value_and_keep_the_order() -> None:
    chart = svg.hbars({"A03 Injection": 6, "A02 Crypto": 3, "A05 Misconfig": 0}, width=560)
    assert [b.label for b in chart.bars] == ["A03 Injection", "A02 Crypto", "A05 Misconfig"]
    longest = chart.bars[0]
    assert longest.value_x == pytest.approx(560 - svg.VALUE_ROOM + 6)
    assert chart.bars[1].value_x == pytest.approx((560 - svg.VALUE_ROOM) / 2 + 6)
    assert chart.bars[2].path == "" and chart.height == 3 * svg.ROW + 4


@pytest.mark.parametrize("top,ticks", [(0, [0, 1]), (3, [0, 1, 2, 3]), (7, [0, 2, 4, 6, 8]), (24, [0, 10, 20, 30]),
                                       (100, [0, 50, 100]), (1234, [0, 500, 1000, 1500])])
def test_nice_ticks(top: int, ticks: list[int]) -> None:
    assert svg.nice_ticks(top) == ticks


def test_line_labels_at_most_about_ten_scans_and_always_the_last() -> None:
    points = [(f"#{i}", i, f"scan {i}") for i in range(1, 26)]
    chart = svg.line(points)
    assert len(chart.x_ticks) <= 11 and chart.x_ticks[-1].text == "#25"
    assert chart.points[0].x == chart.left and chart.points[-1].x == pytest.approx(chart.right)
    single = svg.line([("#1", 5, "only")])
    assert single.points[0].x == pytest.approx((single.left + single.right) / 2)


@pytest.mark.parametrize("header,name", [("127.0.0.1:8080", "127.0.0.1"), ("LocalHost", "localhost"),
                                         ("[::1]:8080", "::1"), ("[::1", ""), ("attacker.example:80", "attacker.example"),
                                         ("", "")])
def test_host_name(header: str, name: str) -> None:
    assert security.host_name(header) == name


def test_the_throttle_locks_after_five_failures_and_reopens(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(security.time, "monotonic", lambda: now[0])
    throttle = security.LoginThrottle()
    for _ in range(security.MAX_FAILURES - 1):
        throttle.failed()
    assert not throttle.locked()
    throttle.failed()
    assert throttle.locked()
    now[0] += security.LOCKOUT_S + 1
    assert not throttle.locked() and throttle.failures == 0
