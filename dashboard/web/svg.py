"""Inline-SVG chart geometry, computed on the server: no chart library, no page script, no inline style.

The specs are the same as the Streamlit charts': each chart is a single series
(the heading names it, so there is no legend) drawn in categorical slot 1; bars
are 14 px thick with a 4 px rounded data end and a square baseline; the line is
2 px with 8 px markers ringed in the surface colour; values are labelled only at
bar tips and at the line's last point; the grid is a recessive hairline; every
mark has a native ``<title>`` hover tooltip on a hit target larger than the mark.
Colours come from CSS classes in ``app.css``, so light and dark each use their
own validated steps. The same numbers are always in a table on the page.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

ROW = 40            # one category per row: name above, bar below
BAR = 14
RADIUS = 4
VALUE_ROOM = 44     # space right of the longest bar for its value label


@dataclass(frozen=True)
class HBar:
    label: str
    value: int
    label_y: float
    path: str           # empty when the value is 0 (no mark, the label still shows 0)
    bar_y: float
    value_x: float
    value_y: float


@dataclass(frozen=True)
class HBarChart:
    width: int
    height: int
    bars: list[HBar]


@dataclass(frozen=True)
class Tick:
    pos: float
    text: str


@dataclass(frozen=True)
class Point:
    x: float
    y: float
    value: int
    tip: str


@dataclass(frozen=True)
class LineChart:
    width: int
    height: int
    left: float
    right: float
    top: float
    bottom: float
    path: str
    points: list[Point]
    y_ticks: list[Tick]
    x_ticks: list[Tick]


def bar_path(x0: float, y: float, length: float, height: float, radius: float = RADIUS) -> str:
    """A horizontal bar from ``x0``: square at the baseline, rounded at the data end."""
    if length <= 0:
        return ""
    r = min(radius, length, height / 2)
    x1 = x0 + length
    return (f"M{x0:.1f},{y:.1f}H{x1 - r:.1f}A{r:g},{r:g} 0 0 1 {x1:.1f},{y + r:.1f}"
            f"V{y + height - r:.1f}A{r:g},{r:g} 0 0 1 {x1 - r:.1f},{y + height:.1f}H{x0:.1f}Z")


def hbars(counts: dict[str, int], width: int = 560) -> HBarChart:
    """Horizontal bars, in the order given (callers sort largest first)."""
    top = max(counts.values(), default=0) or 1
    span = width - VALUE_ROOM
    bars = []
    for i, (label, value) in enumerate(counts.items()):
        y = i * ROW
        bar_y = y + 18
        length = span * value / top
        bars.append(HBar(label, value, y + 12, bar_path(0, bar_y, length, BAR), bar_y, length + 6,
                         bar_y + BAR / 2 + 4))
    return HBarChart(width, max(ROW, len(counts) * ROW + 4), bars)


def nice_ticks(top: int, most: int = 4) -> list[int]:
    """0 and up to ``most`` clean steps (1, 2, 5 x 10^k) covering ``top``."""
    if top <= 0:
        return [0, 1]
    magnitude = 10 ** max(0, int(math.log10(top)) - 1)
    for base in (1, 2, 5, 10, 20, 50, 100):
        step = base * magnitude
        if math.ceil(top / step) <= most:
            return list(range(0, step * math.ceil(top / step) + 1, step))
    step = 10 ** math.ceil(math.log10(top))
    return [0, step]


def line(points: list[tuple[str, int, str]], width: int = 560, height: int = 220) -> LineChart:
    """A line over ordered points: (x label, value, hover text)."""
    left, right, top, bottom = 40.0, width - 28.0, 14.0, height - 30.0
    ticks = nice_ticks(max((v for _, v, _ in points), default=0))
    y_max = ticks[-1] or 1
    n = len(points)
    step = (right - left) / (n - 1) if n > 1 else 0.0

    def x_at(i: int) -> float:
        return left + i * step if n > 1 else (left + right) / 2

    def y_at(v: int) -> float:
        return bottom - (bottom - top) * v / y_max

    marks = [Point(round(x_at(i), 1), round(y_at(v), 1), v, tip) for i, (_, v, tip) in enumerate(points)]
    path = "M" + "L".join(f"{p.x:.1f},{p.y:.1f}" for p in marks) if marks else ""
    every = max(1, math.ceil(n / 10))       # at most ~10 x labels; the last one always shows
    x_ticks = [Tick(round(x_at(i), 1), label) for i, (label, _, _) in enumerate(points)
               if i % every == 0 or i == n - 1]
    y_ticks = [Tick(round(y_at(t), 1), str(t)) for t in ticks]
    return LineChart(width, height, left, right, top, bottom, path, marks, y_ticks, x_ticks)
