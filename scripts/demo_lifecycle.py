#!/usr/bin/env python3
"""Review 3 demonstration: a finding's identity and state across six "commits".

    python scripts/demo_lifecycle.py

Runs offline (pip-audit aside, which queries the PyPI advisory database).
Uses its own database (data/demo_lifecycle.db), recreated on every run, so the
output is reproducible. See evaluation/lifecycle_scenario.py for the steps.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DB = ROOT / "data" / "demo_lifecycle.db"
os.environ["SPA_DATABASE_URL"] = f"sqlite:///{DB.as_posix()}"

from app.core.config import get_settings  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402
from evaluation.lifecycle_scenario import StepResult, run_scenario  # noqa: E402

ORDER = ["NEW", "STILL_OPEN", "RESOLVED", "REGRESSION", "SUPPRESSED", "UNVERIFIED"]


def show(result: StepResult) -> None:
    s = result.summary
    print("=" * 100)
    print(f"  {result.step.label}  --  {result.step.story}")
    print(f"  scan #{s.scan_id}  status={s.status}  findings={s.findings}  "
          + "  ".join(f"{k}={v}" for k, v in s.scanners.items() if v != "OK"))
    print("  lifecycle: " + "  ".join(f"{k}={s.lifecycle.get(k, 0)}" for k in ORDER))
    # Show what this commit *did*; NEW->STILL_OPEN is just a finding carrying forward.
    interesting = [c for c in result.changes
                   if c.unverified or c.to_status in {"RESOLVED", "REGRESSION"}
                   or (c.to_status == "NEW" and result.step.label != "v1-baseline")]
    for c in interesting:
        arrow = f"{c.from_status or '-':>10} -> {c.to_status:<10}"
        flag = "  (absent, but scanner could not verify -> kept open)" if c.unverified else ""
        print(f"     {arrow} #{c.tracked_id:<3} {c.tool:<9} {(c.cwe or '-'):<9} {c.location:<20} {c.rule}{flag}")
    for c in result.suppressed:
        print(f"     {c.from_status:>10} -> SUPPRESSED #{c.tracked_id:<3} {c.tool:<9} {(c.cwe or '-'):<9} "
              f"{c.location:<20} {c.rule}  (human: false positive)")
    print()


def main() -> int:
    DB.parent.mkdir(exist_ok=True)
    DB.unlink(missing_ok=True)
    get_settings.cache_clear()
    configure_logging("ERROR")
    print()
    run_scenario(on_step=show)
    print("  python -m app.cli history --project lifecycle-demo     (with SPA_DATABASE_URL pointing at the demo DB)")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
