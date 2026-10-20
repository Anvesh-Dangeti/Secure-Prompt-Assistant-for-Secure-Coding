#!/usr/bin/env python3
"""Review 4 demonstration: developer-mode verification across eight "commits".

    python scripts/demo_verify.py

Every verdict comes from rescanning and the gates, never from a model. Uses
its own database (data/demo_verify.db), recreated on every run, so the output
is reproducible. See evaluation/verification_scenario.py for the steps.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DB = ROOT / "data" / "demo_verify.db"
os.environ["SPA_DATABASE_URL"] = f"sqlite:///{DB.as_posix()}"

from app.cli_verify import print_verification  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402
from app.db.models import Verification  # noqa: E402
from app.db.session import session_scope  # noqa: E402
from evaluation.verification_scenario import PROJECT, StepResult, run_scenario  # noqa: E402


def show(result: StepResult) -> None:
    s = result.summary
    print("=" * 100)
    print(f"  {result.step.label}  --  {result.step.story}")
    print(f"  scan #{s.scan_id}  status={s.status}  findings={s.findings}  "
          + "  ".join(f"{k}={v}" for k, v in s.scanners.items() if v != "OK"))
    if result.verification_id is None:
        print()
        return
    with session_scope() as session:
        print_verification(session.get(Verification, result.verification_id))


def main() -> int:
    DB.parent.mkdir(exist_ok=True)
    DB.unlink(missing_ok=True)
    get_settings.cache_clear()
    configure_logging("ERROR")
    print()
    results = run_scenario(on_step=show)
    print("=" * 100)
    for r in results:
        if r.verdict:
            print(f"  {r.step.label:<26} #{r.tracked_id:<3} {r.verdict:<18} {r.reason or ''}")
    print(f"\n  python -m app.cli verifications <id> --full   (SPA_DATABASE_URL -> the demo DB; project {PROJECT})\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
