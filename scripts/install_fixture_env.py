#!/usr/bin/env python3
"""Install the interpreter that runs the fixtures' behaviour tests (verification gate 3b, lab mode).

    python scripts/install_fixture_env.py

Creates .tools/fixture, a virtualenv holding only what the fixture apps and
their tests need. It is separate from the application's environment on
purpose: gate 3b executes model-written code, and that code must never run
inside the interpreter that holds the application, its database access or its
configuration.

The versions here are the *runtime* for the tests and are free of known
vulnerabilities. fixtures/flask_vuln_app/requirements.txt deliberately pins a
vulnerable PyYAML; that file is only ever read by pip-audit (the SCA target)
and is never installed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".tools" / "fixture"

PINNED = ["flask==3.1.3", "PyYAML==6.0.3", "pytest==9.1.1"]


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def main() -> int:
    VENV.parent.mkdir(exist_ok=True)
    if not _venv_python(VENV).exists():
        print(f"creating {VENV}")
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True, timeout=300)
    python = str(_venv_python(VENV))
    subprocess.run([python, "-m", "pip", "install", "--quiet", "--upgrade", "pip"], check=True, timeout=600)
    print("installing " + " ".join(PINNED))
    subprocess.run([python, "-m", "pip", "install", "--quiet", *PINNED], check=True, timeout=1200)
    print(f"done. Gate 3b will use {python}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
