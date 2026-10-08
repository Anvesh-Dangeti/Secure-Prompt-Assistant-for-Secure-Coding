#!/usr/bin/env python3
"""Install the Python-based scanners into isolated virtualenvs under .tools/.

    python scripts/install_scanners.py

Why isolated: the scanners are external programs we invoke as subprocesses,
not libraries we import. Semgrep's dependency pins conflict with FastAPI's
(pip backtracks to an old Semgrep source release that refuses to build on
Windows), and keeping each scanner's dependencies out of the application's
environment means a compromised scanner dependency cannot be imported by the
application.

Gitleaks is a standalone Go binary and is not installed by this script:
    Windows: winget install --id Gitleaks.Gitleaks --version 8.30.1 --exact
    Other:   https://github.com/gitleaks/gitleaks/releases (verify the checksum)
then set SPA_GITLEAKS_BIN in .env if it is not on PATH.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".tools"

# Exact versions: results are reproducible only if the scanners are.
PINNED = {
    "semgrep": "semgrep==1.180.0",
    "bandit": "bandit[sarif]==1.9.4",
    "pip-audit": "pip-audit==2.10.1",
}


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def main() -> int:
    TOOLS.mkdir(exist_ok=True)
    for name, requirement in PINNED.items():
        venv = TOOLS / name
        if not _venv_python(venv).exists():
            print(f"creating {venv}")
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=300)
        print(f"installing {requirement}")
        subprocess.run([str(_venv_python(venv)), "-m", "pip", "install", "--quiet", "--upgrade", "pip"],
                       check=True, timeout=600)
        subprocess.run([str(_venv_python(venv)), "-m", "pip", "install", "--quiet", requirement],
                       check=True, timeout=1200)
    print("done. Gitleaks must be installed separately -- see this script's docstring.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
