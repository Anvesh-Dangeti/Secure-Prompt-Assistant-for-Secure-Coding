"""The web interface: FastAPI + server-rendered Jinja2 + htmx (Phase 7b, replacing the Streamlit pages).

    python -m dashboard.web            # http://127.0.0.1:8080, loopback only

The same capabilities as the CLI's developer mode -- scan a local checkout, read
findings, build and lint a prompt, rescan and verify -- over the same read
models (``dashboard/data.py``) and validated actions (``dashboard/actions.py``).
No model runs here and no scanned code is executed; lab mode stays a CLI
instrument. The security envelope is described in ``security.py``.
"""
