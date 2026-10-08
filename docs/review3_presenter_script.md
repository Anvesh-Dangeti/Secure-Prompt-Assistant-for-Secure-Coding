# Review 3 — presenter script

Saturday 10 October 2026 · 15 minutes · 12 presented slides + demo · appendix 14–15 only if asked.

## Before the panel arrives (5 minutes)

```powershell
cd Secure-Prompt-Assistant-for-Secure-Coding
.venv\Scripts\activate
python -m app.cli scanners                 # all four must say "yes"
python scripts\demo_lifecycle.py           # run once to warm caches (~35 s)
```

* pip-audit queries the PyPI advisory service, so the demo needs internet. If the network is down,
  the scan reports pip-audit as ERROR and the lifecycle *refuses* to resolve its findings — which is
  itself a good demonstration of the fail-safe. Say so rather than apologising.
* Close PowerPoint before rebuilding the deck (`python scripts\build_review3_deck.py`): it holds an
  exclusive lock on the file.

## Timing

| Slides | Time | Point to land |
|---|---|---|
| 1–2 | 1:30 | Everything promised at Review 2 is done, plus Phase 4 |
| 3–4 | 1:30 | Four scanners, each run so the scanned code cannot switch it off |
| 5–6 | 2:30 | 10/10 detection; identity survives everything that is not a fix |
| **7 + demo** | 3:30 | Run `python scripts\demo_lifecycle.py`; walk v2, v3, v5 |
| 8 | 1:30 | Absence is not evidence — UNVERIFIED |
| 9–10 | 2:30 | The tool's own security; defects found by testing |
| 11–12 | 1:30 | Real repo + self-scan; plan; hand the floor back with the two questions |

If short on time, cut slides 3 and 11 — never 5, 7, 8.

## The demo, step by step

1. `python scripts\demo_lifecycle.py`
2. While it runs: "Each step is a complete code state, zipped and uploaded through the same validated
   path a user's upload takes."
3. **v2** — "The SQL fix resolves three findings. Same commit adds an `os.system` route: four NEW
   findings. A tool that only asks *is the old finding gone?* calls this commit a success."
4. **v3** — "Every line moved, spacing changed, `# nosec` and `# nosemgrep` added. Zero transitions.
   Silencing is not fixing."
5. **v4** — "The revert is recognised at its new line numbers — REGRESSION, not NEW."
6. **v5** — "Gitleaks is down. Bandit's view of the secret resolves. Gitleaks' view is kept open and
   flagged UNVERIFIED — we never resolve what we could not see." **v6** — "Gitleaks confirms it."

Optional, if there is time:

```powershell
python -m app.cli scan-url https://github.com/fportantier/vulpy --project vulpy
python -m app.cli scan-url https://169.254.169.254/latest/meta-data --project x     # refused
python -m app.cli scan-url file:///etc/passwd --project x                           # refused
```

API view: `python -m uvicorn app.main:app --host 127.0.0.1` then open `http://127.0.0.1:8000/docs`
(needs `SPA_API_KEY` in `.env`; the Authorize button takes it as `X-API-Key`).

## Likely questions (answers are on slides 14–15)

* **"Is scanner silence easy to game?"** — suppression comments ignored, in-repo scanner config removed,
  unexaminable scope cannot resolve; Gate 3 at Review 4 adds "the code still works".
* **"Why four scanners?"** — measured blind spots on our fixture (slide 5 notes).
* **"What is precision 22/24?"** — the 2 Bandit import advisories; suppressed with a reason, never deleted.
* **"What did you learn?"** — slide 10. Tell the `taskkill` story: our own fix introduced a new finding.

## If something fails live

| Symptom | Say / do |
|---|---|
| a scanner shows `NOT_INSTALLED` | `python -m app.cli scanners`; Gitleaks path is `SPA_GITLEAKS_BIN` in `.env` |
| pip-audit `ERROR` | network; point out that its findings stayed open (fail-safe) |
| clone fails | network or GitHub; fall back to the ZIP demo, which is offline apart from pip-audit |
