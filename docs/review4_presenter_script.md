# Review 4 — presenter script

Saturday 24 October 2026 · 15 minutes · 15 presented slides + demo · appendix 17–18 only if asked.

Every expected result below was measured in a rehearsal run on 21 October with the pinned toolchain
(Semgrep 1.180.0, Bandit 1.9.4, Gitleaks 8.30.1, pip-audit 2.10.1).

## Setup

One PowerShell window at the repository root, kept open for the whole review:

```powershell
cd Secure-Prompt-Assistant-for-Secure-Coding
.venv\Scripts\activate
```

## Before the panel arrives (5 minutes)

**A. Scanner check**

```powershell
python -m app.cli scanners
```

* *Why:* every verdict rests on four independent tools at pinned versions. If one is missing, gates 1 and 2
  report UNVERIFIED rather than a verdict, so check before relying on them.
* *Expected (~7 s):* four rows, all `yes` — semgrep 1.180.0, bandit 1.9.4, gitleaks 8.30.1, pip-audit 2.10.1.

**B. Warm-up run**

```powershell
python scripts\demo_verify.py
```

* *Why:* the first run after a restart is slower (Semgrep loads its ruleset, pip-audit fills its cache).
  It also recreates `data\demo_verify.db`, which the dashboard demo (step 4) reads.
* *Expected (~53 s):* exactly the summary table in demo step 3.

**C. A scratch workspace for the developer loop**

```powershell
$demo = "$env:TEMP\spa-demo"
Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue
New-Item -ItemType Directory $demo | Out-Null
Copy-Item -Recurse fixtures\flask_vuln_app "$demo\myapp"
$env:SPA_DATABASE_URL = "sqlite:///" + "$demo\demo.db".Replace('\','/')
```

* *Why:* the loop edits code, so it runs on a copy of the fixture outside the repository, with its own database,
  and finding IDs start fresh (B602 in `ping_host` is #5).

Notes:

* pip-audit queries the PyPI advisory service, so the demo needs internet. If the network is down, the scan
  reports pip-audit as ERROR and verification answers UNVERIFIED rather than VERIFIED — which is itself the
  fail-safe. Say so rather than apologising.
* Close PowerPoint before rebuilding the deck (`python scripts\build_review4_deck.py`): it holds an
  exclusive lock on the file.

## Timing

| Slides | Time | Point to land |
|---|---|---|
| 1–2 | 1:00 | Everything promised at Review 3 is done, plus the dashboard |
| 3 | 1:30 | The two questions: no plugin, assistant-agnostic; tiered plan, ahead of schedule |
| **4 + demo** | 3:00 | Run the developer loop (step 2): prompt → shortened → lint FAIL → `--fix` → verify |
| 5–7 | 2:00 | Nine strategies, one envelope; the linter lints *the developer's* prompt; code is data |
| 8–10 | 3:00 | Four gates; the eight-commit table; **v2: the scanners went quiet, the fix was rejected** |
| 11 | 1:00 | `sqli_wrong_behaviour` — only the behaviour tests catch it |
| 12–13 | 1:30 | The dashboard and its security; rebuilt as a web interface for Review 5 |
| 14–15 | 2:00 | Defects found by testing; plan; hand the floor back with the two questions |

If short on time, cut slides 5, 7, 11 and 14 — never 3, 4, 9 or 10. In the demo, steps 2 and 3 are the core;
4 and 5 are optional.

## Progress — what a strict panel will ask

**Opening line (slide 2):** "At Review 3 we committed to Phases 5 and 6 for today. Both are done, and the
dashboard, which was scheduled for Review 5, is done too. All twelve original requirements now have working
code; what is left is the measured evaluation, hardening and documentation."

### The 12 original requirements

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | Scan source code with open-source scanners | ✅ Semgrep, Bandit, Gitleaks, pip-audit | Phase 2 |
| 2 | Identify vulnerabilities and weaknesses | ✅ 10/10 seeded weaknesses detected | Phase 2 |
| 3 | Map to OWASP Top 10, CWE, CVE | ✅ CVE only where pip-audit reports a known vulnerable package | Phase 2 |
| 4 | Generate a remediation prompt per finding | ✅ strategies S0–S8; S7 linted and fail-closed | Phase 5 |
| 5 | Provide the prompt to Copilot or another assistant | ✅ developer mode: copy into any assistant, no plugin | Phase 5 |
| 6 | Implement the secure-code change | ✅ the developer's assistant (developer mode); the model's fix in a scratch copy (lab mode) | Phase 6 |
| 7 | Re-run the security scanner | ✅ `verify` rescans with the same pinned scanners | Phase 6 |
| 8 | Verify the original vulnerability was resolved | ✅ gate 1, over every finding of the weakness | Phase 6 |
| 9 | Verify no new issues were introduced | ✅ gate 2, commit-wide | Phase 6 |
| 10 | Verification mechanism and dashboard | ✅ gates 1–3b, remediation history, five-page dashboard | Phases 6–7 |
| 11 | Test on OWASP Top 10 cases and vulnerable web apps | ✅ fixture (10 CWEs, 7 OWASP categories) + vulpy; measured evaluation next | Phase 8 |
| 12 | Maintain on GitHub with regular check-ins | ✅ private repository, per-phase commits | ongoing |

### Our written answer to the Review 3 usage-mode question

> The tool is assistant-agnostic and needs no plugin. A developer scans their checkout, takes the remediation
> prompt our tool generates and lints, pastes it into the coding assistant they already use — Copilot,
> Cursor or Codex — commits the change, and asks our tool to verify. Verification rescans with the same
> scanners and runs the gates; the assistant's own opinion of its fix plays no part. Our tool calls no model
> in this mode and spends no tokens. A local open model is used only in lab mode, to compare prompting
> strategies under controlled conditions. An editor extension is possible later but is not needed for any
> requirement.

### Prepared answers

* **"Did you follow AI suggestions blindly?"** — "Every decision is traced to a paper or to a measurement on
  our own runs, and we reversed two when the evidence changed: Bandit was dropped at Review 0 and restored when
  Paper 3 used it as its primary detector; patch-based apply was dropped because small models produce diffs
  that do not apply. AI coding assistants are development aids for us, under team review — the same position
  our tool takes towards them."
* **"Is your 7B model good enough?"** — "It does not need to be. In developer mode it is not used at all. In
  lab mode we compare strategies on the same model, so the comparison stays fair even if every absolute number
  is low."
* **"Where are the live model results?"** — "Phase 8, starting 25 October. Today's lab results are recorded
  answers replayed through the real pipeline, so the gates are shown deterministically."

## The demo, step by step

### 1 · Scan (slide 4)

```powershell
python -m app.cli scan-zip "$demo\myapp" --project myapp
python -m app.cli findings --project myapp
```

* *Why:* the developer's starting point — a full scan with four tools, every finding tracked by identity.
* *Expected (~10 s):* `scan #1 project=myapp status=COMPLETED`, all four scanners `OK`, `findings: 24`,
  `lifecycle: NEW=24`. The findings list shows `5  NEW  bandit  CWE-78  app.py:48  B602`.

### 2 · Prompt, shorten, lint, fix, verify (slides 4–6)

```powershell
python -m app.cli prompt 5 --source "$demo\myapp" --out "$demo\prompt.txt"
```

* *Expected (<1 s):* `lint: PASS  constituents 100%  ~365 tokens  (bound to finding)`, A1–A5 `ok`.
  `prompt.txt` holds three messages (S7 is answer → critique → final).
* *Say:* "No model was called — the explanation comes from a template, so this cost nothing."

Now shorten it the way developers do:

````powershell
@'
Fix the command injection in ping_host in app.py.

```python
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output
```
'@ | Set-Content -Encoding utf8 "$demo\short.txt"
python -m app.cli lint-prompt "$demo\short.txt" --finding 5 --source "$demo\myapp"
python -m app.cli lint-prompt "$demo\short.txt" --finding 5 --source "$demo\myapp" --fix
````

* *Expected:* the first run prints `lint: FAIL  constituents 20%  ~57 tokens`, A1–A4 `MISSING`, A5 `ok`; each
  error carries its fix-it; warnings say the edit removed A1–A4 and shortened the instructions to 18% of the
  generated prompt; exit code 1. With `--fix`, the repaired prompt is printed — the four sentences restored,
  the pasted code wrapped in `untrusted_code` markers with a random id — followed by
  `lint: PASS  constituents 100%  ~261 tokens`.
* *Say:* "This is the part no other tool does: it checks the developer's text, not just ours."

The assistant's fix — apply it by hand in `$demo\myapp\app.py`, in `ping_host` (line 48):

```python
    output = subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, check=False)
    return output.stdout
```

```powershell
python -m app.cli verify 5 --source "$demo\myapp"
```

* *Expected (~10 s):* `weakness: 4 finding(s)` (Bandit B602 and three Semgrep rules); gate 1 `PASS 4/4 finding(s)
  of CWE-78 gone from ping_host`; gate 2 `PASS` with two LOW warnings (Bandit B603, B607); gate 3a `PASS`;
  gate 3b `n/a  developer mode never executes repository code`; `verdict: VERIFIED_RESOLVED`.

### 3 · Eight commits, every verdict (slides 9–10)

```powershell
python scripts\demo_verify.py
```

* *Why:* each verdict and each gate, on the real scanners; the same scenario is an integration test.
* *Expected (~53 s):* a full gate report per commit, then:

```
v2-stub-ping               #5   FIX_REJECTED       gate 3a (function preserved (static)): `ping_host` (app.py): body reduced to a stub ...
v3-fix-ping                #5   VERIFIED_RESOLVED
v4-churn-sql               #21  FIX_REJECTED       gate 1 (target resolved): the same weakness is reported again in `get_user` ...
v5-fix-sql-new-route       #28  FIX_REJECTED       gate 2 (no new findings): 4 new finding(s) at HIGH or above
v6-remove-route            #28  VERIFIED_RESOLVED
v7-token-gitleaks-down     #2   UNVERIFIED         gate 1 (target resolved): 1 finding(s) absent, but their scanner could not verify ...
v8-gitleaks-back           #2   VERIFIED_RESOLVED
```

* *Say at v2:* "Every scanner went quiet — the lifecycle calls this RESOLVED. Verification calls it
  FIX_REJECTED, because the function was emptied."

## Optional, if there is time

### 4 · The dashboard (slides 10, 12–13)

```powershell
$env:SPA_DATABASE_URL = "sqlite:///" + (Resolve-Path data\demo_verify.db).Path.Replace('\','/')
python -m streamlit run dashboard/streamlit_app.py
```

* *Expected:* `http://127.0.0.1:8501` opens a sign-in form; the key is `SPA_API_KEY` from `.env`. Overview shows
  HIGH 5, MEDIUM 7, LOW 5 and the verdict counts; Verification → finding `#5 HIGH B602 app.py:48` shows the v3
  card (VERIFIED_RESOLVED) above the v2 card (FIX_REJECTED, gate 3a FAIL).
* If it says `Port 8501 is not available`, a dashboard is already running — use that tab or close it.
* Stop with Ctrl+C. Run `demo_verify.py` first (step B) so the database exists.

### 5 · Lab mode: the fix only the behaviour tests catch (slide 11)

```powershell
$env:SPA_DATABASE_URL = "sqlite:///" + "$demo\lab.db".Replace('\','/')
python -m app.cli scan-zip fixtures\flask_vuln_app --project lab-fixture
python -m app.cli lab-verify 21 --source fixtures\flask_vuln_app --replay evaluation\replays\sqli_wrong_behaviour.json
```

* *Why:* a recorded model answer is spliced into a scratch copy, both copies are rescanned, and gates 1, 2, 3a
  and then 3b run. The fixture is never modified.
* *Expected (~17 s after the scan):* `weakness: 3 finding(s)`; gates 1, 2, 3a `PASS`; gate 3b
  `FAIL  1 failed, 9 passed` (`test_get_user_returns_the_row`); `verdict: FIX_REJECTED -- gate 3b`.
  On a fresh database B608 is #21 — confirm it in `findings --project lab-fixture`.

### 6 · The test suite

```powershell
python -m pytest -q
```

* *Expected (~4 min):* `637 passed, 2 skipped` (the 2 are symlink tests that need privileges on Windows).
  `python -m pytest -q -m "not scanners"` is the fast subset.

## Likely questions (answers are on slides 17–18)

* **"Why not let the model judge its own fix?"** — v2 (slide 10).
* **"Isn't this Copilot Autofix?"** — we said so at Review 1; ours is open and measures strategies, lints the
  developer's own prompt, and checks function preservation.
* **"Who pays for tokens?"** — nobody, in developer mode; S7's first message is 255–373 tokens for the
  developer's assistant.
* **"Can gate 3a be fooled?"** — yes, by a behaviour change; that is why lab mode has 3b (slide 11).
* **"Why rebuild the dashboard?"** — slide 13 notes.

## If something fails live

| Symptom | Say / do |
|---|---|
| a scanner shows `NOT_INSTALLED` | `python -m app.cli scanners`; the Gitleaks path is `SPA_GITLEAKS_BIN` in `.env` |
| pip-audit `ERROR` | network; point out that the verdict became UNVERIFIED, not VERIFIED (fail-safe) |
| `verify` says the finding is unknown | the database variable points elsewhere; rerun step C |
| the dashboard shows no project | run `scripts\demo_verify.py` and set `SPA_DATABASE_URL` as in step 4 |
| a red `NativeCommandError` block | the command had `2>&1` appended; rerun it without |
