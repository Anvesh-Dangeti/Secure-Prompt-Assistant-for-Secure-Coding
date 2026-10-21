# Mid-semester review — presenter script

Friday 30 October 2026 · 15 minutes · 13 presented slides including the live demo · appendix 15–16 only if
needed. Deck: `../Secure_Prompt_Assistant_MidSem_Review.pptx` (`python scripts/build_midsem_deck.py`).

The panel asked for seven sections, presented as a team: problem statement, state of the art, architecture,
threat model, USPs, a demo of the existing work, and the next two weeks. Every slide names its presenter.

Every expected result below was measured in a rehearsal run with the pinned toolchain (Semgrep 1.180.0,
Bandit 1.9.4, Gitleaks 8.30.1, pip-audit 2.10.1).

## Who presents what

| Slides | Section | Presenter | Time |
|---|---|---|---|
| 1–2 | Title, 1 · Problem statement | Anvesh | 1:15 |
| 3–4 | 2 · State of the art (tools, research) | Dhananjay | 1:45 |
| 5 | 3 · Architecture | Anvesh | 1:30 |
| 6 | 4 · Threat model | Dhananjay | 1:30 |
| 7–9 | 5 · What is new, with its evidence | Anvesh | 2:00 |
| 10 | 6 · Live demo | Anvesh | 4:30 |
| 11–12 | 6 · Results so far · the team | Muday | 1:30 |
| 13 | 7 · Next two weeks, and the question for the panel | Muday | 1:00 |

Hand-offs, word for word:
- Anvesh → Dhananjay after slide 2: "Dhananjay will show what exists already."
- Dhananjay → Anvesh after slide 4: "Anvesh will show how our system is built."
- Anvesh → Dhananjay after slide 5: "And because it reads hostile code, Dhananjay has the threat model."
- Dhananjay → Anvesh after slide 6: "Anvesh, what is new."
- Anvesh → Muday after the demo: "Muday has the numbers."

If short on time, cut slide 4 and slide 9's detail, never 2, 7, 8 or the demo. In the demo, steps 3 and 5
are the core.

## Setup — before the panel arrives (10 minutes)

**Window 1** (PowerShell at the project folder):

```powershell
cd Secure-Prompt-Assistant-for-Secure-Coding
.venv\Scripts\activate
python -m app.cli scanners
```

*Expected (~7 s):* four rows, all `yes`. If a scanner is missing, the gates answer UNVERIFIED instead of a
verdict; that is the fail-safe, but check before the review.

```powershell
$demo = "$env:TEMP\spa-demo"
Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue
New-Item -ItemType Directory $demo | Out-Null
Copy-Item -Recurse fixtures\flask_vuln_app "$demo\myapp"
python -c "import shutil, sys; from pathlib import Path; from evaluation.verification_scenario import stub_ping, fix_ping; d = Path(sys.argv[1]); [shutil.copytree('fixtures/flask_vuln_app', d / n) for n in ('stub', 'fixed')]; stub_ping(d / 'stub'); fix_ping(d / 'fixed')" $demo
$env:SPA_DATABASE_URL = "sqlite:///" + "$demo\demo.db".Replace('\','/')
python -m dashboard.web
```

* `myapp` is the copy we scan and "fix". `stub` holds a fake fix: `ping_host` emptied to `pass`. `fixed` holds
  a real one: an argument list, no shell. Both are made by the same edit functions as `scripts/demo_verify.py`.
* The server prints `http://127.0.0.1:8080`. Leave this window running.
* In the browser, open `http://127.0.0.1:8080` and sign in with `SPA_API_KEY` from `.env`. The start page
  says "Scan a checkout".

**Window 2** (PowerShell), for the two file swaps during the demo:

```powershell
$demo = "$env:TEMP\spa-demo"
```

Notes:
* pip-audit queries the PyPI advisory service, so the demo needs internet. Offline, the scan reports pip-audit
  as ERROR and verification answers UNVERIFIED rather than VERIFIED — itself the fail-safe. Say so rather than
  apologise.
* Close PowerPoint before rebuilding the deck (exclusive file lock).
* Backup if the demo fails: slide 15 (screenshots) and slide 8 (the rejected fix). Never debug live.

## The demo (slide 10, about 4½ minutes)

**1. Scan** — Start page: Project name `myapp`, checkout `C:\Users\<you>\AppData\Local\Temp\spa-demo\myapp`
(the value of `$demo\myapp`), label `before`. Click **Scan**.
* *Expected (~10 s):* the Overview opens with "Scan #1 finished: COMPLETED, 24 findings." Open by severity:
  HIGH 11 · MEDIUM 9 · LOW 4. The OWASP chart and the four scanner rows are all OK.
* *Say:* "Four independent scanners. Every finding is tracked by a fingerprint, not a line number."

**2. The finding** — **Findings** tab → **#5** (bandit B602, `app.py:48`, CWE-78).
* *Say:* "Command injection in `ping_host`: `shell=True` with request data."

**3. Prompt and lint** — **Build the prompt** → strategy **S7** → **Build prompt**.
* *Expected:* a three-message prompt with **Copy prompt**; lint **PASS**, constituents 100%, ~365 tokens for the
  first message.
* Then paste into the lint box: `Fix the command injection in ping_host in app.py.` → **Lint**.
* *Expected:* **FAIL**, constituents 20%: A1, A2, A3 and A4 are MISSING, with a fix-it sentence for each.
* **Apply fix-its** → *Expected:* "Lint after fix-its" **PASS**, constituents 100%, ~148 tokens.
* *Say:* "This is what developers do — shorten the prompt — and it is exactly what removes the security
  constraints. The linter puts them back."

**4. The developer's assistant** — *Say:* "The developer pastes this into Copilot or Cursor and commits what it
returns. We call no model here and spend no tokens."

**5. A fake fix** — Window 2:

```powershell
Copy-Item "$demo\stub\app.py" "$demo\myapp\app.py" -Force
```

**Verify** tab (or **Verify a fix** on finding #5) → **Rescan & verify**.
* *Expected (~6 s):* "Scan #2 (COMPLETED) → verdict **FIX_REJECTED**". Gate 1 PASS (4/4 CWE-78 findings gone),
  gate 2 PASS, **gate 3a FAIL**: "body reduced to a stub". Gate 3b NOT_APPLICABLE.
* *Say:* "Every scanner went quiet — and the fix is rejected. A scanner-only check would accept this."

**6. A real fix** — Window 2:

```powershell
Copy-Item "$demo\fixed\app.py" "$demo\myapp\app.py" -Force
```

**Rescan & verify** → *Expected (~6 s):* "Scan #3 (COMPLETED) → verdict **VERIFIED_RESOLVED**", all gates pass.
The remediation history below it now shows both verdicts, newest first.

**7. (optional)** **Scan history**: three scans and what each changed.

## Progress — what a strict panel will ask

### The 12 original requirements

| # | Requirement | Status |
|---|---|---|
| 1 | Scan source code with open-source scanners | ✅ Semgrep, Bandit, Gitleaks, pip-audit |
| 2 | Identify vulnerabilities and weaknesses | ✅ 10/10 seeded weaknesses detected |
| 3 | Map to OWASP Top 10, CWE, CVE | ✅ CVE only where pip-audit reports a known vulnerable package |
| 4 | Generate a remediation prompt per finding | ✅ strategies S0–S8; S7 linted and fail-closed |
| 5 | Provide the prompt to Copilot or another assistant | ✅ copy into any assistant, no plugin |
| 6 | Implement the secure-code change | ✅ the developer's assistant (developer mode); a local model in a scratch copy (lab) |
| 7 | Re-run the security scanner | ✅ same pinned scanners |
| 8 | Verify the original vulnerability was resolved | ✅ gate 1, over every finding of the weakness |
| 9 | Verify no new issues were introduced | ✅ gate 2, commit-wide |
| 10 | Verification mechanism and dashboard | ✅ gates 1–3b, remediation history, web interface |
| 11 | Test on OWASP Top 10 cases and vulnerable web apps | ✅ fixture (10 CWEs, 7 OWASP categories) + vulpy; E1 and the E2 pilot measured |
| 12 | Maintain on GitHub with regular check-ins | ✅ private repository, per-phase commits |

### Prepared answers

* **"Your own strategy did not win the pilot."** — "Right, and we show it. The contribution is the testbed:
  nine strategies on the same findings under the same gates. In the pilot, CWE-specific guidance won; ours tied
  the comprehensive prompt at five times the tokens. The likely cost is the RCI turns — pure RCI did worst on
  this model — so the next run is S7 without RCI."
* **"One trial per cell is not significant."** — "Agreed, and the slide says pilot. It tells us strategies
  differ by up to four fixes in ten on the same model. The full run repeats trials and doubles the seeded
  instances."
* **"Did you change your measurement after seeing results?"** — "Yes, twice, before the measured run, and both
  are recorded with the first run kept: the model wrote `secrets` instead of `import secrets` under seven of
  nine strategies, and the behaviour tests ran without the API token a deployment would set. Both hit every
  strategy alike. E1 also found a linter gap, which is fixed in the code."
* **"Isn't this Copilot Autofix?"** — "Autofix closes the loop, and we said so at Review 1. It hides its
  prompt, uses one scanner, never checks the function still works, and does not track a finding across
  commits."
* **"Why not let the model judge its own fix?"** — "Slide 8: a fix every scanner accepted that the gates
  rejected. A model that writes a wrong fix confidently judges it confidently too."
* **"Is your 7B model good enough?"** — "In developer mode it is not used at all. In lab mode we compare
  strategies on the same model, so the comparison is fair even when the absolute numbers are low."
* **"Who did what?"** — slide 12; each member speaks to their own section.
