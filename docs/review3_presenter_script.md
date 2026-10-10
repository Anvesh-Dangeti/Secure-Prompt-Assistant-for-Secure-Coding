# Review 3 — presenter script

Saturday 10 October 2026 · 15 minutes · 12 presented slides + demo · appendix 14–15 only if asked.

Every expected result below was measured in the dress rehearsal on the morning of the review, with the
pinned toolchain (Semgrep 1.180.0, Bandit 1.9.4, Gitleaks 8.30.1, pip-audit 2.10.1).

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

* *Why:* every claim we make rests on four independent tools, each installed in its own isolated
  environment at a pinned version. If one is missing, the results change, so we check before relying on them.
* *Expected (~11 s):* four rows, all `yes` — semgrep 1.180.0, bandit 1.9.4, gitleaks 8.30.1,
  pip-audit 2.10.1.

**B. Warm-up run**

```powershell
python scripts\demo_lifecycle.py
```

* *Why:* the first run after a restart is slower (Semgrep loads its ruleset, pip-audit fills its cache).
  Running it once now keeps the live demo inside its time slot.
* *Expected (~35 s):* exactly the output described in demo step 2.

Notes:

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

If short on time, cut slides 3 and 11 — never 5, 7, 8. In the demo, steps 1–3 are the core; 4–8 are
optional.

## Progress — what a strict panel will ask

The panel asked for reasonable progress over three weeks. Lead with what was promised against what was
delivered, then be exact about what is not built yet.

**Opening line (slide 2):** "At Review 2 we committed to Phases 1–3. All three are done, plus Phase 4, which
we had not promised. Of the 12 original project requirements, 5 are met, 4 are partly met, and the
remaining 3 are the AI layer, scheduled for Review 4."

### The 12 original requirements

| # | Requirement | Status | Where it closes |
|---|---|---|---|
| 1 | Scan source code with open-source scanners | ✅ done — Semgrep, Bandit, Gitleaks, pip-audit | Phase 2 |
| 2 | Identify vulnerabilities and weaknesses | ✅ done — 10/10 seeded weaknesses detected | Phase 2 |
| 3 | Map to OWASP Top 10, CWE, CVE | ✅ done — CVE only where pip-audit reports a known vulnerable package | Phase 2 |
| 4 | Generate a remediation prompt per finding | ⬜ next — strategies S0–S8 + prompt linter | Phase 5 · Review 4 |
| 5 | Provide the prompt to Copilot or another assistant | ⬜ next — manual mode | Phase 5 · Review 4 |
| 6 | Implement the secure-code change | ⬜ next — sandboxed apply in a throwaway worktree | Phase 6 · Review 4 |
| 7 | Re-run the security scanner | ✅ done — every rescan of a project is a full scan | Phases 3–4 |
| 8 | Verify the original vulnerability was resolved | ◐ partly — RESOLVED by fingerprint absence, never by a scan that could not see it; formal Gate 1 next | Phase 6 · Review 4 |
| 9 | Verify no new issues were introduced | ◐ partly — NEW findings reported per rescan (demo v2); formal Gate 2 next | Phase 6 · Review 4 |
| 10 | Verification mechanism and dashboard | ◐ partly — lifecycle + API today; dashboard next | Phase 7 · Review 5 |
| 11 | Test on OWASP Top 10 cases and vulnerable web apps | ✅ done — own fixture (10 CWEs, 7 OWASP categories) + vulpy | Phase 2–3; full evaluation Phase 8 |
| 12 | Maintain on GitHub with regular check-ins | ◐ partly — private repo, per-phase commits | ongoing |

### Prepared answers

* **"Where is the prompt assistant?"** — "We built the judge before the contestant. The LLM never decides
  whether a fix worked, so the independent verification had to exist first; without it there is no way
  to compare prompting strategies. Every finding record already carries what a prompt needs — CWE, OWASP,
  severity, path, line, a redacted snippet and a stable fingerprint. Phase 5 consumes it at Review 4:
  strategies S0–S8, the prompt linter, untrusted-code delimiting and a local model."
* **"Isn't this just a scanner wrapper?"** — "The scanners produce the evidence. What we built is
  everything around it: one finding shape across four tools, CWE corrections where a tool mis-tags
  (CWE-704 → 89, 489 → 94, 259 → 798), an identity that survives refactoring and `# nosec`, the
  REGRESSION and UNVERIFIED states, and stopping the scanned code from silencing its own scanners. No
  scanner tracks a finding across commits. Testing found six defects that reading would not have."
* **"Why is there no UI?"** — "The dashboard is Phase 7, at Review 5. The API already exposes everything
  it will show" — then show `/docs` (demo step 7).
* **"Your commits are all from 8 October."** — "The repository was created on 8 October. Each phase was
  committed as it was completed and tested, with the Review 2 material as the first commit. From Phase 5,
  commits are continuous and each member commits under their own account."
* **"What will Review 4 show?"** — "One finding taken end to end: generated prompt with a chosen strategy →
  linted → fix applied in a throwaway worktree → rescan → three gates → `VERIFIED_RESOLVED` or
  `FIX_REJECTED` with the reason recorded."

## The demo, step by step

### 1 · Detection against ground truth (slides 5–6)

```powershell
python -m app.cli scan-dir fixtures\flask_vuln_app --ground-truth
```

* *Why:* this backs the detection and classification claims with a measurement, not a screenshot.
  The fixture has ten seeded weaknesses listed in `ground_truth.yaml`, and the run scores the scanners against
  that list. It is also the measured case for using four scanners: five of the ten weaknesses are caught
  by only one tool (XSS and path traversal only by Semgrep; weak randomness and unsafe deserialisation
  only by Bandit; the vulnerable dependency only by pip-audit).
* *Expected (~9 s):*
  * scanner table: all four `OK` — semgrep 12, bandit 9, gitleaks 1, pip-audit 2 findings;
  * findings table: 24 rows, each with CWE, OWASP category, severity and fingerprint;
  * ground-truth table: GT-01 … GT-10 all `DETECTED`;
  * `recall (any tool) : 10/10 = 100%`, `precision (in-scope) : 22/24 = 92%`,
    `semgrep+bandit agree : 4/4`.
* *Say:* "`CWE-89<-704` is our mapping layer correcting Semgrep, which tags this SQL injection as a type
  conversion error. The two false positives are Bandit import advisories, and step 4 shows what we do with them."

### 2 · Six commits, every lifecycle state (slides 7–8)

```powershell
python scripts\demo_lifecycle.py
```

* *Why:* this is our contribution: tracking a finding's identity across commits. Each version is a
  complete code state, zipped and uploaded through the same validated path a user's upload takes, and
  each tests one property. The same scenario runs as an integration test, so the demo cannot silently break.
* While it runs, say: "Each step is a complete code state, zipped and uploaded through the same validated
  path a user's upload takes."

| Version | Expected output | Why this step / what to say |
|---|---|---|
| **v1-baseline** | `findings=24`, `NEW=24`; #7 B404 and #24 B403 → `SUPPRESSED (human: false positive)` | Baseline. "The two import advisories are marked false positives with a reason. They are kept, not deleted." |
| **v2-fix-sqli** | `NEW=4 STILL_OPEN=19 RESOLVED=3`; three CWE-89 findings `RESOLVED`; four CWE-78 findings `NEW` at app.py:84–85 | Differential check. "The SQL fix resolves three findings. The same commit adds an `os.system` route, which creates four new ones. A tool that only asks *is the old finding gone?* calls this commit a success." |
| **v3-refactor** | `NEW=0 STILL_OPEN=23 RESOLVED=0`, no transition lines | Identity is fingerprint-based, not line-based. "Every line moved, spacing changed, `# nosec` and `# nosemgrep` added. Zero transitions. Silencing is not fixing." |
| **v4-revert** | `REGRESSION=3`; #18, #21, #22 `RESOLVED -> REGRESSION` at app.py:43/46 | Regression detection. "The revert is recognised at its new line numbers — REGRESSION, not NEW." |
| **v5-secret-gitleaks-down** | `status=PARTIAL`, `gitleaks=NOT_INSTALLED`; bandit #2 `RESOLVED`; gitleaks #23 `(absent, but scanner could not verify -> kept open)`; `UNVERIFIED=1` | Fail-safe (slide 8). "Gitleaks is down. Bandit's view of the secret resolves. Gitleaks' view is kept open and flagged UNVERIFIED — we never resolve what we could not see." |
| **v6-gitleaks-back** | `status=COMPLETED`; gitleaks #23 `RESOLVED` | "Gitleaks confirms it. Only now does that finding close." |

### 3 · Unsafe repository URLs are refused (slide 9)

```powershell
python -m app.cli scan-url https://169.254.169.254/latest/meta-data --project x
python -m app.cli scan-url file:///etc/passwd --project x
```

* *Why:* the tool clones whatever URL a user gives it, so it is itself an attack surface (SSRF).
  `169.254.169.254` is the cloud metadata endpoint, a classic SSRF target, and `file://` would read the
  server's own files. The validator refuses both before any network or filesystem access.
* *Expected:* `REFUSED: IP-address hosts are not allowed`, then
  `REFUSED: only https:// repository URLs are allowed`. Exit code 2; nothing is cloned.
* Run the commands exactly as written. Appending `2>&1` makes Windows PowerShell wrap the refusal in a
  red `NativeCommandError` block that looks like a crash.

## Optional, if there is time

### 4 · Upload, mark a false positive, rescan

```powershell
python -m app.cli scan-zip fixtures\flask_vuln_app --project demo
python -m app.cli findings --project demo --state new
python -m app.cli suppress 7 --reason "import advisory only; subprocess use reviewed separately"
python -m app.cli scan-zip fixtures\flask_vuln_app --project demo --label rescan
python -m app.cli history --project demo
```

* *Why:* this is the persisted path a real user takes: zip-slip-safe extraction, database, history.
  It shows that a false positive is kept with a reason, carried across rescans, and excluded from NEW,
  which is the answer to "what is precision 22/24?".
* *Expected:*
  * first scan: `status=COMPLETED`, `findings: 24`, `NEW=24`, all four scanners `OK`;
  * suppress: `#7 bandit B404 -> SUPPRESSED (...)` (on a fresh database #7 is B404 at app.py:16 —
    confirm the ID in the `findings` list);
  * rescan: `STILL_OPEN=23, SUPPRESSED=1`;
  * history: two rows — `#1` with NEW 24, `#2 rescan` with STILL_OPEN 23.
* This writes to `data\spa.db`. If you rehearse this step, delete that file afterwards so the IDs
  start fresh.

### 5 · A repository we did not write (slide 11)

```powershell
python -m app.cli scan-url https://github.com/fportantier/vulpy --project vulpy
```

* *Why:* our fixture is our own code, so we also show the pipeline on a third-party, intentionally vulnerable Flask
  app, cloned through the hardened path (https only, host allowlist, no hooks, shallow).
* *Expected (~11 s, needs internet):* `source=5249cc8b…`, all four scanners `OK`, `findings: 68`,
  `NEW=68`. This is a snapshot, not an asserted number: the upstream repository can change.

### 6 · Our own code, scanned by our own tool (slide 11)

```powershell
python -m app.cli scan-dir app
```

* *Why:* we hold our own code to the standard we apply to others. It also sets up the `taskkill`
  story: our first fix for a Bandit finding introduced a new Semgrep finding, which is exactly why
  Gate 2 (no new findings) exists.
* *Expected (~8 s):* Semgrep 0, Gitleaks 0, pip-audit 0, Bandit 3 LOW in `core/subprocess_runner.py`
  (B404 + 2× B603, inherent to the subprocess wrapper). pip-audit notes "no requirements*.txt files
  found" because `app/` holds none; the application's pinned `requirements.txt` was audited on its own
  and reports 0 known vulnerabilities.

### 7 · The API

```powershell
python -m uvicorn app.main:app --host 127.0.0.1
```

* *Why:* the CLI and the HTTP API share one scan service. The Phase 7 dashboard will be built on this API.
  Authentication fails closed.
* *Expected:* open `http://127.0.0.1:8000/docs`. `GET /health` returns `"status":"ok"` with all four
  scanners available. Every other route returns 401 until **Authorize** is given `SPA_API_KEY` from
  `.env` (sent as `X-API-Key`), then 200. Stop with Ctrl+C.

### 8 · The test suite

```powershell
python -m pytest -q
```

* *Why:* the headline numbers on the slides come from `evaluation/recorded_results.py`, and the
  integration tests re-run the real scanners and assert the same values, so a slide cannot drift from the code.
* *Expected (~75 s):* `278 passed`.

## Likely questions (answers are on slides 14–15)

* **"Is scanner silence easy to game?"** — suppression comments ignored, in-repo scanner config removed,
  unexaminable scope cannot resolve; Gate 3 at Review 4 adds "the code still works".
* **"Why four scanners?"** — measured blind spots on our fixture (slide 5 notes; demo step 1).
* **"What is precision 22/24?"** — the 2 Bandit import advisories; suppressed with a reason, never deleted
  (demo step 4).
* **"What did you learn?"** — slide 10. Tell the `taskkill` story: our own fix introduced a new finding.
* **Progress questions** — "where is the AI?", "just a scanner wrapper?", "no UI?", "commit history?" —
  see *Progress — what a strict panel will ask* above.

## If something fails live

| Symptom | Say / do |
|---|---|
| a scanner shows `NOT_INSTALLED` | `python -m app.cli scanners`; Gitleaks path is `SPA_GITLEAKS_BIN` in `.env` |
| pip-audit `ERROR` | network; point out that its findings stayed open (fail-safe) |
| clone fails | network or GitHub; fall back to the ZIP demo (step 4), which is offline apart from pip-audit |
| a red `NativeCommandError` block | the command had `2>&1` appended; rerun it without |
