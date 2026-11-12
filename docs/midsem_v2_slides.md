# Mid-semester review — plain-language deck (slide content)

Friday 30 October 2026 · 15 minutes · deck: `../Secure_Prompt_Assistant_MidSem_Review_v2.pptx` (built by
`scripts/build_midsem_v2_deck.py`, checked by `tests/unit/test_midsem_v2_deck.py`). The same seven sections as
`docs/midsem_slides.md`, rewritten so each slide explains itself: the headline states the takeaway, internal codes
(strategy ids, lint-rule ids, gates 3a/3b, scanner rule ids) stay off the presented slides, and the remaining terms
are defined in the glossary. Result numbers come from `evaluation/recorded_results.py`; the prompt example and its
lint scores are computed by the real prompt builder and linter for the `ping_host` finding. No presenter labels;
short speaker notes on every slide.

---

1. **Title** — *We find security bugs, help the developer ask their AI assistant for a safe fix, and then check the
   fix ourselves.* Names and roll numbers.
2. **1 · Problem — AI writes the security fix. Nobody checks it.** 40.95% of AI-written Python had a flaw (Paper 2) ·
   1/10 secure answers from GPT-4o with a plain request, 10/10 for the best model with security instructions
   (Backslash) · 14–54% of safe, working code lost by earlier "secure" methods (SecCoderX). Three questions: which
   way of asking gives a safe fix; did the fix really work (decided by scanners, not the AI); does the bug come back.
3. **2 · State of the art — Existing tools each do part of the job.** Five plain rows × six tools (✓ / ~ / ×); Copilot
   Autofix already does scan → fix → re-scan, and we do not claim that loop.
4. **2 · State of the art — What research found, and what we built from it.** Papers 1–3, Backslash, SecCoderX, one
   row each. Gap: research tests prompts on new code; tools fix real projects without testing the prompt.
5. **3 · Architecture — How it works: the scanners decide, never the AI.** Connect → scan → label → write prompt →
   check prompt → verify fix; developer mode (the product, no AI model of ours) and lab mode (experiments); after the
   fix: verified / rejected / unverified.
6. **3 · Architecture — What the developer gets: a complete fix request.** The real prompt for `ping_host`, part by
   part (what & where, why, how to fix, only if, change nothing else, code is data, the code). Built from templates
   and code analysis, not by an AI.
7. **4 · Threat model — Our tool reads untrusted code, so it guards itself.** Seven ways in: repository link (SSRF),
   ZIP upload, running the scanners, code sent to the AI (prompt injection), the AI's answer, testing a fix (lab
   only), the web interface; each with its control and its own attack tests.
8. **5 · What is new — Four things our tool does that others don't.** Tests which prompt works · checks the
   developer's prompt · doesn't take the AI's word · remembers every bug. Works with any assistant; free and local.
   What we do not claim.
9. **5 · Proof 1 — A fake fix fooled the scanners, not our checks.** Emptied function: checks 1 + 2 pass, check 3
   fails → REJECTED; real fix → VERIFIED. 7 scripted test commits: 3 verified, 3 rejected (one by each check), 1
   unverified.
10. **5 · Proof 2 — Shorten the prompt, and the checker notices.** Full prompt PASS 100% → one-liner FAIL 20% →
    suggested fixes PASS 100%. Checker test: 168/168 cuts caught, 0/96 false alarms, 149/149 repaired; honest gap
    16 of 24.
11. **6 · Demo — one developer's Friday release.** The recorded video (core cut, ~4½ min): scan, prompt, shorten,
    fake fix rejected, real fix verified, history.
12. **6 · Results so far — The way you ask the AI changes the result.** Bar chart of fixes passing all checks per way
    of asking (pilot, 90 fixes, one local 7B model); 10/10 planted bugs found; bug-specific advice best (9/10), ours
    7/10 at 5.5× the tokens; "review and improve" worst; 7 fixes fooled every scanner.
13. **7 · Next two weeks — from a working system to evidence.** Experiments (31 Oct–3 Nov) · security review of our
    own tool (4–7 Nov) · final testing and documents (8–11 Nov) · final review (~13 Nov) · submission (18 Nov).
14. **Thank you.**
15–19. **Appendix** — glossary · pilot results in full · questions we expect · demo backup (overview and checker
    screenshots; the verification page and all seven test commits).
