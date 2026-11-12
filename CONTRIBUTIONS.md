# Individual contributions — TEAM-3

Secure Prompt Assistant for Secure Coding · Secure Software Engineering · IIT Hyderabad · July–November 2026

| Member | Roll number | Role | Share |
|---|---|---|---|
| Anvesh Dangeti | EM26MTECH14009 | Team lead and lead developer | 60% |
| Dhananjay Kumar | CS26MTECH13007 | Research, security testing and hardening | 20% |
| Muday Saiprakash Nayak | EM26MTECH11001 | Fixtures, interface and evaluation | 20% |

The split and the phase ownership below are the ones stated in our Review 3
submission (11 October 2026), carried through to the end of the project.

## Phase ownership

| Phase | Lead | Support |
|---|---|---|
| 0 · Scope, literature, landscape | Anvesh Dangeti | Dhananjay Kumar — literature review, tool landscape |
| 1–4 · Foundation, scanners, repository intake, lifecycle | Anvesh Dangeti | Dhananjay Kumar — malicious-input tests; Muday Saiprakash Nayak — fixture and ground truth |
| 5 · AI layer (context, strategies, linter) | Anvesh Dangeti | Dhananjay Kumar — strategy templates S0–S8 grounded in the papers |
| 6 · Verification (checks 1, 2, 3a, 3b) | Anvesh Dangeti | Muday Saiprakash Nayak — behaviour test suite for check 3b |
| 7 / 7b · Dashboard and web interface | Muday Saiprakash Nayak | Anvesh Dangeti — integration with the services |
| 8 · Evaluation (E1, E2 pilot, E5) | Muday Saiprakash Nayak | Dhananjay Kumar — metrics and analysis |
| 9 · Hardening | Dhananjay Kumar | Anvesh Dangeti — fixes |
| 10 · Final integration, lint library, documentation | Anvesh Dangeti | all members |

## Anvesh Dangeti — team lead and lead developer (60%)

- Led the critical review of the original proposal. Found that GitHub Copilot
  Autofix already ships the closed loop, and repositioned the contribution
  around measured prompting strategies, triple-check verification and
  cross-commit tracking. Set the final scope: Python, 10 CWEs, four scanners,
  strategies S0–S8, the verification checks.
- Designed the architecture and the threat model.
- Implemented the foundation, the scanner layer, normalisation and mapping,
  fingerprinting, hardened repository intake, and the lifecycle state machine.
- Built the AI layer: context extraction, guidance, explainer, strategies and
  the prompt security linter with fix-its. Then the verification engine for
  developer and lab mode.
- In the final phase:
  - built the token ladder (S7a, S7m) that answers how low token usage can go;
  - fixed the dependency-version defect found by the pilot (finding 23);
  - extracted the linter as the stand-alone `secure-prompt-lint` library and
    published it for others to continue the research.
- Maintains the GitHub repository. Prepared and presented the review decks and
  demonstrations, and wrote the project reports.

## Dhananjay Kumar — research, security testing and hardening (20%)

- Wrote the literature review of the three assigned papers and the two
  professor-supplied sources (Backslash Security, SecCoderX). Extracted the
  measured figures behind the scope decisions and the research gaps G1–G5.
- Surveyed existing tools and built the capability matrix that differentiates
  the project.
- Wrote malicious-input test cases for repository intake: unsafe and
  internal-network URLs, and malicious ZIP archives.
- Grounded the strategy templates S0–S8 in the papers' definitions.
- Led the security hardening of our own application (Phase 9):
  - the self-scan of `app/`, `dashboard/` and the library;
  - the dependency audit, ending at 0 known vulnerabilities;
  - the review of the retirement of the old dashboard and of the threat model.

## Muday Saiprakash Nayak — fixtures, interface and evaluation (20%)

- Built the deliberately vulnerable Flask fixture, with one seeded weakness per
  scoped CWE, and its symbol-based ground truth. Wrote the behaviour test suite
  that check 3b runs.
- Validated the pipeline on a third-party vulnerable application (vulpy).
  Maintains the recorded-results set that the integration tests assert.
- Led the dashboard and its rebuild as the FastAPI + htmx web interface.
- Led the evaluation:
  - the linter's mutation experiment (E1);
  - the strategy pilot (E2);
  - the token-ladder runs (E5);
  - the related-function evidence.
- Ran the dress rehearsals that reproduce every presented number.

## Shared work

All three members took part in design discussions, review preparation and
question rehearsal.

We confirm that this is an accurate account of the contributions, agreed by all
members of TEAM-3.
