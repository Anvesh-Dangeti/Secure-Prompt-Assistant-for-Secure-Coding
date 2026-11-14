# Individual contributions — TEAM-3

Secure Prompt Assistant for Secure Coding · Secure Software Engineering · IIT Hyderabad · July–November 2026

| Member | Roll number | Area of work |
|---|---|---|
| Anvesh Dangeti | EM26MTECH14009 | Architecture, prompt and verification layers |
| Dhananjay Kumar | CS26MTECH13007 | Research, security testing and hardening |
| Muday Saiprakash Nayak | EM26MTECH11001 | Test applications, web interface and evaluation |

Each member's work is described in the same form: research and design, build,
evaluation, and delivery.

## Anvesh Dangeti — architecture, prompt and verification layers

- **Research & design.** Reviewed the original proposal against existing tools
  (GitHub Copilot Autofix already closes the scan, fix and rescan loop) and
  shaped the final scope. Designed the architecture and the threat model.
- **Build.** Built the scanner and repository-intake layers with finding
  tracking, the prompt layer with the prompt checker and its fix-its, and the
  verification engine for developer and lab mode.
- **Evaluation.** Built the shorter prompt sizes measured in the token ladder,
  and fixed the library-version flaw that the pilot exposed.
- **Delivery.** Extracted the prompt checker as the open `secure-prompt-lint`
  library; maintains the repository; prepared review decks, demonstrations and
  reports.

## Dhananjay Kumar — research, security testing and hardening

- **Research & design.** Wrote the literature review of the three assigned
  papers and the two professor-supplied sources (Backslash Security,
  SecCoderX), with the measured figures behind the scope decisions and the
  research gaps.
- **Build.** Surveyed existing tools and built the comparison that sets the
  project apart; grounded each way of asking in the papers' definitions.
- **Evaluation.** Wrote the attack test cases for repository intake: unsafe and
  internal-network links (SSRF) and malicious ZIP archives.
- **Delivery.** Led the security hardening of our own tool: the self-scan, the
  dependency audit ending at zero known vulnerabilities, the threat-model
  review and the retirement of the old dashboard.

## Muday Saiprakash Nayak — test applications, web interface and evaluation

- **Research & design.** Designed the deliberately vulnerable test
  application, with one planted weakness per bug type in scope, and its
  symbol-based answer key.
- **Build.** Built the dashboard and its rebuild as the web interface, and the
  behaviour test suite that lab mode runs.
- **Evaluation.** Ran the checker experiment, the strategy pilot, the
  token-ladder runs and the related-function evidence; validated the pipeline
  on a public vulnerable application.
- **Delivery.** Maintains the recorded results that the tests assert, and ran
  the dress rehearsals that reproduce every presented number.

## Shared work and declaration

All three members took part in design discussions, review preparation and
question rehearsal.

We confirm that this is an accurate account of the contributions, agreed by all
members of TEAM-3.
