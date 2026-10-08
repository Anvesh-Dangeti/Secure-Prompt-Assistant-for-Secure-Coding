#!/usr/bin/env python3
"""Snapshot Semgrep's p/python ruleset to rules/vendor/ for reproducible scans.

    python scripts/fetch_semgrep_rules.py

Scanning against the live registry means the rules can change between two
scans of the same code, and a finding could "resolve" because a rule was
edited upstream rather than because the code was fixed. Scans therefore use
this local snapshot, and the SHA-256 of the file is stored with every scanner
run so results are attributable to an exact ruleset.

The snapshot is not committed (rules/vendor/ is git-ignored): the rules are
published under the Semgrep Rules License, so each installation fetches its
own copy rather than the project redistributing it.
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

import yaml

URL = "https://semgrep.dev/c/p/python"
DEST = Path(__file__).resolve().parents[1] / "rules" / "vendor" / "semgrep_p_python.yaml"
MAX_BYTES = 10 * 1024 * 1024


def main() -> int:
    request = urllib.request.Request(URL, headers={"User-Agent": "secure-prompt-assistant/ruleset-snapshot"})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 -- fixed https URL
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        print("refusing: ruleset larger than expected", file=sys.stderr)
        return 1
    data = yaml.safe_load(body)
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list) or not rules:
        print("refusing: response is not a Semgrep ruleset", file=sys.stderr)
        return 1
    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_bytes(body)
    print(f"{len(rules)} rules -> {DEST}")
    print(f"sha256 {hashlib.sha256(body).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
