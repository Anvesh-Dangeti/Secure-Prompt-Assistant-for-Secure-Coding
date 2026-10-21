"""E2 (pilot): which prompting strategy yields scanner-verified fixes -- S0..S8 on the seeded fixture, local model.

    python -m evaluation.e2_strategies --out evaluation/results/e2_pilot.json [--resume]

Each trial is one lab-mode run (``app.sandbox.lab.run_lab_trial``): the
strategy's messages go to the local model, its answer is spliced into a scratch
copy of the fixture, the copy is rescanned with all four scanners, and gates 1,
2, 3a and 3b decide. The model never judges its own fix.

The pilot is one trial per (weakness, strategy) cell at temperature 0 with a
fixed top_p and seed: enough to see whether strategies differ, not to claim
that they do. Every trial is written to the results file as soon as it
finishes, so an interrupted run resumes where it stopped (``--resume``).

Run it against a throwaway database (``SPA_DATABASE_URL``): it scans the fixture
into its own project and records one ``Verification`` row per trial.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from sqlalchemy import select

from app.ai.providers import get_provider
from app.ai.providers.base import ProviderError
from app.ai.providers.ollama import loopback_base_url
from app.ai.strategies import STRATEGIES
from app.cli import zip_directory
from app.core.config import get_settings
from app.core.scratch import scratch_dir
from app.db.models import Finding, Scan, ScannerRun, TrackedFinding
from app.db.session import init_db, session_scope
from app.sandbox.lab import LabError, prepare_baseline, run_lab_trial
from app.scan_service import scan_zip
from evaluation.ground_truth import Seeded, load_ground_truth

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "flask_vuln_app"
PROJECT = "e2-lab"
# The finding a trial starts from; any member of the weakness works (the target is
# every same-CWE finding in the symbol), but a code scanner's finding gives the
# model a code context rather than a manifest line.
TOOL_PREFERENCE = ("bandit", "semgrep", "gitleaks", "pip-audit")
NOT_APPLICABLE = "NOT_APPLICABLE"
NO_USABLE_FIX = "reply"     # FIX_REJECTED before any gate ran: the reply was unusable or could not be applied


@dataclass
class Trial:
    seed: str
    cwe: str
    symbol: str
    tracked_id: int
    rule: str
    strategy: str
    verdict: str
    gate: str | None            # first gate that failed or lacked evidence; NO_USABLE_FIX; or None
    reason: str | None
    prompt_tokens: int
    completion_tokens: int
    calls: int
    seconds: float

    @property
    def applicable(self) -> bool:
        return self.verdict != NOT_APPLICABLE


# ---- setup ------------------------------------------------------------------------------


def _overlaps(f: Finding, seed: Seeded) -> bool:
    if seed.lines is None:
        return False
    start = f.start_line or 0
    end = f.end_line or start
    return start <= seed.lines[1] and end >= seed.lines[0]


def targets(scan_id: int, seeds: list[Seeded]) -> dict[str, tuple[int, str]]:
    """seed id -> (tracked finding id, rule id) of the finding each trial starts from."""
    rank = {tool: i for i, tool in enumerate(TOOL_PREFERENCE)}
    chosen: dict[str, tuple[int, str]] = {}
    with session_scope() as s:
        project_id = s.get(Scan, scan_id).project_id
        findings = list(s.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)))
        tracked = {t.fingerprint: t for t in s.scalars(select(TrackedFinding)
                                                       .where(TrackedFinding.project_id == project_id))}
        for seed in seeds:
            matches = [f for f in findings if f.cwe == seed.cwe and f.file_path == seed.file and _overlaps(f, seed)]
            matches.sort(key=lambda f: (rank.get(f.tool, 9), f.id))
            if matches and matches[0].fingerprint in tracked:
                chosen[seed.id] = (tracked[matches[0].fingerprint].id, matches[0].rule_id.split(".")[-1])
    return chosen


def scanner_versions(scan_id: int) -> dict[str, str]:
    with session_scope() as s:
        return {r.tool: r.tool_version or "-" for r in s.scalars(select(ScannerRun).where(ScannerRun.scan_id == scan_id))}


def model_digest() -> str | None:
    """The pulled model's content digest, so a result is tied to exact weights (loopback server only)."""
    settings = get_settings()
    try:
        base = loopback_base_url(settings.ollama_url)
        with httpx.Client(timeout=10.0, trust_env=False) as client:
            models = client.get(f"{base}/api/tags").json().get("models", [])
    except (ProviderError, httpx.HTTPError, ValueError):
        return None
    return next((m.get("digest") for m in models if m.get("name") == settings.ollama_model), None)


# ---- one trial --------------------------------------------------------------------------


def deciding_gate(verdict: str, gates: Iterable[dict]) -> str | None:
    """The same attribution as the verification scenario: the first gate that failed or lacked evidence."""
    gate = next((g["gate"] for g in gates if g.get("status") in {"FAIL", "UNVERIFIED"}), None)
    if gate is None and verdict == "FIX_REJECTED":
        return NO_USABLE_FIX
    return gate


def run_trial(seed: Seeded, tracked_id: int, rule: str, strategy: str, provider, baseline) -> Trial:  # noqa: ANN001
    started = time.monotonic()
    try:
        with session_scope() as s:
            row = run_lab_trial(s, tracked_id, FIXTURE, strategy, provider, baseline=baseline)
            return Trial(seed.id, seed.cwe, seed.symbol, tracked_id, rule, strategy, row.verdict.value,
                         deciding_gate(row.verdict.value, row.gates or []), row.reason, row.prompt_tokens or 0,
                         row.completion_tokens or 0, row.calls, round(time.monotonic() - started, 1))
    except LabError as exc:
        # The lab splice cannot attempt this weakness (e.g. a manifest line): reported, never counted as a failure.
        return Trial(seed.id, seed.cwe, seed.symbol, tracked_id, rule, strategy, NOT_APPLICABLE, None, str(exc),
                     0, 0, 0, round(time.monotonic() - started, 1))


# ---- aggregation (pure; also used by the tests on the committed results) ----------------


def summarise(trials: Iterable[dict]) -> dict[str, dict]:
    """Per strategy: trials, applicable, verified, ESR, where the others failed, tokens, verified fixes per 1k tokens."""
    by_strategy: dict[str, list[dict]] = {}
    for t in trials:
        by_strategy.setdefault(t["strategy"], []).append(t)
    out = {}
    for strategy in sorted(by_strategy):
        rows = by_strategy[strategy]
        applicable = [r for r in rows if r["verdict"] != NOT_APPLICABLE]
        verified = sum(r["verdict"] == "VERIFIED_RESOLVED" for r in applicable)
        tokens = sum(r["prompt_tokens"] + r["completion_tokens"] for r in applicable)
        failed = Counter(r["gate"] or r["verdict"] for r in applicable if r["verdict"] != "VERIFIED_RESOLVED")
        out[strategy] = {
            "trials": len(rows),
            "applicable": len(applicable),
            "verified": verified,
            "esr": round(verified / len(applicable), 2) if applicable else None,
            "failed_at": dict(sorted(failed.items())),
            "prompt_tokens": sum(r["prompt_tokens"] for r in applicable),
            "completion_tokens": sum(r["completion_tokens"] for r in applicable),
            "verified_per_1k_tokens": round(verified / (tokens / 1000), 2) if tokens else None,
        }
    return out


# ---- the run ------------------------------------------------------------------------------


def _write(out: Path, payload: dict) -> None:
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m evaluation.e2_strategies", description=__doc__.split("\n")[0])
    parser.add_argument("--out", required=True, type=Path, help="results file (JSON), rewritten after every trial")
    parser.add_argument("--resume", action="store_true", help="keep the trials already in --out and run the rest")
    parser.add_argument("--strategies", default=",".join(STRATEGIES), help="comma-separated, default S0..S8")
    parser.add_argument("--seeds", help="comma-separated ground-truth ids (default: all ten)")
    args = parser.parse_args(argv)

    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]
    unknown = [s for s in strategies if s not in STRATEGIES]
    if unknown:
        parser.error(f"unknown strategies: {', '.join(unknown)}")
    seeds = load_ground_truth(FIXTURE)
    if args.seeds:
        wanted = {s.strip() for s in args.seeds.split(",")}
        seeds = [s for s in seeds if s.id in wanted]

    provider = get_provider("ollama")
    usable, why = provider.available()
    if not usable:
        print(f"error: the local model is not available: {why}", file=sys.stderr)
        return 2

    init_db()
    with scratch_dir("e2-") as work:
        zip_directory(FIXTURE, work / "fixture.zip")
        summary = scan_zip(PROJECT, work / "fixture.zip", label="e2 baseline")
    chosen = targets(summary.scan_id, seeds)
    baseline = prepare_baseline(FIXTURE)

    previous = json.loads(args.out.read_text(encoding="utf-8")) if args.resume and args.out.exists() else {}
    trials: list[dict] = list(previous.get("trials", []))
    done = {(t["seed"], t["strategy"]) for t in trials}
    payload = {
        "experiment": "E2 pilot -- S0..S8, one trial per (weakness, strategy), local model",
        "fixture": "fixtures/flask_vuln_app",
        "started": previous.get("started") or datetime.now(UTC).isoformat(timespec="seconds"),
        "finished": None,
        "model": {**provider.describe(), "digest": model_digest()},
        "scanners": scanner_versions(summary.scan_id),
        "trials": trials,
    }
    total = len(seeds) * len(strategies)
    for seed in seeds:
        if seed.id not in chosen:
            print(f"  {seed.id}: no tracked finding matches this seeded weakness -- skipped", flush=True)
            continue
        tracked_id, rule = chosen[seed.id]
        for strategy in strategies:
            if (seed.id, strategy) in done:
                continue
            trial = run_trial(seed, tracked_id, rule, strategy, provider, baseline)
            trials.append({**asdict(trial)})
            _write(args.out, payload)
            print(f"  [{len(trials):>3}/{total}] {seed.id} {seed.cwe:<9} {strategy}  {trial.verdict:<17} "
                  f"gate={trial.gate or '-':<5} tokens={trial.prompt_tokens + trial.completion_tokens:<5} "
                  f"{trial.seconds:>5.1f}s", flush=True)
    payload["finished"] = datetime.now(UTC).isoformat(timespec="seconds")
    payload["summary"] = summarise(trials)
    _write(args.out, payload)
    for strategy, row in payload["summary"].items():
        print(f"  {strategy}: ESR {row['esr']}  ({row['verified']}/{row['applicable']})  failed at {row['failed_at']}  "
              f"verified/1k tokens {row['verified_per_1k_tokens']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
