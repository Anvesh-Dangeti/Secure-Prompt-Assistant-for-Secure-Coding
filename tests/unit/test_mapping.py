"""CWE/OWASP classification is data-driven, documented, and refuses bad data."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.mapping.mapper import DATA_DIR, MappingDataError, canonical_cwe, classify, load_tables
from app.normalization.finding import NormalizedFinding


def _f(**kw) -> NormalizedFinding:
    base = dict(tool="semgrep", rule_id="r", message="m", file_path="a.py", start_line=1, end_line=1,
                severity="HIGH")
    return NormalizedFinding(**(base | kw))


@pytest.mark.parametrize("reported, canonical", [
    ("CWE-259", "CWE-798"), ("CWE-328", "CWE-327"), ("CWE-489", "CWE-94"),
    ("CWE-215", "CWE-94"), ("CWE-89", "CWE-89"), (None, None),
])
def test_aliases(reported: str | None, canonical: str | None) -> None:
    assert canonical_cwe(reported) == canonical


def test_scoped_findings_map_to_owasp_2021() -> None:
    f = classify(_f(cwe_reported="CWE-89"))
    assert (f.cwe, f.owasp, f.in_scope, f.mapping_note) == ("CWE-89", "A03", True, None)


def test_documented_rule_override_is_applied_and_visible() -> None:
    f = classify(_f(rule_id="python.flask.security.injection.tainted-sql-string.tainted-sql-string",
                    cwe_reported="CWE-704"))
    assert f.cwe == "CWE-89" and f.cwe_reported == "CWE-704"
    assert "override" in (f.mapping_note or "")


def test_tool_defaults_for_tools_without_cwes() -> None:
    assert classify(_f(tool="gitleaks", rule_id="stripe-access-token")).cwe == "CWE-798"
    dep = classify(_f(tool="pip-audit", rule_id="PYSEC-1", package="pyyaml", vuln_id="PYSEC-1"))
    assert (dep.cwe, dep.owasp) == ("CWE-1395", "A06")


def test_owasp_falls_back_to_tool_tag_only_when_unmapped() -> None:
    f = classify(_f(cwe_reported="CWE-1004", owasp_reported="A05"))
    assert f.owasp == "A05" and not f.in_scope and "tool tag" in (f.mapping_note or "")


def test_every_scoped_cwe_has_an_owasp_category() -> None:
    t = load_tables()
    assert len(t.scoped) == 10
    assert all(cwe in t.cwe_to_owasp for cwe in t.scoped)


def _write_tables(tmp: Path, core_patch: dict | None = None, raw_core: str | None = None) -> Path:
    core = yaml.safe_load((DATA_DIR / "cwe_owasp.yaml").read_text(encoding="utf-8"))
    core.update(core_patch or {})
    (tmp / "cwe_owasp.yaml").write_text(raw_core or yaml.safe_dump(core), encoding="utf-8")
    (tmp / "rule_overrides.yaml").write_text((DATA_DIR / "rule_overrides.yaml").read_text(encoding="utf-8"),
                                             encoding="utf-8")
    return tmp


def test_bad_cwe_id_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(MappingDataError):
        load_tables(_write_tables(tmp_path, {"scoped": ["CWE-89", "SQLI"]}))


def test_alias_chains_are_rejected(tmp_path: Path) -> None:
    aliases = {"CWE-1": {"canonical": "CWE-2"}, "CWE-2": {"canonical": "CWE-3"}}
    with pytest.raises(MappingDataError):
        load_tables(_write_tables(tmp_path, {"aliases": aliases}))


def test_yaml_object_construction_is_impossible(tmp_path: Path) -> None:
    # safe_load must refuse python object tags in a data file.
    hostile = "owasp_2021: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(yaml.YAMLError):
        load_tables(_write_tables(tmp_path, raw_core=hostile))
