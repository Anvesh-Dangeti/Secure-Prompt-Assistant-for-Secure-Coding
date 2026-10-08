"""Finding identity: changes when the weakness changes, and only then.

Ports the Phase 0 guarantees (tests/unit/test_fingerprint_stability.py) onto
the application's fingerprint module and adds the cases discovered since.
"""

from __future__ import annotations

from app.core.redaction import redact
from app.intelligence.fingerprint import assign_fingerprints, native_is_valid
from app.normalization.finding import NormalizedFinding
from app.scanners.semgrep import portable_rule_id

CMD = 'return subprocess.check_output("ping -c 1 " + host, shell=True)'


def _f(**kw) -> NormalizedFinding:
    base = dict(tool="bandit", rule_id="B602", message="shell=True", file_path="app.py",
                start_line=48, end_line=48, severity="HIGH", snippet=CMD)
    return NormalizedFinding(**(base | kw))


def _fp(**kw) -> str:
    return assign_fingerprints([_f(**kw)])[0].fingerprint


def test_line_number_is_not_identity() -> None:
    assert _fp(start_line=48, end_line=48) == _fp(start_line=999, end_line=999)


def test_whitespace_reformatting_is_not_a_fix() -> None:
    assert _fp() == _fp(snippet='return  subprocess.check_output( "ping -c 1 "+host,\n    shell=True )')


def test_suppression_comments_are_not_a_fix() -> None:
    for comment in ("  # nosec", "  # nosemgrep", "  # nosec B602 -- reviewed", "  # gitleaks:allow"):
        assert _fp() == _fp(snippet=CMD + comment)


def test_comment_lines_inside_a_match_are_not_a_fix() -> None:
    a = 'user_id = request.args.get("id")\ncursor.execute("SELECT %s" % user_id)'
    b = 'user_id = request.args.get("id")\n# TODO: validate\ncursor.execute("SELECT %s" % user_id)'
    assert _fp(snippet=a) == _fp(snippet=b)


def test_hash_inside_a_string_is_code_not_a_comment() -> None:
    assert _fp(snippet='color = "#fff"') != _fp(snippet='color = "#000"')


def test_a_real_code_change_changes_identity() -> None:
    assert _fp() != _fp(snippet='return subprocess.check_output(["ping", "-c", "1", host])')


def test_path_and_rule_are_part_of_identity() -> None:
    assert _fp() != _fp(file_path="other.py")
    assert _fp() != _fp(rule_id="B603")


def test_rotating_a_hardcoded_secret_keeps_identity() -> None:
    old = redact('API_TOKEN = "sk_live_' + 'AAAAAAAAAAAAAAAAAAAAAAAA"')
    new = redact('API_TOKEN = "sk_live_' + 'BBBBBBBBBBBBBBBBBBBBBBBB"')
    assert _fp(tool="gitleaks", rule_id="stripe-access-token", snippet=old) == \
        _fp(tool="gitleaks", rule_id="stripe-access-token", snippet=new)


def test_placeholder_native_fingerprints_are_rejected() -> None:
    assert not native_is_valid("requires login")
    assert not native_is_valid("")
    assert not native_is_valid(None)
    assert native_is_valid("3f6c1a9e0b7d4c2a8e5f1b3d7c9a0e2f")
    # Two different Semgrep findings that both say "requires login" must NOT collide.
    a, b = assign_fingerprints([
        _f(tool="semgrep", rule_id="r1", native_fingerprint="requires login"),
        _f(tool="semgrep", rule_id="r2", native_fingerprint="requires login"),
    ])
    assert a.fingerprint != b.fingerprint and a.fingerprint_source == "derived"


def test_valid_native_fingerprints_are_preferred_except_for_gitleaks() -> None:
    native = "3f6c1a9e0b7d4c2a8e5f1b3d7c9a0e2f"
    (s,) = assign_fingerprints([_f(tool="semgrep", native_fingerprint=native)])
    (g,) = assign_fingerprints([_f(tool="gitleaks", native_fingerprint=native)])
    assert s.fingerprint_source == "native" and g.fingerprint_source == "derived"


def test_identical_matches_in_one_file_get_distinct_stable_identities() -> None:
    twins = assign_fingerprints([_f(start_line=10, end_line=10), _f(start_line=20, end_line=20)])
    assert len({t.fingerprint for t in twins}) == 2
    # Same pair shifted down by 5 lines: same two identities.
    shifted = assign_fingerprints([_f(start_line=25, end_line=25), _f(start_line=15, end_line=15)])
    assert {t.fingerprint for t in twins} == {t.fingerprint for t in shifted}


def test_dependency_identity_ignores_version() -> None:
    def dep(version: str) -> str:
        return _fp(tool="pip-audit", rule_id="PYSEC-2021-142", file_path="requirements.txt",
                   package="PyYAML", package_version=version, vuln_id="PYSEC-2021-142",
                   snippet=f"PyYAML=={version}")
    # Bumping to another still-vulnerable version is not a fix.
    assert dep("5.3") == dep("5.3.1")


def test_semgrep_rule_ids_are_portable_across_install_paths() -> None:
    known = frozenset({"python.flask.security.audit.debug-enabled.debug-enabled"})
    a = portable_rule_id("D.projects.spa.rules.vendor.python.flask.security.audit.debug-enabled"
                         ".debug-enabled", known)
    b = portable_rule_id("home.alice.spa.rules.vendor.python.flask.security.audit.debug-enabled"
                         ".debug-enabled", known)
    assert a == b == "python.flask.security.audit.debug-enabled.debug-enabled"
