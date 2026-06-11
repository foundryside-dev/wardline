"""WS-B1: pure conjunctive finding filter shared by MCP `scan(where=)` and CLI
`wardline findings --where`."""

import pytest

from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.finding_query import filter_findings


def _f(
    rule_id="PY-WL-101",
    qualname="pkg.mod.fn",
    path="pkg/mod.py",
    severity=Severity.ERROR,
    kind=Kind.DEFECT,
    suppressed=SuppressionState.ACTIVE,
    properties=None,
):
    return Finding(
        rule_id=rule_id,
        message="m",
        severity=severity,
        kind=kind,
        location=Location(path=path, line_start=3),
        fingerprint=rule_id + path + (qualname or ""),
        qualname=qualname,
        properties=properties or {},
        suppressed=suppressed,
    )


def test_no_where_returns_all():
    fs = [_f(), _f(rule_id="PY-WL-106")]
    assert filter_findings(fs, None) == fs
    assert filter_findings(fs, {}) == fs


def test_filter_by_rule_id():
    a, b = _f(rule_id="PY-WL-101"), _f(rule_id="PY-WL-106")
    assert filter_findings([a, b], {"rule_id": "PY-WL-106"}) == [b]


def test_filter_by_qualname():
    a, b = _f(qualname="pkg.a"), _f(qualname="pkg.b")
    assert filter_findings([a, b], {"qualname": "pkg.b"}) == [b]


def test_filter_by_severity_and_suppression_and_kind():
    a = _f(severity=Severity.ERROR, suppressed=SuppressionState.ACTIVE, kind=Kind.DEFECT)
    b = _f(severity=Severity.WARN, suppressed=SuppressionState.BASELINED, kind=Kind.FACT)
    assert filter_findings([a, b], {"severity": "ERROR"}) == [a]
    assert filter_findings([a, b], {"suppression": "baselined"}) == [b]
    assert filter_findings([a, b], {"kind": "fact"}) == [b]


def test_filter_by_path_glob():
    a, b = _f(path="src/api/h.py"), _f(path="src/core/x.py")
    assert filter_findings([a, b], {"path_glob": "src/api/**"}) == [a]


def test_filter_by_sink_property():
    a = _f(rule_id="PY-WL-106", properties={"sink": "pickle.loads", "tier": "ASSURED"})
    b = _f(rule_id="PY-WL-107", properties={"sink": "eval", "tier": "ASSURED"})
    assert filter_findings([a, b], {"sink": "pickle.loads"}) == [a]


def test_filter_by_tier_matches_any_tier_property():
    # 101 carries actual_return; 106 carries tier/arg_taint — `tier` matches either.
    a = _f(rule_id="PY-WL-101", properties={"actual_return": "EXTERNAL_RAW", "declared_return": "INTEGRAL"})
    b = _f(rule_id="PY-WL-106", properties={"tier": "ASSURED", "arg_taint": "UNKNOWN_RAW"})
    assert filter_findings([a, b], {"tier": "EXTERNAL_RAW"}) == [a]
    assert filter_findings([a, b], {"tier": "UNKNOWN_RAW"}) == [b]


def test_conjunction_all_must_match():
    a = _f(rule_id="PY-WL-101", qualname="pkg.a")
    b = _f(rule_id="PY-WL-101", qualname="pkg.b")
    assert filter_findings([a, b], {"rule_id": "PY-WL-101", "qualname": "pkg.b"}) == [b]


def test_unknown_key_raises_valueerror():
    with pytest.raises(ValueError, match="unknown filter key"):
        filter_findings([_f()], {"bogus": "x"})


# --- N-5 (wardline-dc6f44707d): closed-vocab values normalize, never silent-empty ---


def test_severity_matches_case_insensitively():
    a = _f(severity=Severity.WARN)
    assert filter_findings([a], {"severity": "warn"}) == [a]
    assert filter_findings([a], {"severity": "WARN"}) == [a]
    assert filter_findings([a], {"severity": "Warn"}) == [a]


def test_kind_and_suppression_match_case_insensitively():
    a = _f(kind=Kind.FACT, suppressed=SuppressionState.BASELINED, severity=Severity.NONE)
    assert filter_findings([a], {"kind": "FACT"}) == [a]
    assert filter_findings([a], {"suppression": "Baselined"}) == [a]


def test_severity_out_of_domain_raises_with_allowed_values():
    # A value that can NEVER match (e.g. filigree's 'medium' scale) must error
    # loudly with the allowed vocabulary — a silent empty result is the N-5
    # bad-error an agent cannot diagnose.
    with pytest.raises(ValueError, match="medium"):
        filter_findings([_f()], {"severity": "medium"})
    with pytest.raises(ValueError, match="WARN"):
        filter_findings([_f()], {"severity": "medium"})


def test_suppression_and_kind_out_of_domain_raise():
    with pytest.raises(ValueError, match="suppression"):
        filter_findings([_f()], {"suppression": "suppressed"})
    with pytest.raises(ValueError, match="kind"):
        filter_findings([_f()], {"kind": "bug"})


def test_open_keys_stay_exact_and_silent():
    # rule_id/qualname/sink/tier are open vocabularies (packs can extend tiers) —
    # no normalization, no domain error; unmatched simply filters to empty.
    assert filter_findings([_f()], {"rule_id": "py-wl-101"}) == []
