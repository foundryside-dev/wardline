# tests/unit/core/test_finding.py
import json

from wardline.core.finding import (
    Finding,
    Kind,
    Location,
    Severity,
    compute_finding_fingerprint,
)


def _finding(**kw: object) -> Finding:
    base = dict(
        rule_id="WLN-001",
        message="boundary not validated",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/pkg/mod.py", line_start=10, line_end=10),
        fingerprint="deadbeef",
    )
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def test_finding_is_frozen() -> None:
    f = _finding()
    try:
        f.rule_id = "x"  # type: ignore[misc]
    except AttributeError:
        return
    raise AssertionError("Finding must be immutable")


def test_to_jsonl_is_valid_json_with_expected_keys() -> None:
    line = _finding(suggestion="validate at boundary", qualname="pkg.mod.f").to_jsonl()
    obj = json.loads(line)
    assert obj["rule_id"] == "WLN-001"
    assert obj["severity"] == "ERROR"
    assert obj["kind"] == "defect"
    assert obj["location"]["line_start"] == 10
    assert obj["fingerprint"] == "deadbeef"
    assert obj["suggestion"] == "validate at boundary"
    assert obj["qualname"] == "pkg.mod.f"
    assert "\n" not in line


def test_to_jsonl_round_trips_collections() -> None:
    line = _finding(related_entities=("e1", "e2"), properties={"cwe": "CWE-200"}).to_jsonl()
    obj = json.loads(line)
    assert obj["related_entities"] == ["e1", "e2"]
    assert obj["properties"] == {"cwe": "CWE-200"}


def test_finding_fingerprint_is_deterministic_and_discriminating() -> None:
    a = compute_finding_fingerprint(rule_id="PY-WL-101", path="a.py", qualname="m.f", taint_path="EXTERNAL_RAW|g")
    b = compute_finding_fingerprint(rule_id="PY-WL-101", path="a.py", qualname="m.f", taint_path="EXTERNAL_RAW|g")
    # same inputs -> stable
    assert a == b
    assert len(a) == 64
    # path-sensitive
    assert a != compute_finding_fingerprint(
        rule_id="PY-WL-101", path="b.py", qualname="m.f", taint_path="EXTERNAL_RAW|g"
    )
    # TWO TAINT PATHS INTO ONE SINK: same (rule, file, qualname) but a different
    # taint path -> DISTINCT fingerprint (Filigree constraint, §7).
    assert a != compute_finding_fingerprint(rule_id="PY-WL-101", path="a.py", qualname="m.f", taint_path="MIXED_RAW|h")
    # optional fields default cleanly
    assert len(compute_finding_fingerprint(rule_id="WLN-ENGINE-X", path="a.py")) == 64


def test_finding_defaults_to_active_suppression() -> None:
    from wardline.core.finding import SuppressionState

    assert _finding().suppressed is SuppressionState.ACTIVE
    assert _finding().suppression_reason is None


def test_suppressed_serializes_in_jsonl() -> None:
    from wardline.core.finding import SuppressionState

    f = _finding(suppressed=SuppressionState.WAIVED, suppression_reason="reviewed")
    obj = json.loads(f.to_jsonl())
    assert obj["suppression_state"] == "waived"
    assert obj["suppression_reason"] == "reviewed"


def test_active_suppression_serializes_too() -> None:
    obj = json.loads(_finding().to_jsonl())
    assert obj["suppression_state"] == "active"
    assert obj["suppression_reason"] is None


def test_suppressed_not_in_fingerprint_inputs() -> None:
    # suppression must never change identity.
    from dataclasses import replace

    from wardline.core.finding import SuppressionState

    f = _finding()
    g = replace(f, suppressed=SuppressionState.BASELINED)
    assert f.fingerprint == g.fingerprint  # fingerprint is a stored field, unaffected


def test_filigree_metadata_includes_suppression_only_when_suppressed() -> None:
    from wardline.core.finding import SuppressionState, to_filigree_metadata

    active = to_filigree_metadata(_finding())["wardline"]
    assert "suppression_state" not in active
    waived = to_filigree_metadata(_finding(suppressed=SuppressionState.WAIVED, suppression_reason="ok"))["wardline"]
    assert waived["suppression_state"] == "waived"
    assert waived["suppression_reason"] == "ok"
