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
    a = compute_finding_fingerprint(
        rule_id="PY-WL-101", path="a.py", line_start=1, qualname="m.f", taint_path="EXTERNAL_RAW|g"
    )
    b = compute_finding_fingerprint(
        rule_id="PY-WL-101", path="a.py", line_start=1, qualname="m.f", taint_path="EXTERNAL_RAW|g"
    )
    # same inputs -> stable
    assert a == b
    assert len(a) == 64
    # path-sensitive
    assert a != compute_finding_fingerprint(
        rule_id="PY-WL-101", path="b.py", line_start=1, qualname="m.f", taint_path="EXTERNAL_RAW|g"
    )
    # TWO TAINT PATHS INTO ONE SINK: same (rule, file, line, qualname) but a
    # different taint path -> DISTINCT fingerprint (Filigree constraint, §7).
    assert a != compute_finding_fingerprint(
        rule_id="PY-WL-101", path="a.py", line_start=1, qualname="m.f", taint_path="MIXED_RAW|h"
    )
    # optional fields default cleanly
    assert len(compute_finding_fingerprint(rule_id="WLN-ENGINE-X", path="a.py", line_start=None)) == 64
