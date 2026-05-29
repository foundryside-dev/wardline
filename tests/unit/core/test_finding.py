# tests/unit/core/test_finding.py
import json

from wardline.core.finding import (
    Finding,
    Kind,
    Location,
    Severity,
    compute_placeholder_fingerprint,
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


def test_placeholder_fingerprint_is_deterministic_and_path_sensitive() -> None:
    a = compute_placeholder_fingerprint("WLN-001", "a.py", 1, "msg")
    b = compute_placeholder_fingerprint("WLN-001", "a.py", 1, "msg")
    c = compute_placeholder_fingerprint("WLN-001", "b.py", 1, "msg")
    assert a == b
    assert a != c
    assert len(a) == 64
