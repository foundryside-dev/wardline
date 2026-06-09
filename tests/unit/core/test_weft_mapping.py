# tests/unit/core/test_weft_mapping.py
from wardline.core.finding import (
    FINGERPRINT_SCHEME,
    Finding,
    Kind,
    Location,
    Severity,
    severity_to_filigree,
    to_filigree_metadata,
)


def test_severity_map_covers_all_levels() -> None:
    assert severity_to_filigree(Severity.CRITICAL) == "critical"
    assert severity_to_filigree(Severity.ERROR) == "high"
    assert severity_to_filigree(Severity.WARN) == "medium"
    assert severity_to_filigree(Severity.INFO) == "low"
    assert severity_to_filigree(Severity.NONE) == "info"


def test_metadata_namespaces_rich_fields_under_wardline() -> None:
    f = Finding(
        rule_id="WLN-002",
        message="m",
        severity=Severity.WARN,
        kind=Kind.DEFECT,
        location=Location(path="a.py", line_start=1),
        fingerprint="fp123",
        qualname="pkg.mod.C.method",
        confidence=0.9,
        properties={"cwe": "CWE-200"},
    )
    md = to_filigree_metadata(f)
    assert set(md) == {"wardline"}
    wl = md["wardline"]
    assert wl["fingerprint"] == f"{FINGERPRINT_SCHEME}:fp123"  # wire/metadata fp is scheme-prefixed (S6)
    assert wl["internal_severity"] == "WARN"
    assert wl["kind"] == "defect"
    assert wl["qualname"] == "pkg.mod.C.method"
    assert wl["confidence"] == 0.9
    assert wl["properties"] == {"cwe": "CWE-200"}


def test_metadata_omits_absent_optionals() -> None:
    f = Finding(
        rule_id="WLN-003",
        message="m",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="a.py"),
        fingerprint="fp",
    )
    wl = to_filigree_metadata(f)["wardline"]
    assert "qualname" not in wl
    assert "confidence" not in wl
    assert "properties" not in wl
