from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from wardline.core.baseline import (
    BASELINE_VERSION,
    build_baseline_document,
    inspect_baseline_store,
    load_baseline,
    write_baseline,
)
from wardline.core.errors import ConfigError, SchemeMismatchError, WardlineError
from wardline.core.finding import FINGERPRINT_SCHEME, Finding, Kind, Location, Maturity, Severity
from wardline.core.paths import baseline_path
from wardline.core.suppression import gate_trips

_FP_A = "a" * 64
_FP_B = "b" * 64


def _finding(fp: str, *, rule: str = "PY-WL-101", sev: Severity = Severity.ERROR, path: str = "src/m.py") -> Finding:
    return Finding(
        rule_id=rule,
        message=f"msg {fp[:4]}",
        severity=sev,
        kind=Kind.DEFECT,
        location=Location(path=path, line_start=1),
        fingerprint=fp,
    )


def _preview_finding(fp: str) -> Finding:
    return Finding(
        rule_id="PY-WL-119",
        message="preview taint",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/m.py", line_start=1),
        fingerprint=fp,
        maturity=Maturity.PREVIEW,
    )


def test_build_document_shape_and_version() -> None:
    doc = build_baseline_document([_finding(_FP_A)])
    assert doc["version"] == BASELINE_VERSION
    assert doc["fingerprint_scheme"] == FINGERPRINT_SCHEME == "wlfp2"
    assert doc["entries"][0]["fingerprint"] == _FP_A
    assert doc["entries"][0]["rule_id"] == "PY-WL-101"
    assert "path" in doc["entries"][0] and "message" in doc["entries"][0]
    # entry fingerprint stays BARE 64-hex (no scheme prefix in-store)
    assert ":" not in doc["entries"][0]["fingerprint"]


def test_missing_scheme_header_raises_scheme_mismatch_not_version(tmp_path: Path) -> None:
    # A header-less store must fail with the actionable SchemeMismatchError
    # (naming the file + `wardline rekey`), NOT a hintless version error — and
    # the scheme check must run BEFORE the version check.
    p = tmp_path / "b.yaml"
    p.write_text(yaml.safe_dump({"version": BASELINE_VERSION, "entries": []}), encoding="utf-8")
    with pytest.raises(SchemeMismatchError) as ei:
        load_baseline(p)
    assert "wardline rekey" in str(ei.value)


def test_wrong_scheme_raises_scheme_mismatch(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(
        yaml.safe_dump({"fingerprint_scheme": "wlfp1", "version": BASELINE_VERSION, "entries": []}),
        encoding="utf-8",
    )
    with pytest.raises(SchemeMismatchError):
        load_baseline(p)


def test_non_string_scheme_header_treated_as_missing(tmp_path: Path) -> None:
    # A non-string fingerprint_scheme (hand-mangled) is treated as missing and
    # raises the actionable SchemeMismatchError, not a crash. Locks the isinstance
    # guard in require_fingerprint_scheme.
    p = tmp_path / "b.yaml"
    p.write_text(yaml.safe_dump({"fingerprint_scheme": 1, "version": BASELINE_VERSION, "entries": []}), "utf-8")
    with pytest.raises(SchemeMismatchError) as ei:
        load_baseline(p)
    assert "wardline rekey" in str(ei.value)


def test_empty_mapping_is_empty_baseline_no_scheme_error(tmp_path: Path) -> None:
    # Fresh checkout: an empty `{}` store returns empty, never SchemeMismatchError
    # (empty-guard precedes the scheme check).
    p = tmp_path / "b.yaml"
    p.write_text("{}\n", encoding="utf-8")
    assert load_baseline(p).fingerprints == frozenset()


def test_build_document_dedups_and_sorts_severity_first() -> None:
    findings = [
        _finding(_FP_A, sev=Severity.WARN, rule="PY-WL-103"),
        _finding(_FP_B, sev=Severity.CRITICAL, rule="PY-WL-101"),
        _finding(_FP_A, sev=Severity.WARN, rule="PY-WL-103"),  # dup fingerprint
    ]
    entries = build_baseline_document(findings)["entries"]
    assert [e["fingerprint"] for e in entries] == [_FP_B, _FP_A]  # CRITICAL first; dup collapsed


def test_build_document_is_order_independent() -> None:
    # Git-stability: the committed file must not churn on finding order.
    fs = [_finding(_FP_A, sev=Severity.WARN), _finding(_FP_B, sev=Severity.CRITICAL)]
    assert build_baseline_document(fs) == build_baseline_document(list(reversed(fs)))


def test_build_document_excludes_preview_findings_that_never_gate() -> None:
    preview = _preview_finding(_FP_A)
    stable = _finding(_FP_B)

    doc = build_baseline_document([preview, stable])

    assert gate_trips([preview], Severity.ERROR) is False
    assert [entry["fingerprint"] for entry in doc["entries"]] == [_FP_B]


def test_write_then_load_round_trips(tmp_path: Path) -> None:
    p = tmp_path / ".wardline" / "baseline.yaml"
    write_baseline(p, [_finding(_FP_A), _finding(_FP_B)])
    bl = load_baseline(p)
    assert bl.fingerprints == frozenset({_FP_A, _FP_B})
    assert bl.contains(_FP_A) and not bl.contains("c" * 64)


def test_write_baseline_refuses_direct_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("", encoding="utf-8")
    link = tmp_path / "baseline.yaml"
    link.symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        write_baseline(link, [_finding(_FP_A)])

    assert outside.read_text(encoding="utf-8") == ""


def test_write_baseline_refuses_rooted_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("", encoding="utf-8")
    bp = baseline_path(tmp_path)
    bp.parent.mkdir(parents=True)
    bp.symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        write_baseline(bp, [_finding(_FP_A)], root=tmp_path)

    assert outside.read_text(encoding="utf-8") == ""


def test_missing_file_is_empty_baseline(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "nope.yaml").fingerprints == frozenset()


def test_empty_file_is_empty_baseline(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text("", encoding="utf-8")
    assert load_baseline(p).fingerprints == frozenset()


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text("entries: [1, 2\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_version_mismatch_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(
        yaml.safe_dump({"fingerprint_scheme": FINGERPRINT_SCHEME, "version": 999, "entries": []}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_bad_fingerprint_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": FINGERPRINT_SCHEME,
                "version": BASELINE_VERSION,
                "entries": [{"fingerprint": "short"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_duplicate_fingerprint_in_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": FINGERPRINT_SCHEME,
                "version": BASELINE_VERSION,
                "entries": [{"fingerprint": _FP_A}, {"fingerprint": _FP_A}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_baseline(p)


# ---------------------------------------------------------------------------
# inspect_baseline_store — READ-ONLY repo-binding / store-read probe (doctor seam)
# ---------------------------------------------------------------------------


def test_inspect_store_absent_is_present_false_binding_false(tmp_path: Path) -> None:
    # Opt-in feature simply not set up: absence is NOT the stale-binary incident.
    status = inspect_baseline_store(tmp_path)
    assert status.present is False
    assert status.readable is False
    assert status.schema_version is None
    assert status.baseline_finding_count is None
    assert status.binding_ok is False
    assert status.message  # a soft, non-empty hint


def test_inspect_store_present_readable_reads_schema_and_count(tmp_path: Path) -> None:
    # Round-trip through the REAL writer at the REAL path (read-path == write-path):
    # the load-bearing fact is the schema version READ FROM INSIDE the store.
    write_baseline(baseline_path(tmp_path), [_finding(_FP_A), _finding(_FP_B)], root=tmp_path)
    status = inspect_baseline_store(tmp_path)
    assert status.present is True
    assert status.readable is True
    assert status.schema_version == BASELINE_VERSION
    assert status.baseline_finding_count == 2
    assert status.binding_ok is True


def test_inspect_store_present_unreadable_version_mismatch(tmp_path: Path) -> None:
    # The stale-binary incident: the store exists but carries a schema this build
    # does not serve. binding_ok flips false; schema_version reports null (= a
    # version I can serve); the on-disk version rides in the diagnostic message.
    write_baseline(baseline_path(tmp_path), [_finding(_FP_A)], root=tmp_path)
    p = baseline_path(tmp_path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    raw["version"] = 999
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    status = inspect_baseline_store(tmp_path)
    assert status.present is True
    assert status.readable is False
    assert status.schema_version is None
    assert status.baseline_finding_count is None
    assert status.binding_ok is False
    assert "999" in status.message
    assert str(BASELINE_VERSION) in status.message


def test_inspect_store_present_malformed_is_unreadable(tmp_path: Path) -> None:
    # A not-a-mapping top-level store is unreadable too (the broader incident class).
    p = baseline_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    status = inspect_baseline_store(tmp_path)
    assert status.present is True
    assert status.readable is False
    assert status.binding_ok is False
    assert status.schema_version is None


def test_inspect_store_does_not_create_anything(tmp_path: Path) -> None:
    # READ-ONLY: probing an absent store must never mkdir or write the baseline.
    inspect_baseline_store(tmp_path)
    assert not (tmp_path / ".weft").exists()


def test_inspect_store_empty_store_has_null_schema_and_no_binding(tmp_path: Path) -> None:
    # A degenerate empty `{}` store is loader-valid (readable) but carries NO version:
    # schema_version stays null STRICTLY (never the served constant) and binding_ok is
    # false — wardline can open it but has no servable-version fact. This keeps the
    # non-tautological signal honest. (A real baseline always carries `version`, so the
    # writer never produces this shape; only a crafted/truncated store does.)
    p = baseline_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{}\n", encoding="utf-8")
    status = inspect_baseline_store(tmp_path)
    assert status.present is True
    assert status.readable is True  # loader accepts an empty mapping — not the incident
    assert status.schema_version is None  # nothing was READ from the file
    assert status.binding_ok is False  # so the harness predicate is NOT satisfied
    assert status.baseline_finding_count == 0


def test_inspect_store_unreadable_message_does_not_echo_store_content(tmp_path: Path) -> None:
    # Trust-boundary: a crafted store must NOT be able to smuggle its content (an absolute
    # path, a planted token) out through the doctor diagnostic message. A bad fingerprint
    # scheme carrying a secret-shaped string must yield a content-free message.
    leak = "/etc/secret/peer-token-AKIAEXFILTRATE"
    p = baseline_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        yaml.safe_dump({"fingerprint_scheme": leak, "version": BASELINE_VERSION, "entries": []}),
        encoding="utf-8",
    )
    status = inspect_baseline_store(tmp_path)
    assert status.readable is False
    assert status.binding_ok is False
    assert leak not in status.message  # the crafted content never reaches the seam
    assert "AKIA" not in status.message
    assert "baseline.yaml" in status.message  # only the store name + served version are named
    assert str(BASELINE_VERSION) in status.message
    # SchemeMismatchError is the raised type for a wrong scheme (a ConfigError subclass).
    assert issubclass(SchemeMismatchError, ConfigError)
