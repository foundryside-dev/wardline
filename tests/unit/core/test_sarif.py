from __future__ import annotations

import json
from pathlib import Path

from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.sarif import SarifSink, build_sarif


def _f(
    *,
    rule_id: str = "PY-WL-101",
    sev: Severity = Severity.ERROR,
    kind: Kind = Kind.DEFECT,
    path: str = "src/m.py",
    line_start: int | None = 10,
    fp: str = "a" * 64,
    suppressed: SuppressionState = SuppressionState.ACTIVE,
    reason: str | None = None,
    qualname: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="msg",
        severity=sev,
        kind=kind,
        location=Location(path=path, line_start=line_start, line_end=line_start),
        fingerprint=fp,
        suppressed=suppressed,
        suppression_reason=reason,
        qualname=qualname,
    )


def test_log_shape_and_version() -> None:
    log = build_sarif([_f()])
    assert log["version"] == "2.1.0"
    assert "$schema" in log
    assert len(log["runs"]) == 1
    assert log["runs"][0]["tool"]["driver"]["name"] == "wardline"


def test_severity_maps_to_level() -> None:
    levels = {
        f["properties"]["internalSeverity"]: f["level"]
        for f in build_sarif(
            [
                _f(sev=Severity.CRITICAL),
                _f(sev=Severity.ERROR),
                _f(sev=Severity.WARN),
                _f(sev=Severity.INFO),
                _f(sev=Severity.NONE),
            ]
        )["runs"][0]["results"]
    }
    assert levels == {"CRITICAL": "error", "ERROR": "error", "WARN": "warning", "INFO": "note", "NONE": "none"}


def test_partial_fingerprint_and_location() -> None:
    res = build_sarif([_f(line_start=42)])["runs"][0]["results"][0]
    assert res["partialFingerprints"] == {"wardlineFingerprint/v1": "a" * 64}
    region = res["locations"][0]["physicalLocation"]["region"]
    # _f sets line_start == line_end and no columns -> exactly these two keys, no null cols
    assert set(region) == {"startLine", "endLine"}
    assert region["startLine"] == 42
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/m.py"


def test_no_line_finding_has_no_region() -> None:
    res = build_sarif([_f(line_start=None)])["runs"][0]["results"][0]
    phys = res["locations"][0]["physicalLocation"]
    assert "region" not in phys
    assert phys["artifactLocation"]["uri"] == "src/m.py"


def test_rules_array_is_first_seen_unique() -> None:
    log = build_sarif([_f(rule_id="B"), _f(rule_id="A"), _f(rule_id="B")])
    driver = log["runs"][0]["tool"]["driver"]
    assert [r["id"] for r in driver["rules"]] == ["B", "A"]
    results = log["runs"][0]["results"]
    assert results[0]["ruleIndex"] == 0 and results[1]["ruleIndex"] == 1
    assert results[2]["ruleIndex"] == 0


def test_suppressed_finding_emits_suppressions() -> None:
    baselined = build_sarif([_f(suppressed=SuppressionState.BASELINED)])["runs"][0]["results"][0]
    assert baselined["suppressions"] == [{"kind": "external", "status": "accepted"}]
    waived = build_sarif([_f(suppressed=SuppressionState.WAIVED, reason="false positive")])["runs"][0]["results"][0]
    assert waived["suppressions"][0]["justification"] == "false positive"


def test_active_finding_has_no_suppressions() -> None:
    res = build_sarif([_f()])["runs"][0]["results"][0]
    assert "suppressions" not in res


def test_properties_omit_absent_optionals() -> None:
    props = build_sarif([_f(qualname=None)])["runs"][0]["results"][0]["properties"]
    assert "qualname" not in props
    assert props["kind"] == "defect"


def test_sink_writes_valid_json(tmp_path: Path) -> None:
    out = tmp_path / "findings.sarif"
    SarifSink(out).write([_f()])
    loaded = json.loads(out.read_text("utf-8"))
    assert loaded["version"] == "2.1.0"


def test_judged_finding_emits_suppression() -> None:
    res = build_sarif([_f(suppressed=SuppressionState.JUDGED, reason="over-taint floor")])["runs"][0]["results"][0]
    assert res["suppressions"][0]["kind"] == "external"
    assert res["suppressions"][0]["justification"] == "over-taint floor"
