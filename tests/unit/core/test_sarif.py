from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.sarif import SarifSink, build_sarif
from wardline.core.taints import TaintState
from wardline.scanner.context import AnalysisContext
from wardline.scanner.index import Entity
from wardline.scanner.taint.propagation import TaintProvenance


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


def test_partial_fingerprint_key_is_v2() -> None:
    res = build_sarif([_f(line_start=42)])["runs"][0]["results"][0]
    # The KEY versions to /v2 to signal the scheme change; the VALUE stays bare
    # (SARIF consumers read the value, not a prefixed form).
    assert res["partialFingerprints"] == {"wardlineFingerprint/v2": "a" * 64}
    assert ":" not in res["partialFingerprints"]["wardlineFingerprint/v2"]
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


def test_sink_refuses_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("keep\n", encoding="utf-8")
    out = tmp_path / "findings.sarif"
    out.symlink_to(outside)

    with pytest.raises(WardlineError, match="refusing to write through a symlink"):
        SarifSink(out).write([_f()])

    assert outside.read_text(encoding="utf-8") == "keep\n"


def test_metric_findings_excluded_from_sarif() -> None:
    """Kind.METRIC findings (engine telemetry) must not appear in SARIF output."""
    metric = _f(rule_id="WLN-L3-LOW-RESOLUTION", sev=Severity.INFO, kind=Kind.METRIC)
    defect = _f(rule_id="PY-WL-101", sev=Severity.ERROR, kind=Kind.DEFECT)
    fact = _f(rule_id="WLN-ENGINE-UNKNOWN-IMPORT", sev=Severity.NONE, kind=Kind.FACT)

    log = build_sarif([metric, defect, fact])
    results = log["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}

    assert "WLN-L3-LOW-RESOLUTION" not in rule_ids, "METRIC finding leaked into SARIF"
    assert "PY-WL-101" in rule_ids
    assert "WLN-ENGINE-UNKNOWN-IMPORT" in rule_ids

    res = build_sarif([_f(suppressed=SuppressionState.JUDGED, reason="over-taint floor")])["runs"][0]["results"][0]
    assert res["suppressions"][0]["kind"] == "external"
    assert res["suppressions"][0]["justification"] == "over-taint floor"


def test_sarif_code_flow_untrusted_reaches_trusted() -> None:
    entity1 = Entity(
        qualname="test_module.func1",
        kind="function",
        node=ast.parse("def func1():\n    return func2()").body[0],
        location=Location(path="src/test_module.py", line_start=1, line_end=2),
    )
    entity2 = Entity(
        qualname="test_module.func2",
        kind="function",
        node=ast.parse("def func2():\n    return raw_input()").body[0],
        location=Location(path="src/test_module.py", line_start=4, line_end=5),
    )

    finding = Finding(
        rule_id="PY-WL-101",
        message="test violation",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/test_module.py", line_start=2, line_end=2),
        fingerprint="f" * 64,
        qualname="test_module.func1",
    )

    context = AnalysisContext(
        project_taints={"test_module.func1": TaintState.EXTERNAL_RAW, "test_module.func2": TaintState.EXTERNAL_RAW},
        project_return_taints={},
        function_var_taints={"test_module.func1": {}, "test_module.func2": {}},
        function_return_taints={},
        function_return_callee={"test_module.func1": "func2", "test_module.func2": "raw_input"},
        entities={"test_module.func1": entity1, "test_module.func2": entity2},
        taint_provenance={
            "test_module.func1": TaintProvenance(source="callgraph", via_callee="test_module.func2"),
            "test_module.func2": TaintProvenance(source="anchored", via_callee=None),
        },
    )

    log = build_sarif([finding], context)
    res = log["runs"][0]["results"][0]

    assert "codeFlows" in res
    assert len(res["codeFlows"]) == 1
    code_flow = res["codeFlows"][0]
    assert len(code_flow["threadFlows"]) == 1
    thread_flow = code_flow["threadFlows"][0]

    # Locations should walk source -> intermediate -> sink
    # Source: test_module.func2 (defined at line 4)
    # Sink: test_module.func1 (finding's location, line 2)
    locations = thread_flow["locations"]
    assert len(locations) == 2

    # Step 1: Source
    assert locations[0]["location"]["physicalLocation"]["artifactLocation"]["uri"] == "src/test_module.py"
    assert locations[0]["location"]["physicalLocation"]["region"]["startLine"] == 4
    assert locations[0]["location"]["message"]["text"] == "Taint source: test_module.func2"

    # Step 2: Sink
    assert locations[1]["location"]["physicalLocation"]["artifactLocation"]["uri"] == "src/test_module.py"
    assert locations[1]["location"]["physicalLocation"]["region"]["startLine"] == 2
    assert locations[1]["location"]["message"]["text"] == "test violation"


def test_sarif_code_flow_sink_rule() -> None:
    node = ast.parse("def func3():\n    x = func2()\n    eval(x)")
    entity3 = Entity(
        qualname="test_module.func3",
        kind="function",
        node=node.body[0],
        location=Location(path="src/test_module.py", line_start=1, line_end=3),
    )
    entity2 = Entity(
        qualname="test_module.func2",
        kind="function",
        node=ast.parse("def func2():\n    return raw_input()").body[0],
        location=Location(path="src/test_module.py", line_start=4, line_end=5),
    )

    finding = Finding(
        rule_id="PY-WL-107",
        message="eval check",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/test_module.py", line_start=3, line_end=3),
        fingerprint="f" * 64,
        qualname="test_module.func3",
    )

    context = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={"test_module.func3": {"x": TaintState.EXTERNAL_RAW}},
        function_return_taints={},
        function_return_callee={},
        entities={"test_module.func3": entity3, "test_module.func2": entity2},
        taint_provenance={
            "test_module.func3": TaintProvenance(source="callgraph", via_callee=None),
        },
        function_call_site_taints={"test_module.func3": {id(node.body[0].body[1]): {"x": TaintState.EXTERNAL_RAW}}},
    )

    log = build_sarif([finding], context)
    res = log["runs"][0]["results"][0]

    assert "codeFlows" in res
    assert len(res["codeFlows"]) == 1
    locations = res["codeFlows"][0]["threadFlows"][0]["locations"]

    # 1. test_module.func2 (source) -> 2. eval(x) call (sink)
    assert len(locations) == 2
    assert locations[0]["location"]["physicalLocation"]["region"]["startLine"] == 4
    assert locations[0]["location"]["message"]["text"] == "Taint source: test_module.func2"
    assert locations[1]["location"]["physicalLocation"]["region"]["startLine"] == 3
    assert locations[1]["location"]["message"]["text"] == "eval check"


def test_sarif_code_flow_method_calling_top_level_function() -> None:
    entity_method = Entity(
        qualname="test_module.MyClass.my_method",
        kind="method",
        node=ast.parse("def my_method(self):\n    x = helper_func()\n    eval(x)").body[0],
        location=Location(path="src/test_module.py", line_start=1, line_end=3),
    )
    entity_helper = Entity(
        qualname="test_module.helper_func",
        kind="function",
        node=ast.parse("def helper_func():\n    return raw_input()").body[0],
        location=Location(path="src/test_module.py", line_start=4, line_end=5),
    )

    finding = Finding(
        rule_id="PY-WL-107",
        message="eval check",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/test_module.py", line_start=3, line_end=3),
        fingerprint="f" * 64,
        qualname="test_module.MyClass.my_method",
    )

    context = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={"test_module.MyClass.my_method": {"x": TaintState.EXTERNAL_RAW}},
        function_return_taints={},
        function_return_callee={},
        entities={"test_module.MyClass.my_method": entity_method, "test_module.helper_func": entity_helper},
        taint_provenance={
            "test_module.MyClass.my_method": TaintProvenance(source="callgraph", via_callee=None),
        },
        function_call_site_taints={
            "test_module.MyClass.my_method": {id(entity_method.node.body[1]): {"x": TaintState.EXTERNAL_RAW}}
        },
    )

    log = build_sarif([finding], context)
    res = log["runs"][0]["results"][0]

    assert "codeFlows" in res
    assert len(res["codeFlows"]) == 1
    locations = res["codeFlows"][0]["threadFlows"][0]["locations"]

    assert len(locations) == 2
    assert locations[0]["location"]["physicalLocation"]["region"]["startLine"] == 4
    assert locations[0]["location"]["message"]["text"] == "Taint source: test_module.helper_func"
