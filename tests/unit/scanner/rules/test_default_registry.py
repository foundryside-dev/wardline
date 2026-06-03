from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.context import AnalysisContext
from wardline.scanner.rules import build_default_registry


def _analyze(tmp_path: Path, files: dict[str, str]):
    paths = []
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        paths.append(p)
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(sorted(paths), WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, findings


def _empty_context() -> AnalysisContext:
    return AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
    )


def test_default_registry_has_all_builtin_rules() -> None:
    reg = build_default_registry(WardlineConfig())
    ids = {r.rule_id for r in reg.rules}
    assert ids == {
        "PY-WL-101",
        "PY-WL-102",
        "PY-WL-103",
        "PY-WL-104",
        "PY-WL-105",
        "PY-WL-106",
        "PY-WL-107",
        "PY-WL-108",
        "PY-WL-109",
        "PY-WL-110",
        "PY-WL-111",
        "PY-WL-112",
        "PY-WL-113",
        "PY-WL-114",
        "PY-WL-115",
        "PY-WL-116",
        "PY-WL-117",
        "PY-WL-118",
        "PY-WL-119",
        "PY-WL-120",
    }


def test_rules_enable_filters() -> None:
    reg = build_default_registry(WardlineConfig(rules_enable=("PY-WL-101",)))
    assert {r.rule_id for r in reg.rules} == {"PY-WL-101"}
    reg2 = build_default_registry(WardlineConfig(rules_enable=("PY-WL-10[34]",)))  # fnmatch
    assert {r.rule_id for r in reg2.rules} == {"PY-WL-103", "PY-WL-104"}


def test_rules_enable_unknown_pattern_emits_gate_defect() -> None:
    reg = build_default_registry(WardlineConfig(rules_enable=("NO_SUCH_RULE",)))
    assert {r.rule_id for r in reg.rules} == {"WLN-ENGINE-POLICY-CONFIG"}

    findings = reg.run(_empty_context())
    assert len(findings) == 2
    assert all(f.rule_id == "WLN-ENGINE-POLICY-CONFIG" for f in findings)
    assert all(f.kind is Kind.DEFECT and f.severity is Severity.ERROR for f in findings)


def test_rules_severity_overrides_base() -> None:
    reg = build_default_registry(WardlineConfig(rules_severity={"PY-WL-103": "CRITICAL"}))
    rule = next(r for r in reg.rules if r.rule_id == "PY-WL-103")
    assert rule.base_severity == Severity.CRITICAL


def test_rules_severity_none_for_defect_rule_emits_gate_defect_and_uses_default() -> None:
    reg = build_default_registry(WardlineConfig(rules_severity={"PY-WL-101": "NONE"}))
    rule = next(r for r in reg.rules if r.rule_id == "PY-WL-101")
    assert rule.base_severity == Severity.ERROR

    findings = reg.run(_empty_context())
    config_findings = [f for f in findings if f.rule_id == "WLN-ENGINE-POLICY-CONFIG"]
    assert len(config_findings) == 1
    assert config_findings[0].kind is Kind.DEFECT
    assert config_findings[0].severity is Severity.ERROR


def test_analyzer_runs_default_rules_end_to_end(tmp_path) -> None:
    # A @trusted function that leaks raw -> the analyzer (default registry) emits PY-WL-101.
    _, findings = _analyze(
        tmp_path,
        {
            "io.py": "from wardline.decorators import external_boundary\n"
            "@external_boundary\ndef read_raw(p):\n    return p\n",
            "svc.py": "from wardline.decorators import trusted\nfrom io import read_raw\n"
            "@trusted\ndef leaky(p):\n    return read_raw(p)\n",
        },
    )
    defects = [f for f in findings if f.kind == Kind.DEFECT]
    assert any(f.rule_id == "PY-WL-101" and f.qualname == "svc.leaky" for f in defects)


def test_preview_rules_are_non_gating() -> None:
    from wardline.core.finding import Finding, Kind, Location, Maturity, Severity
    from wardline.core.finding import compute_finding_fingerprint as _fp
    from wardline.core.suppression import gate_trips
    from wardline.scanner.context import AnalysisContext, RuleRegistry
    from wardline.scanner.rules.metadata import RuleMetadata

    class DummyPreviewRule:
        rule_id = "PY-WL-TEST-PREVIEW"
        metadata = RuleMetadata(
            rule_id="PY-WL-TEST-PREVIEW",
            base_severity=Severity.ERROR,
            kind=Kind.DEFECT,
            description="test preview rule",
            maturity=Maturity.PREVIEW,
        )

        def __init__(self, base_severity=None):
            pass

        def check(self, context: AnalysisContext) -> list[Finding]:
            return [
                Finding(
                    rule_id=self.rule_id,
                    message="preview finding",
                    severity=Severity.ERROR,
                    kind=Kind.DEFECT,
                    location=Location(path="test.py", line_start=1),
                    fingerprint=_fp(rule_id=self.rule_id, path="test.py", line_start=1),
                )
            ]

    registry = RuleRegistry()
    registry.register(DummyPreviewRule())

    context = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
    )

    findings = registry.run(context)
    assert len(findings) == 1
    assert findings[0].maturity == Maturity.PREVIEW

    # Check that it doesn't trip the gate
    assert not gate_trips(findings, Severity.ERROR)
