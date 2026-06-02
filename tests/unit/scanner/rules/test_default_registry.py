from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
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


def test_default_registry_has_all_builtin_rules() -> None:
    reg = build_default_registry(WardlineConfig())
    ids = {r.rule_id for r in reg.rules}
    assert ids == {"PY-WL-101", "PY-WL-102", "PY-WL-103", "PY-WL-104", "PY-WL-110"}


def test_rules_enable_filters() -> None:
    reg = build_default_registry(WardlineConfig(rules_enable=("PY-WL-101",)))
    assert {r.rule_id for r in reg.rules} == {"PY-WL-101"}
    reg2 = build_default_registry(WardlineConfig(rules_enable=("PY-WL-10[34]",)))  # fnmatch
    assert {r.rule_id for r in reg2.rules} == {"PY-WL-103", "PY-WL-104"}


def test_rules_severity_overrides_base() -> None:
    reg = build_default_registry(WardlineConfig(rules_severity={"PY-WL-103": "CRITICAL"}))
    rule = next(r for r in reg.rules if r.rule_id == "PY-WL-103")
    assert rule.base_severity == Severity.CRITICAL


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
