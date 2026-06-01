from __future__ import annotations

import ast

from wardline.core.finding import Kind, Severity
from wardline.scanner.diagnostics import (
    build_diagnostic_findings,
    build_metric_finding,
    build_unknown_import_findings,
    diagnose_unknown_imports,
)
from wardline.scanner.taint.resolver_metadata import ResolverRunMetadata


def _meta() -> ResolverRunMetadata:
    return ResolverRunMetadata(
        scc_size_distribution=((1, 3),),
        convergence_iterations_max=1,
        convergence_iterations_histogram=((1, 3),),
        taint_source_counts={"anchored": 1, "module_default": 0, "fallback": 2},
    )


def test_metric_finding_is_metric_kind_none_severity() -> None:
    f = build_metric_finding(_meta(), cache_hit_rate=0.5)
    assert f.kind == Kind.METRIC
    assert f.severity == Severity.NONE
    assert f.properties["convergence_iterations_max"] == 1
    assert f.properties["cache_hit_rate"] == 0.5
    assert f.properties["taint_source_counts"]["anchored"] == 1


def test_metric_finding_fingerprint_stable_across_values() -> None:
    # Fingerprint is keyed on metric IDENTITY, not the (drifting) values.
    a = build_metric_finding(_meta(), cache_hit_rate=0.0)
    b = build_metric_finding(_meta(), cache_hit_rate=1.0)
    assert a.fingerprint == b.fingerprint


def test_l3_diagnostic_findings_map_code_to_severity() -> None:
    diags = [
        ("L3_MONOTONICITY_VIOLATION", "func x moved up"),
        ("L3_CONVERGENCE_BOUND", "SCC of size 3 hit bound"),
        ("L3_LOW_RESOLUTION", "Function m.f has 80% unresolved (4/5)"),
    ]
    out = {f.rule_id: f for f in build_diagnostic_findings(diags)}
    assert out["WLN-L3-MONOTONICITY-VIOLATION"].severity == Severity.ERROR
    assert out["WLN-L3-MONOTONICITY-VIOLATION"].kind == Kind.DEFECT
    assert out["WLN-L3-CONVERGENCE-BOUND"].severity == Severity.WARN
    assert out["WLN-L3-LOW-RESOLUTION"].severity == Severity.INFO
    assert out["WLN-L3-LOW-RESOLUTION"].kind == Kind.METRIC


def test_unknown_diagnostic_code_is_error_not_silent() -> None:
    out = build_diagnostic_findings([("MYSTERY_CODE", "???")])
    assert out[0].severity == Severity.ERROR
    assert "MYSTERY_CODE" in out[0].message


def test_diagnose_unknown_imports_flags_external_named_import() -> None:
    tree = ast.parse("from external_pkg import thing\n")
    out = diagnose_unknown_imports(
        tree=tree,
        module_path="m",
        project_modules=frozenset({"m"}),
        stdlib_keys=frozenset(),
    )
    assert len(out) == 1
    assert out[0][0] == "m"
    assert "external_pkg" in out[0][2]


def test_diagnose_unknown_imports_skips_stdlib_and_project_and_relative() -> None:
    tree = ast.parse(
        "import os\n"
        "from typing import TYPE_CHECKING\n"
        "from m import sibling\n"  # project module
        "from . import rel\n"  # relative
    )
    out = diagnose_unknown_imports(
        tree=tree,
        module_path="m.sub",
        project_modules=frozenset({"m", "m.sub"}),
        stdlib_keys=frozenset(),
    )
    assert out == []


def test_unknown_import_findings_are_facts() -> None:
    tree = ast.parse("from external_pkg import thing\n")
    findings = build_unknown_import_findings(
        [("pkg/mod.py", "pkg.mod", tree)],
        project_modules=frozenset({"pkg.mod"}),
    )
    assert len(findings) == 1
    assert findings[0].kind == Kind.FACT
    assert findings[0].rule_id == "WLN-ENGINE-UNKNOWN-IMPORT"
    # Fingerprint stable from (module, package) — not message text.
    again = build_unknown_import_findings([("pkg/mod.py", "pkg.mod", tree)], project_modules=frozenset({"pkg.mod"}))
    assert findings[0].fingerprint == again[0].fingerprint
