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


def test_diagnose_resolved_star_module_emits_no_fact() -> None:
    # A statically-resolvable star module (the trust vocabulary, T1.2) is NOT a
    # coverage gap once materialised — it must not produce an UNKNOWN-IMPORT FACT.
    tree = ast.parse("from wardline.decorators import *\n")
    out = diagnose_unknown_imports(
        tree=tree,
        module_path="proj.m",
        project_modules=frozenset(),
        stdlib_keys=frozenset(),
        resolvable_star_modules=frozenset({"wardline.decorators"}),
    )
    assert out == []


def test_diagnose_builtin_marker_named_imports_emit_no_fact() -> None:
    tree = ast.parse("from wardline.decorators import trusted\nfrom wardline.decorators.trust import trust_boundary\n")

    out = diagnose_unknown_imports(
        tree=tree,
        module_path="proj.m",
        project_modules=frozenset(),
        stdlib_keys=frozenset(),
        resolvable_star_modules=frozenset({"wardline.decorators"}),
    )

    assert out == []


def test_diagnose_unresolved_star_module_still_emits_fact() -> None:
    # Fail-closed preserved: any star import we cannot materialise stays an honest FACT.
    tree = ast.parse("from somethirdparty.plugins import *\n")
    out = diagnose_unknown_imports(
        tree=tree,
        module_path="proj.m",
        project_modules=frozenset(),
        stdlib_keys=frozenset(),
        resolvable_star_modules=frozenset({"wardline.decorators"}),
    )
    assert any("somethirdparty.plugins" in d[2] for d in out)


# --- Native / first-party module resolution (Task C) -------------------------
# When wardline.core becomes a compiled (PyO3) module it has NO Python AST in the
# scanned tree, so it drops out of project_modules and would fire UNKNOWN-IMPORT.
# The declarative native-prefix allowlist resolves it. These tests SIMULATE the
# native case by passing an empty project_modules (the obvious "scan self" test
# is green today because the .py files are still present, so it would gate
# nothing).


def test_native_first_party_core_import_resolves_without_project_module() -> None:
    # Post-Rust: wardline.core.registry has no .py in the tree -> absent from
    # project_modules. It must still resolve via the native allowlist.
    tree = ast.parse("from wardline.core.registry import REGISTRY\n")
    out = diagnose_unknown_imports(
        tree=tree,
        module_path="wardline.scanner.grammar",
        project_modules=frozenset(),  # native module NOT present
        stdlib_keys=frozenset(),
    )
    assert out == [], f"native first-party import wrongly flagged: {out}"


def test_native_first_party_decorators_import_resolves() -> None:
    tree = ast.parse("from wardline.decorators import trust_boundary\n")
    out = diagnose_unknown_imports(tree=tree, module_path="x", project_modules=frozenset(), stdlib_keys=frozenset())
    assert out == []


def test_native_allowlist_does_not_suppress_genuine_third_party() -> None:
    # Over-suppression guard: a real unknown third-party import MUST still fire.
    tree = ast.parse("from acme_totally_unknown_pkg import thing\n")
    out = diagnose_unknown_imports(tree=tree, module_path="x", project_modules=frozenset(), stdlib_keys=frozenset())
    assert len(out) == 1 and "acme_totally_unknown_pkg" in out[0][2]


def test_native_allowlist_does_not_suppress_undeclared_wardline_submodule() -> None:
    # Precision: only DECLARED native prefixes resolve. A wardline.* module that is
    # neither a project module nor a declared native prefix must still report, so
    # the allowlist can't silently swallow a real gap.
    tree = ast.parse("from wardline.experimental.zzz import q\n")
    out = diagnose_unknown_imports(tree=tree, module_path="x", project_modules=frozenset(), stdlib_keys=frozenset())
    assert len(out) == 1


def test_native_allowlist_prefix_boundary_is_dotted() -> None:
    # An adjacent prefix that shares a string-prefix but is NOT under the package
    # (wardline.core_helpers vs wardline.core) must NOT be suppressed — guards the
    # ``mod == p or mod.startswith(p + ".")`` boundary against a future ``+ "."`` drop.
    tree = ast.parse("from wardline.core_helpers import q\n")
    out = diagnose_unknown_imports(tree=tree, module_path="x", project_modules=frozenset(), stdlib_keys=frozenset())
    assert len(out) == 1
