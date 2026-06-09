from __future__ import annotations

import ast

from wardline.core.finding import ENGINE_PATH, Finding, Kind, Location, Severity
from wardline.scanner.diagnostics import _fingerprint as _diag_fp
from wardline.scanner.diagnostics import (
    build_collision_findings,
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


# --- Fingerprint-collision guard (wardline-8fb773a7af) -----------------------
# Every fingerprint consumer (baseline/judged/waivers/filigree_emit/sarif) treats
# Finding.fingerprint as a UNIQUE join key — baseline (setdefault) and judged
# (last-write-wins) SILENTLY collapse same-fp findings, the three YAML loaders
# REJECT duplicate fps, and SARIF/Filigree dedup downstream. So two *distinct*
# findings sharing a fingerprint is always a soundness defect (one masks the
# other). Two *byte-identical* findings are a benign duplicate (collapsing loses
# nothing) and must NOT fire. The guard converts the silent mask into a loud
# ERROR/DEFECT engine diagnostic at the analyzer chokepoint.


def _forge(fp: str, *, rule_id: str = "PY-WL-114", message: str = "m", line: int | None = 3) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=message,
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="a.py", line_start=line),
        fingerprint=fp,
    )


def test_collision_guard_flags_distinct_findings_sharing_a_fingerprint() -> None:
    fp = "a" * 64
    out = build_collision_findings([_forge(fp, message="first"), _forge(fp, message="second")])
    assert len(out) == 1
    diag = out[0]
    assert diag.rule_id == "WLN-ENGINE-FINGERPRINT-COLLISION"
    assert diag.severity == Severity.ERROR  # trips --fail-on ERROR (WLN-L3-MONOTONICITY precedent)
    assert diag.kind == Kind.DEFECT
    assert diag.location.path == ENGINE_PATH  # lineless ENGINE_PATH DEFECT still gates (suppression.py:40)
    assert fp in diag.message
    assert diag.properties["colliding_fingerprint"] == fp
    assert diag.properties["finding_count"] == 2


def test_collision_guard_ignores_byte_identical_duplicates() -> None:
    # A rule that emits the SAME finding twice is a benign duplicate — collapsing
    # on the join key loses nothing, so it is NOT a collision.
    fp = "b" * 64
    out = build_collision_findings([_forge(fp, message="same"), _forge(fp, message="same")])
    assert out == []


def test_collision_guard_clean_set_emits_nothing() -> None:
    out = build_collision_findings([_forge("c" * 64), _forge("d" * 64, rule_id="PY-WL-101")])
    assert out == []


def test_collision_guard_distinguishes_on_any_consumer_visible_field() -> None:
    # Same fp, identical message, but differing properties => still a lossy collapse.
    fp = "e" * 64
    a = Finding("PY-WL-114", "m", Severity.ERROR, Kind.DEFECT, Location("a.py", 3), fp, properties={"k": 1})
    b = Finding("PY-WL-114", "m", Severity.ERROR, Kind.DEFECT, Location("a.py", 3), fp, properties={"k": 2})
    out = build_collision_findings([a, b])
    assert len(out) == 1
    # finding_count and members must agree on the SAME distinctness key — a
    # properties-only difference must be counted AND listed (one member per distinct).
    assert out[0].properties["finding_count"] == 2
    assert len(out[0].properties["members"]) == 2
    assert {m["properties"]["k"] for m in out[0].properties["members"]} == {1, 2}


def test_collision_guard_is_deterministic_and_per_group() -> None:
    fp1, fp2 = "1" * 64, "2" * 64
    # Pass groups out of fingerprint order to prove the output is sorted by colliding fp.
    out = build_collision_findings(
        [_forge(fp2, message="x"), _forge(fp1, message="y"), _forge(fp2, message="z"), _forge(fp1, message="w")]
    )
    assert [d.properties["colliding_fingerprint"] for d in out] == [fp1, fp2]
    # Each diagnostic's OWN fingerprint is keyed on its colliding fp => distinct + stable.
    assert out[0].fingerprint == _diag_fp("WLN-ENGINE-FINGERPRINT-COLLISION", fp1)
    assert out[1].fingerprint == _diag_fp("WLN-ENGINE-FINGERPRINT-COLLISION", fp2)
    assert out[0].fingerprint != out[1].fingerprint


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
