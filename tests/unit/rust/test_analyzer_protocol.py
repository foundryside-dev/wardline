"""WP6: ``RustAnalyzer`` satisfies the engine ``Analyzer`` protocol.

The WP5 ``analyze_source`` is the single-string entry the rule tests drive. WP6 adds
the ``analyze(files, config, *, root)`` protocol method ``run_scan`` calls, plus the
two protocol invariants the integration depends on:

* ``last_context`` returns the *Python-shaped* ``AnalysisContext | None`` (None in
  slice-1 — the Rust-native context is incompatible and would crash the delta/SARIF
  consumers; it lives on the separate ``last_rust_context`` accessor); and
* a file tree-sitter cannot fully parse yields a ``WLN-ENGINE-PARSE-ERROR`` FACT and
  contributes NO ``RS-WL-*`` findings (never half-analyze a file), mirroring the
  Python pipeline's parse-error policy so it counts toward ``ScanSummary.unanalyzed``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.config import WardlineConfig  # noqa: E402
from wardline.rust.analyzer import RustAnalyzer  # noqa: E402

_TRUSTED = "/// @trusted(level=ASSURED)\n"
_INJECTION = _TRUSTED + 'fn run() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n'


def _cfg() -> WardlineConfig:
    return WardlineConfig()


def test_analyze_over_files_finds_injection_with_repo_relative_path(tmp_path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "m.rs").write_text(_INJECTION, encoding="utf-8")

    analyzer = RustAnalyzer()
    findings = list(analyzer.analyze([src / "m.rs"], _cfg(), root=tmp_path))

    rs = [f for f in findings if f.rule_id.startswith("RS-WL-")]
    assert [f.rule_id for f in rs] == ["RS-WL-108"]
    # repo-relative POSIX path (the Filigree/Location anchor), not the absolute fs path.
    assert rs[0].location.path == "src/m.rs"
    # No Cargo.toml and no src/lib|main.rs anywhere -> no crate root registers, so the
    # SP2 router falls back to the pre-SP2 mechanical route (crate=root.name, src/ NOT
    # stripped) — byte-unchanged for no-Cargo trees. Real crate-prefixed routes are
    # pinned in tests/unit/rust/test_crate_roots.py.
    assert rs[0].qualname == f"{tmp_path.name}.src.m.run"


def test_last_context_is_none_but_rust_context_is_retained(tmp_path) -> None:
    (tmp_path / "m.rs").write_text(_INJECTION, encoding="utf-8")
    analyzer = RustAnalyzer()
    list(analyzer.analyze([tmp_path / "m.rs"], _cfg(), root=tmp_path))

    # Protocol conformance: the engine ``Analyzer.last_context`` is AnalysisContext|None.
    # Returning the RustAnalysisContext here would fail mypy and crash the delta/SARIF
    # consumers (no .project_edges, wrong field shape). Slice-1 returns None.
    assert analyzer.last_context is None
    # The Rust-native context stays reachable on its own accessor for introspection.
    assert analyzer.last_rust_context is not None
    assert analyzer.last_rust_context.triggers


def test_unparseable_file_emits_parse_error_fact_and_no_rs_findings(tmp_path) -> None:
    # A truncated fn: tree-sitter recovers a partial tree (root_node.has_error). We must
    # surface the diagnostic and NOT report findings over a half-parsed file.
    (tmp_path / "broken.rs").write_text("fn f( {\n    let t = std::env::var(\n", encoding="utf-8")
    findings = list(RustAnalyzer().analyze([tmp_path / "broken.rs"], _cfg(), root=tmp_path))

    parse_errors = [f for f in findings if f.rule_id == "WLN-ENGINE-PARSE-ERROR"]
    assert len(parse_errors) == 1
    assert parse_errors[0].location.path == "broken.rs"
    assert parse_errors[0].severity.value == "NONE"
    assert all(not f.rule_id.startswith("RS-WL-") for f in findings)


def test_coverage_posture_fact_reports_trust_surface(tmp_path) -> None:
    # One @trusted fn + one unmarked fn: the coverage METRIC must report 1 of 2 declared,
    # so a default-clean scan cannot read as a clean PASS when nothing was in the trust surface.
    (tmp_path / "m.rs").write_text(
        _TRUSTED + 'fn declared() {\n    Command::new("ls").output();\n}\n'
        'fn undeclared() {\n    Command::new("ls").output();\n}\n',
        encoding="utf-8",
    )
    findings = list(RustAnalyzer().analyze([tmp_path / "m.rs"], _cfg(), root=tmp_path))
    cov = [f for f in findings if f.rule_id == "WLN-RUST-COVERAGE"]
    assert len(cov) == 1
    assert cov[0].properties["functions_total"] == 2
    assert cov[0].properties["functions_declared"] == 1
    assert cov[0].severity.value == "NONE"


def test_coverage_posture_flags_empty_trust_surface(tmp_path) -> None:
    # A repo with ZERO @trusted markers: every finding is modulated to NONE (default-clean),
    # so the scan is vacuously green. The coverage FACT must expose functions_declared == 0
    # over a non-zero function count — the anti-false-green signal.
    (tmp_path / "m.rs").write_text(
        'fn a() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n',
        encoding="utf-8",
    )
    findings = list(RustAnalyzer().analyze([tmp_path / "m.rs"], _cfg(), root=tmp_path))
    assert [f for f in findings if f.rule_id.startswith("RS-WL-")] == []  # vacuously clean
    (cov,) = [f for f in findings if f.rule_id == "WLN-RUST-COVERAGE"]
    assert cov.properties["functions_declared"] == 0
    assert cov.properties["functions_total"] == 1


def test_non_callable_entities_do_not_enter_taint_analysis(tmp_path) -> None:
    # Phase 1b: the index now emits struct/enum/const/trait (etc.) rows. The taint
    # path must judge CALLABLES ONLY — leaf entities have no body/trust marker, so
    # feeding them to taint_for/dataflow would crash or fabricate findings, and the
    # coverage METRIC's functions_total must keep counting callables only.
    src = 'struct Cfg;\npub enum Mode { A }\npub const NAME: &str = "x";\npub trait Run {}\n' + _INJECTION
    (tmp_path / "m.rs").write_text(src, encoding="utf-8")
    findings = list(RustAnalyzer().analyze([tmp_path / "m.rs"], _cfg(), root=tmp_path))
    rs = [f for f in findings if f.rule_id.startswith("RS-WL-")]
    assert [f.rule_id for f in rs] == ["RS-WL-108"]  # exactly the one fn's finding
    assert all(f.qualname is not None and f.qualname.endswith(".run") for f in rs)
    (cov,) = [f for f in findings if f.rule_id == "WLN-RUST-COVERAGE"]
    assert cov.properties["functions_total"] == 1  # callables only, not 5
    assert cov.properties["functions_declared"] == 1


def test_fn_struct_same_name_keeps_both_entities_and_counts_one_callable(tmp_path) -> None:
    # Keystone panel: `fn S` and `struct S` share a qualname (the per-kind twin counter
    # deliberately adds no @cfg suffix across kinds), so a context map keyed on qualname
    # alone silently drops one of them at dict-ification. The context must keep BOTH
    # (keys are kind-disambiguated entity ids) and the coverage denominator counts the
    # ONE callable — computed from the entity list, never the (collapsible) mapping.
    src = (
        "struct S { x: i32 }\n"
        + _TRUSTED
        + 'fn S() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n'
    )
    (tmp_path / "m.rs").write_text(src, encoding="utf-8")
    analyzer = RustAnalyzer()
    findings = list(analyzer.analyze([tmp_path / "m.rs"], _cfg(), root=tmp_path))

    rs = [f for f in findings if f.rule_id.startswith("RS-WL-")]
    assert [f.rule_id for f in rs] == ["RS-WL-108"]  # the fn IS exercised
    ctx = analyzer.last_rust_context
    assert ctx is not None
    qual = f"{tmp_path.name}.m.S"
    # BOTH entities survive, addressable by their kind-disambiguated entity-id keys.
    assert f"rust:struct:{qual}" in ctx.entities
    assert f"rust:function:{qual}" in ctx.entities
    assert {(e.kind, e.qualname) for e in ctx.entities.values()} >= {("struct", qual), ("function", qual)}
    (cov,) = [f for f in findings if f.rule_id == "WLN-RUST-COVERAGE"]
    assert cov.properties["functions_total"] == 1  # one callable, not two, not zero
    assert cov.properties["functions_declared"] == 1


def test_clean_file_yields_no_findings(tmp_path) -> None:
    (tmp_path / "clean.rs").write_text(
        _TRUSTED + 'fn run() {\n    Command::new("ls").arg("-la").output();\n}\n', encoding="utf-8"
    )
    findings = list(RustAnalyzer().analyze([tmp_path / "clean.rs"], _cfg(), root=tmp_path))
    assert [f for f in findings if f.rule_id.startswith("RS-WL-")] == []


def test_multiple_files_accumulate_findings(tmp_path) -> None:
    (tmp_path / "a.rs").write_text(_INJECTION, encoding="utf-8")
    (tmp_path / "b.rs").write_text(_INJECTION.replace("fn run()", "fn other()"), encoding="utf-8")
    findings = list(RustAnalyzer().analyze([tmp_path / "a.rs", tmp_path / "b.rs"], _cfg(), root=tmp_path))
    rs = [f for f in findings if f.rule_id.startswith("RS-WL-")]
    assert sorted(f.location.path for f in rs) == ["a.rs", "b.rs"]


def test_one_crashing_file_is_isolated_and_does_not_lose_other_findings(tmp_path) -> None:
    # A clean-parsing but pathologically deep expression overflows the recursive dataflow
    # walk (RecursionError). Per-file isolation must degrade THAT file to a counted
    # WLN-ENGINE-FILE-FAILED FACT and still emit the OTHER file's real RS-WL-108 — never
    # abort the whole scan (the engine's per-function isolation, mirrored per-file).
    deep_expr = "+".join(["x"] * 6000)  # nested binary_expression depth >> default recursionlimit
    deep = tmp_path / "deep.rs"
    deep.write_text(
        f"/// @trusted(level=ASSURED)\nfn boom() {{\n    let t = {deep_expr};\n    Command::new(t).output();\n}}\n",
        encoding="utf-8",
    )
    inject = tmp_path / "inject.rs"
    inject.write_text(_INJECTION, encoding="utf-8")

    # deep.rs FIRST so the crash precedes the clean file — isolation must let inject.rs through.
    findings = list(RustAnalyzer().analyze([deep, inject], _cfg(), root=tmp_path))

    file_failed = [f for f in findings if f.rule_id == "WLN-ENGINE-FILE-FAILED"]
    assert len(file_failed) == 1 and file_failed[0].location.path == "deep.rs"
    assert file_failed[0].severity.value == "NONE"
    # The other file's real finding survived the neighbour's crash.
    survivors = [f for f in findings if f.rule_id == "RS-WL-108"]
    assert len(survivors) == 1 and survivors[0].location.path == "inject.rs"
