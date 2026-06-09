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

    assert [f.rule_id for f in findings] == ["RS-WL-108"]
    # repo-relative POSIX path (the Filigree/Location anchor), not the absolute fs path.
    assert findings[0].location.path == "src/m.rs"
    # dumb-but-deterministic slice-1 route: crate=root.name, src_root=root (src/ NOT
    # stripped — full Cargo-aware routing is SP2; provisional_identity disclaims it).
    assert findings[0].qualname == f"{tmp_path.name}.src.m.run"


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


def test_clean_file_yields_no_findings(tmp_path) -> None:
    (tmp_path / "clean.rs").write_text(
        _TRUSTED + 'fn run() {\n    Command::new("ls").arg("-la").output();\n}\n', encoding="utf-8"
    )
    findings = list(RustAnalyzer().analyze([tmp_path / "clean.rs"], _cfg(), root=tmp_path))
    assert findings == []


def test_multiple_files_accumulate_findings(tmp_path) -> None:
    (tmp_path / "a.rs").write_text(_INJECTION, encoding="utf-8")
    (tmp_path / "b.rs").write_text(_INJECTION.replace("fn run()", "fn other()"), encoding="utf-8")
    findings = list(RustAnalyzer().analyze([tmp_path / "a.rs", tmp_path / "b.rs"], _cfg(), root=tmp_path))
    assert sorted(f.location.path for f in findings) == ["a.rs", "b.rs"]
