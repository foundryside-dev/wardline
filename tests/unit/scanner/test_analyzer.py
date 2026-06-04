from __future__ import annotations

import ast
import tempfile
import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.core.taints import TaintState as T
from wardline.scanner.analyzer import WardlineAnalyzer


def _write(root: Path, rel: str, src: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


def test_analyzer_emits_metrics_and_computes_transitive_taint(tmp_path) -> None:
    # io_layer.read_raw is anchored MIXED_RAW via a provider; flows up.
    _write(tmp_path, "pkg/io_layer.py", "def read_raw(p):\n    return p\n")
    _write(tmp_path, "pkg/service.py", "from pkg.io_layer import read_raw\ndef fetch(p):\n    return read_raw(p)\n")
    files = [tmp_path / "pkg/io_layer.py", tmp_path / "pkg/service.py"]

    class _Provider:
        def taint_for(self, entity, ctx):  # noqa: ANN001, ANN201
            from wardline.scanner.taint.provider import FunctionTaint, SeedResult

            if entity.qualname.endswith(".read_raw"):
                return SeedResult(taint=FunctionTaint(body_taint=T.MIXED_RAW, return_taint=T.MIXED_RAW))
            return SeedResult(taint=None)

        def fingerprint(self) -> str:
            return "test-v1"

    analyzer = WardlineAnalyzer(provider=_Provider())
    findings = analyzer.analyze(files, WardlineConfig(), root=tmp_path)

    # A metrics finding is always emitted.
    assert any(f.rule_id == "WLN-ENGINE-METRICS" and f.kind == Kind.METRIC for f in findings)
    # Transitive taint is exposed for SP2.
    ctx = analyzer.last_context
    assert ctx is not None
    assert ctx.project_taints["pkg.io_layer.read_raw"] == T.MIXED_RAW
    assert ctx.project_taints["pkg.service.fetch"] == T.MIXED_RAW


def test_analyzer_emits_unknown_import_fact(tmp_path) -> None:
    _write(tmp_path, "app.py", "from some_external_lib import thing\ndef f(): return thing()\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "app.py"], WardlineConfig(), root=tmp_path)
    assert any(f.rule_id == "WLN-ENGINE-UNKNOWN-IMPORT" and f.kind == Kind.FACT for f in findings)


def test_analyzer_default_provider_all_unknown_raw(tmp_path) -> None:
    _write(tmp_path, "m.py", "def f(p):\n    return p\n")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([tmp_path / "m.py"], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    assert set(analyzer.last_context.project_taints.values()) == {T.UNKNOWN_RAW}


def test_analyzer_pathological_deep_expression_skips_file_not_scan(tmp_path) -> None:
    # A deep left-assoc BinOp chain parses fine but recurses in the tree walk
    # (entity discovery, then L2). The file-level boundary must skip the
    # pathological file with a FACT while a clean sibling file is still analysed.
    expr = "p" + " + p" * 3000
    _write(tmp_path, "deep.py", f"def deep(p):\n    x = {expr}\n    return x\n")
    _write(tmp_path, "ok.py", "def ok():\n    return 1\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "deep.py", tmp_path / "ok.py"], WardlineConfig(), root=tmp_path)
    assert any(f.rule_id == "WLN-ENGINE-FILE-SKIPPED" for f in findings)
    assert any(f.rule_id == "WLN-ENGINE-METRICS" for f in findings)
    ctx = analyzer.last_context
    assert ctx is not None
    assert "ok.ok" in ctx.project_taints  # clean file analysed
    assert "deep.deep" not in ctx.project_taints  # pathological file skipped


def test_analyzer_l2_recursion_boundary_contains_per_function(monkeypatch) -> None:
    # Directly exercise the per-function L2 boundary: if the L2 pipeline stage
    # raises RecursionError for one function, the analyzer contains it (that
    # function -> empty var-taints) and still produces a context.
    import wardline.scanner.analyzer as analyzer_mod

    real = analyzer_mod.run_l2_function_stage

    def _boom(stage_input):  # noqa: ANN001, ANN202
        if any(isinstance(n, ast.Name) and n.id == "boom" for n in ast.walk(stage_input.node)):
            raise RecursionError("simulated deep L2")
        return real(stage_input)

    monkeypatch.setattr(analyzer_mod, "run_l2_function_stage", _boom)

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write(root, "m.py", "def a():\n    boom = 1\n    return boom\ndef b():\n    return 1\n")
        analyzer = WardlineAnalyzer()
        findings = analyzer.analyze([root / "m.py"], WardlineConfig(), root=root)
        ctx = analyzer.last_context
        assert ctx is not None
        assert ctx.function_var_taints["m.a"] == {}  # L2 contained
        assert "b" in ctx.function_var_taints["m.b"] or ctx.function_var_taints["m.b"] == {}
        # The contained function is NOT silently dropped — a FACT records the skip
        # so its absent return taint is observable, not an invisible under-taint.
        skips = [f for f in findings if f.rule_id == "WLN-ENGINE-FUNCTION-SKIPPED"]
        assert [f.qualname for f in skips] == ["m.a"]
        assert all(f.kind == Kind.FACT for f in skips)
        assert "m.a" not in ctx.function_return_taints


def test_analyzer_default_provider_seeds_from_decorators(tmp_path) -> None:
    # The DEFAULT provider (no provider= arg) now reads the trust vocabulary and
    # seeds real, non-trivial taints in both directions.
    _write(
        tmp_path,
        "io_layer.py",
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted\ndef constant():\n    return 1\n",
    )
    # An undecorated caller of a single source: fetch's fail-closed floor is
    # UNKNOWN_RAW (rank 6), which is ALREADY less-trusted than its EXTERNAL_RAW
    # (rank 5) callee. The engine only moves non-anchored functions toward
    # less-trusted, so fetch correctly stays UNKNOWN_RAW — EXTERNAL_RAW does not
    # "flow up" into an already-more-tainted caller.
    _write(tmp_path, "service.py", "from io_layer import read_raw\ndef fetch(p):\n    return read_raw(p)\n")
    files = [tmp_path / "io_layer.py", tmp_path / "service.py"]

    analyzer = WardlineAnalyzer()  # default provider
    analyzer.analyze(files, WardlineConfig(), root=tmp_path)
    ctx = analyzer.last_context
    assert ctx is not None
    assert ctx.project_taints["io_layer.read_raw"] == T.EXTERNAL_RAW
    assert ctx.project_taints["io_layer.constant"] == T.INTEGRAL
    assert ctx.project_taints["service.fetch"] == T.UNKNOWN_RAW


def test_analyzer_seeded_taints_drive_transitive_propagation(tmp_path) -> None:
    # The real transitive demonstration: an undecorated function reaching a raw
    # external boundary (EXTERNAL_RAW) alongside a trusted constant (INTEGRAL).
    # The L3 callee-set aggregation is the rank-meet least_trusted (weakest-link),
    # NOT taint_join (wardline-17b9ce2c70): least_trusted(EXTERNAL_RAW, INTEGRAL)
    # = EXTERNAL_RAW, then floored to mix's own UNKNOWN_RAW seed (rank 6) — a
    # genuinely-raw result at its PRECISE rank. taint_join would have spiked it to
    # MIXED_RAW (rank 7), the spurious provenance-clash over-label this migration
    # removes. The raw still propagates (UNKNOWN_RAW is in the firing RAW_ZONE).
    _write(
        tmp_path,
        "m.py",
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef ext(p):\n    return p\n"
        "@trusted\ndef tru():\n    return 1\n"
        "def mix(p):\n    a = ext(p)\n    b = tru()\n    return a if p else b\n",
    )
    analyzer = WardlineAnalyzer()
    analyzer.analyze([tmp_path / "m.py"], WardlineConfig(), root=tmp_path)
    ctx = analyzer.last_context
    assert ctx is not None
    assert ctx.project_taints["m.ext"] == T.EXTERNAL_RAW
    assert ctx.project_taints["m.tru"] == T.INTEGRAL
    assert ctx.project_taints["m.mix"] == T.UNKNOWN_RAW  # raw, floored — NOT MIXED_RAW


def test_analyzer_skips_unparseable_file_with_fact(tmp_path) -> None:
    _write(tmp_path, "bad.py", "def f(:\n")  # syntax error
    _write(tmp_path, "good.py", "def g(): return 1\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "bad.py", tmp_path / "good.py"], WardlineConfig(), root=tmp_path)
    assert any(f.rule_id == "WLN-ENGINE-PARSE-ERROR" and f.kind == Kind.FACT for f in findings)
    assert analyzer.last_context is not None
    assert "good.g" in analyzer.last_context.project_taints


def test_analyzer_emits_no_module_fact(tmp_path) -> None:
    # A top-level __init__.py maps to no module (module_dotted_name -> None) and
    # used to be silently dropped with ZERO findings. The skip must now be
    # OBSERVABLE as a WLN-ENGINE-NO-MODULE FACT. This is its OWN rule_id, distinct
    # from WLN-ENGINE-FILE-SKIPPED — a benign layout artifact (nothing to analyze),
    # NOT a "tried and failed" signal, so it must NOT count as unanalyzed.
    _write(tmp_path, "__init__.py", "VERSION = 1\n")
    _write(tmp_path, "mod.py", "def g(): return 1\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "__init__.py", tmp_path / "mod.py"], WardlineConfig(), root=tmp_path)
    skip = [f for f in findings if f.rule_id == "WLN-ENGINE-NO-MODULE" and f.location.path == "__init__.py"]
    assert len(skip) == 1
    assert skip[0].kind == Kind.FACT
    assert skip[0].properties.get("reason") == "no_module_mapping"
    # It is NOT a FILE-SKIPPED (reserved for genuine analysis failures).
    assert not any(f.rule_id == "WLN-ENGINE-FILE-SKIPPED" for f in findings)
    # The clean sibling is still analysed.
    assert analyzer.last_context is not None
    assert "mod.g" in analyzer.last_context.project_taints


def test_analyzer_exposes_return_taints_and_resolves_validators(tmp_path) -> None:
    # @trust_boundary validator raises trust EXTERNAL_RAW(body) -> ASSURED(return).
    # A @trusted(ASSURED) caller that returns the VALIDATED value must see ASSURED
    # (the validator's RETURN), not EXTERNAL_RAW (its body) — proving the call
    # bucket now resolves callee RETURN taints.
    _write(
        tmp_path,
        "io_layer.py",
        "from wardline.decorators import external_boundary, trust_boundary\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trust_boundary(to_level='ASSURED')\n"
        "def validate(p):\n    if not p:\n        raise ValueError\n    return p\n",
    )
    _write(
        tmp_path,
        "service.py",
        "from wardline.decorators import trusted\n"
        "from io_layer import read_raw, validate\n"
        "@trusted(level='ASSURED')\n"
        "def safe(p):\n    return validate(read_raw(p))\n"
        "@trusted\ndef leaky(p):\n    return read_raw(p)\n",
    )
    files = [tmp_path / "io_layer.py", tmp_path / "service.py"]
    analyzer = WardlineAnalyzer()
    analyzer.analyze(files, WardlineConfig(), root=tmp_path)
    ctx = analyzer.last_context
    assert ctx is not None
    # effective return taint of the validator is its declared return
    assert ctx.project_return_taints["io_layer.validate"] == T.ASSURED
    assert ctx.project_taints["io_layer.validate"] == T.EXTERNAL_RAW  # body unchanged
    # actual returned-value taint per function
    assert ctx.function_return_taints["service.safe"] == T.ASSURED  # validated -> clean
    assert ctx.function_return_taints["service.leaky"] == T.EXTERNAL_RAW  # leaks raw
