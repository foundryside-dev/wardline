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
    _write(tmp_path, "pkg/service.py",
           "from pkg.io_layer import read_raw\ndef fetch(p):\n    return read_raw(p)\n")
    files = [tmp_path / "pkg/io_layer.py", tmp_path / "pkg/service.py"]

    class _Provider:
        def taint_for(self, entity, ctx):  # noqa: ANN001, ANN201
            from wardline.scanner.taint.provider import FunctionTaint
            if entity.qualname.endswith(".read_raw"):
                return FunctionTaint(body_taint=T.MIXED_RAW, return_taint=T.MIXED_RAW)
            return None

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
    assert any(
        f.rule_id == "WLN-ENGINE-UNKNOWN-IMPORT" and f.kind == Kind.FACT for f in findings
    )


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
    findings = analyzer.analyze(
        [tmp_path / "deep.py", tmp_path / "ok.py"], WardlineConfig(), root=tmp_path
    )
    assert any(f.rule_id == "WLN-ENGINE-FILE-SKIPPED" for f in findings)
    assert any(f.rule_id == "WLN-ENGINE-METRICS" for f in findings)
    ctx = analyzer.last_context
    assert ctx is not None
    assert "ok.ok" in ctx.project_taints          # clean file analysed
    assert "deep.deep" not in ctx.project_taints   # pathological file skipped


def test_analyzer_l2_recursion_boundary_contains_per_function(monkeypatch) -> None:
    # Directly exercise the per-function L2 boundary: if compute_variable_taints
    # raises RecursionError for one function, the analyzer contains it (that
    # function -> empty var-taints) and still produces a context.
    import wardline.scanner.analyzer as analyzer_mod

    real = analyzer_mod.compute_variable_taints

    def _boom(func_node, function_taint, taint_map):  # noqa: ANN001, ANN202
        if any(isinstance(n, ast.Name) and n.id == "boom" for n in ast.walk(func_node)):
            raise RecursionError("simulated deep L2")
        return real(func_node, function_taint, taint_map)

    monkeypatch.setattr(analyzer_mod, "compute_variable_taints", _boom)

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write(root, "m.py", "def a():\n    boom = 1\n    return boom\ndef b():\n    return 1\n")
        analyzer = WardlineAnalyzer()
        analyzer.analyze([root / "m.py"], WardlineConfig(), root=root)
        ctx = analyzer.last_context
        assert ctx is not None
        assert ctx.function_var_taints["m.a"] == {}   # L2 contained
        assert "b" in ctx.function_var_taints["m.b"] or ctx.function_var_taints["m.b"] == {}


def test_analyzer_skips_unparseable_file_with_fact(tmp_path) -> None:
    _write(tmp_path, "bad.py", "def f(:\n")  # syntax error
    _write(tmp_path, "good.py", "def g(): return 1\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(
        [tmp_path / "bad.py", tmp_path / "good.py"], WardlineConfig(), root=tmp_path
    )
    assert any(f.rule_id == "WLN-ENGINE-PARSE-ERROR" and f.kind == Kind.FACT for f in findings)
    assert analyzer.last_context is not None
    assert "good.g" in analyzer.last_context.project_taints
