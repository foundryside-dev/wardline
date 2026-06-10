from __future__ import annotations

import ast

from wardline.core.config import WardlineConfig
from wardline.core.taints import TaintState
from wardline.scanner.pipeline import L2FunctionInput, ParseProjectInput, run_l2_function_stage, run_parse_project_stage
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider, vocabulary_star_exports

T = TaintState


def test_l2_function_stage_returns_explicit_typed_output() -> None:
    tree = ast.parse("def f(p):\n    x = read_raw(p)\n    sink(x)\n    return x\n")
    node = tree.body[0]
    assert isinstance(node, ast.FunctionDef)
    sink_call = next(
        call
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "sink"
    )

    result = run_l2_function_stage(
        L2FunctionInput(
            node=node,
            function_taint=T.INTEGRAL,
            taint_map={"read_raw": T.EXTERNAL_RAW},
            alias_map={},
            module_prefix="svc",
        )
    )

    assert result.variable_taints["x"] == T.EXTERNAL_RAW
    assert result.return_taint == T.EXTERNAL_RAW
    assert result.return_callee == "read_raw"
    assert result.call_site_arg_taints[id(sink_call)][0] == T.EXTERNAL_RAW


def test_parse_project_stage_returns_typed_modules_and_dirty_scope(tmp_path) -> None:
    path = tmp_path / "m.py"
    path.write_text(
        "from wardline.decorators import external_boundary\n@external_boundary\ndef read_raw(p):\n    return p\n",
        encoding="utf-8",
    )

    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )

    assert result.parse_findings == []
    assert result.dirty_modules == frozenset({"m"})
    assert result.modules[0].module_path == "m"
    assert result.files[0].relpath == "m.py"
    assert result.files[0].module == "m"
    assert result.files[0].entities[0].qualname == "m.read_raw"


def _shadow_project(tmp_path, root: str):  # noqa: ANN001, ANN202
    """Write an app that spoofs ``@trusted`` from a project-local shadow of *root*."""
    app = tmp_path / "app.py"
    app.write_text(
        f"from {root} import trusted\n@trusted\ndef unsafe(p):\n    return p\n",
        encoding="utf-8",
    )
    shadow_pkg = tmp_path / root / "decorators" if root == "wardline" else tmp_path / root
    shadow_pkg.mkdir(parents=True)
    if root == "wardline":
        (tmp_path / "wardline" / "__init__.py").write_text("", encoding="utf-8")
        files = (app, tmp_path / "wardline" / "__init__.py", shadow_pkg / "__init__.py")
    else:
        files = (app, shadow_pkg / "__init__.py")
    (shadow_pkg / "__init__.py").write_text("def trusted(fn):\n    return fn\n", encoding="utf-8")
    return app, files


def test_parse_project_stage_fails_closed_for_shadowed_wardline_decorators(tmp_path) -> None:
    _app, files = _shadow_project(tmp_path, "wardline")
    result = run_parse_project_stage(
        ParseProjectInput(
            files=files,
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    app_module = next(m for m in result.modules if m.module_path == "app")
    seed = app_module.seeds["app.unsafe"]
    assert seed.source == "default"
    assert seed.body_taint == T.UNKNOWN_RAW
    assert "shadowed-roots=" in result.provider_fingerprint
    assert "wardline" in result.provider_fingerprint


def test_parse_project_stage_fails_closed_for_shadowed_weft_markers(tmp_path) -> None:
    # The generalization the codex PR left open: shadowing ``weft_markers`` must also
    # fail closed and the shadow bit must reach the provider fingerprint.
    _app, files = _shadow_project(tmp_path, "weft_markers")
    result = run_parse_project_stage(
        ParseProjectInput(
            files=files,
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    app_module = next(m for m in result.modules if m.module_path == "app")
    seed = app_module.seeds["app.unsafe"]
    assert seed.source == "default"
    assert seed.body_taint == T.UNKNOWN_RAW
    assert "weft_markers" in result.provider_fingerprint


def test_parse_project_stage_unshadowed_fingerprint_is_bare(tmp_path) -> None:
    # No shadow → today's exact (cache/baseline-stable) fingerprint, no suffix.
    path = tmp_path / "m.py"
    path.write_text(
        "from wardline.decorators import trusted\n@trusted\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    assert "shadowed-roots=" not in result.provider_fingerprint
    assert result.provider_fingerprint == DecoratorTaintSourceProvider().fingerprint()
    seed = result.modules[0].seeds["m.f"]
    assert seed.body_taint == T.INTEGRAL


def test_parse_project_stage_records_entity_qualname_config_source_match(tmp_path) -> None:
    # An untrusted_sources entry naming a project entity qualname is APPLIED here
    # (the seed override below) — the match must be reported back to the analyzer
    # so the directive is never misreported as WLN-CONFIG-UNUSED-SOURCE.
    path = tmp_path / "m.py"
    path.write_text("def get_input():\n    return 'x'\n", encoding="utf-8")
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(untrusted_sources=("m.get_input", "elsewhere.unmatched")),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.get_input"]
    assert seed.body_taint == T.EXTERNAL_RAW  # the directive took effect...
    assert result.matched_config_sources == frozenset({"m.get_input"})  # ...and is recorded
    # The unmatched entry is NOT recorded — the unused-source diagnostic stays live.


def test_parse_project_stage_parse_failure_is_gating_error_defect(tmp_path) -> None:
    # A discovered-but-unparseable file is a gate-eligible ERROR DEFECT (fail-closed:
    # unscanned code must not pass the default --fail-on ERROR loop), never a NONE
    # FACT. line_start is ALWAYS set (fallback 1) so the lineless-DEFECT downgrade
    # in suppression.py cannot demote a no-line encoding failure out of the gate.
    from wardline.core.finding import Kind, Severity

    (tmp_path / "syntax.py").write_text("def f(:\n", encoding="utf-8")
    (tmp_path / "enc.py").write_bytes(b'# -*- coding: latin-1 -*-\nx = "\xe9"\n')
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(tmp_path / "syntax.py", tmp_path / "enc.py"),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    by_path = {f.location.path: f for f in result.parse_findings}
    assert set(by_path) == {"syntax.py", "enc.py"}
    for finding in by_path.values():
        assert finding.rule_id == "WLN-ENGINE-PARSE-ERROR"
        assert finding.kind is Kind.DEFECT
        assert finding.severity is Severity.ERROR
        assert finding.location.line_start is not None
    # The syntax error keeps its real line; the encoding error falls back to 1.
    assert by_path["syntax.py"].location.line_start == 1
    assert by_path["enc.py"].location.line_start == 1


def test_parse_project_stage_recursion_skip_stays_nongating_fact(tmp_path) -> None:
    # The fail-closed change is scoped to PARSE failures: the recursion-limit
    # file skip keeps its released non-gating FACT contract (it mirrors
    # WLN-ENGINE-FUNCTION-SKIPPED, surfaced via summary.unanalyzed instead).
    from wardline.core.finding import Kind, Severity

    expr = "p" + " + p" * 3000
    (tmp_path / "deep.py").write_text(f"def deep(p):\n    x = {expr}\n    return x\n", encoding="utf-8")
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(tmp_path / "deep.py",),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(),
            star_exports=vocabulary_star_exports(),
        )
    )
    skips = [f for f in result.parse_findings if f.rule_id == "WLN-ENGINE-FILE-SKIPPED"]
    assert len(skips) == 1
    assert skips[0].kind is Kind.FACT
    assert skips[0].severity is Severity.NONE
