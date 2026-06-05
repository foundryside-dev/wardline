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


def test_parse_project_stage_fails_closed_for_shadowed_loom_markers(tmp_path) -> None:
    # The generalization the codex PR left open: shadowing ``loom_markers`` must also
    # fail closed and the shadow bit must reach the provider fingerprint.
    _app, files = _shadow_project(tmp_path, "loom_markers")
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
    assert "loom_markers" in result.provider_fingerprint


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
