from __future__ import annotations

import ast

from wardline.core.config import WardlineConfig
from wardline.core.taints import TaintState
from wardline.scanner.pipeline import L2FunctionInput, ParseProjectInput, run_l2_function_stage, run_parse_project_stage
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider, vocabulary_star_exports

T = TaintState


def test_l2_function_stage_returns_explicit_typed_output() -> None:
    tree = ast.parse(
        "def f(p):\n"
        "    x = read_raw(p)\n"
        "    sink(x)\n"
        "    return x\n"
    )
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
        "from wardline.decorators import external_boundary\n"
        "@external_boundary\n"
        "def read_raw(p):\n"
        "    return p\n",
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
