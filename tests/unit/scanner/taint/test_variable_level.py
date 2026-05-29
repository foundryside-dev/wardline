from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.taint.variable_level import compute_variable_taints

T = TaintState


def _vt(
    src: str,
    function_taint: TaintState = T.UNKNOWN_RAW,
    taint_map: dict[str, TaintState] | None = None,
) -> dict[str, TaintState]:
    func = ast.parse(src).body[0]
    assert isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
    return compute_variable_taints(func, function_taint, taint_map or {})


def test_literal_is_integral() -> None:
    assert _vt("def f():\n    x = 42\n")["x"] == T.INTEGRAL


def test_parameters_inherit_function_taint() -> None:
    out = _vt("def f(a, b, *c, **d):\n    pass\n", function_taint=T.EXTERNAL_RAW)
    assert out["a"] == out["b"] == out["c"] == out["d"] == T.EXTERNAL_RAW


def test_binop_joins_operands() -> None:
    # a=INTEGRAL, p=function_taint(UNKNOWN_RAW); INTEGRAL ⋈ UNKNOWN_RAW = MIXED_RAW
    out = _vt("def f(p):\n    a = 42\n    b = a + p\n", function_taint=T.UNKNOWN_RAW)
    assert out["a"] == T.INTEGRAL
    assert out["b"] == T.MIXED_RAW


def test_collection_joins_elements_and_empty_is_integral() -> None:
    out = _vt("def f(p):\n    x = [42, p]\n    y = []\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.MIXED_RAW  # INTEGRAL ⋈ EXTERNAL_RAW
    assert out["y"] == T.INTEGRAL


def test_ternary_joins_branches() -> None:
    out = _vt("def f(p):\n    x = 42 if cond else p\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.MIXED_RAW


def test_if_else_merges_branches() -> None:
    src = "def f(p):\n    if c:\n        x = 42\n    else:\n        x = p\n"
    assert _vt(src, function_taint=T.EXTERNAL_RAW)["x"] == T.MIXED_RAW


def test_if_without_else_merges_with_pre_state() -> None:
    # x assigned only in the if-branch; the implicit else is the pre-if value.
    src = "def f():\n    x = 42\n    if c:\n        x = unknown\n"
    # if-branch: x=unknown→function_taint=GUARDED; else(pre)=INTEGRAL → join
    assert _vt(src, function_taint=T.GUARDED)["x"] == T.MIXED_RAW


def test_try_except_merges_branches() -> None:
    src = (
        "def f():\n"
        "    x = unknown\n"
        "    try:\n"
        "        x = 42\n"
        "    except Exception:\n"
        "        x = 7\n"
    )
    # try→INTEGRAL, handler→INTEGRAL → join = INTEGRAL
    assert _vt(src, function_taint=T.EXTERNAL_RAW)["x"] == T.INTEGRAL


def test_for_loop_merges_body_with_pre_loop() -> None:
    # loop may not execute: body assignment joins with pre-loop state
    src = "def f(p):\n    x = 42\n    for i in p:\n        x = i\n"
    out = _vt(src, function_taint=T.UNKNOWN_RAW)
    # i gets iterable(p=UNKNOWN_RAW) taint; x = join(INTEGRAL pre, UNKNOWN_RAW body)
    assert out["x"] == T.MIXED_RAW


def test_walrus_assigns_target() -> None:
    out = _vt("def f(p):\n    if (x := p):\n        pass\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW


def test_tuple_unpack_elementwise() -> None:
    out = _vt("def f(p):\n    a, b = 42, p\n", function_taint=T.EXTERNAL_RAW)
    assert out["a"] == T.INTEGRAL
    assert out["b"] == T.EXTERNAL_RAW


def test_aug_assign_joins_existing() -> None:
    out = _vt("def f(p):\n    x = 42\n    x += p\n", function_taint=T.UNKNOWN_RAW)
    assert out["x"] == T.MIXED_RAW


def test_call_bare_name_resolved_via_taint_map() -> None:
    out = _vt("def f():\n    x = helper()\n", taint_map={"helper": T.GUARDED})
    assert out["x"] == T.GUARDED


def test_call_dotted_name_resolved_via_taint_map() -> None:
    out = _vt("def f():\n    x = mod.fn()\n", taint_map={"mod.fn": T.ASSURED})
    assert out["x"] == T.ASSURED


def test_serialisation_sink_sheds_to_unknown_raw() -> None:
    # Even from a fully-trusted context, json.dumps output is UNKNOWN_RAW.
    out = _vt("def f():\n    x = json.dumps(d)\n", function_taint=T.INTEGRAL)
    assert out["x"] == T.UNKNOWN_RAW


def test_unresolved_call_falls_back_to_function_taint() -> None:
    out = _vt("def f():\n    x = mystery()\n", function_taint=T.GUARDED, taint_map={})
    assert out["x"] == T.GUARDED


def test_nested_function_body_is_skipped() -> None:
    src = "def f():\n    x = 42\n    def inner():\n        y = unknown\n"
    out = _vt(src, function_taint=T.UNKNOWN_RAW)
    assert "x" in out
    assert "y" not in out  # nested scope handled as its own entity


def test_walrus_inside_call_argument_is_captured() -> None:
    # foo(x := json.loads(p)) must bind x to the sink's UNKNOWN_RAW, not leave it
    # to fall back (more-trusted) at a later read. Guards the under-taint gap.
    src = "def f(p):\n    y = foo(x := json.loads(p))\n    z = x\n"
    out = _vt(src, function_taint=T.ASSURED, taint_map={})
    assert out["x"] == T.UNKNOWN_RAW
    assert out["z"] == T.UNKNOWN_RAW


def test_walrus_in_return_is_captured() -> None:
    # Positive control: a walrus in a `return` (routed via the walrus walker)
    # binds the enclosing scope.
    out = _vt("def f(p):\n    return (z := p)\n", function_taint=T.EXTERNAL_RAW)
    assert out["z"] == T.EXTERNAL_RAW


def test_walrus_inside_lambda_does_not_leak_to_enclosing_scope() -> None:
    # A walrus in a lambda body binds the lambda's scope, not f's. The `return`
    # routes through the walrus walker, which must skip the lambda subtree.
    out = _vt("def f(p):\n    return (lambda: (z := p))\n", function_taint=T.EXTERNAL_RAW)
    assert "z" not in out


def test_compute_return_taint_all_shapes() -> None:
    import ast
    import textwrap

    from wardline.core.taints import TaintState as T
    from wardline.scanner.taint.variable_level import compute_return_taint, compute_variable_taints

    tm = {"read_raw": T.EXTERNAL_RAW, "validate": T.ASSURED}

    def rt(src: str) -> T | None:
        node = ast.parse(textwrap.dedent(src)).body[0]
        var_taints = compute_variable_taints(node, T.INTEGRAL, dict(tm))
        return compute_return_taint(node, T.INTEGRAL, dict(tm), var_taints)

    assert rt("def f(p):\n x = read_raw(p)\n return x\n") == T.EXTERNAL_RAW
    assert rt("def f(p):\n return read_raw(p)\n") == T.EXTERNAL_RAW
    assert rt("def f(p):\n return validate(read_raw(p))\n") == T.ASSURED
    assert rt("def f():\n return 1\n") == T.INTEGRAL
    # least-trusted across multiple return paths
    assert rt("def f(p):\n if p:\n  return 1\n return read_raw(p)\n") == T.EXTERNAL_RAW
    # no value-bearing return -> None (nothing to check)
    assert rt("def f():\n return\n") is None
    assert rt("def f():\n pass\n") is None
    # a return inside a NESTED function must not count toward THIS function
    assert rt("def f():\n def g():\n  return read_raw(1)\n return 1\n") == T.INTEGRAL


def test_compute_return_taint_reaches_match_and_except_returns() -> None:
    # Regression: returns reachable only through a match arm or an except handler
    # must be collected (ast.match_case / ast.ExceptHandler are NOT ast.stmt, so a
    # stmt-gated descent silently dropped them -> fail-open under-taint).
    import ast
    import textwrap

    from wardline.core.taints import TaintState as T
    from wardline.scanner.taint.variable_level import compute_return_taint, compute_variable_taints

    tm = {"read_raw": T.EXTERNAL_RAW}

    def rt(src: str) -> T | None:
        node = ast.parse(textwrap.dedent(src)).body[0]
        var_taints = compute_variable_taints(node, T.INTEGRAL, dict(tm))
        return compute_return_taint(node, T.INTEGRAL, dict(tm), var_taints)

    assert rt("def f(p):\n match p:\n  case 1:\n   return read_raw(p)\n  case _:\n   return 1\n") == T.EXTERNAL_RAW
    assert rt("def f(p):\n try:\n  return 1\n except ValueError:\n  return read_raw(p)\n") == T.EXTERNAL_RAW
    # a lambda body return-expr is a separate scope and must not be collected
    assert rt("def f():\n g = lambda: read_raw(1)\n return 1\n") == T.INTEGRAL
