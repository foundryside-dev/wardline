# tests/unit/scanner/rules/test_sink_machinery.py
"""Unit tests for the shared sink-resolution machinery in ``_sink_helpers``.

Covers the three additive capabilities (consumers wire in separately):
  1. CONSTRUCT-THEN-METHOD: ``obj.method(...)`` resolves to ``<ClassFqn>.method``
     when the receiver's class is statically known in the function (direct
     construction, chained construction, with/async-with targets, ann-assign).
  2. VARIABLE-BINDING ALIAS: ``runner = subprocess.run; runner(...)`` participates
     in sink matching under the resolved FQN (module- or function-level).
  3. ARG-POSITION-AWARE matching: an :class:`ArgSpec` restricts taint resolution
     to the declared dangerous argument slots; no spec keeps "worst of all args".
"""

from __future__ import annotations

import ast
import textwrap

from wardline.core.taints import TaintState
from wardline.scanner.context import AnalysisContext
from wardline.scanner.rules._sink_helpers import (
    ArgSpec,
    SinkBindings,
    collect_sink_bindings,
    resolve_bound_call_fqn,
    resolved_sink_calls,
    worst_dangerous_arg_taint,
)


def _last_def(src: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    node = ast.parse(textwrap.dedent(src)).body[-1]
    assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    return node


def _module(src: str) -> ast.Module:
    return ast.parse(textwrap.dedent(src))


def _sinks(
    func: ast.AST,
    sink_names: set[str],
    alias_map: dict[str, str] | None = None,
    module_bindings: SinkBindings | None = None,
) -> list[str]:
    return [
        fqn
        for _call, fqn in resolved_sink_calls(
            func, frozenset(sink_names), alias_map or {}, "m", module_bindings=module_bindings
        )
    ]


# ---------------------------------------------------------------------------
# Capability 1: construct-then-method
# ---------------------------------------------------------------------------


def test_direct_construction_resolves_method_to_class_fqn() -> None:
    func = _last_def(
        """
        def f(u):
            c = httpx.Client()
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == ["httpx.Client.get"]


def test_chained_construction_resolves() -> None:
    func = _last_def(
        """
        def f(u):
            a = httpx.Client().get(u)
            b = requests.Session().get(u)
            return a, b
        """
    )
    assert _sinks(
        func,
        {"httpx.Client.get", "requests.Session.get"},
        {"httpx": "httpx", "requests": "requests"},
    ) == ["httpx.Client.get", "requests.Session.get"]


def test_with_target_resolves() -> None:
    func = _last_def(
        """
        def f(u):
            with httpx.Client() as c:
                return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == ["httpx.Client.get"]


def test_async_with_target_resolves() -> None:
    func = _last_def(
        """
        async def f(u):
            async with httpx.AsyncClient() as client:
                return await client.get(u)
        """
    )
    assert _sinks(func, {"httpx.AsyncClient.get"}, {"httpx": "httpx"}) == ["httpx.AsyncClient.get"]


def test_ann_assign_annotation_resolves() -> None:
    # A bare annotation (no value) is a declaration of the var's class.
    func = _last_def(
        """
        def f(u, factory):
            c: httpx.Client
            c = factory()
            return c.get(u)
        """
    )
    # The later factory() rebind is unresolvable and invalidates — annotation
    # alone (without an intervening unresolvable rebind) must resolve:
    func2 = _last_def(
        """
        def f(u):
            c: httpx.Client = make_client()
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == []
    assert _sinks(func2, {"httpx.Client.get"}, {"httpx": "httpx"}) == ["httpx.Client.get"]


def test_construction_honors_import_alias() -> None:
    func = _last_def(
        """
        def f(u):
            c = hx.Client()
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"hx": "httpx"}) == ["httpx.Client.get"]


def test_rebind_to_different_class_uses_new_class_never_stale() -> None:
    func = _last_def(
        """
        def f(u):
            c = httpx.Client()
            c = requests.Session()
            return c.get(u)
        """
    )
    alias = {"httpx": "httpx", "requests": "requests"}
    # last-binding-wins: the stale httpx class must NOT match
    assert _sinks(func, {"httpx.Client.get"}, alias) == []
    assert _sinks(func, {"requests.Session.get"}, alias) == ["requests.Session.get"]


def test_rebind_to_unresolvable_invalidates() -> None:
    # rebind via a non-dotted callable (subscript) — class no longer known
    func = _last_def(
        """
        def f(u, factories):
            c = httpx.Client()
            c = factories[0]()
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == []


def test_rebind_to_constant_invalidates() -> None:
    func = _last_def(
        """
        def f(u):
            c = httpx.Client()
            c = None
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == []


def test_tuple_unpack_rebind_invalidates() -> None:
    func = _last_def(
        """
        def f(u, pair):
            c = httpx.Client()
            c, d = pair
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == []


def test_unknown_class_method_never_matches() -> None:
    func = _last_def(
        """
        def f(u):
            c = mystery.Thing()
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == []


def test_method_on_unbound_name_never_matches() -> None:
    func = _last_def(
        """
        def f(u, c):
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == []


def test_nested_def_bindings_do_not_leak_into_outer_scope() -> None:
    func = _last_def(
        """
        def f(u):
            def g():
                c = httpx.Client()
                return c
            c = g()
            return c.get(u)
        """
    )
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}) == []


# ---------------------------------------------------------------------------
# Capability 2: variable-binding alias of a sink
# ---------------------------------------------------------------------------


def test_function_level_callable_alias_matches() -> None:
    func = _last_def(
        """
        def f(raw):
            runner = subprocess.run
            runner(raw, shell=True)
        """
    )
    assert _sinks(func, {"subprocess.run"}, {"subprocess": "subprocess"}) == ["subprocess.run"]


def test_from_import_alias_callable_binding() -> None:
    func = _last_def(
        """
        def f(raw):
            runner = run
            runner(raw)
        """
    )
    # ``from subprocess import run`` puts {"run": "subprocess.run"} in the alias map
    assert _sinks(func, {"subprocess.run"}, {"run": "subprocess.run"}) == ["subprocess.run"]


def test_builtin_callable_alias() -> None:
    func = _last_def(
        """
        def f(raw):
            do = eval
            do(raw)
        """
    )
    assert _sinks(func, {"eval"}) == ["eval"]


def test_module_level_callable_alias_via_module_bindings() -> None:
    mod = _module(
        """
        runner = subprocess.run

        def f(raw):
            runner(raw, shell=True)
        """
    )
    module_bindings = collect_sink_bindings(mod, {"subprocess": "subprocess"}, "m")
    func = mod.body[-1]
    assert _sinks(func, {"subprocess.run"}, {"subprocess": "subprocess"}, module_bindings) == ["subprocess.run"]


def test_module_level_instance_binding_via_module_bindings() -> None:
    mod = _module(
        """
        client = httpx.Client()

        def f(u):
            return client.get(u)
        """
    )
    module_bindings = collect_sink_bindings(mod, {"httpx": "httpx"}, "m")
    func = mod.body[-1]
    assert _sinks(func, {"httpx.Client.get"}, {"httpx": "httpx"}, module_bindings) == ["httpx.Client.get"]


def test_function_rebind_shadows_module_alias() -> None:
    mod = _module(
        """
        runner = subprocess.run

        def f(raw, other):
            runner = other
            runner(raw)
        """
    )
    module_bindings = collect_sink_bindings(mod, {"subprocess": "subprocess"}, "m")
    func = mod.body[-1]
    assert _sinks(func, {"subprocess.run"}, {"subprocess": "subprocess"}, module_bindings) == []


def test_alias_of_non_sink_never_matches() -> None:
    func = _last_def(
        """
        def f(raw):
            runner = os.path.join
            runner(raw)
        """
    )
    assert _sinks(func, {"subprocess.run"}, {"os": "os", "subprocess": "subprocess"}) == []


def test_alias_rebind_last_binding_wins() -> None:
    func = _last_def(
        """
        def f(raw):
            runner = subprocess.run
            runner = print
            runner(raw)
        """
    )
    assert _sinks(func, {"subprocess.run"}, {"subprocess": "subprocess"}) == []


def test_direct_sink_calls_still_match_alongside_bindings() -> None:
    # the extended iterator is a superset of sink_calls: direct dotted spellings keep working
    func = _last_def(
        """
        def f(raw):
            runner = subprocess.run
            runner(raw)
            subprocess.run(raw, shell=True)
        """
    )
    assert _sinks(func, {"subprocess.run"}, {"subprocess": "subprocess"}) == [
        "subprocess.run",
        "subprocess.run",
    ]


def test_collect_sink_bindings_separates_kinds() -> None:
    func = _last_def(
        """
        def f():
            c = httpx.Client()
            runner = subprocess.run
        """
    )
    bindings = collect_sink_bindings(func, {"httpx": "httpx", "subprocess": "subprocess"}, "m")
    assert bindings.instance_classes == {"c": "httpx.Client"}
    assert bindings.callable_aliases == {"runner": "subprocess.run"}


def test_resolve_bound_call_fqn_negative_paths() -> None:
    bindings = SinkBindings(instance_classes={"c": "httpx.Client"}, callable_aliases={})
    # dynamic receiver (subscript) resolves to nothing
    call = ast.parse("x[0].get(u)").body[0].value
    assert isinstance(call, ast.Call)
    assert resolve_bound_call_fqn(call, bindings, {}, "m") is None
    # plain name call with no alias binding resolves to nothing
    call2 = ast.parse("runner(u)").body[0].value
    assert isinstance(call2, ast.Call)
    assert resolve_bound_call_fqn(call2, bindings, {}, "m") is None


# ---------------------------------------------------------------------------
# Capability 3: arg-position-aware matching
# ---------------------------------------------------------------------------


def _call(src: str) -> ast.Call:
    call = ast.parse(src).body[0].value  # type: ignore[attr-defined]
    assert isinstance(call, ast.Call)
    return call


def _ctx(call: ast.Call, taints: dict[int | str | None, TaintState]) -> AnalysisContext:
    return AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
        function_call_site_arg_taints={"m.f": {id(call): taints}},
    )


def test_no_spec_keeps_worst_of_all_args() -> None:
    call = _call("requests.get(a, b)")
    ctx = _ctx(call, {0: TaintState.ASSURED, 1: TaintState.EXTERNAL_RAW})
    assert worst_dangerous_arg_taint(call, "m.f", ctx, None) == TaintState.EXTERNAL_RAW


def test_spec_restricts_to_dangerous_positions() -> None:
    # position 0 (the URL) is trusted; the raw arg sits in a non-dangerous slot
    call = _call("requests.get(a, b)")
    ctx = _ctx(call, {0: TaintState.ASSURED, 1: TaintState.EXTERNAL_RAW})
    spec = ArgSpec(positions=(0,))
    assert worst_dangerous_arg_taint(call, "m.f", ctx, spec) == TaintState.ASSURED


def test_spec_matches_dangerous_keyword() -> None:
    call = _call("requests.get(timeout=t, url=u)")
    ctx = _ctx(call, {"timeout": TaintState.ASSURED, "url": TaintState.EXTERNAL_RAW})
    spec = ArgSpec(positions=(0,), keywords=("url",))
    assert worst_dangerous_arg_taint(call, "m.f", ctx, spec) == TaintState.EXTERNAL_RAW


def test_spec_with_no_dangerous_args_present_returns_none() -> None:
    call = _call("requests.get(timeout=t)")
    ctx = _ctx(call, {"timeout": TaintState.EXTERNAL_RAW})
    spec = ArgSpec(positions=(0,), keywords=("url",))
    assert worst_dangerous_arg_taint(call, "m.f", ctx, spec) is None


def test_starred_positional_is_included_fail_closed() -> None:
    # *parts may land in ANY positional slot — fail closed when positions are dangerous
    call = _call("requests.get(*parts, t)")
    ctx = _ctx(
        call,
        {0: TaintState.EXTERNAL_RAW, "*0": TaintState.EXTERNAL_RAW, 1: TaintState.ASSURED},
    )
    spec = ArgSpec(positions=(0,))
    assert worst_dangerous_arg_taint(call, "m.f", ctx, spec) == TaintState.EXTERNAL_RAW


def test_starred_not_included_when_only_keywords_dangerous() -> None:
    call = _call("requests.get(*parts, url=u)")
    ctx = _ctx(
        call,
        {0: TaintState.EXTERNAL_RAW, "*0": TaintState.EXTERNAL_RAW, "url": TaintState.ASSURED},
    )
    spec = ArgSpec(keywords=("url",))
    assert worst_dangerous_arg_taint(call, "m.f", ctx, spec) == TaintState.ASSURED


def test_double_star_kwargs_included_for_dangerous_keywords_fail_closed() -> None:
    # **kw may supply any keyword — fail closed when keywords are dangerous
    call = _call("requests.get(**kw)")
    ctx = _ctx(call, {None: TaintState.EXTERNAL_RAW})
    spec = ArgSpec(keywords=("url",))
    assert worst_dangerous_arg_taint(call, "m.f", ctx, spec) == TaintState.EXTERNAL_RAW


def test_double_star_kwargs_not_included_when_only_positions_dangerous() -> None:
    call = _call("requests.get(a, **kw)")
    ctx = _ctx(call, {0: TaintState.ASSURED, None: TaintState.EXTERNAL_RAW})
    spec = ArgSpec(positions=(0,))
    assert worst_dangerous_arg_taint(call, "m.f", ctx, spec) == TaintState.ASSURED


def test_missing_snapshot_falls_back_pessimistic_for_dangerous_slot() -> None:
    import warnings

    call = _call("requests.get(u)")
    ctx = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
    )
    spec = ArgSpec(positions=(0,))
    # The degradation is RECORDED on the context (surfaced by the analyzer as one
    # WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK FACT per scan), never warned — a
    # warnings-as-error embedder must not lose a whole rule to the diagnostic.
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert worst_dangerous_arg_taint(call, "m.f", ctx, spec) == TaintState.UNKNOWN_RAW
    assert ctx.flow_insensitive_fallbacks == {"m.f"}
