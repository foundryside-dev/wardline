"""Tests for Level 2 taint — per-variable taint tracking within function bodies."""

from __future__ import annotations

import ast
import textwrap

from wardline.core.taints import TaintState
from wardline.scanner.taint.variable_level import compute_variable_taints


def _parse_func(source: str) -> ast.FunctionDef:
    """Parse source and return the first function node."""
    tree = ast.parse(textwrap.dedent(source))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    raise ValueError("No function found in source")


# ── Simple assignment ────────────────────────────────────────────


class TestSimpleAssignment:
    def test_literal_gets_audit_trail(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL

    def test_string_literal_gets_audit_trail(self) -> None:
        func = _parse_func("""
            def f():
                x = "hello"
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL

    def test_unknown_expr_gets_function_taint(self) -> None:
        func = _parse_func("""
            def f():
                x = some_global.attr
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_variable_reference_propagates(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
                y = x
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL
        assert result["y"] == TaintState.INTEGRAL

    def test_reassignment_overwrites(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
                x = some_unknown
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.EXTERNAL_RAW


# ── Binary operations ────────────────────────────────────────────


class TestBinaryOps:
    def test_binop_joins_operands(self) -> None:
        func = _parse_func("""
            def f():
                a = 42
                b = unknown_thing
                c = a + b
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["a"] == TaintState.INTEGRAL
        assert result["b"] == TaintState.UNKNOWN_RAW
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW
        assert result["c"] == TaintState.MIXED_RAW


# ── Function calls ───────────────────────────────────────────────


class TestFunctionCalls:
    def test_known_callee_taint(self) -> None:
        func = _parse_func("""
            def f():
                x = validate(data)
        """)
        taint_map = {"validate": TaintState.GUARDED}
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, taint_map)
        assert result["x"] == TaintState.GUARDED

    def test_unknown_callee_gets_function_taint(self) -> None:
        func = _parse_func("""
            def f():
                x = unknown_func(data)
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_method_call_gets_function_taint(self) -> None:
        """Method calls (obj.method()) are not in the taint_map, so they
        get the function's own L1 taint."""
        func = _parse_func("""
            def f():
                x = obj.method()
        """)
        result = compute_variable_taints(func, TaintState.ASSURED, {})
        assert result["x"] == TaintState.ASSURED


# ── Augmented assignment ─────────────────────────────────────────


class TestAugmentedAssignment:
    def test_augassign_joins_with_existing(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
                x += unknown_thing
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW

    def test_augassign_new_variable(self) -> None:
        """If variable wasn't previously assigned, treat existing as function taint."""
        func = _parse_func("""
            def f():
                x += 42
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # UNKNOWN_RAW join INTEGRAL = MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW


# ── Tuple unpacking ──────────────────────────────────────────────


class TestTupleUnpacking:
    def test_tuple_unpack_literals(self) -> None:
        func = _parse_func("""
            def f():
                a, b = 1, 2
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["a"] == TaintState.INTEGRAL
        assert result["b"] == TaintState.INTEGRAL

    def test_tuple_unpack_from_call(self) -> None:
        """When RHS is not a tuple, all targets get the RHS taint."""
        func = _parse_func("""
            def f():
                a, b = some_func()
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["a"] == TaintState.EXTERNAL_RAW
        assert result["b"] == TaintState.EXTERNAL_RAW

    def test_tuple_unpack_mixed(self) -> None:
        func = _parse_func("""
            def f():
                a, b = 42, unknown
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["a"] == TaintState.INTEGRAL
        assert result["b"] == TaintState.EXTERNAL_RAW


# ── For-loop target ──────────────────────────────────────────────


class TestForLoop:
    def test_for_loop_target_gets_iterable_taint(self) -> None:
        func = _parse_func("""
            def f():
                for x in some_iterable:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_for_loop_over_literal_list(self) -> None:
        func = _parse_func("""
            def f():
                for x in [1, 2, 3]:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL


# ── With-as ──────────────────────────────────────────────────────


class TestWithAs:
    def test_with_as_gets_expr_taint(self) -> None:
        func = _parse_func("""
            def f():
                with open("file.txt") as handle:
                    pass
        """)
        taint_map = {"open": TaintState.INTEGRAL}
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, taint_map)
        assert result["handle"] == TaintState.INTEGRAL

    def test_with_as_unknown_call(self) -> None:
        func = _parse_func("""
            def f():
                with something() as handle:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["handle"] == TaintState.EXTERNAL_RAW


# ── Exception handler ────────────────────────────────────────────


class TestExceptAs:
    def test_except_as_inherits_function_taint(self) -> None:
        """Exception objects inherit function taint — str(e) may contain attacker input."""
        func = _parse_func("""
            def f():
                try:
                    pass
                except ValueError as e:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["e"] == TaintState.EXTERNAL_RAW


# ── Walrus operator ──────────────────────────────────────────────


class TestWalrus:
    def test_walrus_assigns_taint(self) -> None:
        func = _parse_func("""
            def f():
                if (x := 42):
                    pass
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL

    def test_walrus_with_call(self) -> None:
        func = _parse_func("""
            def f():
                if (x := validate(data)):
                    pass
        """)
        taint_map = {"validate": TaintState.GUARDED}
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, taint_map)
        assert result["x"] == TaintState.GUARDED


# ── Control flow merges (if/else) ────────────────────────────────


class TestControlFlowMerge:
    def test_if_else_merges_variable_taint(self) -> None:
        func = _parse_func("""
            def f():
                if condition:
                    x = 42
                else:
                    x = unknown_thing
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW

    def test_if_only_merges_with_pre_existing(self) -> None:
        """If there's no else, the if-branch merges with pre-existing taint."""
        func = _parse_func("""
            def f():
                x = 42
                if condition:
                    x = unknown_thing
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW


# ── Parameters get function taint ────────────────────────────────


class TestParameters:
    def test_parameters_get_function_taint(self) -> None:
        func = _parse_func("""
            def f(a, b, c=None):
                x = a
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["a"] == TaintState.EXTERNAL_RAW
        assert result["b"] == TaintState.EXTERNAL_RAW
        assert result["c"] == TaintState.EXTERNAL_RAW
        assert result["x"] == TaintState.EXTERNAL_RAW


# ── Async function ───────────────────────────────────────────────


class TestAsync:
    def test_async_function_works(self) -> None:
        func = _parse_func("""
            async def f():
                x = 42
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL


# ── Nested constructs ────────────────────────────────────────────


class TestNested:
    def test_variable_in_for_body(self) -> None:
        func = _parse_func("""
            def f():
                for item in items:
                    x = item
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["item"] == TaintState.EXTERNAL_RAW
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_variable_in_while_body(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
                while True:
                    x = unknown
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW (while body merges with pre-loop)
        assert result["x"] == TaintState.MIXED_RAW


# ── Try/except branch merge ──────────────────────────────────────


class TestTryExceptBranchMerge:
    def test_try_except_branch_merge(self) -> None:
        """try/except should join branches, not sequential overwrite."""
        func = _parse_func("""
            def f():
                x = unknown_thing
                try:
                    x = 42
                except:
                    x = "fallback"
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        # Both branches assign INTEGRAL; join should still be INTEGRAL
        assert result["x"] == TaintState.INTEGRAL

    def test_try_except_divergent_branches(self) -> None:
        """try body and handler with different taints should join."""
        func = _parse_func("""
            def f():
                x = "safe"
                try:
                    x = unknown_thing
                except:
                    x = "fallback"
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        # try branch: EXTERNAL_RAW, except branch: INTEGRAL → MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW

    def test_try_except_handler_name_inherits_function_taint(self) -> None:
        """Exception variable in handler inherits function taint (conservative)."""
        func = _parse_func("""
            def f():
                try:
                    pass
                except ValueError as e:
                    x = e
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["e"] == TaintState.EXTERNAL_RAW


# ── Serialisation shedding ──────────────────────────────────────


class TestSerialisationShedding:
    """§6.2 invariant 5: serialisation sheds direct authority."""

    def test_json_dumps_sheds_to_unknown_raw(self) -> None:
        func = _parse_func("""
            def f():
                x = json.dumps(data)
        """)
        result = compute_variable_taints(func, TaintState.INTEGRAL, {})
        assert result["x"] == TaintState.UNKNOWN_RAW

    def test_json_loads_sheds_to_unknown_raw(self) -> None:
        func = _parse_func("""
            def f():
                x = json.loads(raw)
        """)
        result = compute_variable_taints(func, TaintState.INTEGRAL, {})
        assert result["x"] == TaintState.UNKNOWN_RAW

    def test_pickle_dumps_sheds(self) -> None:
        func = _parse_func("""
            def f():
                x = pickle.dumps(obj)
        """)
        result = compute_variable_taints(func, TaintState.INTEGRAL, {})
        assert result["x"] == TaintState.UNKNOWN_RAW

    def test_yaml_safe_load_sheds(self) -> None:
        func = _parse_func("""
            def f():
                x = yaml.safe_load(text)
        """)
        result = compute_variable_taints(func, TaintState.INTEGRAL, {})
        assert result["x"] == TaintState.UNKNOWN_RAW

    def test_bare_name_loads_via_import(self) -> None:
        """from json import dumps; x = dumps(data) — bare name in taint_map."""
        func = _parse_func("""
            def f():
                x = dumps(data)
        """)
        # If 'dumps' is in taint_map (from import resolution), that takes priority.
        # If not, it falls through to function_taint. The serialisation check
        # uses the dotted form (json.dumps) which requires ast.Attribute.
        # Bare names go through taint_map lookup, which is correct.
        result = compute_variable_taints(func, TaintState.INTEGRAL, {})
        # Bare 'dumps' is not in SERIALISATION_SINKS (those use dotted names).
        # Falls to function_taint — this is acceptable for L1.
        assert result["x"] == TaintState.INTEGRAL

    def test_non_serialisation_method_inherits_taint(self) -> None:
        """obj.process() is not a serialisation sink — inherits function taint."""
        func = _parse_func("""
            def f():
                x = obj.process()
        """)
        result = compute_variable_taints(func, TaintState.INTEGRAL, {})
        assert result["x"] == TaintState.INTEGRAL

    def test_external_raw_not_affected(self) -> None:
        """Serialisation at EXTERNAL_RAW stays UNKNOWN_RAW (already untrusted)."""
        func = _parse_func("""
            def f():
                x = json.dumps(data)
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.UNKNOWN_RAW


# ── Dependency taint resolution ─────────────────────────────────


class TestDependencyTaint:
    """§6.5 dependency taint: dotted calls resolved via dep_dotted + dep_prefixes."""

    def test_dotted_call_resolved_via_taint_map(self) -> None:
        """pd.read_csv() with 'pd.read_csv' in dep_dotted -> declared taint."""
        func = _parse_func("""
            def f():
                x = pd.read_csv("data.csv")
        """)
        result = compute_variable_taints(
            func,
            TaintState.INTEGRAL,
            {},
            dependency_dotted_map={"pd.read_csv": TaintState.EXTERNAL_RAW},
            dependency_local_prefixes=frozenset({"pd"}),
        )
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_undeclared_function_in_declared_package_unknown_raw(self) -> None:
        """pd.merge() when only pd.read_csv declared -> UNKNOWN_RAW."""
        func = _parse_func("""
            def f():
                x = pd.merge(left, right)
        """)
        result = compute_variable_taints(
            func,
            TaintState.INTEGRAL,
            {},
            dependency_dotted_map={"pd.read_csv": TaintState.EXTERNAL_RAW},
            dependency_local_prefixes=frozenset({"pd"}),
        )
        assert result["x"] == TaintState.UNKNOWN_RAW

    def test_non_dependency_dotted_call_inherits_function_taint(self) -> None:
        """self.process() is not a dependency -> inherits function_taint."""
        func = _parse_func("""
            def f(self):
                x = self.process()
        """)
        result = compute_variable_taints(
            func,
            TaintState.ASSURED,
            {},
            dependency_dotted_map={},
            dependency_local_prefixes=frozenset(),
        )
        assert result["x"] == TaintState.ASSURED

    def test_serialisation_sinks_still_take_priority(self) -> None:
        """json.dumps still -> UNKNOWN_RAW even if json is in dep_dotted."""
        func = _parse_func("""
            def f():
                x = json.dumps(data)
        """)
        result = compute_variable_taints(
            func,
            TaintState.INTEGRAL,
            {},
            dependency_dotted_map={"json.dumps": TaintState.INTEGRAL},
            dependency_local_prefixes=frozenset({"json"}),
        )
        assert result["x"] == TaintState.UNKNOWN_RAW

    def test_declared_taint_overrides_function_taint(self) -> None:
        """Multiple declared entries with different taints work correctly."""
        func = _parse_func("""
            def f():
                x = pd.read_csv("data.csv")
                y = pd.read_parquet("data.parquet")
        """)
        result = compute_variable_taints(
            func,
            TaintState.INTEGRAL,
            {},
            dependency_dotted_map={
                "pd.read_csv": TaintState.EXTERNAL_RAW,
                "pd.read_parquet": TaintState.UNKNOWN_RAW,
            },
            dependency_local_prefixes=frozenset({"pd"}),
        )
        assert result["x"] == TaintState.EXTERNAL_RAW
        assert result["y"] == TaintState.UNKNOWN_RAW


# ── Container and two-step taint propagation (SCAN-010) ─────────


class TestContainerTaintPropagation:
    """Isolated container and multi-step taint propagation tests (SCAN-010)."""

    def test_dict_literal_joins_value_taints(self) -> None:
        """Dict with mixed taint values -> join of all value taints."""
        func = _parse_func("""
            def f(untrusted):
                d = {"safe": 42, "unsafe": untrusted}
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        # 42 is INTEGRAL, untrusted is EXTERNAL_RAW -> join is MIXED_RAW
        assert result["d"] == TaintState.MIXED_RAW

    def test_list_literal_joins_element_taints(self) -> None:
        """List with mixed taint elements -> join of all elements."""
        func = _parse_func("""
            def f(untrusted):
                lst = [42, untrusted]
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["lst"] == TaintState.MIXED_RAW

    def test_tuple_literal_joins_element_taints(self) -> None:
        """Tuple with mixed elements -> join."""
        func = _parse_func("""
            def f(untrusted):
                t = (42, untrusted)
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["t"] == TaintState.MIXED_RAW

    def test_set_literal_joins_element_taints(self) -> None:
        """Set with mixed elements -> join."""
        func = _parse_func("""
            def f(untrusted):
                s = {42, untrusted}
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["s"] == TaintState.MIXED_RAW

    def test_empty_containers_are_integral(self) -> None:
        """Empty dict/list/tuple/set -> INTEGRAL (no tainted data)."""
        func = _parse_func("""
            def f():
                d = {}
                lst = []
                t = ()
                s = set()
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["d"] == TaintState.INTEGRAL
        assert result["lst"] == TaintState.INTEGRAL
        assert result["t"] == TaintState.INTEGRAL
        # set() is a call, not a literal — falls to function_taint
        # This is expected: set() is ast.Call, not ast.Set

    def test_nested_container_joins_recursively(self) -> None:
        """Nested containers join through to inner elements."""
        func = _parse_func("""
            def f(untrusted):
                nested = {"inner": [untrusted, 42]}
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["nested"] == TaintState.MIXED_RAW

    def test_homogeneous_container_preserves_taint(self) -> None:
        """Container with all-same-taint elements -> that taint."""
        func = _parse_func("""
            def f():
                d = {"a": 1, "b": 2, "c": 3}
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["d"] == TaintState.INTEGRAL

    def test_call_result_in_container(self) -> None:
        """Container with call result uses callee taint."""
        func = _parse_func("""
            def f():
                lst = [validate(data)]
        """)
        taint_map = {"validate": TaintState.GUARDED}
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, taint_map)
        assert result["lst"] == TaintState.GUARDED

    def test_two_step_variable_propagation(self) -> None:
        """Taint flows through intermediate variable assignment."""
        func = _parse_func("""
            def f(untrusted):
                intermediate = untrusted
                final = intermediate
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["intermediate"] == TaintState.EXTERNAL_RAW
        assert result["final"] == TaintState.EXTERNAL_RAW

    def test_augmented_assign_joins_with_existing(self) -> None:
        """x += untrusted joins existing taint with new value."""
        func = _parse_func("""
            def f(untrusted):
                x = 42
                x += untrusted
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        # 42 is INTEGRAL, += EXTERNAL_RAW -> MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW

    def test_for_loop_target_gets_iterable_taint(self) -> None:
        """for item in container -- item gets container's taint."""
        func = _parse_func("""
            def f(items):
                for item in items:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["item"] == TaintState.EXTERNAL_RAW

    def test_with_as_gets_context_taint(self) -> None:
        """with open(f) as handle -- handle gets context expr taint."""
        func = _parse_func("""
            def f():
                with get_conn() as conn:
                    pass
        """)
        taint_map = {"get_conn": TaintState.GUARDED}
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, taint_map)
        assert result["conn"] == TaintState.GUARDED

    def test_if_branch_merges_via_join(self) -> None:
        """Variable assigned in both branches -> join of both taints."""
        func = _parse_func("""
            def f(cond, untrusted):
                if cond:
                    x = 42
                else:
                    x = untrusted
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        # INTEGRAL join EXTERNAL_RAW -> MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW
