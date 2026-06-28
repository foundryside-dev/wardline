# tests/unit/scanner/taint/test_engine_precision.py
"""Engine-precision regression suite (2026-06-10 eval batch).

Covers the confirmed taint-engine FNs plus the engine-precision expansion
ticket (wardline-93d608c997) and the typed-dispatch launder
(wardline-03c8805449):

1. Container-conversion builtins (list/tuple/set/dict/sorted/frozenset/
   reversed) must propagate the worst argument taint, not launder to the
   caller seed.
2. ``str.format_map`` is a sibling of ``str.format`` — receiver+args combine.
3. Non-literal nested-tuple unpack ``a, (b, c) = raw`` must taint b and c.
4. A try handler can observe ANY prefix of the try body (an exception may be
   raised mid-body), so its seed is the worst of the pre-try snapshot and the
   try-body states — not the pre-try snapshot alone.
5. A TYPED parameter seeded declared-raw (EXTERNAL_RAW/MIXED_RAW) must not be
   laundered by its class method's clean @trusted summary.
6. Expansion: ``**raw`` spread into a lambda's ``**kw`` param; Subscript
   unpack/for targets contaminate their base container; unresolved bare-name
   calls propagate the worst of (caller seed, arg taints).
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

import wardline.scanner.taint.variable_level as variable_level
from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.taint.variable_level import (
    SELF_ATTRIBUTE_KEY,
    attribute_write_recording,
    compute_variable_taints,
)

T = TaintState

_RAW_TM = {"read_raw": T.UNKNOWN_RAW}

_HEADER = (
    "import os, subprocess\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _vt(
    src: str,
    function_taint: TaintState = T.UNKNOWN_RAW,
    taint_map: dict[str, TaintState] | None = None,
    alias_map: dict[str, str] | None = None,
    param_meets: dict[str, TaintState] | None = None,
) -> dict[str, TaintState]:
    func = ast.parse(src).body[0]
    assert isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
    return compute_variable_taints(func, function_taint, taint_map or {}, alias_map=alias_map, param_meets=param_meets)


def _func(src: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    func = ast.parse(src).body[0]
    assert isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
    return func


def _defects(tmp_path: Path, src: str) -> list[tuple[str, int | None]]:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    findings = WardlineAnalyzer().analyze([p], WardlineConfig(), root=tmp_path)
    return [(f.rule_id, f.location.line_start) for f in findings if f.kind is Kind.DEFECT]


# ── L2 work budget bounds attacker-authored super-linear inputs ─────────────


def test_l2_work_budget_bounds_per_statement_snapshots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(variable_level, "L2_WORK_BUDGET", 8)
    call_site_taints: dict[int, dict[str, TaintState]] = {}

    with pytest.raises(variable_level.L2BudgetExceeded) as exc:
        compute_variable_taints(
            _func("def f(p):\n    v0 = read_raw(p)\n    v1 = read_raw(p)\n    v2 = read_raw(p)\n"),
            T.INTEGRAL,
            _RAW_TM,
            call_site_taints=call_site_taints,
        )

    assert exc.value.operation == "statement_snapshot"
    assert exc.value.attempted > exc.value.budget


def test_l2_work_budget_bounds_loop_fixpoint_iterations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(variable_level, "L2_WORK_BUDGET", 18)

    with pytest.raises(variable_level.L2BudgetExceeded) as exc:
        compute_variable_taints(
            _func(
                "def f(flag, raw):\n"
                "    x2 = raw\n"
                "    x1 = 'safe'\n"
                "    x0 = 'safe'\n"
                "    while flag:\n"
                "        x0 = x1\n"
                "        x1 = x2\n"
            ),
            T.INTEGRAL,
            {},
        )

    assert exc.value.operation in {"loop_iteration", "loop_merge"}


def test_l2_work_budget_bounds_branch_candidate_copies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(variable_level, "L2_WORK_BUDGET", 30)
    body = "\n".join(f"    if flag{i}:\n        cb = lambda v: sink{i}(v)" for i in range(8))

    with pytest.raises(variable_level.L2BudgetExceeded) as exc:
        compute_variable_taints(_func(f"def f(p):\n{body}\n    cb(p)\n"), T.INTEGRAL, {})

    assert exc.value.operation in {"lambda_branch_copy", "lambda_branch_merge"}


# ── (1) container-conversion builtins propagate argument taint ──────────────


@pytest.mark.parametrize("builtin", ["list", "tuple", "set", "frozenset", "dict", "sorted", "reversed"])
def test_container_builtin_propagates_arg_taint(builtin: str) -> None:
    out = _vt(
        f"def f(p):\n    x = {builtin}(read_raw(p))\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


@pytest.mark.parametrize("builtin", ["list", "tuple", "set", "frozenset", "dict", "sorted"])
def test_container_builtin_no_args_is_integral(builtin: str) -> None:
    out = _vt(f"def f():\n    x = {builtin}()\n", function_taint=T.UNKNOWN_RAW)
    assert out["x"] == T.INTEGRAL


def test_sorted_raw_argv_fires_subprocess_sink(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            args = sorted(raw)
            subprocess.run(args, shell=True)
        """,
    )
    assert ("PY-WL-112", 11) in rules


# ── (2) str.format_map combines receiver and mapping argument ───────────────


def test_format_map_method_combines_receiver_and_args() -> None:
    out = _vt(
        "def f(p):\n    x = 'echo {x}'.format_map(read_raw(p))\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_format_map_validated_arg_stays_clean() -> None:
    # FP guard: validated mapping in an ASSURED producer stays clean
    # (least_trusted(INTEGRAL receiver, ASSURED) = ASSURED, no MIXED_RAW clash).
    out = _vt(
        "def f(p):\n    x = '{x}'.format_map(validate(p))\n",
        function_taint=T.ASSURED,
        taint_map={"validate": T.ASSURED},
    )
    assert out["x"] == T.ASSURED


def test_format_map_raw_mapping_fires_command_sink(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            cmd = "echo {x}".format_map(raw)
            os.system(cmd)
        """,
    )
    assert ("PY-WL-108", 11) in rules


# ── (3) non-literal nested-tuple unpack keeps RHS taint on every leaf ───────


def test_nested_tuple_unpack_of_call_rhs_taints_leaves() -> None:
    out = _vt(
        "def f(p):\n    a, (b, c) = read_raw(p)\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["a"] == T.UNKNOWN_RAW
    assert out["b"] == T.UNKNOWN_RAW
    assert out["c"] == T.UNKNOWN_RAW


def test_nested_tuple_unpack_leaf_reaches_exec_sink(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            a, (b, c) = read_raw(p)
            eval(b)
            return 1
        """,
    )
    assert ("PY-WL-107", 10) in rules


# ── (4) try handler sees the worst of any try-body prefix ───────────────────


def test_handler_sees_try_body_assignment_post_state() -> None:
    # x is reassigned raw in the try body BEFORE a possibly-raising call; the
    # handler may observe it. Seeding the handler from dict(pre_try) alone
    # dropped the raw value (fail-open under-taint).
    out = _vt(
        "def f(p):\n"
        "    x = 'safe'\n"
        "    try:\n"
        "        x = read_raw(p)\n"
        "        risky()\n"
        "    except ValueError:\n"
        "        y = x\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["y"] == T.UNKNOWN_RAW


def test_handler_sink_on_try_assigned_raw_fires(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            x = "safe"
            try:
                x = read_raw(p)
                risky()
            except ValueError:
                eval(x)
            return 1
        """,
    )
    assert any(r == "PY-WL-107" for r, _line in rules)


def test_handler_sink_sees_mid_try_prefix_worst(tmp_path: Path) -> None:
    # x is raw after the FIRST try statement and cleaned by the second; an
    # exception between them still hands the handler the raw value, so the
    # handler seed is the worst over every try-body prefix, not the post-state.
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            x = "safe"
            try:
                x = read_raw(p)
                x = "clean"
                risky()
            except ValueError:
                eval(x)
            return 1
        """,
    )
    assert any(r == "PY-WL-107" for r, _line in rules)


def test_post_try_clean_reassign_in_both_arms_stays_clean() -> None:
    # FP guard: when the try body ends clean AND the handler reassigns clean,
    # the post-merge state stays clean (handler seeding must not leak into the
    # merge for a var both arms finished clean).
    out = _vt(
        "def f(p):\n    try:\n        x = a()\n    except Exception:\n        x = b()\n",
        function_taint=T.INTEGRAL,
        taint_map={"a": T.ASSURED, "b": T.GUARDED},
    )
    assert out["x"] == T.GUARDED


# ── (5) declared-raw typed receiver is not laundered by a clean summary ─────


def test_declared_raw_typed_param_not_laundered_by_clean_summary() -> None:
    out = _vt(
        "def f(h: mymod.Schema):\n    x = h.validate()\n",
        function_taint=T.ASSURED,
        taint_map={"mymod.Schema.validate": T.ASSURED},
        alias_map={"mymod": "mymod"},
        param_meets={"h": T.EXTERNAL_RAW},
    )
    assert out["x"] == T.EXTERNAL_RAW


def test_unknown_raw_typed_receiver_still_resolves_clean_summary() -> None:
    # FP guard (wardline-f6a29ce23a): an unmodeled ``Type()`` constructor seeds
    # the receiver UNKNOWN_RAW; the typed dispatch must STILL resolve the clean
    # summary — only DECLARED-raw (EXTERNAL_RAW/MIXED_RAW) receivers are gated.
    out = _vt(
        "def f(obj: mymod.Schema):\n    x = obj.validate()\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"mymod.Schema.validate": T.ASSURED},
        alias_map={"mymod": "mymod"},
    )
    assert out["x"] == T.ASSURED


def test_typed_param_seeded_raw_interprocedurally_fires_sink(tmp_path: Path) -> None:
    # Mirror of the wardline-03c8805449 var_typed repro: only the annotation
    # differs from the untyped control, which already fires.
    src = """
        class Helper:
            @trusted(level='ASSURED')
            def get_cmd(self):
                return "noop()"

        @trusted(level='ASSURED')
        def f(h{ann}):
            eval(h.get_cmd())

        @trusted(level='ASSURED')
        def caller(p):
            f(read_raw(p))
        """
    untyped = _defects(tmp_path, src.format(ann=""))
    assert any(r == "PY-WL-107" for r, _line in untyped)  # control
    typed = _defects(tmp_path, src.format(ann=": Helper"))
    assert any(r == "PY-WL-107" for r, _line in typed)


# ── (6a) **spread taint reaches a lambda's **kw param at the call site ───────


def test_double_star_spread_seeds_lambda_kwarg_param(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def process(p):
            raw_kwargs = read_raw(p)
            (lambda **kw: os.system(kw.get('cmd', '')))(**raw_kwargs)
        """,
    )
    assert any(r == "PY-WL-108" for r, _line in rules)


def test_double_star_spread_seeds_lambda_named_param(tmp_path: Path) -> None:
    # A **spread can also bind a NAMED lambda parameter by key.
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def process(p):
            raw_kwargs = read_raw(p)
            (lambda cmd='': os.system(cmd))(**raw_kwargs)
        """,
    )
    assert any(r == "PY-WL-108" for r, _line in rules)


# ── (6b) Subscript unpack / for targets contaminate the base container ──────


def test_unpack_subscript_target_contaminates_base_literal_rhs() -> None:
    out = _vt(
        "def f(p):\n    d = {}\n    d['cmd'], y = read_raw(p), 1\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["d"] == T.UNKNOWN_RAW


def test_unpack_subscript_target_contaminates_base_call_rhs() -> None:
    out = _vt(
        "def f(p):\n    d = {}\n    d['cmd'], y = read_raw(p)\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["d"] == T.UNKNOWN_RAW
    assert out["y"] == T.UNKNOWN_RAW


def test_for_subscript_target_contaminates_base() -> None:
    out = _vt(
        "def f(p):\n    d = {}\n    for d['k'] in [read_raw(p)]:\n        pass\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["d"] == T.UNKNOWN_RAW


def test_for_subscript_target_reaches_command_sink(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def process(p):
            d = {}
            raw = read_raw(p)
            for d['cmd'] in [raw]:
                pass
            os.system(d['cmd'])
        """,
    )
    assert any(r == "PY-WL-108" for r, _line in rules)


# ── (6c) unresolved bare-name calls propagate worst(seed, args) ──────────────


def test_unresolved_bare_call_propagates_worst_arg_taint() -> None:
    # ``transform`` is absent from the taint_map (a bare parameter / runtime
    # callable): an unknown callee cannot be assumed to clean its raw argument,
    # matching the imported-unmodeled path's conservatism.
    out = _vt(
        "def f(p, transform):\n    x = transform(read_raw(p))\n",
        function_taint=T.GUARDED,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_unresolved_bare_call_clean_args_keeps_function_taint() -> None:
    # FP guard: clean arguments do not demote — the result stays at the worst
    # of the caller seed and the args (here the seed).
    out = _vt(
        "def f(p, transform):\n    x = transform('const')\n",
        function_taint=T.GUARDED,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.GUARDED


def test_measuring_builtins_still_fall_back_to_function_taint() -> None:
    # len/int validate/measure, they do not carry the data through — the
    # curated non-propagating carve-out keeps them at the caller seed.
    assert _vt("def f(p):\n    x = len(read_raw(p))\n", function_taint=T.GUARDED, taint_map=_RAW_TM)["x"] == T.GUARDED
    assert _vt("def f(p):\n    x = int(read_raw(p))\n", function_taint=T.GUARDED, taint_map=_RAW_TM)["x"] == T.GUARDED


def test_bare_param_transform_call_fires_command_sink(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p, transform):
            raw = read_raw(p)
            os.system(transform(raw))
        """,
    )
    assert any(r == "PY-WL-108" for r, _line in rules)


# ── (7) io.StringIO/io.BytesIO constructors carry the WORST ARG taint ────────


@pytest.mark.parametrize("ctor", ["io.StringIO", "io.BytesIO"])
def test_io_buffer_ctor_const_arg_is_integral(ctor: str) -> None:
    # An in-memory buffer over a constant is NOT external data — the ctor
    # result carries the worst argument taint, not the unresolved-import
    # UNKNOWN_RAW default.
    out = _vt(
        f"def f():\n    x = {ctor}('const')\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
        alias_map={"io": "io"},
    )
    assert out["x"] == T.INTEGRAL


@pytest.mark.parametrize("ctor", ["io.StringIO", "io.BytesIO"])
def test_io_buffer_ctor_raw_arg_stays_raw(ctor: str) -> None:
    out = _vt(
        f"def f(p):\n    x = {ctor}(read_raw(p))\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
        alias_map={"io": "io"},
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_io_buffer_ctor_no_args_is_integral() -> None:
    out = _vt(
        "def f():\n    x = io.StringIO()\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
        alias_map={"io": "io"},
    )
    assert out["x"] == T.INTEGRAL


def test_io_buffer_from_import_alias_resolves() -> None:
    # ``from io import StringIO`` resolves through the alias map to the same
    # canonical FQN — the bare-name form must not regress to UNKNOWN_RAW.
    out = _vt(
        "def f():\n    x = StringIO('const')\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
        alias_map={"StringIO": "io.StringIO"},
    )
    assert out["x"] == T.INTEGRAL


def test_io_buffer_shadowed_by_raw_local_not_laundered() -> None:
    # A raw local shadowing the ``io`` module name must not inherit the
    # clean worst-arg ctor model (the wardline-f6a29ce23a shadow guard).
    out = _vt(
        "def f(p):\n    io = read_raw(p)\n    x = io.StringIO('const')\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
        alias_map={"io": "io"},
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_stringio_const_read_no_longer_fires_return_rule(tmp_path: Path) -> None:
    # End-to-end: returning the .read() of a CLEAN in-memory buffer is not a
    # raw return — the PY-WL-101 FP this residual tracked.
    rules = _defects(
        tmp_path,
        """
        import io
        @trusted(level='ASSURED')
        def render():
            buf = io.StringIO("constant template")
            return buf.read()
        """,
    )
    assert not any(r == "PY-WL-101" for r, _line in rules)


def test_stringio_raw_read_still_fires_return_rule(tmp_path: Path) -> None:
    # Soundness control: raw content poured into the buffer still propagates
    # through .read() and fires the raw-return rule.
    rules = _defects(
        tmp_path,
        """
        import io
        @trusted(level='ASSURED')
        def render(p):
            buf = io.StringIO(read_raw(p))
            return buf.read()
        """,
    )
    assert any(r == "PY-WL-101" for r, _line in rules)


# ── (8) tuple-unpack attribute targets record into the attr-write channel ────


def test_tuple_unpack_attribute_target_records_self_write() -> None:
    func = ast.parse("def put(self, p):\n    self.x, y = read_raw(p), 1\n").body[0]
    assert isinstance(func, ast.FunctionDef)
    out: dict[str, dict[str, TaintState]] = {}
    with attribute_write_recording(out):
        compute_variable_taints(func, T.INTEGRAL, dict(_RAW_TM), alias_map={})
    assert out[SELF_ATTRIBUTE_KEY]["x"] == T.UNKNOWN_RAW


def test_tuple_unpack_attribute_pair_from_call_records_both() -> None:
    # ``(self.x, self.y) = pair`` with a non-literal RHS: both elements get
    # the RHS taint and BOTH record into the channel.
    func = ast.parse("def put(self, p):\n    (self.x, self.y) = read_raw(p)\n").body[0]
    assert isinstance(func, ast.FunctionDef)
    out: dict[str, dict[str, TaintState]] = {}
    with attribute_write_recording(out):
        compute_variable_taints(func, T.INTEGRAL, dict(_RAW_TM), alias_map={})
    assert out[SELF_ATTRIBUTE_KEY]["x"] == T.UNKNOWN_RAW
    assert out[SELF_ATTRIBUTE_KEY]["y"] == T.UNKNOWN_RAW


def test_tuple_unpack_attribute_write_fires_cross_method_sink(tmp_path: Path) -> None:
    # End-to-end: the unpack-written attribute feeds the cross-method summary
    # exactly like the plain ``self.x = raw`` path (which already fires).
    rules = _defects(
        tmp_path,
        """
        class Store:
            def put(self, p):
                self.x, y = read_raw(p), 1
            @trusted(level='ASSURED')
            def use(self):
                os.system(self.x)
        """,
    )
    assert any(r == "PY-WL-108" for r, _line in rules)


# ── (9) lambda DEFAULT taint seeds the param when omitted at the call site ───


def test_lambda_raw_default_omitted_at_call_fires_sink(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def process(p):
            raw = read_raw(p)
            cb = lambda x=raw: os.system(x)
            cb()
        """,
    )
    assert any(r == "PY-WL-108" for r, _line in rules)


def test_lambda_raw_kwonly_default_omitted_at_call_fires_sink(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def process(p):
            raw = read_raw(p)
            cb = lambda *, x=raw: os.system(x)
            cb()
        """,
    )
    assert any(r == "PY-WL-108" for r, _line in rules)


def test_lambda_raw_default_overridden_clean_does_not_fire(tmp_path: Path) -> None:
    # FP guard: a clean argument supplied at the call site replaces the raw
    # default — the default expression never evaluates on this path.
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def process(p):
            raw = read_raw(p)
            cb = lambda x=raw: os.system(x)
            cb("echo ok")
        """,
    )
    assert not any(r == "PY-WL-108" for r, _line in rules)


def test_lambda_raw_default_overridden_by_keyword_does_not_fire(tmp_path: Path) -> None:
    rules = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def process(p):
            raw = read_raw(p)
            cb = lambda x=raw: os.system(x)
            cb(x="echo ok")
        """,
    )
    assert not any(r == "PY-WL-108" for r, _line in rules)
