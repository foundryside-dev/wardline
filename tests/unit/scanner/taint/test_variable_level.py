from __future__ import annotations

import ast
import time
from collections.abc import Callable

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.taint.variable_level import compute_variable_taints

T = TaintState


def _vt(
    src: str,
    function_taint: TaintState = T.UNKNOWN_RAW,
    taint_map: dict[str, TaintState] | None = None,
    alias_map: dict[str, str] | None = None,
) -> dict[str, TaintState]:
    func = ast.parse(src).body[0]
    assert isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
    return compute_variable_taints(func, function_taint, taint_map or {}, alias_map=alias_map)


def test_literal_is_integral() -> None:
    assert _vt("def f():\n    x = 42\n")["x"] == T.INTEGRAL


def test_parameters_inherit_function_taint() -> None:
    out = _vt("def f(a, b, *c, **d):\n    pass\n", function_taint=T.EXTERNAL_RAW)
    assert out["a"] == out["b"] == out["c"] == out["d"] == T.EXTERNAL_RAW


def test_binop_combines_operands_via_least_trusted() -> None:
    # a=INTEGRAL, p=function_taint(UNKNOWN_RAW); value-building combines via the
    # rank-meet least_trusted (weakest-link) = UNKNOWN_RAW — raw propagates at its
    # precise rank, NOT a MIXED_RAW provenance clash.
    out = _vt("def f(p):\n    a = 42\n    b = a + p\n", function_taint=T.UNKNOWN_RAW)
    assert out["a"] == T.INTEGRAL
    assert out["b"] == T.UNKNOWN_RAW


def test_collection_combines_elements_and_empty_is_integral() -> None:
    # [42, p] — container summary = least_trusted(INTEGRAL, EXTERNAL_RAW) = EXTERNAL_RAW.
    out = _vt("def f(p):\n    x = [42, p]\n    y = []\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW
    assert out["y"] == T.INTEGRAL


def test_ternary_combines_branches_via_least_trusted() -> None:
    # 42 if cond else p — either/or = least_trusted(INTEGRAL, EXTERNAL_RAW) = EXTERNAL_RAW.
    out = _vt("def f(p):\n    x = 42 if cond else p\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW


def test_if_else_merges_branches() -> None:
    # x holds ONE branch's value (an alternative), so the merge is the rank-meet
    # least_trusted (weakest-link): least_trusted(INTEGRAL, EXTERNAL_RAW) =
    # EXTERNAL_RAW — raw propagates at its precise rank, NOT a MIXED_RAW clash.
    src = "def f(p):\n    if c:\n        x = 42\n    else:\n        x = p\n"
    assert _vt(src, function_taint=T.EXTERNAL_RAW)["x"] == T.EXTERNAL_RAW


def test_if_without_else_merges_with_pre_state() -> None:
    # x assigned only in the if-branch; the implicit else is the pre-if value.
    src = "def f():\n    x = 42\n    if c:\n        x = unknown\n"
    # if-branch: x=unknown→function_taint=GUARDED; else(pre)=INTEGRAL →
    # least_trusted(GUARDED, INTEGRAL) = GUARDED (no MIXED_RAW clash).
    assert _vt(src, function_taint=T.GUARDED)["x"] == T.GUARDED


def test_try_except_merges_branches() -> None:
    src = "def f():\n    x = unknown\n    try:\n        x = 42\n    except Exception:\n        x = 7\n"
    # try→INTEGRAL, handler→INTEGRAL → join = INTEGRAL
    assert _vt(src, function_taint=T.EXTERNAL_RAW)["x"] == T.INTEGRAL


def test_for_loop_merges_body_with_pre_loop() -> None:
    # loop may not execute: body assignment merges with pre-loop state via the
    # rank-meet least_trusted (weakest-link).
    src = "def f(p):\n    x = 42\n    for i in p:\n        x = i\n"
    out = _vt(src, function_taint=T.UNKNOWN_RAW)
    # i gets iterable(p=UNKNOWN_RAW) taint; x = least_trusted(INTEGRAL pre,
    # UNKNOWN_RAW body) = UNKNOWN_RAW — raw at its precise rank, no MIXED_RAW clash.
    assert out["x"] == T.UNKNOWN_RAW


# ── Clean-direction merge tests (wardline-4d9f840c24) ──────────────────────
# Control-flow merges combine via the rank-meet least_trusted (weakest-link), NOT
# the provenance-clash taint_join: two clean-but-different-family branches must
# NOT manufacture a MIXED_RAW false positive, while a raw branch still propagates
# at its precise rank (and fires). taint_join would yield MIXED_RAW (rank 7) for
# every case below — the false positives this fix removes.


def test_if_else_two_clean_families_stays_clean() -> None:
    # if c: x = validate(p) else: x = guard(p) — two clean families.
    # least_trusted(ASSURED, GUARDED) = GUARDED (clean). taint_join → MIXED_RAW (FP).
    src = "def f(p):\n    if c:\n        x = validate(p)\n    else:\n        x = guard(p)\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"validate": T.ASSURED, "guard": T.GUARDED})
    assert out["x"] == T.GUARDED


def test_for_loop_clean_accumulate_stays_clean() -> None:
    # s = ''; for v in data: s += conv(v) — the back-edge merge of a clean
    # accumuland must not clash to MIXED_RAW. least_trusted(ASSURED, INTEGRAL '')
    # = ASSURED (clean). taint_join would re-clash at the back-edge (FP).
    src = "def f():\n    s = ''\n    for v in data:\n        s += conv(v)\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"conv": T.ASSURED})
    assert out["s"] == T.ASSURED


def test_while_loop_merges_body_with_pre_loop() -> None:
    # while has no prior merge test — a raw body still propagates at its rank.
    # least_trusted(EXTERNAL_RAW body, INTEGRAL pre) = EXTERNAL_RAW.
    src = "def f(p):\n    x = 1\n    while c:\n        x = p\n"
    assert _vt(src, function_taint=T.EXTERNAL_RAW)["x"] == T.EXTERNAL_RAW


def test_while_loop_clean_body_stays_clean() -> None:
    # least_trusted(GUARDED body, ASSURED pre) = GUARDED (clean). taint_join → MIXED_RAW (FP).
    src = "def f():\n    x = ok()\n    while c:\n        x = ok2()\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"ok": T.ASSURED, "ok2": T.GUARDED})
    assert out["x"] == T.GUARDED


def test_try_except_clean_families_stays_clean() -> None:
    # try → ASSURED, handler → GUARDED. least_trusted = GUARDED (clean).
    # taint_join → MIXED_RAW (FP).
    src = "def f():\n    try:\n        x = a()\n    except Exception:\n        x = b()\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"a": T.ASSURED, "b": T.GUARDED})
    assert out["x"] == T.GUARDED


def test_try_except_raw_handler_still_propagates() -> None:
    # try → ASSURED, handler → p (EXTERNAL_RAW). least_trusted keeps the raw rank.
    src = "def f(p):\n    try:\n        x = safe()\n    except Exception:\n        x = p\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW, taint_map={"safe": T.ASSURED})
    assert out["x"] == T.EXTERNAL_RAW


def test_match_two_clean_families_stays_clean() -> None:
    # arms ASSURED / GUARDED + INTEGRAL fall-through. least_trusted = GUARDED (clean).
    # taint_join → MIXED_RAW (FP).
    src = (
        "def f(p):\n"
        "    x = 1\n"
        "    match p:\n"
        "        case 1:\n"
        "            x = a()\n"
        "        case _:\n"
        "            x = b()\n"
    )
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"a": T.ASSURED, "b": T.GUARDED})
    assert out["x"] == T.GUARDED


def test_walrus_assigns_target() -> None:
    out = _vt("def f(p):\n    if (x := p):\n        pass\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW


def test_tuple_unpack_elementwise() -> None:
    out = _vt("def f(p):\n    a, b = 42, p\n", function_taint=T.EXTERNAL_RAW)
    assert out["a"] == T.INTEGRAL
    assert out["b"] == T.EXTERNAL_RAW


def test_aug_assign_combines_existing_via_least_trusted() -> None:
    # x=INTEGRAL; x += p (UNKNOWN_RAW) is value-building → least_trusted = UNKNOWN_RAW.
    out = _vt("def f(p):\n    x = 42\n    x += p\n", function_taint=T.UNKNOWN_RAW)
    assert out["x"] == T.UNKNOWN_RAW


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


def test_unresolved_imported_call_returns_unknown_raw_not_function_taint() -> None:
    out = _vt(
        "def f():\n    x = vendor.clean()\n",
        function_taint=T.GUARDED,
        taint_map={},
        alias_map={"vendor": "vendor"},
    )
    assert out["x"] == T.UNKNOWN_RAW


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


def _lambda_body_sink_arg(src: str) -> TaintState:
    """Run the variable-taint pass over *src* (a function with a ``sink(c)`` call inside
    a lambda body bound in one branch arm and a tainted ``cb(raw)`` call in a sibling
    arm) and return the taint recorded for the lambda body's ``sink(c)`` argument.

    Used by the wardline-36016d26f3 branch-locality regression tests: if the lambda
    binding leaks into the sibling arm, the else/handler/case arm's ``raw`` reaches the
    lambda body and the recorded arg becomes EXTERNAL_RAW (the over-fire). Branch-local,
    it stays INTEGRAL (if-arm direct call + the floor pass, both neutral)."""
    func = ast.parse(src).body[0]
    assert isinstance(func, ast.FunctionDef)
    csat: dict[int, dict[int | str | None, TaintState]] = {}
    compute_variable_taints(
        func,
        T.INTEGRAL,
        {},
        call_site_taints={},
        alias_map={},
        call_site_arg_taints=csat,
        param_meets={"raw": T.EXTERNAL_RAW},
    )
    sink_call = next(
        n for n in ast.walk(func) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "sink"
    )
    return csat[id(sink_call)][0]


def test_lambda_binding_is_branch_local_across_if_else() -> None:
    # wardline-36016d26f3: a lambda bound in the if-arm must NOT leak into the sibling
    # else-arm. _CURRENT_LAMBDA_BINDINGS was shared across branches (unlike var_taints,
    # which is copied per arm), so `cb(raw)` in the else-arm — where `cb` is NOT bound
    # to the lambda — spuriously resolved the if-arm's lambda body against the raw arg,
    # over-tainting the body's inner `sink(c)` call. Over-fire only (the final
    # worst-ever pass is the soundness floor), but a real false positive in adversarial
    # branch layouts.
    src = (
        "def handler(raw):\n"
        "    if flag:\n"
        "        cb = lambda c: sink(c)\n"
        "        cb('safe')\n"
        "    else:\n"
        "        cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.INTEGRAL


def test_lambda_binding_is_branch_local_across_try_except() -> None:
    # Same leak class for mutually-exclusive try-success vs except-handler arms.
    src = (
        "def handler(raw):\n"
        "    try:\n"
        "        cb = lambda c: sink(c)\n"
        "        cb('safe')\n"
        "    except Exception:\n"
        "        cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.INTEGRAL


def test_lambda_binding_is_branch_local_across_match() -> None:
    # Same leak class for mutually-exclusive match case arms.
    src = (
        "def handler(raw, kind):\n"
        "    match kind:\n"
        "        case 'a':\n"
        "            cb = lambda c: sink(c)\n"
        "            cb('safe')\n"
        "        case _:\n"
        "            cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.INTEGRAL


def test_lambda_rebinding_survives_no_else_if_for_post_branch_call() -> None:
    # wardline-36016d26f3 (merge-OUT direction, no-false-negative guard): branch-local
    # bindings must still re-converge so a rebinding made inside a no-`else` ``if``
    # survives for a call AFTER the branch. ``cb`` is bound to a safe lambda, rebound to
    # the sink lambda in the if-arm, then ``cb(raw)`` runs after the branch — ``cb`` MAY
    # be the sink lambda, so the body's ``sink(c)`` arg must stay EXTERNAL_RAW
    # (conservative). A clear-then-union merge that let the implicit (no-else)
    # fall-through arm win last reverted ``cb`` to the safe lambda and dropped the
    # detection — a false negative the pre-branch-local engine did not have.
    src = "def handler(raw):\n    cb = lambda c: c\n    if flag:\n        cb = lambda c: sink(c)\n    cb(raw)\n"
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_lambda_rebinding_survives_match_without_catch_all_for_post_branch_call() -> None:
    # Same merge-out no-false-negative guard for a ``match`` with no catch-all case: the
    # synthetic no-match fall-through arm must not revert a case-arm rebinding.
    src = (
        "def handler(raw, kind):\n"
        "    cb = lambda c: c\n"
        "    match kind:\n"
        "        case 'a':\n"
        "            cb = lambda c: sink(c)\n"
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_lambda_rebinding_in_try_survives_for_post_block_call() -> None:
    # Same merge-out no-false-negative guard for try/except. (The prior try->finally
    # form was VACUOUS: the finalbody call runs linearly after the try body, so the
    # rebinding is seen with no branch join to revert it — it passed even without the
    # fix.) The genuine join: a rebinding in the try body must survive for a call AFTER
    # the whole try/except. The except arm is a sibling fall-through that does NOT
    # rebind ``cb``, so a clear-then-union merge letting that arm win last would revert
    # ``cb`` to the safe lambda and drop the detection (the FN). ``cb`` MAY be the sink
    # lambda, so the body's ``sink(c)`` arg must stay EXTERNAL_RAW. Non-vacuity is
    # pinned by test_lambda_binding_is_branch_local_across_try_except: the same
    # rebinding called INSIDE the except arm stays INTEGRAL (the try-body binding does
    # not leak sideways), so this EXTERNAL_RAW comes from the post-block merge join.
    src = (
        "def handler(raw):\n"
        "    cb = lambda c: c\n"
        "    try:\n"
        "        cb = lambda c: sink(c)\n"
        "    except Exception:\n"
        "        pass\n"
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_sink_lambda_in_non_last_if_arm_survives_for_post_branch_call() -> None:
    # wardline-383f83fafe: the single-slot ceiling. A sink-lambda bound in a NON-last
    # branch arm and a BENIGN lambda bound to the same name in the last arm — the old
    # single-slot ``dict[str, ast.Lambda]`` kept only the last-arm-in-source-order
    # binding, so the benign last arm overwrote the sink binding and the post-branch
    # ``cb(raw)`` resolved only the benign body → the taint→sink flow was MISSED (FN).
    # The candidate-set model keeps BOTH bindings (``cb`` MAY be either lambda after the
    # branch), so the body's ``sink(c)`` arg must stay EXTERNAL_RAW.
    src = (
        "def handler(raw):\n"
        "    if flag:\n"
        "        cb = lambda c: sink(c)\n"  # sink-lambda — NON-last arm
        "    else:\n"
        "        cb = lambda c: c\n"  # benign — last arm in source order
        "    cb(raw)\n"  # raw reaches sink() via the if-arm lambda
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_sink_lambda_in_non_last_try_arm_survives_for_post_branch_call() -> None:
    # Same single-slot ceiling for try/except: the sink-lambda is bound in the try-success
    # arm (a non-last arm) and a benign lambda rebinds ``cb`` in the handler arm. The
    # candidate-set merge keeps both for the post-block ``cb(raw)``.
    src = (
        "def handler(raw):\n"
        "    try:\n"
        "        cb = lambda c: sink(c)\n"
        "    except Exception:\n"
        "        cb = lambda c: c\n"
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_sink_lambda_in_non_last_match_arm_survives_for_post_branch_call() -> None:
    # Same single-slot ceiling for match/case: the sink-lambda is bound in a non-last
    # case-arm and a benign lambda rebinds ``cb`` in the catch-all arm.
    src = (
        "def handler(raw, kind):\n"
        "    match kind:\n"
        "        case 'a':\n"
        "            cb = lambda c: sink(c)\n"
        "        case _:\n"
        "            cb = lambda c: c\n"
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_lambda_rebind_after_branch_replaces_candidate_set() -> None:
    # wardline-383f83fafe FP guard: the candidate-set model must NOT accumulate stale
    # bindings across a LINEAR rebind. After the branch, ``cb`` is rebound to a fresh
    # benign lambda; that REPLACES the (sink + benign) post-branch candidate set, so the
    # subsequent ``cb(raw)`` resolves ONLY the ``log`` body — the if-arm sink lambda is
    # gone and ``sink(c)`` must stay INTEGRAL (the floor pass's neutral recording only).
    src = (
        "def handler(raw):\n"
        "    if flag:\n"
        "        cb = lambda c: sink(c)\n"
        "    else:\n"
        "        cb = lambda c: c\n"
        "    cb = lambda c: log(c)\n"  # linear rebind — REPLACES the candidate set
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.INTEGRAL


def test_all_arms_rebind_to_non_lambda_drops_candidate_set() -> None:
    # wardline-383f83fafe, claim-#4 lock: when EVERY mutually-exclusive arm rebinds the
    # name to a non-lambda, ``cb`` is provably not a lambda on any post-branch path, so
    # the union drops it (the candidate set is empty) and ``cb(raw)`` resolves nothing —
    # only the floor pass records the orphaned sink lambda neutrally → INTEGRAL. This
    # pins the union's DROP semantics against a regression to the old delta-merge
    # "left in place" over-approximation (which would have spuriously stayed EXTERNAL_RAW).
    src = (
        "def handler(raw, flag):\n"
        "    cb = lambda c: sink(c)\n"
        "    if flag:\n"
        "        cb = 1\n"
        "    else:\n"
        "        cb = 2\n"
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.INTEGRAL


def test_sink_lambda_in_elif_middle_arm_survives_for_post_branch_call() -> None:
    # wardline-383f83fafe: the sink-lambda is in the MIDDLE arm of an if/elif/else (elif
    # is a nested ``If`` in the outer ``orelse``), so the union/merge must compose through
    # the nesting. ``cb(raw)`` after the branch must see the elif-arm sink body.
    src = (
        "def handler(raw, k):\n"
        "    if k == 1:\n"
        "        cb = lambda c: c\n"
        "    elif k == 2:\n"
        "        cb = lambda c: sink(c)\n"
        "    else:\n"
        "        cb = lambda c: c\n"
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_sink_lambda_in_loop_body_survives_for_post_loop_call() -> None:
    # wardline-383f83fafe coverage: loops take a structurally different path from
    # if/try/match — ``_handle_for`` walks the body via ``_walk_body`` directly on the
    # shared bindings map (the linear-rebind REPLACE), no _branch_copy/_merge. A
    # sink-lambda bound in the loop body persists in the post-loop bindings, so a tainted
    # ``cb(raw)`` after the loop must fire. (Pins the loop path the candidate-set's FP
    # concern names; verified it neither hangs nor accumulates — rebinds are idempotent.)
    src = "def handler(raw):\n    for i in items:\n        cb = lambda c: sink(c)\n    cb(raw)\n"
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_benign_rebind_after_loop_replaces_lambda_candidate() -> None:
    # wardline-383f83fafe FP guard on the loop path: a benign linear rebind AFTER the loop
    # REPLACES the loop body's sink binding, so ``cb(raw)`` resolves only the benign body
    # — no stale accumulation across the loop boundary.
    src = "def handler(raw):\n    for i in items:\n        cb = lambda c: sink(c)\n    cb = lambda c: c\n    cb(raw)\n"
    assert _lambda_body_sink_arg(src) == T.INTEGRAL


def _time_chained_rebind_analysis(make_src: Callable[[int], str]) -> tuple[float, float]:
    """Analyze a chained-rebind source (built by *make_src(n)*) at N=700 and N=2000;
    return ``(t_small, t_big)`` wall-clock seconds.

    The ``t_big / t_small`` ratio discriminates the merge's complexity CLASS
    independent of hardware speed — a uniform slow-CI factor cancels in the ratio.
    The eliminated nested-scan dedup was O(N**3): ~(2000/700)**3 ≈ 23x from small to
    big. The set-based dedup is O(N**2): ~(2000/700)**2 ≈ 8x. A reversion to cubic
    lands well above the 16x gate below on any box; first-run cold-cache noise only
    inflates ``t_small`` (shrinks the ratio — the safe direction for an upper bound)."""

    def run(n: int) -> float:
        func = ast.parse(make_src(n)).body[0]
        assert isinstance(func, ast.FunctionDef)
        start = time.perf_counter()
        compute_variable_taints(func, T.UNKNOWN_RAW, {}, call_site_taints={}, alias_map={}, call_site_arg_taints={})
        return time.perf_counter() - start

    return run(700), run(2000)


def test_lambda_candidate_merge_is_not_cubic_on_chained_rebinds() -> None:
    # wardline-c797baf28b (DoS): a sequence of one-armed branches each rebinding the
    # SAME name to a fresh lambda grows the candidate set to N, and the per-merge
    # identity dedup was a nested linear scan — O(bucket) per insert, O(bucket**2)
    # per merge, O(N**3) cumulative. At ~1100 branches a single attacker-authored
    # file made a DEFAULT-gate scan take ~15s. The merge dedups via an identity set
    # now (O(bucket) per merge, O(N**2) cumulative). The primary guard is the
    # hardware-independent scaling ratio (see _time_chained_rebind_analysis); the
    # absolute backstop only trips on absurd slowness (nominal ~0.26s at N=2000).
    def make_src(n: int) -> str:
        lines = ["def f(raw):", "    cb = lambda c: noop(c)"]
        for i in range(n):
            lines.append(f"    if flag{i}:")
            lines.append(f"        cb = lambda c: sink{i}(c)")
        lines.append("    cb(raw)")
        return "\n".join(lines)

    t_small, t_big = _time_chained_rebind_analysis(make_src)
    assert t_big / t_small < 16.0  # ~8x quadratic vs ~23x cubic — catches a cubic reversion on any box
    assert t_big < 8.0


def test_var_type_candidate_merge_is_not_cubic_on_chained_rebinds() -> None:
    # wardline-c797baf28b sibling: ``_merge_branch_types`` unions receiver-type FQN
    # candidate sets with the IDENTICAL nested-linear-scan dedup, so a chain of
    # one-armed ``if flagK: x = ClsK()`` rebinds had the same O(N**3) blowup. The
    # equality-set dedup makes it O(N**2). Same ratio + backstop guards.
    def make_src(n: int) -> str:
        lines = ["def f(raw):", "    x = Base()"]
        for i in range(n):
            lines.append(f"    if flag{i}:")
            lines.append(f"        x = Cls{i}()")
        lines.append("    x.method(raw)")
        return "\n".join(lines)

    t_small, t_big = _time_chained_rebind_analysis(make_src)
    assert t_big / t_small < 16.0
    assert t_big < 8.0


def test_chained_one_armed_rebinds_keep_every_lambda_candidate() -> None:
    # wardline-c797baf28b SOUNDNESS lock (NOT the cubic-regression guard — this also
    # passed pre-fix, where distinct lambdas were never wrongly coalesced). It pins
    # the two ways the set-based dedup could silently change behavior: (1) a candidate
    # CAP being introduced, or (2) the id-set coalescing distinct lambda bodies. A
    # sink-lambda bound in the FIRST of many one-armed branches must remain a live
    # candidate at the post-branch ``cb(raw)`` even though 39 later branches rebind the
    # same name to benign lambdas — ``cb`` MAY still hold the first body on the path
    # where only ``f0`` was taken, so the full union must survive (sink arg EXTERNAL_RAW).
    lines = ["def handler(raw):", "    if f0:", "        cb = lambda c: sink(c)"]
    for i in range(1, 40):
        lines.append(f"    if f{i}:")
        lines.append(f"        cb = lambda c: noop{i}(c)")
    lines.append("    cb(raw)")
    assert _lambda_body_sink_arg("\n".join(lines)) == T.EXTERNAL_RAW


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


def test_match_arm_assignment_merges_across_arms() -> None:
    # x assigned raw in one arm, integral in another; arms + the no-match
    # fall-through (pre-match x=INTEGRAL) merge via the rank-meet least_trusted
    # (weakest-link): least_trusted(EXTERNAL_RAW, INTEGRAL, INTEGRAL) =
    # EXTERNAL_RAW — the raw arm propagates at its rank, NOT a MIXED_RAW clash.
    src = (
        "def f(p):\n"
        "    x = 1\n"
        "    match p:\n"
        "        case 1:\n"
        "            x = tainted()\n"
        "        case _:\n"
        "            x = 2\n"
    )
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["x"] == T.EXTERNAL_RAW


def test_match_capture_binds_subject_taint() -> None:
    # `case y:` binds y to the subject's taint (conservative: whole-subject taint).
    src = "def f(p):\n    match tainted():\n        case y:\n            z = y\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["z"] == T.EXTERNAL_RAW


def test_match_sequence_and_class_captures_bind_subject_taint() -> None:
    seq = _vt(
        "def f(p):\n    match tainted():\n        case [a, b]:\n            z = a\n",
        function_taint=T.INTEGRAL,
        taint_map={"tainted": T.EXTERNAL_RAW},
    )
    assert seq["z"] == T.EXTERNAL_RAW
    cls = _vt(
        "def f(p):\n    match tainted():\n        case Point(x=px):\n            z = px\n",
        function_taint=T.INTEGRAL,
        taint_map={"tainted": T.EXTERNAL_RAW},
    )
    assert cls["z"] == T.EXTERNAL_RAW


def test_match_guard_walrus_is_captured() -> None:
    # A walrus in a case guard binds the enclosing scope (evaluated when testing
    # the arm). Pin it like the if/try walrus handling.
    src = "def f(p):\n    match p:\n        case 1 if (w := tainted()):\n            z = w\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["w"] == T.EXTERNAL_RAW


def test_match_subject_walrus_is_captured() -> None:
    src = "def f(p):\n    match (s := tainted()):\n        case _:\n            pass\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["s"] == T.EXTERNAL_RAW


def test_match_subject_nested_walrus_is_captured() -> None:
    src = "def f(p):\n    match (s := tainted())[0]:\n        case _:\n            pass\n"
    out = _vt(src, function_taint=T.ASSURED, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["s"] == T.EXTERNAL_RAW


def test_match_does_not_descend_into_nested_function() -> None:
    src = (
        "def f(p):\n"
        "    match p:\n"
        "        case 1:\n"
        "            def inner():\n"
        "                y = tainted()\n"
        "            x = 1\n"
    )
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert "x" in out
    assert "y" not in out  # nested scope is its own entity


def test_collect_pattern_targets_covers_all_binding_shapes() -> None:
    import ast

    from wardline.scanner.taint.variable_level import _collect_pattern_targets

    def targets(pattern_src: str) -> set[str]:
        # parse `match _:\n case <pattern>: pass` and pull the case pattern
        m = ast.parse(f"match x:\n case {pattern_src}:\n  pass\n").body[0]
        return _collect_pattern_targets(m.cases[0].pattern)  # type: ignore[attr-defined]

    assert targets("1") == set()  # MatchValue — no binding
    assert targets("_") == set()  # wildcard — no binding
    assert targets("y") == {"y"}  # MatchAs capture
    assert targets("[a, b]") == {"a", "b"}  # MatchSequence
    assert targets("[a, *rest]") == {"a", "rest"}  # MatchStar
    assert targets("Point(x=px, y=py)") == {"px", "py"}  # MatchClass kwd patterns
    assert targets("Point(px, py)") == {"px", "py"}  # MatchClass positional
    assert targets("{'k': v, **others}") == {"v", "others"}  # MatchMapping + rest
    assert targets("Point() as whole") == {"whole"}  # MatchAs with sub-pattern
    assert targets("[a] | (b)") == {"a", "b"}  # MatchOr — union of alternatives
    assert targets("1 | 2") == set()  # MatchOr of values — no binding


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


def test_compute_return_callee_identifies_least_trusted_call() -> None:
    import ast
    import textwrap

    from wardline.core.taints import TaintState as T
    from wardline.scanner.taint.variable_level import (
        compute_return_callee,
        compute_variable_taints,
    )

    tm = {"read_raw": T.EXTERNAL_RAW, "validate": T.ASSURED, "svc.read_raw": T.EXTERNAL_RAW}

    def rc(src: str) -> str | None:
        node = ast.parse(textwrap.dedent(src)).body[0]
        var_taints = compute_variable_taints(node, T.INTEGRAL, dict(tm))
        return compute_return_callee(node, T.INTEGRAL, dict(tm), var_taints)

    # direct-call return → the callee name
    assert rc("def f(p):\n return read_raw(p)\n") == "read_raw"
    # dotted direct-call return → the dotted callee name
    assert rc("def f(p):\n return svc.read_raw(p)\n") == "svc.read_raw"
    # worst return path is an indirect `return <var>` set by a direct call → the
    # contributing callee is now resolved single-hop (T1.3, was SP9-deferred None).
    assert rc("def f(p):\n x = read_raw(p)\n return x\n") == "read_raw"
    # `return <param>` has no contributing call → still None (honest, not invented).
    assert rc("def f(p):\n return p\n") is None
    # multiple returns: the least-trusted path is the call → that callee, even though
    # the integral path comes first in source order.
    assert rc("def f(p):\n if p:\n  return 1\n return read_raw(p)\n") == "read_raw"
    # tie-break across the SAME worst tier: both `return x` (a bare name carrying the
    # raw taint) and `return read_raw(p)` land at EXTERNAL_RAW, but the first is a
    # non-call. The loop must skip the worst-tier non-call to reach the worst-tier
    # direct call — so the callee is `read_raw`, not None.
    assert rc("def f(p):\n x = read_raw(p)\n if p:\n  return x\n return read_raw(p)\n") == "read_raw"
    # the worst path is the validated (trusted) call, not the raw one it wraps; the
    # top-level direct call of the least-trusted return is `validate`.
    assert rc("def f(p):\n return validate(read_raw(p))\n") == "validate"
    # no value-bearing return → None
    assert rc("def f():\n return\n") is None


# ── PART A: expression-coverage soundness (fail-open laundering closed) ──────
#
# Every test seeds ``function_taint=INTEGRAL`` (a TRUSTED tier) so the bug is
# visible: the line-134 fallback used to ``return function_taint`` — for an
# anchored @trusted producer that resets laundered raw data back to INTEGRAL.
# We assert each shape carries the contributing taint (UNKNOWN_RAW — the precise
# rank-meet least_trusted result, raw propagating), never the trusted seed.

_RAW_TM = {"read_raw": T.UNKNOWN_RAW}


def test_fstring_carries_interpolated_taint() -> None:
    # f"{read_raw(p)}" — pure interpolation, no literal text → UNKNOWN_RAW.
    out = _vt("def f(p):\n    x = f'{read_raw(p)}'\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_fstring_with_literal_text_combines_via_least_trusted() -> None:
    # f"x={read_raw(p)}" — string-building uses the rank-meet least_trusted (NOT
    # taint_join): least_trusted(INTEGRAL literal, UNKNOWN_RAW) = UNKNOWN_RAW. The
    # literal text is benign and must not manufacture a MIXED_RAW provenance clash.
    out = _vt("def f(p):\n    x = f'x={read_raw(p)}'\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_fstring_with_literal_text_and_validated_stays_clean() -> None:
    # f"x={validate(p)}" inside an ASSURED producer: least_trusted(INTEGRAL, ASSURED)
    # = ASSURED — the benign literal does NOT demote validated data. (No false
    # positive; taint_join would wrongly yield MIXED_RAW here.)
    out = _vt(
        "def f(p):\n    x = f'x={validate(p)}'\n",
        function_taint=T.ASSURED,
        taint_map={"validate": T.ASSURED},
    )
    assert out["x"] == T.ASSURED


def test_fstring_empty_is_integral() -> None:
    out = _vt("def f():\n    x = f''\n", function_taint=T.INTEGRAL)
    assert out["x"] == T.INTEGRAL


def test_str_and_format_call_fall_through_to_arg_walrus_but_carry_function_taint() -> None:
    # str()/"{}".format() are unmodelled Calls absent from the taint_map; they fall
    # back to function_taint. That is SOUND when function_taint is the raw seed
    # (over-approx). The laundering bug is the f-string / subscript / etc. shapes,
    # not str() — but we still assert the arg walrus is resolved for side effects.
    out = _vt(
        "def f(p):\n    x = str(y := read_raw(p))\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["y"] == T.UNKNOWN_RAW  # walrus side-effect captured


def test_subscript_carries_container_taint() -> None:
    # [read_raw(p)][0] — list is UNKNOWN_RAW, subscript carries it.
    out = _vt("def f(p):\n    x = [read_raw(p)][0]\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_subscript_dict_literal_carries_value_taint() -> None:
    out = _vt("def f(p):\n    x = {'k': read_raw(p)}['k']\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_subscript_resolves_slice_for_walrus() -> None:
    # d[(i := read_raw(p))] — the slice walrus must bind.
    out = _vt(
        "def f(p, d):\n    x = d[(i := read_raw(p))]\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["i"] == T.UNKNOWN_RAW


def test_attribute_read_carries_object_taint() -> None:
    # o is UNKNOWN_RAW; o.x carries the object's taint.
    out = _vt(
        "def f(p):\n    o = read_raw(p)\n    x = o.attr\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_await_unwraps_inner_call() -> None:
    out = _vt(
        "async def f(p):\n    r = await read_raw(p)\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["r"] == T.UNKNOWN_RAW


def test_boolop_combines_all_values_via_least_trusted() -> None:
    # read_raw(p) or 'x' — either/or = least_trusted(UNKNOWN_RAW, INTEGRAL) = UNKNOWN_RAW.
    out = _vt("def f(p):\n    x = read_raw(p) or 'x'\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_boolop_and_with_raw_value() -> None:
    # p and read_raw(p) — p is INTEGRAL; least_trusted(INTEGRAL, UNKNOWN_RAW) = UNKNOWN_RAW.
    out = _vt("def f(p):\n    x = p and read_raw(p)\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_boolop_all_raw_stays_raw() -> None:
    out = _vt(
        "def f(p):\n    x = read_raw(p) or read_raw(p)\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_listcomp_carries_element_taint() -> None:
    # [x for x in [read_raw(p)]] — iter is UNKNOWN_RAW, x binds UNKNOWN_RAW, elt is x.
    out = _vt(
        "def f(p):\n    x = [y for y in [read_raw(p)]]\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_setcomp_carries_element_taint() -> None:
    out = _vt(
        "def f(p):\n    x = {y for y in [read_raw(p)]}\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_genexp_carries_element_taint() -> None:
    out = _vt(
        "def f(p):\n    x = (y for y in [read_raw(p)])\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_dictcomp_combines_key_and_value_taint() -> None:
    # {k: read_raw(p) for k in range(1)} — least_trusted(INTEGRAL key, UNKNOWN_RAW value)
    # = UNKNOWN_RAW (raw value propagates at its precise rank).
    out = _vt(
        "def f(p):\n    x = {k: read_raw(p) for k in range(1)}\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_multi_generator_comprehension_chains_taint() -> None:
    # Flatten pattern: the SECOND generator's iterable references the FIRST
    # generator's target. The target must be visible in the comprehension's local
    # scope, or gen2's iter resolves to function_taint (trusted seed) → launder.
    out = _vt(
        "def f(p):\n    x = [y for row in [read_raw(p)] for y in row]\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_comprehension_walrus_leaks_to_enclosing_scope() -> None:
    # PEP 572: a walrus inside a comprehension binds the ENCLOSING scope.
    out = _vt(
        "def f(p):\n    x = [(w := read_raw(p)) for _ in range(1)]\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["w"] == T.UNKNOWN_RAW


# ── PART B: container-write taint (subscript / attribute assignment targets) ──


def test_subscript_write_taints_base_container() -> None:
    # d[k] = read_raw(p); then read d back — d must carry the contaminated taint.
    out = _vt(
        "def f(p):\n    d = {}\n    d['k'] = read_raw(p)\n    x = d\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    # d was INTEGRAL ({}); least_trusted(INTEGRAL, UNKNOWN_RAW) = UNKNOWN_RAW — raw
    # write still contaminates (fires), at its precise rank rather than MIXED_RAW.
    assert out["d"] == T.UNKNOWN_RAW
    assert out["x"] == T.UNKNOWN_RAW


def test_attribute_write_taints_base_object() -> None:
    # o.x = read_raw(p); return o.x — the object's tracked taint absorbs the write.
    out = _vt(
        "def f(p, o):\n    o.attr = read_raw(p)\n    x = o.attr\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    # o is INTEGRAL (param at function_taint); least_trusted(INTEGRAL, UNKNOWN_RAW)
    # = UNKNOWN_RAW; o.attr read carries o's taint.
    assert out["o"] == T.UNKNOWN_RAW
    assert out["x"] == T.UNKNOWN_RAW


def test_nested_subscript_write_taints_root_name() -> None:
    # d[a][b] = read_raw(p) — the ROOT Name d absorbs the taint.
    out = _vt(
        "def f(p, d):\n    d[a][b] = read_raw(p)\n    x = d\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["d"] == T.UNKNOWN_RAW
    assert out["x"] == T.UNKNOWN_RAW


def test_augassign_subscript_target_taints_base() -> None:
    # d[k] += read_raw(p) — the base d absorbs the RHS taint via least_trusted.
    out = _vt(
        "def f(p, d):\n    d[k] += read_raw(p)\n    x = d\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["d"] == T.UNKNOWN_RAW


def test_annassign_attribute_target_taints_base() -> None:
    # self.x: str = read_raw(p) — an ANNOTATED container write. Same fail-open
    # shape as the plain-assign Part B fix: the base must absorb the RHS taint,
    # else a later read of self.x reads it back at the creation taint.
    out = _vt(
        "def f(p, o):\n    o.x: str = read_raw(p)\n    y = o.x\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["o"] == T.UNKNOWN_RAW
    assert out["y"] == T.UNKNOWN_RAW


def test_annassign_subscript_target_taints_base() -> None:
    # d['k']: str = read_raw(p) — annotated subscript write contaminates the base.
    out = _vt(
        "def f(p, d):\n    d['k']: str = read_raw(p)\n    x = d\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["d"] == T.UNKNOWN_RAW
    assert out["x"] == T.UNKNOWN_RAW


# ── PART E: curated taint-PROPAGATING operations (closed fail-open launders) ──
#
# A small explicit table (mirroring _SERIALISATION_SINKS) of builtin conversions
# and propagating methods. UNKNOWN calls STILL fall back to function_taint — only
# these curated names propagate, so len(raw)/int(raw)/validate(raw) stay
# unaffected (no FP explosion). Seed INTEGRAL to expose the launder.


def test_str_builtin_propagates_arg_taint() -> None:
    out = _vt("def f(p):\n    x = str(read_raw(p))\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_repr_builtin_propagates_arg_taint() -> None:
    out = _vt("def f(p):\n    x = repr(read_raw(p))\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_bytes_builtin_propagates_arg_taint() -> None:
    out = _vt("def f(p):\n    x = bytes(read_raw(p))\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_str_builtin_no_args_is_integral() -> None:
    out = _vt("def f():\n    x = str()\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.INTEGRAL


def test_str_builtin_constant_arg_stays_integral() -> None:
    # Clean counterpart: str("constant") in any context stays INTEGRAL (no FP).
    out = _vt("def f():\n    x = str('constant')\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.INTEGRAL


def test_format_builtin_joins_args() -> None:
    out = _vt(
        "def f(p):\n    x = format(read_raw(p))\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_next_builtin_propagates_iterator_taint() -> None:
    # next(genexp) — the iterator arg's taint propagates through.
    out = _vt(
        "def f(p):\n    x = next(y for y in [read_raw(p)])\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_format_method_combines_receiver_and_args_via_least_trusted() -> None:
    # "{}".format(read_raw(p)) — string-building combines via least_trusted:
    # least_trusted(INTEGRAL receiver, UNKNOWN_RAW) = UNKNOWN_RAW (still fires).
    out = _vt(
        "def f(p):\n    x = '{}'.format(read_raw(p))\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_format_method_validated_arg_stays_clean() -> None:
    # "{}".format(validate(p)) in an ASSURED producer: least_trusted(INTEGRAL,
    # ASSURED) = ASSURED — no false positive. (taint_join would give MIXED_RAW.)
    out = _vt(
        "def f(p):\n    x = '{}'.format(validate(p))\n",
        function_taint=T.ASSURED,
        taint_map={"validate": T.ASSURED},
    )
    assert out["x"] == T.ASSURED


def test_join_method_combines_receiver_and_args_via_least_trusted() -> None:
    # ",".join([read_raw(p)]) — least_trusted(INTEGRAL receiver, UNKNOWN_RAW list)
    # = UNKNOWN_RAW (still fires).
    out = _vt(
        "def f(p):\n    x = ','.join([read_raw(p)])\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_join_method_validated_arg_stays_clean() -> None:
    # ",".join([validate(p)]) in an ASSURED producer: the INTEGRAL separator does
    # NOT demote the ASSURED element — least_trusted(INTEGRAL, ASSURED) = ASSURED.
    out = _vt(
        "def f(p):\n    x = ','.join([validate(p)])\n",
        function_taint=T.ASSURED,
        taint_map={"validate": T.ASSURED},
    )
    assert out["x"] == T.ASSURED


def test_dict_get_carries_receiver_taint() -> None:
    out = _vt(
        "def f(p):\n    d = {'k': read_raw(p)}\n    x = d.get('k')\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_dict_pop_carries_receiver_taint() -> None:
    out = _vt(
        "def f(p):\n    d = {'k': read_raw(p)}\n    x = d.pop('k')\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_dict_setdefault_carries_receiver_taint() -> None:
    out = _vt(
        "def f(p):\n    d = {'k': read_raw(p)}\n    x = d.setdefault('k')\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_dict_get_joins_tainted_default_arg() -> None:
    # d.get('k', read_raw(p)) — the DEFAULT is a possible return value, so its
    # taint must propagate even from an INTEGRAL container. The lookup KEY (first
    # positional) is not a return value and is not joined. Joining a tainted
    # default propagates an existing taint (not a new SOURCE).
    out = _vt(
        "def f(p):\n    d = {}\n    x = d.get('k', read_raw(p))\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    # receiver d is INTEGRAL ({}), default is UNKNOWN_RAW → least_trusted = UNKNOWN_RAW
    # (raw default propagates and fires PY-WL-101; NOT the laundered INTEGRAL).
    assert out["x"] == T.UNKNOWN_RAW


def test_dict_get_clean_constant_default_stays_integral() -> None:
    # Clean counterpart: an INTEGRAL container + constant default stays INTEGRAL.
    out = _vt(
        "def f(p):\n    d = {}\n    x = d.get('k', 'fallback')\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.INTEGRAL


def test_dict_pop_joins_tainted_default_arg() -> None:
    out = _vt(
        "def f(p):\n    d = {}\n    x = d.pop('k', read_raw(p))\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    # receiver INTEGRAL, default UNKNOWN_RAW → least_trusted = UNKNOWN_RAW (raw zone, fires).
    assert out["x"] == T.UNKNOWN_RAW


def test_unknown_builtin_call_still_falls_back_to_function_taint() -> None:
    # HARD BOUNDARY: len()/int() are curated NON-propagators (validators/
    # measurers) — they keep the function_taint fallback. An unknown bare call
    # like validate() (absent from the taint_map) is the OPPOSITE: it now
    # propagates the worst of (caller seed, args) — an unmodeled callee cannot
    # be assumed to clean a raw argument (wardline-93d608c997; the unresolved
    # bare-name launder closure). See test_engine_precision.py for the family.
    assert _vt("def f(p):\n    x = len(read_raw(p))\n", function_taint=T.GUARDED, taint_map=_RAW_TM)["x"] == T.GUARDED
    assert _vt("def f(p):\n    x = int(read_raw(p))\n", function_taint=T.GUARDED, taint_map=_RAW_TM)["x"] == T.GUARDED
    assert (
        _vt("def f(p):\n    x = validate(read_raw(p))\n", function_taint=T.GUARDED, taint_map=_RAW_TM)["x"]
        == T.UNKNOWN_RAW
    )


def test_serialisation_sink_still_wins_over_generic_method() -> None:
    # json.dumps is a sink (UNKNOWN_RAW) and must keep precedence over the generic
    # .format/.join/.get method handling — sink check stays AHEAD.
    out = _vt("def f(p):\n    x = json.dumps(p)\n", function_taint=T.INTEGRAL, taint_map=_RAW_TM)
    assert out["x"] == T.UNKNOWN_RAW


def test_mapped_method_still_wins_over_generic_get() -> None:
    # A taint_map hit for a dotted method (e.g. self.get resolved to a project
    # method) must win over the generic .get receiver-propagation.
    out = _vt(
        "def f(p):\n    x = self.get(p)\n",
        function_taint=T.INTEGRAL,
        taint_map={"self.get": T.ASSURED},
    )
    assert out["x"] == T.ASSURED


def test_join_via_local_var_does_not_demote_validated_data() -> None:
    # String-building uses the rank-meet least_trusted, NOT taint_join: the INTEGRAL
    # separator is the weakest-link winner only when it is LESS trusted than the
    # element, which it never is. least_trusted(INTEGRAL, ASSURED) = ASSURED — the
    # benign separator does not manufacture a MIXED_RAW provenance clash, so a
    # validated producer stays CLEAN (no false positive). The BinOp/List/Dict/IfExp/
    # BoolOp/.get combiners use the SAME least_trusted rule (see PART F); and
    # control-flow MERGES (if/else, loops, match arms) ALSO use least_trusted
    # (migration wardline-4d9f840c24) — no combiner uses taint_join.
    out = _vt(
        "def f(p):\n    v = validate(p)\n    x = ','.join([v])\n",
        function_taint=T.ASSURED,
        taint_map={"validate": T.ASSURED},
    )
    assert out["x"] == T.ASSURED


# ── PART F: expression combiners use the rank-meet least_trusted (weakest-link),
# NOT the provenance-clash taint_join — so a benign literal/clean operand does not
# manufacture a MIXED_RAW false positive on validated data, while raw still
# propagates at its precise rank. Mirrors the f-string/.format/.join precedent.
# Control-flow MERGES (if/else, loop back-edge, match arms) ALSO use least_trusted
# (migration wardline-4d9f840c24) and are covered by the merge tests above. ──

_VALIDATE_TM = {"validate": T.ASSURED}


def test_binop_validated_operand_stays_clean() -> None:
    # '' + validate(p): least_trusted(INTEGRAL, ASSURED) = ASSURED (clean). taint_join
    # would wrongly yield MIXED_RAW — a false positive on validated data.
    out = _vt(
        "def f(p):\n    v = validate(p)\n    x = '' + v\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["x"] == T.ASSURED


def test_binop_raw_operand_propagates_precise_rank() -> None:
    # '' + read_raw(p): least_trusted(INTEGRAL, UNKNOWN_RAW) = UNKNOWN_RAW — raw still
    # propagates (and fires), just at its precise rank rather than MIXED_RAW.
    out = _vt(
        "def f(p):\n    x = '' + read_raw(p)\n",
        function_taint=T.INTEGRAL,
        taint_map=_RAW_TM,
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_ifexp_validated_branches_stay_clean() -> None:
    # validate(p) if c else 'fallback': least_trusted(ASSURED, INTEGRAL) = ASSURED.
    out = _vt(
        "def f(p):\n    v = validate(p)\n    x = v if p else 'fallback'\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["x"] == T.ASSURED


def test_boolop_validated_operand_stays_clean() -> None:
    # validate(p) or 'fallback': least_trusted(ASSURED, INTEGRAL) = ASSURED.
    out = _vt(
        "def f(p):\n    v = validate(p)\n    x = v or 'fallback'\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["x"] == T.ASSURED


def test_list_validated_element_stays_clean() -> None:
    # ['lit', validate(p)]: least_trusted(INTEGRAL, ASSURED) = ASSURED.
    out = _vt(
        "def f(p):\n    v = validate(p)\n    x = ['lit', v]\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["x"] == T.ASSURED


def test_dict_literal_validated_value_stays_clean() -> None:
    # {'k': validate(p), 'j': 'lit'}: least_trusted(ASSURED, INTEGRAL) = ASSURED.
    out = _vt(
        "def f(p):\n    v = validate(p)\n    x = {'k': v, 'j': 'lit'}\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["x"] == T.ASSURED


def test_dictcomp_validated_value_stays_clean() -> None:
    # {k: validate(p) for k in range(1)}: least_trusted(INTEGRAL key, ASSURED) = ASSURED.
    out = _vt(
        "def f(p):\n    v = validate(p)\n    x = {k: v for k in range(1)}\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["x"] == T.ASSURED


def test_dict_get_validated_default_stays_clean() -> None:
    # d.get('k', validate(p)) from a trusted container: least_trusted(INTEGRAL, ASSURED)
    # = ASSURED — no MIXED_RAW clash. (A RAW default still propagates: see
    # test_dict_get_joins_tainted_default_arg.)
    out = _vt(
        "def f(p):\n    v = validate(p)\n    d = {}\n    x = d.get('k', v)\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["x"] == T.ASSURED


def test_augassign_validated_operand_stays_clean() -> None:
    # s = ''; s += validate(p): least_trusted(INTEGRAL, ASSURED) = ASSURED.
    out = _vt(
        "def f(p):\n    v = validate(p)\n    s = ''\n    s += v\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["s"] == T.ASSURED


def test_container_write_validated_value_stays_clean() -> None:
    # d = {}; d['k'] = validate(p): the base absorbs least_trusted(INTEGRAL, ASSURED)
    # = ASSURED — clean. A RAW write still contaminates (see Part B tests).
    out = _vt(
        "def f(p):\n    v = validate(p)\n    d = {}\n    d['k'] = v\n    x = d\n",
        function_taint=T.INTEGRAL,
        taint_map=_VALIDATE_TM,
    )
    assert out["d"] == T.ASSURED
    assert out["x"] == T.ASSURED


def test_compute_return_callee_resolves_single_hop_indirection() -> None:
    # T1.3: `x = read_raw(p); return x` — the worst return path is a bare Name whose
    # value came from a direct call. Name THAT callee (was None — SP9-deferred).
    import ast
    import textwrap

    from wardline.core.taints import TaintState as T
    from wardline.scanner.taint.variable_level import (
        compute_return_callee,
        compute_variable_taints,
    )

    tm = {"read_raw": T.EXTERNAL_RAW, "validate": T.ASSURED}

    def rc(src: str) -> str | None:
        node = ast.parse(textwrap.dedent(src)).body[0]
        var_taints = compute_variable_taints(node, T.INTEGRAL, dict(tm))
        return compute_return_callee(node, T.INTEGRAL, dict(tm), var_taints)

    # single-hop indirection through a local var → the contributing callee
    assert rc("def f(p):\n x = read_raw(p)\n return x\n") == "read_raw"
    # last source-order worst-taint assignment wins when reassigned
    assert rc("def f(p):\n x = validate(p)\n x = read_raw(p)\n return x\n") == "read_raw"
    # `return p` (a parameter, no call assignment) stays None — honest, not invented
    assert rc("def f(p):\n return p\n") is None
    # deeper/aliased chains beyond one hop stay None (deferred to the N-hop store path)
    assert rc("def f(p):\n x = read_raw(p)\n y = x\n return y\n") is None


def test_compute_return_taint_value_unchanged_for_indirection() -> None:
    # T1.3 is explain-surface ONLY: the taint VALUE compute_return_taint returns must
    # be identical for an indirect return (pin the invariant the audit fixed).
    import ast
    import textwrap

    from wardline.core.taints import TaintState as T
    from wardline.scanner.taint.variable_level import (
        compute_return_taint,
        compute_variable_taints,
    )

    tm = {"read_raw": T.EXTERNAL_RAW}
    src = "def f(p):\n x = read_raw(p)\n return x\n"
    node = ast.parse(textwrap.dedent(src)).body[0]
    var_taints = compute_variable_taints(node, T.INTEGRAL, dict(tm))
    assert compute_return_taint(node, T.INTEGRAL, dict(tm), var_taints) == T.EXTERNAL_RAW


# ── Coverage: control-flow / target shapes that the existing corpus does not reach.
# Each drives a specific structural arm AND asserts the resulting variable taint. ──


def test_standalone_formattedvalue_resolves_inner_value() -> None:
    # A bare FormattedValue node (the interpolation field, no surrounding JoinedStr)
    # must carry its inner expression's taint. Resolved directly via _resolve_expr.
    import ast

    from wardline.scanner.taint.variable_level import _resolve_expr

    node = ast.parse("f'{p}'").body[0].value  # JoinedStr
    field = node.values[0]
    assert isinstance(field, ast.FormattedValue)
    out = _resolve_expr(field, T.UNKNOWN_RAW, {}, {"p": T.EXTERNAL_RAW})
    assert out == T.EXTERNAL_RAW


def test_nested_walrus_in_comprehension_element_binds_outer_scope() -> None:
    # _name_bound_by_walrus recurses through nested children: a walrus buried BELOW
    # the comprehension's direct element (inside a call wrapping it) is found by the
    # recursive descent, so PEP 572's enclosing-scope binding leaks back and the
    # bound name reads the assigned (raw) taint, not the literal default.
    src = "def f(p):\n    z = [g((x := read_raw(p))) for _ in r]\n    y = x\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"read_raw": T.EXTERNAL_RAW})
    assert out["y"] == T.EXTERNAL_RAW


def test_comprehension_walrus_rebinds_existing_outer_name() -> None:
    # PEP 572 writes a comprehension walrus target into the enclosing function
    # scope even when the name already exists. A clean initializer must not mask
    # the later raw assignment.
    src = "def f(p):\n    x = 1\n    z = [(x := read_raw(p)) for _ in items]\n    y = x\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"read_raw": T.EXTERNAL_RAW})
    assert out["y"] == T.EXTERNAL_RAW


@pytest.mark.parametrize(
    "expr",
    [
        "[(x := read_raw(p)) for _ in items]",
        "{(x := read_raw(p)) for _ in items}",
        "{_: (x := read_raw(p)) for _ in items}",
        "((x := read_raw(p)) for _ in items)",
    ],
)
def test_comprehension_walrus_rebinds_existing_outer_name_for_all_forms(expr: str) -> None:
    src = f"def f(p):\n    x = 1\n    z = {expr}\n    y = x\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"read_raw": T.EXTERNAL_RAW})
    assert out["y"] == T.EXTERNAL_RAW


def test_propagating_builtin_multi_arg_combines_via_least_trusted() -> None:
    # format(value, spec) is a curated propagating builtin: it combines ALL arg taints
    # via least_trusted (the loop over arg_taints[1:]), so a raw arg taints the result
    # even alongside a clean one. least_trusted(INTEGRAL, EXTERNAL_RAW) = EXTERNAL_RAW.
    out = _vt(
        "def f(p):\n    spec = ''\n    x = format(p, spec)\n",
        function_taint=T.EXTERNAL_RAW,
    )
    assert out["x"] == T.EXTERNAL_RAW


def test_multi_target_assign_with_container_write_walks_every_target() -> None:
    # ``d[0] = y = p`` has two targets: a Subscript FIRST then a Name. After the
    # Subscript-write branch the for-loop must continue to the next (Name) target —
    # tainting the plain Name y AND contaminating the container base d.
    src = "def f(p):\n    d = {}\n    d[0] = y = p\n    z = d\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["y"] == T.EXTERNAL_RAW  # the plain-Name target, reached after the subscript
    assert out["z"] == T.EXTERNAL_RAW  # container base contaminated by the subscript write


def test_nested_tuple_unpack_elementwise() -> None:
    # ``((b, c), d) = ((2, p), 9)`` — element-wise unpack: the FIRST pair is a nested
    # tuple target, so after recursing into it the loop must continue to the trailing
    # Name pair (d, 9). p is function_taint(EXTERNAL_RAW); the nested c must receive it.
    src = "def f(p):\n    ((b, c), d) = ((2, p), 9)\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["b"] == T.INTEGRAL
    assert out["c"] == T.EXTERNAL_RAW
    assert out["d"] == T.INTEGRAL


def test_matching_unpack_with_starred_middle_element() -> None:
    # ``(a, *b, c) = (1, 2, p)`` — element-wise matching unpack. The middle target is
    # a Starred that captures the literal middle slice, while c gets p's taint.
    src = "def f(p):\n    (a, *b, c) = (1, 2, p)\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["a"] == T.INTEGRAL
    assert out["b"] == T.INTEGRAL
    assert out["c"] == T.EXTERNAL_RAW  # the literal p element


def test_matching_unpack_starred_middle_captures_raw_slice() -> None:
    # ``rest`` captures the raw middle element. Skipping the Starred target would
    # leave later reads of rest at the trusted function seed.
    src = "def f(p):\n    (a, *rest, c) = (1, read_raw(p), 2)\n    y = rest\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"read_raw": T.EXTERNAL_RAW})
    assert out["rest"] == T.EXTERNAL_RAW
    assert out["y"] == T.EXTERNAL_RAW


def test_nonmatching_unpack_with_nested_list_target_skipped() -> None:
    # ``[x, [y], z] = p`` — RHS is not a matching literal tuple, so every Name target
    # gets the RHS taint. The middle target is a nested List (neither Name nor
    # Starred), so the loop must skip it and continue to the trailing Name z.
    src = "def f(p):\n    [x, [y], z] = p\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW
    assert out["z"] == T.EXTERNAL_RAW  # reached after the skipped nested-list target


def test_starred_target_in_nonmatching_unpack_gets_rhs_taint() -> None:
    # ``*rest, a = p`` — RHS is not a matching literal tuple, so every target gets the
    # RHS taint. The Starred target comes FIRST, so after its branch the loop must
    # continue to the trailing Name target a.
    src = "def f(p):\n    *rest, a = p\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["rest"] == T.EXTERNAL_RAW
    assert out["a"] == T.EXTERNAL_RAW


def test_container_write_through_call_base_is_noop() -> None:
    # ``foo()[k] = p`` — the write target's chain bottoms out at a Call, not a Name,
    # so _container_base_name returns None and _taint_container_base does nothing
    # (the 606->exit arm). No variable is tracked, but the walk must not crash and any
    # genuinely tracked var is untouched.
    src = "def f(p):\n    z = 42\n    foo()[0] = p\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["z"] == T.INTEGRAL  # unaffected — the call-base write tracked nothing


def test_for_else_body_is_walked() -> None:
    # ``for ... else`` — the orelse body runs after normal completion and must be
    # walked so its assignments are tracked.
    src = "def f(p):\n    for i in p:\n        pass\n    else:\n        x = p\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW


def test_while_else_body_is_walked() -> None:
    # ``while ... else`` — the orelse body must be walked.
    src = "def f(p):\n    while c:\n        pass\n    else:\n        x = p\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW


def test_try_finally_body_is_walked() -> None:
    # ``try/finally`` — the finalbody runs unconditionally after merge and must be
    # walked so its assignments are tracked.
    src = "def f(p):\n    try:\n        pass\n    finally:\n        x = p\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW


def test_match_mapping_rest_and_norest_capture_targets() -> None:
    # _collect_pattern_targets over a MatchMapping: WITH a ``**rest`` capture (rest is
    # not None → bound) and WITHOUT (rest is None → the 890->899 fall-through). Both
    # captured names inherit the subject taint; a no-rest mapping binds only its value
    # sub-patterns.
    src_rest = "def f(p):\n    match p:\n        case {'k': v, **rest}:\n            a = rest\n            b = v\n"
    out = _vt(src_rest, function_taint=T.EXTERNAL_RAW)
    assert out["a"] == T.EXTERNAL_RAW  # **rest captured the subject
    assert out["b"] == T.EXTERNAL_RAW  # value sub-pattern captured the subject

    src_norest = "def f(p):\n    match p:\n        case {'k': v}:\n            b = v\n"
    out2 = _vt(src_norest, function_taint=T.EXTERNAL_RAW)
    assert out2["b"] == T.EXTERNAL_RAW  # value sub-pattern captured; no rest binding


def test_match_sequence_named_and_anonymous_star() -> None:
    # MatchStar: a NAMED ``*rest`` binds (name is not None), while a bare ``*_`` binds
    # nothing (name is None → the 891->908 fall-through). The named star captures the
    # subject taint; the head capture does too.
    src = (
        "def f(p):\n"
        "    match p:\n"
        "        case [head, *rest]:\n"
        "            a = head\n"
        "            b = rest\n"
        "        case [first, *_]:\n"
        "            c = first\n"
    )
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["a"] == T.EXTERNAL_RAW  # head capture
    assert out["b"] == T.EXTERNAL_RAW  # *rest named-star capture
    assert out["c"] == T.EXTERNAL_RAW  # first capture (the *_ binds nothing — no crash)


def test_for_subscript_target_assigns_nothing_tracked() -> None:
    # ``for d[k] in p`` — the loop target is a Subscript, which _assign_target does not
    # bind (no Name/Tuple/List/Starred match → the 922->exit fall-through). The walk
    # must not crash and leaves no spurious tracked variable; a genuinely tracked var
    # is untouched.
    src = "def f(p):\n    d = {}\n    z = 42\n    for d[0] in p:\n        pass\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["z"] == T.INTEGRAL  # untouched


def test_for_target_nested_starred_assigns_taint() -> None:
    # ``for (a, *rest) in p`` — _assign_target recurses into the Tuple target and hits
    # the Starred arm (913-914), binding both a and rest to the iterable element taint.
    src = "def f(p):\n    for (a, *rest) in p:\n        pass\n"
    out = _vt(src, function_taint=T.EXTERNAL_RAW)
    assert out["a"] == T.EXTERNAL_RAW
    assert out["rest"] == T.EXTERNAL_RAW


def test_return_callee_indirect_call_func_is_none() -> None:
    # ``return foo[0]()`` — the return value IS a Call but its func is a Subscript
    # (neither Name nor Attribute), so _return_callee returns None: there is no
    # direct callee name to surface (the 1034->1036 fall-through). The taint is still
    # computed (function_taint fallback for the unmodelled call shape).
    import ast
    import textwrap

    from wardline.scanner.taint.variable_level import (
        compute_return_callee,
        compute_variable_taints,
    )

    src = "def f(p):\n return foo[0]()\n"
    node = ast.parse(textwrap.dedent(src)).body[0]
    vt = compute_variable_taints(node, T.EXTERNAL_RAW, {})
    assert compute_return_callee(node, T.EXTERNAL_RAW, {}, vt) is None


def test_generator_yield_carries_yielded_taint() -> None:
    import ast
    import textwrap

    from wardline.scanner.taint.variable_level import compute_return_taint, compute_variable_taints

    tm = {"read_raw": T.EXTERNAL_RAW}
    src = "def f(p):\n    yield read_raw(p)\n"
    node = ast.parse(textwrap.dedent(src)).body[0]
    var_taints = compute_variable_taints(node, T.INTEGRAL, dict(tm))
    assert compute_return_taint(node, T.INTEGRAL, dict(tm), var_taints) == T.EXTERNAL_RAW


def test_unresolved_nested_imported_call_returns_unknown_raw() -> None:
    out = _vt(
        "def f():\n    x = vendor.sub.clean()\n",
        function_taint=T.GUARDED,
        taint_map={},
        alias_map={"vendor": "vendor"},
    )
    assert out["x"] == T.UNKNOWN_RAW


def test_loop_carried_chain_deeper_than_lattice_height_propagates() -> None:
    # wardline-e04db6e656: the loop fixpoint cap was range(8) — lattice HEIGHT, not
    # propagation DEPTH. A read-before-write rebind chain propagates one link per
    # iteration, so an N-link chain needs N(+1) iterations; at cap=8 a chain > 8 links
    # left the head under-tainted (a fail-open soundness FN). Iterate-to-convergence
    # (num_vars × lattice_height backstop) fixes it for both for and while.
    def chain(n: int, loop: str) -> tuple[str, str]:
        names = [f"v{i}" for i in range(n)]
        body = [f"        {names[i]} = {names[i - 1]}" for i in range(n - 1, 0, -1)]
        body.append(f"        {names[0]} = read_raw(p)")
        head = "for _ in p:" if loop == "for" else "while p:"
        src = f"def f(p):\n    {names[n - 1]} = ''\n    {head}\n" + "\n".join(body) + "\n"
        return src, names[n - 1]

    for loop in ("for", "while"):
        for n in (9, 25):
            src, sink = chain(n, loop)
            out = _vt(src, function_taint=T.INTEGRAL, taint_map={"read_raw": T.EXTERNAL_RAW})
            assert out[sink] == T.EXTERNAL_RAW, (loop, n, out[sink])

    # CONTROL (FP guard): a deep chain whose head is a constant literal — never a raw
    # source — must stay clean regardless of iteration count.
    names = [f"v{i}" for i in range(12)]
    body = [f"        {names[i]} = {names[i - 1]}" for i in range(11, 0, -1)]
    body.append(f"        {names[0]} = ''")
    src = f"def f(p):\n    {names[11]} = ''\n    for _ in p:\n" + "\n".join(body) + "\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={})
    assert out[names[11]] == T.INTEGRAL, out[names[11]]


def test_storage_read_methods_seed_external_raw() -> None:
    # wardline-e7c7cda31a: cursor.fetch{one,all,many}() loads stored/external data and
    # must seed EXTERNAL_RAW (the formerly-dead PY-WL-120 branch). Clean function_taint
    # so only the seed can introduce taint.
    for method in ("fetchone", "fetchall", "fetchmany"):
        out = _vt(f"def f(cursor):\n    rows = cursor.{method}()\n", function_taint=T.ASSURED)
        assert out["rows"] == T.EXTERNAL_RAW, (method, out["rows"])


def test_container_mutator_writes_arg_taint_back_to_receiver() -> None:
    # wardline-67c7498931: a container mutator called with a tainted arg contaminates the
    # receiver (box.append(raw) matches the literal box=[raw]). Clean ASSURED seed + raw
    # via taint_map so only the mutated arg carries taint.
    tm = {"read_raw": T.UNKNOWN_RAW}
    for stmt, recv in (
        ("box = []\n    box.append(raw)", "box"),
        ("box = []\n    box.extend([raw])", "box"),
        ("s = set()\n    s.add(raw)", "s"),
        ("d = {}\n    d.update({'k': raw})", "d"),
        ("d = {}\n    d.update(k=raw)", "d"),
        ("self.cache.append(raw)", "self"),
    ):
        out = _vt(f"def f(self, p):\n    raw = read_raw(p)\n    {stmt}\n", function_taint=T.ASSURED, taint_map=tm)
        assert out[recv] == T.UNKNOWN_RAW, (stmt, out.get(recv))

    # CONTROL: a clean arg must NOT taint the receiver (FP guard).
    out = _vt(
        "def f(p):\n    box = []\n    box.append('safe')\n    box.append(42)\n", function_taint=T.ASSURED, taint_map=tm
    )
    assert out["box"] == T.INTEGRAL
    # CONTROL: list.insert's INDEX arg is positional metadata, not content — a tainted
    # index must not contaminate the container (panel finding wardline-67c7498931).
    out = _vt(
        "def f(p):\n    raw = read_raw(p)\n    lst = ['a']\n    lst.insert(raw, 'clean')\n",
        function_taint=T.ASSURED,
        taint_map=tm,
    )
    assert out["lst"] == T.INTEGRAL, out["lst"]
    # but a tainted VALUE in insert DOES contaminate.
    out = _vt(
        "def f(p):\n    raw = read_raw(p)\n    lst = []\n    lst.insert(0, raw)\n",
        function_taint=T.ASSURED,
        taint_map=tm,
    )
    assert out["lst"] == T.UNKNOWN_RAW, out["lst"]


# ── Receiver shadow laundering: a raw local/param that shadows a module name ──
#
# wardline-f6a29ce23a. A dotted/imported ``taint_map`` entry describes a
# MODULE-LEVEL symbol (``mod.fn`` / from-imported func / config sanitiser). When a
# tracked LOCAL or PARAMETER named the same as the module holds RAW data, the early
# ``taint_map`` short-circuits in ``_resolve_call`` used to return the module's
# clean taint — laundering the raw receiver before the RAW_ZONE receiver guard
# could fire. The discriminator: a real module import is never in ``var_taints``,
# whereas an assigned/param local IS; suppress the short-circuit only when the
# receiver is a tracked raw local, leaving genuine module sanitisers untouched.

_SHADOW_TM = {"read_raw": T.UNKNOWN_RAW, "cfg.validate": T.ASSURED}


def test_raw_local_shadowing_module_does_not_launder_dotted_path() -> None:
    # Direct dotted-lookup path (no alias_map): cfg is a raw LOCAL shadowing the
    # ``cfg`` module; cfg.validate() must NOT inherit the module entry's ASSURED.
    out = _vt(
        "def f(p):\n    cfg = read_raw(p)\n    x = cfg.validate()\n",
        function_taint=T.INTEGRAL,
        taint_map=_SHADOW_TM,
    )
    assert out["cfg"] == T.UNKNOWN_RAW
    assert out["x"] == T.UNKNOWN_RAW, out["x"]


def test_raw_local_shadowing_module_does_not_launder_imported_fqn_path() -> None:
    # imported_fqn path (alias_map present): same shadow, resolved via the alias
    # map to the fqn ``cfg.validate`` — must still defer to the raw receiver.
    out = _vt(
        "def f(p):\n    cfg = read_raw(p)\n    x = cfg.validate()\n",
        function_taint=T.INTEGRAL,
        taint_map=_SHADOW_TM,
        alias_map={"cfg": "cfg"},
    )
    assert out["x"] == T.UNKNOWN_RAW, out["x"]


def test_raw_param_shadowing_module_does_not_launder() -> None:
    # A PARAMETER (not just an assigned local) named like the module, seeded raw.
    out = _vt(
        "def f(cfg):\n    x = cfg.validate()\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"cfg.validate": T.ASSURED},
        alias_map={"cfg": "cfg"},
    )
    assert out["x"] == T.UNKNOWN_RAW, out["x"]


def test_genuine_module_sanitiser_stays_clean_dotted() -> None:
    # FP GUARD: ``cfg`` is NOT a tracked local (a real ``import cfg``), so
    # cfg.validate(p) is the genuine module sanitiser and must stay ASSURED even
    # when the function/arg is raw — the fix must not over-fire here.
    out = _vt(
        "def f(p):\n    x = cfg.validate(p)\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"cfg.validate": T.ASSURED},
        alias_map={"cfg": "cfg"},
    )
    assert out["x"] == T.ASSURED, out["x"]


def test_genuine_module_sanitiser_stays_clean_no_alias() -> None:
    # Same guard via the direct dotted-lookup path (no alias_map).
    out = _vt(
        "def f(p):\n    x = cfg.validate(p)\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"cfg.validate": T.ASSURED},
    )
    assert out["x"] == T.ASSURED, out["x"]


def test_clean_local_shadow_keeps_module_entry() -> None:
    # A tracked local that is NOT raw (INTEGRAL) does not trigger suppression — the
    # module entry still resolves (both are clean, so no soundness issue and no
    # spurious change). Confirms suppression is gated on RAW_ZONE, not mere tracking.
    out = _vt(
        "def f():\n    cfg = 42\n    x = cfg.validate()\n",
        function_taint=T.INTEGRAL,
        taint_map={"cfg.validate": T.ASSURED},
    )
    assert out["x"] == T.ASSURED, out["x"]


# ── Receiver-shadow family: chained receivers, self/cls preservation, bare-name,
#    var_types typed-receiver (wardline-f6a29ce23a, consolidated) ──────────────


def test_chained_receiver_shadow_does_not_launder() -> None:
    # a.b.method(): node.func.value is ast.Attribute. The guard must walk to the
    # ROOT name 'a'; a raw 'a' shadowing a multi-component module must not inherit
    # the module entry's clean taint.
    out = _vt(
        "def f(p):\n    a = read_raw(p)\n    x = a.b.urlopen()\n",
        function_taint=T.INTEGRAL,
        taint_map={"read_raw": T.UNKNOWN_RAW, "a.b.urlopen": T.ASSURED},
        alias_map={"a": "a"},
    )
    assert out["x"] == T.UNKNOWN_RAW, out["x"]


def test_self_method_cross_summary_preserved_when_self_raw() -> None:
    # self.sibling() with self seeded RAW must STILL read the analyzer-injected
    # cross-method summary (self/cls are never module shadows). The guard must
    # exclude self/cls roots, else it demotes a legitimate clean sibling summary.
    out = _vt(
        "def m(self, p):\n    x = self.sanitize()\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"self.sanitize": T.ASSURED},
    )
    assert out["x"] == T.ASSURED, out["x"]


def test_cls_method_cross_summary_preserved_when_cls_raw() -> None:
    out = _vt(
        "def m(cls, p):\n    x = cls.sanitize()\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"cls.sanitize": T.ASSURED},
    )
    assert out["x"] == T.ASSURED, out["x"]


def test_bare_name_shadow_does_not_launder() -> None:
    # foo() where foo is a raw local shadowing a clean from-imported function:
    # calling raw data yields raw, never the import's clean taint.
    out = _vt(
        "def f(p):\n    validate = read_raw(p)\n    x = validate()\n",
        function_taint=T.INTEGRAL,
        taint_map={"read_raw": T.UNKNOWN_RAW, "validate": T.ASSURED},
    )
    assert out["x"] == T.UNKNOWN_RAW, out["x"]


def test_bare_name_genuine_import_call_stays_clean() -> None:
    # FP GUARD: a genuine (un-shadowed) from-imported sanitiser stays clean.
    out = _vt(
        "def f(p):\n    x = validate(p)\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"validate": T.ASSURED},
    )
    assert out["x"] == T.ASSURED, out["x"]


def test_var_types_typed_receiver_resolves_via_type_when_value_raw() -> None:
    # The var_types path is DELIBERATELY NOT shadow-gated: a legitimately typed
    # object routinely carries a RAW-ZONE value taint (an unmodeled ``Type()``
    # constructor defaults to UNKNOWN_RAW), yet must still resolve ``Type.method``
    # via its type. Gating on the value taint would FP the ``h = Helper();
    # h.get_assured()`` pattern (test_helper_method_returning_assured_does_not_
    # false_positive). The var_types path serves typed objects, never module
    # shadows (a raw ``cfg = read_raw(p)`` carries no tracked type), so leaving it
    # ungated costs no shadow coverage. The narrow raw-typed-PARAMETER +
    # config-sanitiser residual is accepted over that FP cost (wardline-f6a29ce23a).
    out = _vt(
        "def f(obj: mymod.Schema):\n    x = obj.validate()\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"mymod.Schema.validate": T.ASSURED},
        alias_map={"mymod": "mymod"},
    )
    assert out["x"] == T.ASSURED, out["x"]


def test_encoder_method_shadow_does_not_launder() -> None:
    # shlex = raw; shlex.quote(x): the _CONTEXT_ENCODERS branch must not encode a
    # raw shadowed receiver into a clean GUARDED result.
    out = _vt(
        "def f(p):\n    shlex = read_raw(p)\n    x = shlex.quote(p)\n",
        function_taint=T.INTEGRAL,
        taint_map={"read_raw": T.UNKNOWN_RAW},
        alias_map={"shlex": "shlex"},
    )
    assert out["x"] in (T.UNKNOWN_RAW, T.EXTERNAL_RAW), out["x"]


def test_read_path_raw_local_shadow_does_not_launder() -> None:
    # Sibling of the call-path fix on the attribute-READ path (_resolve_expr): a raw
    # local shadowing a module name, READ as ``cfg.validate`` (not called), must not
    # inherit the module entry's clean taint (wardline-f6a29ce23a / -6b79150e79).
    out = _vt(
        "def f(p):\n    cfg = read_raw(p)\n    x = cfg.validate\n",
        function_taint=T.INTEGRAL,
        taint_map={"read_raw": T.UNKNOWN_RAW, "cfg.validate": T.ASSURED},
    )
    assert out["x"] == T.UNKNOWN_RAW, out["x"]


def test_read_path_self_attr_cross_summary_preserved_when_self_raw() -> None:
    # self.<attr> cross-method summary must STILL be read even when self is raw —
    # the read-path guard must exclude self/cls (same as the call path).
    out = _vt(
        "def m(self, p):\n    x = self.cache\n",
        function_taint=T.UNKNOWN_RAW,
        taint_map={"self.cache": T.ASSURED},
    )
    assert out["x"] == T.ASSURED, out["x"]
