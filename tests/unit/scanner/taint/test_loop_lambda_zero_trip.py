"""Zero-trip loop preserves a pre-loop lambda binding (wardline-d6af917bde).

A loop body is a CONDITIONALLY-executed arm: a reachable 0-iteration path means the
post-loop binding for a name MAY still be its pre-loop value. ``_handle_for`` /
``_handle_while`` walk the body in place (sound for loop-carried in-body resolution)
but, before this fix, dropped a pre-loop sink-lambda when the body rebound the name to a
clean lambda — the zero-trip path's candidate vanished and a post-loop call through the
name missed the sink (FN). The fix unions the pre-loop bindings (the "loop did not run"
arm) back after the fixpoint, exactly like a no-``else`` ``if``.
"""

from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.taint.variable_level import compute_variable_taints

T = TaintState


def _lambda_body_sink_arg(src: str) -> TaintState:
    """Run the variable-taint pass over *src* and return the taint recorded for the
    lambda body's ``sink(c)`` argument (mirrors the helper in test_variable_level.py)."""
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


def test_for_zero_trip_preserves_preloop_sink_lambda() -> None:
    # ``cb`` is the SINK lambda before the loop; the body rebinds it to a clean lambda. On
    # the zero-trip path (``items`` empty) ``cb`` is STILL the sink lambda when ``cb(raw)``
    # runs after the loop, so the body's ``sink(c)`` arg MUST stay EXTERNAL_RAW. The FN:
    # the body's clean rebind replaced the candidate set and the loop never unioned the
    # pre-loop binding back (wardline-d6af917bde).
    src = (
        "def handler(raw, items):\n"
        "    cb = lambda c: sink(c)\n"
        "    for it in items:\n"
        "        cb = lambda c: c\n"
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_while_zero_trip_preserves_preloop_sink_lambda() -> None:
    # Same zero-trip FN for ``while`` (the test never executes the body).
    src = (
        "def handler(raw, flag):\n    cb = lambda c: sink(c)\n    while flag:\n        cb = lambda c: c\n    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW


def test_clean_loop_does_not_overfire() -> None:
    # FP guard: the pre-loop-union must NOT fabricate taint for clean loops. ``safe`` is a
    # sink-lambda bound to a SEPARATE name that never receives ``raw``; the looped name
    # ``cb`` is clean in both the pre-loop and body arms. The union must neither leak
    # ``cb``'s raw arg into ``safe`` nor invent a sink candidate for ``cb`` — the only
    # recording for ``sink(c)`` is the floor pass's neutral one, so it stays INTEGRAL.
    src = (
        "def handler(raw, items):\n"
        "    safe = lambda c: sink(c)\n"
        "    cb = lambda c: c\n"
        "    for it in items:\n"
        "        cb = lambda c: c\n"
        "    cb(raw)\n"
    )
    assert _lambda_body_sink_arg(src) == T.INTEGRAL


def test_loop_carried_in_body_lambda_still_resolves() -> None:
    # Non-vacuity / no-regression guard for in-body resolution: ``cb(raw)`` runs BEFORE the
    # in-body rebind to the sink lambda, so on iteration n it MAY hold iteration (n-1)'s
    # sink candidate. The in-place body walk inside the fixpoint must keep resolving it —
    # the pre-loop-union fix sits AFTER the fixpoint and must not weaken this. EXTERNAL_RAW.
    src = (
        "def handler(raw, items):\n"
        "    cb = lambda c: c\n"
        "    for it in items:\n"
        "        cb(raw)\n"
        "        cb = lambda c: sink(c)\n"
    )
    assert _lambda_body_sink_arg(src) == T.EXTERNAL_RAW
