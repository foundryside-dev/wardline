"""Reachable-set & operator-closure invariants for the taint algebra.

These tests pin the linchpin invariant from the 2026-05-31 taint-combination
audit (see docs/concepts/taint-algebra.md): the only states reachable in the
live pipeline are {INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}, the
trio {MIXED_RAW, UNKNOWN_GUARDED, UNKNOWN_ASSURED} is never produced, and
least_trusted is closed over the reachable set. They make the invariant ENFORCED
rather than incidental.
"""

from __future__ import annotations

import itertools
from pathlib import Path

from wardline.core.run import run_scan
from wardline.core.taints import TRUST_RANK, TaintState, least_trusted, taint_join

# The states any source can introduce into the live pipeline (audit linchpin).
REACHABLE: frozenset[TaintState] = frozenset(
    {
        TaintState.INTEGRAL,
        TaintState.ASSURED,
        TaintState.GUARDED,
        TaintState.EXTERNAL_RAW,
        TaintState.UNKNOWN_RAW,
    }
)
# The states that must NEVER be produced.
UNREACHABLE: frozenset[TaintState] = frozenset(TaintState) - REACHABLE


def test_unreachable_set_is_the_trio() -> None:
    expected = frozenset(
        {
            TaintState.MIXED_RAW,
            TaintState.UNKNOWN_GUARDED,
            TaintState.UNKNOWN_ASSURED,
        }
    )
    assert expected == UNREACHABLE


def test_least_trusted_closed_over_reachable_set() -> None:
    # For every ordered pair over the reachable set, least_trusted stays inside it.
    for a, b in itertools.product(REACHABLE, repeat=2):
        result = least_trusted(a, b)
        assert result in REACHABLE, f"least_trusted({a}, {b}) = {result} escaped the reachable set"
        # least_trusted always returns one of its inputs.
        assert result in (a, b)


def test_least_trusted_rank_invariant_over_all_states() -> None:
    # Over ALL 8 states, least_trusted never yields a MORE-trusted result than
    # taint_join — the rank-meet is always at least as conservative as the
    # provenance-clash join (the safety contrast the migrations relied on).
    for a, b in itertools.product(TaintState, repeat=2):
        assert TRUST_RANK[least_trusted(a, b)] <= TRUST_RANK[taint_join(a, b)]


# ── Pipeline-level invariant: a real end-to-end scan over a corpus exercising
# every decorator/seed shape must never surface a trio state in any taint map. ──

_CORPUS = (
    "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
    "\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
    "\n"
    "@trust_boundary(to_level='GUARDED')\n"
    "def guard(p):\n"
    "    if not p:\n"
    "        raise ValueError('bad')\n"
    "    return p\n"
    "\n"
    "@trust_boundary(to_level='ASSURED')\n"
    "def validate(p):\n"
    "    if not p:\n"
    "        raise ValueError('bad')\n"
    "    return p\n"
    "\n"
    "@trusted\n"
    "def produce_integral(p):\n"
    "    return validate(read_raw(p))\n"
    "\n"
    "@trusted(level='ASSURED')\n"
    "def produce_assured(p):\n"
    "    return validate(read_raw(p))\n"
    "\n"
    "def undecorated(p):\n"
    "    a = validate(read_raw(p))\n"
    "    b = produce_integral(p)\n"
    "    if p:\n"
    "        x = a\n"
    "    else:\n"
    "        x = b\n"
    "    return guard(x)\n"
    "\n"
    "def merges(p):\n"
    "    parts = [validate(p), guard(p), read_raw(p)]\n"
    "    return ','.join(parts) + produce_integral(p)\n"
)


def test_no_unreachable_state_in_scan_output(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_CORPUS, encoding="utf-8")
    result = run_scan(proj)
    ctx = result.context
    assert ctx is not None

    saw_some = False
    for label, mapping in (
        ("project_taints", ctx.project_taints),
        ("project_return_taints", ctx.project_return_taints),
        ("function_return_taints", ctx.function_return_taints),
    ):
        for qualname, state in mapping.items():
            saw_some = True
            assert state not in UNREACHABLE, (
                f"{label}[{qualname}] = {state} — an unreachable taint state "
                f"surfaced in scan output (reachable-set invariant violated)"
            )
    # Guard against the test silently passing on empty maps.
    assert saw_some, "scan produced no taint entries — corpus did not exercise the engine"
