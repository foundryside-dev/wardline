"""Reachable-set & operator-closure invariants for the taint algebra.

These tests pin the linchpin invariant from the 2026-05-31 taint-combination
audit (see docs/concepts/taint-algebra.md): the only states reachable in the
live pipeline are {INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}, the
complement is not produced today, and least_trusted is closed over the reachable
set. They make the invariant ENFORCED rather than incidental.

P5 (declaration-surface-v2 §8.4) SPLIT the old "trio" claim, because the three
complement states do NOT share a lifetime: MIXED_RAW is never produced,
permanently, whereas UNKNOWN_ASSURED / UNKNOWN_GUARDED are RESERVED for witnessed
restoration declarations and become producible when S3 ships. See
``NEVER_PRODUCED`` / ``RESTORATION_ONLY`` below — the old docstring's flat "the
trio is never produced" is exactly the claim P5 exists to deny.
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
# P5 (declaration-surface-v2 §8.4): the old "trio" splits into two invariants
# with different lifetimes. MIXED_RAW is the taint_join falsification record —
# NEVER produced, permanently. UNKNOWN_ASSURED/UNKNOWN_GUARDED are reserved for
# witnessed restoration declarations (S3): until restoration ships they are
# equally unproduced, and after it ships they may appear ONLY with a witness.
NEVER_PRODUCED: frozenset[TaintState] = frozenset({TaintState.MIXED_RAW})
RESTORATION_ONLY: frozenset[TaintState] = frozenset({TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED})
UNREACHABLE: frozenset[TaintState] = NEVER_PRODUCED | RESTORATION_ONLY


def test_unreachable_set_is_the_two_partitions() -> None:
    """BRIEF (P5)."""
    assert frozenset(TaintState) - REACHABLE == UNREACHABLE
    assert NEVER_PRODUCED.isdisjoint(RESTORATION_ONLY)


def test_never_produced_survives_the_arrival_of_restoration_only() -> None:
    """ADDED — the split is only worth making if the two lifetimes stay separate.

    The whole point of P5 is that ``RESTORATION_ONLY`` becomes producible when
    S3 ships while ``NEVER_PRODUCED`` does not. That is a claim about the FUTURE
    reachable set, and no test above varies it: every closure row is taken over
    today's ``REACHABLE``. Pinned here — over ``REACHABLE | RESTORATION_ONLY``,
    ``least_trusted`` still cannot introduce ``MIXED_RAW``, so S3 admitting the
    restoration states does not, by itself, make the never-produced state
    producible. (``taint_join`` WOULD produce it — it yields ``MIXED_RAW`` on
    cross-family pairs — which is why the live pipeline calls ``least_trusted``
    everywhere and why the two operators must not be "simplified" into one.)
    """
    post_s3 = REACHABLE | RESTORATION_ONLY
    for a, b in itertools.product(post_s3, repeat=2):
        assert least_trusted(a, b) in post_s3
        assert least_trusted(a, b) not in NEVER_PRODUCED
    # Contrast, so the pin above cannot be read as a property of the state set:
    # the OTHER operator does reach MIXED_RAW from the very same inputs.
    assert taint_join(TaintState.GUARDED, TaintState.UNKNOWN_ASSURED) in NEVER_PRODUCED


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
