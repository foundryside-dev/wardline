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

from wardline.core.finding import Kind
from wardline.core.run import run_scan
from wardline.core.taints import RAW_ZONE, TRUST_RANK, TaintState, least_trusted, taint_join

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
    """BRIEF (P5), plus the membership anchors the mandated form omits.

    The two mandated asserts constrain the UNION and the pairwise disjointness,
    which both hold for ANY placement of the three complement states: measured,
    moving ``UNKNOWN_ASSURED`` from ``RESTORATION_ONLY`` into ``NEVER_PRODUCED``
    leaves every test in this file green, because ``UNREACHABLE`` is unchanged
    and ``isdisjoint`` compares two literals in this same file. So the split
    made the ``NEVER_PRODUCED`` side falsifiable (via the ``taint_join``
    contrast below) and the ``RESTORATION_ONLY`` side vacuous ON PLACEMENT.

    The two asserts below anchor placement against the ENGINE rather than
    against this file: ``MIXED_RAW`` is a raw-zone state (a provenance clash is
    untrusted, and ``modulate`` silences it), whereas the restoration states are
    deliberately NOT raw-zone (uplifted, unknown-provenance — they downgrade one
    step instead of going silent). Mis-place either partition and one of them
    reds.
    """
    assert frozenset(TaintState) - REACHABLE == UNREACHABLE
    assert NEVER_PRODUCED.isdisjoint(RESTORATION_ONLY)
    assert NEVER_PRODUCED <= RAW_ZONE
    assert RESTORATION_ONLY.isdisjoint(RAW_ZONE)


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


# ── The declaration false green, pinned end-to-end. ──────────────────────────
# The programme's governing fact (measured, wardline-e88c098f91) is that declaring
# trust is what SUBJECTS a function to the leak rules; an undeclared function is
# resolved to UNKNOWN_RAW, which is RAW_ZONE, which modulate maps to NONE, which
# _sink_helpers.py:849 turns into `continue`. The severity-model half of that chain
# is pinned by test_raw_zone_matrix.py. The half NOT pinned anywhere was the FIRST
# link — undeclared resolving to UNKNOWN_RAW at all — so the chain was verified
# from its second step onward. This pins it from the source.

_SINK_BODY = "def run_it(arg):\n    s = read_input(arg)\n    subprocess.run(s, shell=True)\n"
_UNDECLARED_SINK = f"import subprocess\n\n\ndef read_input(p):\n    return p\n\n\n{_SINK_BODY}"
_DECLARED_SINK = (
    "import subprocess\n\n"
    "from wardline.decorators import external_boundary, trusted\n\n\n"
    "@external_boundary\n"
    "def read_input(p):\n    return p\n\n\n"
    f"@trusted\n{_SINK_BODY}"
)


def _scan_source(tmp_path: Path, name: str, source: str) -> tuple[list[str], dict[str, TaintState]]:
    proj = tmp_path / name
    proj.mkdir()
    (proj / "svc.py").write_text(source, encoding="utf-8")
    result = run_scan(proj)
    ctx = result.context
    assert ctx is not None
    return [f.rule_id for f in result.findings if f.kind is Kind.DEFECT], dict(ctx.project_taints)


def test_undeclared_sink_is_silent_and_declaring_trust_is_what_arms_it(tmp_path: Path) -> None:
    """The false green and its cure, over the SAME sink, in both directions.

    Byte-for-byte the same ``subprocess.run(s, shell=True)`` reached by the same
    argument. The ONLY difference is the two decorators. Undeclared: every
    function resolves to ``UNKNOWN_RAW`` and the scan reports ZERO defects —
    a ``--fail-on ERROR`` gate over this file passes green while checking
    nothing. Declared: the sink carrier becomes ``INTEGRAL``, its source becomes
    ``EXTERNAL_RAW``, and PY-WL-112 fires.

    This is the direction that surprises people, so it is pinned as a pair:
    demoting a seed toward the raw zone does NOT fail closed, it goes SILENT.
    A one-sided version of this test would be satisfied by an engine that never
    fires at all (undeclared half) or by one that fires on everything (declared
    half); only the pair excludes both.
    """
    undeclared_defects, undeclared_taints = _scan_source(tmp_path, "undeclared", _UNDECLARED_SINK)
    declared_defects, declared_taints = _scan_source(tmp_path, "declared", _DECLARED_SINK)

    # Direction 1 — the false green. The first link of the silencing chain:
    # undeclared resolves to UNKNOWN_RAW, and UNKNOWN_RAW is RAW_ZONE.
    assert undeclared_taints == {
        "svc.read_input": TaintState.UNKNOWN_RAW,
        "svc.run_it": TaintState.UNKNOWN_RAW,
    }
    assert set(undeclared_taints.values()) <= RAW_ZONE
    assert undeclared_defects == [], (
        f"an undeclared function piping its argument into subprocess.run(shell=True) "
        f"produced {undeclared_defects} — the documented silence has changed; if the "
        f"engine now fires here, the false-green mechanism this pins has been fixed and "
        f"this test should be re-derived, not deleted"
    )

    # Direction 2 — the same sink, armed by declaration alone.
    assert declared_taints == {
        "svc.read_input": TaintState.EXTERNAL_RAW,
        "svc.run_it": TaintState.INTEGRAL,
    }
    assert "PY-WL-112" in declared_defects
    # ...and the arming is NOT an artifact of the sink being differently reachable:
    # the executable body is character-identical across the two corpora.
    assert _SINK_BODY in _UNDECLARED_SINK
    assert _SINK_BODY in _DECLARED_SINK
