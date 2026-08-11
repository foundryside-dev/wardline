"""P6 — the RAW_ZONE x reserved-states decision matrix, pinned before S3 exists.

Both restoration states sit OUTSIDE RAW_ZONE (they are uplifted, unknown-
provenance states, not raw ones), and the severity model already treats them as
_PARTIAL (one step down) — a deliberate, stated policy the S3 work must not
re-litigate silently.

The load-bearing direction (measured, wardline-e88c098f91): RAW_ZONE membership
buys SILENCE, not escalation. ``modulate`` maps every raw-zone state to
``Severity.NONE`` at every base, so demoting a seed to ``UNKNOWN_RAW`` does NOT
fail closed — it makes the tier-gated rules go quiet. Declaring trust is what
SUBJECTS a function to the leak rules. ``test_raw_zone_means_silence_not_escalation``
and ``test_modulate_never_escalates`` state that in the words a future reader
will otherwise re-derive backwards.

Tests marked BRIEF are the Task-15 mandated pins, transcribed verbatim from the
task brief. Tests marked ADDED close axes no mandated row varies (see the report:
the ``Severity.NONE`` base is the one ``_DOWNGRADE`` entry the mandated 32-cell
product cannot reach, and it is the base every FACT rule — PY-WL-130's siblings
``WLN-ENGINE-UNKNOWN-MARKER`` / ``WLN-ENGINE-UNREADABLE-MARKER-VALUE`` — uses).
"""

from __future__ import annotations

import itertools

import pytest

from wardline.core.finding import Severity
from wardline.core.taints import RAW_ZONE, TaintState
from wardline.scanner.rules.severity_model import modulate

_TRUSTED = {TaintState.INTEGRAL, TaintState.ASSURED}
_PARTIAL = {TaintState.GUARDED, TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED}
_DOWNGRADE = {
    Severity.CRITICAL: Severity.ERROR,
    Severity.ERROR: Severity.WARN,
    Severity.WARN: Severity.INFO,
    Severity.INFO: Severity.INFO,  # floor — never below INFO via downgrade
    Severity.NONE: Severity.NONE,
}


def test_raw_zone_membership_is_pinned() -> None:
    """BRIEF."""
    assert frozenset({TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW}) == RAW_ZONE
    assert TaintState.UNKNOWN_ASSURED not in RAW_ZONE
    assert TaintState.UNKNOWN_GUARDED not in RAW_ZONE


@pytest.mark.parametrize(
    ("base", "taint"),
    list(itertools.product((Severity.CRITICAL, Severity.ERROR, Severity.WARN, Severity.INFO), TaintState)),
)
def test_modulate_full_matrix(base: Severity, taint: TaintState) -> None:
    """BRIEF."""
    expected = base if taint in _TRUSTED else _DOWNGRADE[base] if taint in _PARTIAL else Severity.NONE
    assert modulate(base, taint) is expected


@pytest.mark.parametrize("taint", list(TaintState))
def test_modulate_none_base_row(taint: TaintState) -> None:
    """ADDED — the base axis the mandated product does not vary.

    Every mandated row assumes ``base != Severity.NONE``, so the
    ``Severity.NONE: Severity.NONE`` entry of ``_DOWNGRADE`` is unreachable from
    the 32-cell product. ``Severity.NONE`` is the base severity of every FACT
    rule the marker work shipped (``WLN-ENGINE-UNKNOWN-MARKER`` /
    ``WLN-ENGINE-UNREADABLE-MARKER-VALUE``), so both ways of getting that entry
    wrong are live, and BOTH were measured against the mandated matrix:

      * DELETE it from the source map -> the 32 mandated cells stay green while
        ``modulate(NONE, GUARDED)`` raises ``KeyError`` (a crash on every FACT
        finding at a partial tier);
      * make it ESCALATE (``Severity.NONE: Severity.INFO``) -> the 32 mandated
        cells stay green while a FACT becomes a gateable INFO.

    ONE assertion, deliberately. At a NONE base every branch of the mandated
    expectation collapses to ``Severity.NONE`` (nothing downgrades below the
    floor), so a mirrored ``expected`` would restate the pin rather than check
    it, and a ``_DOWNGRADE[Severity.NONE] is Severity.NONE`` tie-back would
    assert a literal in this file against itself. The direct value pin is the
    only form here that can fail.
    """
    assert modulate(Severity.NONE, taint) is Severity.NONE


@pytest.mark.parametrize(
    ("base", "taint"),
    list(itertools.product(Severity, sorted(RAW_ZONE))),
)
def test_raw_zone_means_silence_not_escalation(base: Severity, taint: TaintState) -> None:
    """ADDED — the composition of RAW_ZONE (taints.py) with modulate (severity_model.py).

    Neither mandated pin tests the two together: ``test_raw_zone_membership_is_pinned``
    reads the set and never calls ``modulate``; ``test_modulate_full_matrix``
    calls ``modulate`` and never reads ``RAW_ZONE``. Widening RAW_ZONE without
    widening ``modulate``'s else-branch (or vice versa) must red HERE.
    """
    assert modulate(base, taint) is Severity.NONE


@pytest.mark.parametrize(("base", "taint"), list(itertools.product(Severity, TaintState)))
def test_modulate_never_escalates(base: Severity, taint: TaintState) -> None:
    """ADDED — the other failure direction: no taint state may RAISE a severity.

    Expressed as set membership over {base, one-step-down, NONE} rather than an
    invented ordering over ``Severity``.
    """
    assert modulate(base, taint) in {base, _DOWNGRADE[base], Severity.NONE}


def test_restoration_states_downgrade_rather_than_silence() -> None:
    """ADDED — composition with P5's RESTORATION_ONLY partition.

    ``UNKNOWN_ASSURED``/``UNKNOWN_GUARDED`` are the S3 restoration states. They
    are NOT raw-zone, so they must keep a rule audible one step down; if S3 ever
    moved them into RAW_ZONE the rules would go silent on restored data — the
    exact false-green shape this programme has been closing.
    """
    restoration = (TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED)
    assert RAW_ZONE.isdisjoint(restoration)
    for taint in restoration:
        assert modulate(Severity.ERROR, taint) is Severity.WARN
        assert modulate(Severity.CRITICAL, taint) is Severity.ERROR
        assert modulate(Severity.INFO, taint) is Severity.INFO  # floor, not silence
