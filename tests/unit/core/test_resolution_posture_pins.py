"""P12 — the inertness denominators, decided and pinned (declaration-surface-v2 §11.4).

Decision of record for S0: recognition buckets are ("anchored", "config"); the
non-trivial-scan floor is 5 analyzed functions; the trip is recognized==0 over
a scan at/above the floor. S1's per-group arming EXTENDS this base (one counter
per declaration group; uplift-only groups never de-inert) — it must not move it.

KNOWN LIMITATION (filed, not fixed here): the engine's per-function provenance
histogram emits only {anchored, module_default, fallback} into
``taint_source_counts`` — the "config" and "callgraph" provenances never reach the
histogram, so a config-sources-only project computes INERT and functions_analyzed
undercounts. These pins freeze the POSTURE COMPUTATION's contract; the emission gap
is the filed engine bug ``wardline-7e0a3b1e3d``.

The gap is DEEPER than the dict literal at ``project_resolver.py`` (measured
2026-08-12: the literal is at :291-295, not the :285-289 the plan cites). The
histogram is built from the merged SUMMARY-level source map, and
``summary.py:31`` types that as ``Literal["anchored", "module_default",
"fallback"]`` — re-validated at ``summary_cache.py:311``. ``config`` is therefore
STRUCTURALLY unable to reach the histogram, even though ``propagation.py:578``
genuinely computes ``prov_source="config"`` into the SEPARATE provenance map.
Net: the ``config`` half of ``_RECOGNIZED_BOUNDARY_BUCKETS`` is live at this
function's boundary and dead at the engine's. Widening the Literal is the fix;
it is out of S0 scope because it drifts the METRIC bytes in the golden.

The second preserved pin (``wardline-894faaec24``, PY-WL-110 counts markers off
the AST irrespective of whether each seeded, so its message can claim a clash
resolution that never occurred) does not touch this module; it is recorded here
only because Task 15 must keep both engine defects visible and unduplicated.
Re-measured 2026-08-12 against ``contradictory_trust.py``: the description still
holds — the rule gates on ``prov.source == "anchored"`` but COUNTS distinct
markers over ``entity.node.decorator_list``.

Tests marked BRIEF are the Task-15 mandated pins, transcribed verbatim from the
task brief. Tests marked ADDED close axes no mandated row varies.
"""

from __future__ import annotations

from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint
from wardline.core.resolution_posture import (
    _MIN_FUNCTIONS,
    _RECOGNIZED_BOUNDARY_BUCKETS,
    compute_resolution_posture,
)


def _metrics(counts: dict[str, int]) -> Finding:
    return Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="m",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path="<engine>"),
        fingerprint=compute_finding_fingerprint(rule_id="WLN-ENGINE-METRICS", path="<engine>"),
        properties={"taint_source_counts": counts},
    )


def _no_counts() -> Finding:
    """A metrics finding whose properties carry no ``taint_source_counts`` key."""
    return Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="m",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path="<engine>"),
        fingerprint=compute_finding_fingerprint(rule_id="WLN-ENGINE-METRICS", path="<engine>"),
        properties={"files_scanned": 3},
    )


def _bad_counts() -> Finding:
    """A metrics finding whose ``taint_source_counts`` is not a mapping."""
    return Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="m",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path="<engine>"),
        fingerprint=compute_finding_fingerprint(rule_id="WLN-ENGINE-METRICS", path="<engine>"),
        properties={"taint_source_counts": [("anchored", 3)]},
    )


def test_denominator_constants_are_pinned() -> None:
    """BRIEF."""
    assert _MIN_FUNCTIONS == 5
    assert _RECOGNIZED_BOUNDARY_BUCKETS == ("anchored", "config")


def test_inert_iff_zero_recognized_at_or_above_floor() -> None:
    """BRIEF."""
    assert compute_resolution_posture([_metrics({"fallback": 5})]).inert is True
    assert compute_resolution_posture([_metrics({"fallback": 4})]).inert is False  # below floor
    assert compute_resolution_posture([_metrics({"fallback": 5, "anchored": 1})]).inert is False
    assert compute_resolution_posture([_metrics({"fallback": 5, "config": 1})]).inert is False
    # callgraph/module_default recognition does NOT clear the trip.
    assert compute_resolution_posture([_metrics({"fallback": 5, "callgraph": 3})]).inert is True
    assert compute_resolution_posture([_metrics({"fallback": 5, "module_default": 3})]).inert is True


def test_floor_is_a_total_over_every_bucket_not_the_fallback_bucket() -> None:
    """ADDED — every mandated row reaches the floor through ``fallback`` alone.

    The floor is compared against the SUM of the histogram, so four fallback
    functions plus one module_default is at the floor and trips, while four
    alone does not. No mandated row separates "5 fallback" from "5 functions".
    """
    assert compute_resolution_posture([_metrics({"fallback": 4, "module_default": 1})]).inert is True
    assert compute_resolution_posture([_metrics({"fallback": 2, "module_default": 2})]).inert is False
    # ...and the floor is inclusive: exactly _MIN_FUNCTIONS trips, one below does not.
    at_floor = {"fallback": _MIN_FUNCTIONS}
    below = {"fallback": _MIN_FUNCTIONS - 1}
    assert compute_resolution_posture([_metrics(at_floor)]).inert is True
    assert compute_resolution_posture([_metrics(below)]).inert is False


def test_recognition_is_summed_while_the_denominator_is_maxed() -> None:
    """ADDED — every mandated row passes exactly ONE metrics finding.

    ``compute_resolution_posture`` ACCUMULATES ``recognized_boundaries`` across
    metrics findings but takes the MAX of the totals for ``functions_analyzed``.
    Those two aggregations differ in kind, and no mandated row varies the axis
    that exposes it. Pinned as-is (this is the shipped contract, not a defect):
    two findings that each recognise nothing still read inert; one that
    recognises something clears the trip for the whole stream.
    """
    two_inert = [_metrics({"fallback": 5}), _metrics({"fallback": 9})]
    posture = compute_resolution_posture(two_inert)
    assert posture.functions_analyzed == 9  # max, not 14
    assert posture.recognized_boundaries == 0
    assert posture.inert is True

    mixed = [_metrics({"fallback": 5}), _metrics({"fallback": 5, "anchored": 2})]
    posture = compute_resolution_posture(mixed)
    assert posture.recognized_boundaries == 2  # summed across findings
    assert posture.inert is False


def test_every_named_bucket_is_classified_by_the_pinned_tuple() -> None:
    """ADDED — the function must CONSULT the tuple, not re-list it.

    The mandated rows name four buckets one at a time; this drives the same
    decision from ``_RECOGNIZED_BOUNDARY_BUCKETS`` over the full engine
    vocabulary, so a hardcoded bucket list inside ``compute_resolution_posture``
    that diverges from the module constant reds HERE (measured: hardcoding
    ``("anchored",)`` in the body reds this and leaves
    ``test_denominator_constants_are_pinned`` green).

    NOT a pin on the tuple's VALUE, and deliberately so: because it derives its
    expectation from the tuple, narrowing or widening the tuple keeps it green
    (measured). ``test_denominator_constants_are_pinned`` is the value pin. The
    two are complementary and neither substitutes for the other.
    """
    engine_buckets = ("anchored", "config", "callgraph", "module_default", "fallback")
    for bucket in engine_buckets:
        # Pad to the floor WITHOUT a duplicate key: a ``{"fallback": 5, bucket: 3}``
        # literal silently collapses when *bucket* is "fallback" and drops the row
        # below the floor — the row would then pass for the wrong reason.
        counts = {"fallback": _MIN_FUNCTIONS}
        counts[bucket] = counts.get(bucket, 0) + 3
        posture = compute_resolution_posture([_metrics(counts)])
        recognised = bucket in _RECOGNIZED_BOUNDARY_BUCKETS
        assert posture.inert is not recognised, f"{bucket} classified against the pinned tuple"
        assert posture.recognized_boundaries == (3 if recognised else 0)


def test_absent_histogram_fails_OPEN_defect_record() -> None:
    """DEFECT RECORD — not a contract, and NOT the behaviour anyone should want.

    ``compute_resolution_posture`` answers the question "is this gate enforcing?"
    from one datum: the ``taint_source_counts`` histogram on
    ``WLN-ENGINE-METRICS``. When that datum is ABSENT the function does not say
    "unknown" — it returns ``inert=False, reason=None``, i.e. *the gate looks
    healthy*. That is catalogue #8: a guard that answers from a datum silently
    switches off wherever the datum is absent, and here absence routes to the
    UNSAFE answer. Every other pin in this module is an over-warn-direction pin;
    this is the under-warn direction, and it had no coverage at all.

    MEASURED LIVE, 2026-08-12 — this is not hypothetical. ``cli/scan.py:774``
    guards the Python inert warning with ``lang != "rust"``, but
    ``core/run.py:817`` (the shared gate decision, which the CLI and the MCP scan
    tool both consume) has NO such guard, and the Rust pipeline emits no
    ``WLN-ENGINE-METRICS``. Two scans of the SAME shape — six functions, zero
    trust declarations, one command-execution sink:

      * Python, ``--fail-on-inert``: ``gate: FAILED (--fail-on-inert)``, exit 1.
      * Rust,   ``--fail-on-inert``: ``gate: PASSED (--fail-on-inert only) —
        0 recognized trust boundaries (fail_on_inert passed)``, exit 0.

    So ``--fail-on-inert`` SILENTLY NO-OPS on Rust: a gate that does not gate,
    with a reason string that recites the trip condition and then reports a pass.
    (The Rust surface has its own separate "no function declares @trusted"
    warning, which did fire — the signal exists, the GATE does not.)

    WHEN THIS IS FIXED, INVERT THIS TEST — do not delete it. It exists to stop
    the fail-open being re-introduced quietly, and to stop anyone reading the
    surrounding pins as evidence that the absent-histogram case was considered
    and blessed. It was considered and found broken.
    """
    for label, findings in (
        ("no findings at all", []),
        ("metrics finding with no histogram", [_metrics({})]),
        ("histogram key absent", [_no_counts()]),
        ("histogram present but not a dict", [_bad_counts()]),
    ):
        posture = compute_resolution_posture(findings)
        assert posture.inert is False, label
        assert posture.reason is None, label
        assert posture.functions_analyzed == 0, label
        # The tell: zero analyzed functions and a confident not-inert verdict.
        # A sound implementation would have a third state here, or would trip.
        assert posture.recognized_boundaries == 0, label


def test_reason_is_present_exactly_when_inert() -> None:
    """ADDED — no mandated row reads ``reason``.

    The inert verdict is only useful because a surface renders its reason; a
    trip with ``reason=None`` would be a silent gate, the failure shape this
    module exists to prevent.
    """
    inert = compute_resolution_posture([_metrics({"fallback": 5})])
    assert inert.inert is True
    assert inert.reason is not None
    assert str(inert.functions_analyzed) in inert.reason

    live = compute_resolution_posture([_metrics({"fallback": 5, "anchored": 1})])
    assert live.inert is False
    assert live.reason is None
