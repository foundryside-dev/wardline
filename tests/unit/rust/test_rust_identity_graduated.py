"""SP2 graduation: RS-WL-* findings are full citizens of the suppression machinery.

The pre-SP2 ``properties["provisional_identity"]`` short-circuits (never baseline-match,
never baseline-capture) are GONE — Rust identity is frozen (crate-prefixed, gated by
``tests/golden/identity/rust/``), so an RS-WL-* finding:
* IS matched against a committed baseline entry like any other defect; and
* IS written into a generated baseline.

These tests are the inversion of the retired ``test_provisional_identity.py``. A stray
``provisional_identity`` property (e.g. from a stale producer) must be inert — no code
path consults it anymore.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from wardline.core.baseline import Baseline, build_baseline_document
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.judged import JudgedFP, JudgedSet
from wardline.core.suppression import apply_suppressions, gate_trips
from wardline.core.waivers import Waiver, WaiverSet


def _rs_finding(*, stray_provisional_prop: bool = False) -> Finding:
    props: dict[str, object] = {"taint_path": "x"}
    if stray_provisional_prop:
        props["provisional_identity"] = True
    return Finding(
        rule_id="RS-WL-108",
        message="program injection",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/m.rs", line_start=3, line_end=3),
        fingerprint="a" * 64,
        qualname="m.f",
        properties=props,
    )


def test_rs_finding_is_suppressed_by_a_matching_baseline() -> None:
    f = _rs_finding()
    baseline = Baseline(frozenset({"a" * 64}))  # a committed entry keyed to its exact fingerprint
    (out,) = apply_suppressions([f], baseline, WaiverSet([]), today=date(2026, 6, 10))
    assert out.suppressed is SuppressionState.BASELINED  # graduated: baseline-eligible


def test_rs_finding_is_captured_in_a_generated_baseline() -> None:
    doc = build_baseline_document([_rs_finding()])
    assert [e["fingerprint"] for e in doc["entries"]] == ["a" * 64]


def test_rs_finding_is_suppressed_by_a_matching_waiver() -> None:
    # Graduation covers the WHOLE suppression machinery, not just the baseline leg:
    # a hand-authored waiver keyed to the RS-WL fingerprint must resolve WAIVED
    # (waiver > judged > baseline precedence lives in resolve_identity).
    f = _rs_finding()
    waivers = WaiverSet([Waiver(fingerprint="a" * 64, reason="accepted: sandboxed CLI", expires=None)])
    (out,) = apply_suppressions([f], Baseline(frozenset()), waivers, today=date(2026, 6, 10))
    assert out.suppressed is SuppressionState.WAIVED
    assert out.suppression_reason  # the waiver's reason travels with the verdict


def test_rs_finding_is_suppressed_by_a_judged_false_positive() -> None:
    f = _rs_finding()
    judged = JudgedSet(
        [
            JudgedFP(
                fingerprint="a" * 64,
                rule_id="RS-WL-108",
                path="src/m.rs",
                message="program injection",
                rationale="the program is a vetted constant at runtime",
                model_id="test-judge",
                confidence=0.97,
                recorded_at=datetime(2026, 6, 10, tzinfo=UTC),
                policy_hash="p" * 8,
            )
        ]
    )
    (out,) = apply_suppressions([f], Baseline(frozenset()), WaiverSet([]), today=date(2026, 6, 10), judged=judged)
    assert out.suppressed is SuppressionState.JUDGED


def test_active_rs_error_trips_the_gate() -> None:
    # An ACTIVE (unsuppressed) RS-WL-108 ERROR participates in --fail-on like any
    # Python defect — graduated findings are gate citizens, not advisory.
    assert gate_trips([_rs_finding()], Severity.ERROR) is True


def test_producer_no_longer_emits_the_provisional_property() -> None:
    # The real RS-WL-* producer (rules.py) emits no retired identity flag.
    pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")
    from wardline.rust.analyzer import RustAnalyzer

    source = (
        "/// @trusted(level=ASSURED)\n"
        "fn f() {\n"
        '    let t = std::env::var("X").unwrap();\n'
        "    Command::new(t).output();\n"
        "}\n"
    )
    (finding,) = RustAnalyzer().analyze_source(source, module="demo.m", path="src/m.rs")
    assert finding.rule_id == "RS-WL-108"
    assert "provisional_identity" not in finding.properties


def test_stray_provisional_property_is_inert() -> None:
    # The plumbing is removed, not bypassed: a finding still carrying the retired
    # property baselines and captures exactly like any other defect.
    f = _rs_finding(stray_provisional_prop=True)
    baseline = Baseline(frozenset({"a" * 64}))
    (out,) = apply_suppressions([f], baseline, WaiverSet([]), today=date(2026, 6, 10))
    assert out.suppressed is SuppressionState.BASELINED
    doc = build_baseline_document([f])
    assert [e["fingerprint"] for e in doc["entries"]] == ["a" * 64]
