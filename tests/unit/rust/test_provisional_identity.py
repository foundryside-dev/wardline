"""WP6 fold: the CLI banner's "provisional identity (baseline-ineligible)" claim is
ENFORCED, not just printed.

A finding carrying ``properties["provisional_identity"] = True`` (every RS-WL-* finding):
* is never matched against a committed baseline/waiver/judged entry (stays ACTIVE, so it
  always gates — even under ``--trust-suppressions`` a stale committed suppression cannot
  clear it); and
* is never written INTO a generated baseline (its unstable fingerprint would orphan).
"""

from __future__ import annotations

from datetime import date

from wardline.core.baseline import Baseline, build_baseline_document
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.suppression import apply_suppressions
from wardline.core.waivers import WaiverSet


def _rs_finding(*, provisional: bool) -> Finding:
    props = {"taint_path": "x"}
    if provisional:
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


def test_provisional_finding_is_not_suppressed_by_a_matching_baseline() -> None:
    f = _rs_finding(provisional=True)
    baseline = Baseline(frozenset({"a" * 64}))  # a committed entry keyed to its exact fingerprint
    (out,) = apply_suppressions([f], baseline, WaiverSet([]), today=date(2026, 6, 9))
    assert out.suppressed is SuppressionState.ACTIVE  # baseline-ineligible: stays ACTIVE


def test_non_provisional_finding_is_still_baselined() -> None:
    # The guard must be SCOPED to provisional findings — a normal defect still baselines.
    f = _rs_finding(provisional=False)
    baseline = Baseline(frozenset({"a" * 64}))
    (out,) = apply_suppressions([f], baseline, WaiverSet([]), today=date(2026, 6, 9))
    assert out.suppressed is SuppressionState.BASELINED


def test_provisional_finding_is_excluded_from_a_generated_baseline() -> None:
    doc = build_baseline_document([_rs_finding(provisional=True)])
    assert doc["entries"] == []  # never captured — its fingerprint is not stable


def test_non_provisional_finding_is_captured_in_a_baseline() -> None:
    doc = build_baseline_document([_rs_finding(provisional=False)])
    assert [e["fingerprint"] for e in doc["entries"]] == ["a" * 64]
