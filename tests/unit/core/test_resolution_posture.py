"""Scan-level enforcement-posture discriminator (Part A of wardline-bd9d1e65cb).

wardline is annotation-driven: a PY-WL defect fires only when untrusted data crosses a
DECLARED trust boundary. A codebase with zero recognized boundaries produces zero
defects no matter what it does, so a ``--fail-on ERROR`` gate over it passes green while
checking nothing. ``compute_resolution_posture`` turns the engine's own run metrics into
a scan-level "inert" verdict an agent cannot miss.

Calibration anchors (verified live during the investigation):
  * elspeth full-repo scan: taint_source_counts={anchored:0, fallback:5319} — no wardline
    annotations anywhere -> MUST flag inert.
  * wardline corpus scan: taint_source_counts={anchored:43, fallback:5} -> MUST stay quiet.
  * a single @trusted firing fixture: anchored=1 -> quiet.
"""

from __future__ import annotations

from wardline.core.finding import ENGINE_PATH, Finding, Kind, Location, Severity
from wardline.core.resolution_posture import compute_resolution_posture


def _metric(counts: dict[str, int]) -> Finding:
    return Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="L3 resolver run metrics",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path=ENGINE_PATH),
        fingerprint="fp-metrics",
        properties={"taint_source_counts": counts},
    )


def _low_res(i: int) -> Finding:
    return Finding(
        rule_id="WLN-L3-LOW-RESOLUTION",
        message=f"Function m.f{i} has 100% unresolved calls (1/1)",
        severity=Severity.INFO,
        kind=Kind.METRIC,
        location=Location(path=ENGINE_PATH),
        fingerprint=f"fp-lowres-{i}",
    )


def test_elspeth_shaped_scan_is_inert() -> None:
    findings = [_metric({"anchored": 0, "fallback": 5319, "module_default": 0})]
    findings += [_low_res(i) for i in range(3314)]
    posture = compute_resolution_posture(findings)
    assert posture.inert is True
    assert posture.recognized_boundaries == 0
    assert posture.functions_analyzed == 5319
    assert posture.reason is not None and "0 trust boundaries" in posture.reason


def test_corpus_shaped_scan_with_boundaries_is_not_inert() -> None:
    # anchored=43 => declared boundaries exist => the gate has something to enforce.
    findings = [_metric({"anchored": 43, "fallback": 5, "module_default": 0})]
    findings += [_low_res(i) for i in range(6)]
    posture = compute_resolution_posture(findings)
    assert posture.inert is False
    assert posture.recognized_boundaries == 43
    assert posture.reason is None


def test_single_anchored_boundary_is_not_inert() -> None:
    posture = compute_resolution_posture([_metric({"anchored": 1, "fallback": 0})])
    assert posture.inert is False


def test_config_sources_count_as_recognized() -> None:
    # A configured untrusted source is a recognized boundary too.
    posture = compute_resolution_posture([_metric({"anchored": 0, "config": 3, "fallback": 40})])
    assert posture.recognized_boundaries == 3
    assert posture.inert is False


def test_tiny_scan_below_function_floor_is_not_inert() -> None:
    # A single crafted file in a temp dir is an exploration, not a gate.
    posture = compute_resolution_posture([_metric({"anchored": 0, "fallback": 1})])
    assert posture.inert is False


def test_no_metrics_finding_does_not_crash() -> None:
    posture = compute_resolution_posture([_low_res(0)])
    assert posture.inert is False
    assert posture.functions_analyzed == 0


def test_empty_findings() -> None:
    posture = compute_resolution_posture([])
    assert posture.inert is False
    assert posture.low_resolution_ratio == 0.0
