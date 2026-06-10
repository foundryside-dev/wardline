"""P4 review fold — the rekey population must cover EVERY stored DEFECT, not just
PY-WL-*, and must reconstruct old_fp by the right mechanism per finding.

The dead-engine oracle (test_rekey_dual_fp) only sees PY-WL-* (the identity corpus
predicate), so the engine-DEFECT path is proven HERE — and the POLICY-CONFIG old_fp
is pinned to an INDEPENDENT hand-rolled wlfp1 hash (NOT via the production v0), so a
reconstruction drift fails this test, not just a membership bug.
"""

from __future__ import annotations

import hashlib

from wardline.core.finding import ENGINE_PATH, Finding, Kind, Location, Severity
from wardline.core.rekey import (
    _POLICY_CONFIG_RULE_ID,
    _is_scheme_independent,
    build_remap,
    carry_baseline_forward,
    compute_old_new_fingerprints,
    is_join_population,
)

_POLICY_TAINT = "rules.enable:empty"


def _hand_rolled_wlfp1(rule_id: str, path: str, line_start: str, qualname: str, taint_path: str) -> str:
    # Independent of compute_finding_fingerprint_v0 — the non-circular oracle.
    return hashlib.sha256("\x00".join((rule_id, path, line_start, qualname, taint_path)).encode()).hexdigest()


def _policy_config_finding(new_fp: str) -> Finding:
    return Finding(
        rule_id=_POLICY_CONFIG_RULE_ID,
        message="config weakens rules",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path=ENGINE_PATH),  # lineless -> line_start is None
        fingerprint=new_fp,
        taint_path_v0=_POLICY_TAINT,
    )


def _engine_diagnostic_finding(fp: str) -> Finding:
    return Finding(
        rule_id="WLN-L3-MONOTONICITY-VIOLATION",
        message="engine diagnostic",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path=ENGINE_PATH),
        fingerprint=fp,
        taint_path_v0=None,
    )


def test_policy_config_is_in_the_join_population() -> None:
    # The gate regression: this gating ERROR DEFECT must NOT be excluded from the remap.
    assert is_join_population(_policy_config_finding("9" * 64))


def test_policy_config_old_fp_is_v0_reconstructed_noncircular() -> None:
    f = _policy_config_finding("9" * 64)
    assert f.location.line_start is None  # lineless -> "None" in the wlfp1 parts
    expected_old = _hand_rolled_wlfp1(_POLICY_CONFIG_RULE_ID, ENGINE_PATH, "None", "", _POLICY_TAINT)
    assert expected_old == "c168d13a201d791952cac46ced9f9ab8910c7ee2d39711261601e557f11d7701"
    assert not _is_scheme_independent(_POLICY_CONFIG_RULE_ID)  # v0 branch, NOT identity

    [remap] = compute_old_new_fingerprints([f])
    assert remap.old_fp == expected_old, "POLICY-CONFIG old_fp must byte-match the wlfp1 dead-engine hash"
    assert remap.new_fp == "9" * 64
    assert remap.old_fp != remap.new_fp  # it genuinely rekeyed (line_start dropped)


def test_engine_diagnostic_old_fp_is_identity() -> None:
    # diagnostics._fingerprint is scheme-independent (no line_start), so old_fp == new_fp.
    assert _is_scheme_independent("WLN-L3-MONOTONICITY-VIOLATION")
    f = _engine_diagnostic_finding("d" * 64)
    [remap] = compute_old_new_fingerprints([f])
    assert remap.old_fp == remap.new_fp == "d" * 64


def test_policy_config_baselined_verdict_carries_across_rekey() -> None:
    import pytest

    yaml = pytest.importorskip("yaml")
    import tempfile
    from pathlib import Path

    f = _policy_config_finding("9" * 64)
    result = build_remap(compute_old_new_fingerprints([f]))
    old_fp = next(iter(result.old_to_new))
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td) / "baseline.yaml"
        sp.write_text(
            yaml.safe_dump(
                {
                    "fingerprint_scheme": "wlfp1",
                    "version": 1,
                    "entries": [
                        {"fingerprint": old_fp, "rule_id": _POLICY_CONFIG_RULE_ID, "path": ENGINE_PATH, "message": "x"}
                    ],
                }
            ),
            encoding="utf-8",
        )
        carry = carry_baseline_forward(sp, result.old_to_new)
    assert carry.carried == (old_fp,)  # NOT orphaned (the regression: it used to drop)
    assert carry.orphaned == ()
    assert {e["fingerprint"] for e in carry.document["entries"]} == {"9" * 64}


def test_rekey_policy_config_rule_id_matches_scanner() -> None:
    # core/ must not import scanner/ (layering), so the rule_id is duplicated — lock it.
    from wardline.scanner.rules import _POLICY_CONFIG_RULE_ID as SCANNER_PCID

    assert _POLICY_CONFIG_RULE_ID == SCANNER_PCID


def test_rs_wl_included_in_the_migration_population() -> None:
    # P5-REVISIT decided 2026-06-10 (identity keystone): Rust identity graduated —
    # RS-WL-* DEFECTs are baseline-eligible, so a stored RS-WL verdict must migrate
    # like any other DEFECT (the former exclusion became a live orphaning path).
    rs = Finding(
        rule_id="RS-WL-108",
        message="rust cmd injection",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="m.rs", line_start=4),
        fingerprint="r" * 64,
    )
    assert is_join_population(rs)
