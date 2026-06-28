from __future__ import annotations

import pytest

from wardline._live_oracle import (
    LIVE_ORACLE_MARKERS,
    LIVE_ORACLE_REQUIRED_ENV,
    should_fail_live_oracle_skip,
)


def test_warpline_e2e_is_a_live_oracle_marker() -> None:
    assert "warpline_e2e" in LIVE_ORACLE_MARKERS


def test_rust_e2e_is_not_a_live_oracle_marker() -> None:
    # rust_e2e is deliberately excluded from the SKIP->FAIL fail-closed set;
    # this guards against an accidental copy-paste addition.
    assert "rust_e2e" not in LIVE_ORACLE_MARKERS


def test_warpline_skip_fails_only_when_env_var_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LIVE_ORACLE_REQUIRED_ENV, "1")
    assert should_fail_live_oracle_skip(["warpline_e2e"], "skipped") is True

    monkeypatch.delenv(LIVE_ORACLE_REQUIRED_ENV, raising=False)
    assert should_fail_live_oracle_skip(["warpline_e2e"], "skipped") is False


def test_rust_only_skip_never_fails_even_when_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LIVE_ORACLE_REQUIRED_ENV, "1")
    assert should_fail_live_oracle_skip(["rust_e2e"], "skipped") is False


def test_sei_and_worklist_drift_are_live_oracle_markers() -> None:
    # crit-3b: the SEI-oracle (wardline-79ba05f464) and warpline worklist
    # (wardline-c0563eee74) SOURCE-byte drift rechecks are run armed in the weekly
    # `source-drift` CI job (which checks out the loomweave + warpline sources), so a
    # missing-source skip must FAIL closed there instead of passing clean. That is only
    # honest if these drift markers are in the fail-closed set.
    assert "sei_drift" in LIVE_ORACLE_MARKERS
    assert "worklist_drift" in LIVE_ORACLE_MARKERS


def test_source_drift_markers_fail_closed_only_when_armed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LIVE_ORACLE_REQUIRED_ENV, "1")
    assert should_fail_live_oracle_skip(["sei_drift"], "skipped") is True
    assert should_fail_live_oracle_skip(["worklist_drift"], "skipped") is True

    monkeypatch.delenv(LIVE_ORACLE_REQUIRED_ENV, raising=False)
    assert should_fail_live_oracle_skip(["sei_drift"], "skipped") is False
    assert should_fail_live_oracle_skip(["worklist_drift"], "skipped") is False


def test_unrun_drift_markers_are_not_live_oracle_markers() -> None:
    # These _drift seams are run by NO armed CI job, so they stay the skip-clean
    # release-gate tier (their default-suite guard is the Layer-1 byte-pin). Promoting one
    # to LIVE_ORACLE_MARKERS without an armed job that runs it would be a false fail-closed
    # claim. Guards against an accidental copy-paste promotion.
    for name in ("loomweave_drift", "reason_vocab_drift", "filigree_token_drift", "legis_scan_artifact_drift"):
        assert name not in LIVE_ORACLE_MARKERS


@pytest.mark.warpline_e2e
def test_warpline_marker_is_registered() -> None:
    # If `warpline_e2e` were unregistered, collecting this test would raise a
    # PytestUnknownMarkWarning (treated as an error in strict-markers configs);
    # the test running at all proves the marker is declared in pyproject.toml.
    # Skip cleanly under the default deselection so the body never executes
    # (and so the SKIP->FAIL hook is exercised under WARDLINE_LIVE_ORACLE_REQUIRED=1).
    pytest.skip("warpline_e2e is a live-oracle marker; no live binary in unit runs")
