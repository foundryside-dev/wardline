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


@pytest.mark.warpline_e2e
def test_warpline_marker_is_registered() -> None:
    # If `warpline_e2e` were unregistered, collecting this test would raise a
    # PytestUnknownMarkWarning (treated as an error in strict-markers configs);
    # the test running at all proves the marker is declared in pyproject.toml.
    # Skip cleanly under the default deselection so the body never executes
    # (and so the SKIP->FAIL hook is exercised under WARDLINE_LIVE_ORACLE_REQUIRED=1).
    pytest.skip("warpline_e2e is a live-oracle marker; no live binary in unit runs")
