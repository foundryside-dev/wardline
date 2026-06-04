"""Pytest configuration. src-layout editable install handles imports."""

from __future__ import annotations

from typing import Any

import pytest

from wardline._live_oracle import LIVE_ORACLE_REQUIRED_ENV, should_fail_live_oracle_skip


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]):
    outcome = yield
    report = outcome.get_result()
    marker_names = (marker.name for marker in item.iter_markers())
    if should_fail_live_oracle_skip(marker_names, report.outcome):
        report.outcome = "failed"
        report.longrepr = f"{LIVE_ORACLE_REQUIRED_ENV}=1 forbids skipped live oracle tests: {report.longrepr}"
