from __future__ import annotations

import os
from collections.abc import Iterable

LIVE_ORACLE_REQUIRED_ENV = "WARDLINE_LIVE_ORACLE_REQUIRED"
LIVE_ORACLE_MARKERS = frozenset({"network", "loomweave_e2e", "legis_e2e", "filigree_e2e"})

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def live_oracle_required() -> bool:
    return os.environ.get(LIVE_ORACLE_REQUIRED_ENV, "").strip().lower() in _TRUE_VALUES


def has_live_oracle_marker(marker_names: Iterable[str]) -> bool:
    return any(name in LIVE_ORACLE_MARKERS for name in marker_names)


def should_fail_live_oracle_skip(marker_names: Iterable[str], outcome: str) -> bool:
    return live_oracle_required() and outcome == "skipped" and has_live_oracle_marker(marker_names)
