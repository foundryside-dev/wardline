from __future__ import annotations

import os
from collections.abc import Iterable

LIVE_ORACLE_REQUIRED_ENV = "WARDLINE_LIVE_ORACLE_REQUIRED"
# Markers whose SKIP is turned into a FAILURE under an armed WARDLINE_LIVE_ORACLE_REQUIRED=1
# run (the conftest pytest_runtest_makereport hook). Two tiers:
#   * `_e2e` live oracles — need a sibling binary/server provisioned in the weekly
#     live-oracles CI matrix.
#   * `_drift` source-byte rechecks that an armed CI job actually RUNS against a
#     provisioned sibling source: `sei_drift`/`worklist_drift` are run by the weekly
#     `source-drift` job (loomweave + warpline sources checked out), so a missing-source
#     skip there must fail closed (crit-3b: wardline-79ba05f464 / wardline-c0563eee74).
# Other `_drift` markers stay OUT: no armed job runs them, so their default-suite guard is
# the Layer-1 byte-pin and a clean skip is correct. See the taxonomy block in
# tests/conformance/test_seam_registry.py.
LIVE_ORACLE_MARKERS = frozenset(
    {"network", "loomweave_e2e", "legis_e2e", "filigree_e2e", "warpline_e2e", "sei_drift", "worklist_drift"}
)

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def live_oracle_required() -> bool:
    return os.environ.get(LIVE_ORACLE_REQUIRED_ENV, "").strip().lower() in _TRUE_VALUES


def has_live_oracle_marker(marker_names: Iterable[str]) -> bool:
    return any(name in LIVE_ORACLE_MARKERS for name in marker_names)


def should_fail_live_oracle_skip(marker_names: Iterable[str], outcome: str) -> bool:
    return live_oracle_required() and outcome == "skipped" and has_live_oracle_marker(marker_names)
