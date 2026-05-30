# src/wardline/clarion/write.py
"""SP9: the fail-soft scan-time write orchestration.

Build facts → write them. The whole step is non-load-bearing: a Clarion outage,
403 WRITE_DISABLED, or PROJECT_MISMATCH returns a WriteResult the caller reports
but never fails on. There is no capability probe — the contract does not advertise
the store, so the write is attempt-then-handle-403 (the client already does this).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from wardline.clarion.client import WriteResult
from wardline.clarion.facts import build_taint_facts
from wardline.core.run import ScanResult


class _WriteClient(Protocol):
    def write_taint_facts(self, facts: list[dict[str, Any]]) -> WriteResult: ...


def write_facts_to_clarion(result: ScanResult, root: Path, client: _WriteClient) -> WriteResult:
    """Project the scan into facts and write them. Fail-soft by construction —
    the client returns a WriteResult (reachable False on outage/disabled), never raises
    for soft conditions. A 4xx (bad request) still raises ClarionError from the client."""
    facts = build_taint_facts(result, root)
    if not facts:
        return WriteResult(reachable=True, written=0)
    return client.write_taint_facts(facts)
