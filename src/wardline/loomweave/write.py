# src/wardline/loomweave/write.py
"""SP9: the fail-soft scan-time write orchestration.

Build facts → write them. The whole step is non-load-bearing: a Loomweave outage,
403 WRITE_DISABLED, or PROJECT_MISMATCH returns a WriteResult the caller reports
but never fails on. There is no capability probe — the contract does not advertise
the store, so the write is attempt-then-handle-403 (the client already does this).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from wardline.core.run import ScanResult
from wardline.loomweave.client import WriteResult
from wardline.loomweave.facts import build_taint_facts


class _WriteClient(Protocol):
    def write_taint_facts(self, facts: list[dict[str, Any]]) -> WriteResult: ...


# Stable ``disabled_reason`` labels for the two no-attempt skips below. Consumers
# compare against these constants, never the prose.
DELTA_SKIP_REASON = "delta scan: taint-fact write skipped (display-filtered findings would hollow per-entity facts)"
NO_FACTS_REASON = "no facts to write (write not attempted)"


def write_facts_to_loomweave(result: ScanResult, root: Path, client: _WriteClient) -> WriteResult:
    """Project the scan into facts and write them. Fail-soft by construction —
    the client returns a WriteResult (reachable False on outage/disabled), never raises
    for soft conditions. A 4xx (bad request) still raises LoomweaveError from the client.

    Delta guard (the Loomweave analog of the Filigree INV-5 ``mark_unseen`` guard): an
    ``--affected`` delta scan display-filters ``result.findings`` to the affected
    entities while ``result.context`` still carries every entity in every analyzed
    file, so a write would replace previously-correct store facts with hollow
    ``findings: []`` blobs stamped with a CURRENT content hash — a fresh-looking false
    green for every co-located / caller-closure entity. The write is therefore SKIPPED
    in delta mode, and the skip is SIGNALLED (never silent): the returned WriteResult
    carries ``disabled_reason`` so the CLI status line and the ``loomweave_write``
    envelope block both name why nothing was written. ``mode == "full-fallback"``
    analyzed the full tree and writes normally. Both no-attempt skips (delta,
    zero facts) report ``reachable=False`` — consistent with 403 WRITE_DISABLED,
    ``reachable`` means "the store was written-to", never a fabricated probe result.
    Consumers distinguish the stable reason labels: delta remains a warning, while
    zero facts is a neutral no-attempt status."""
    if result.scope is not None and result.scope.mode == "delta":
        return WriteResult(reachable=False, written=0, disabled_reason=DELTA_SKIP_REASON)
    facts = build_taint_facts(result, root)
    if not facts:
        return WriteResult(reachable=False, written=0, disabled_reason=NO_FACTS_REASON)
    return client.write_taint_facts(facts)
