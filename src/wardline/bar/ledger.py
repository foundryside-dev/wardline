"""Compliance-ledger loading for BAR review inputs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class BarLedgerError(Exception):
    """Raised when the compliance ledger cannot be loaded for BAR review."""


def load_compliance_ledger(path: Path) -> dict[str, object]:
    """Load a Wardline compliance ledger JSON document."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BarLedgerError(f"unable to read compliance ledger at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise BarLedgerError(f"compliance ledger at {path} must contain a JSON object")
    obligations = data.get("obligations")
    if not isinstance(obligations, list):
        raise BarLedgerError(f"compliance ledger at {path} must contain an obligations array")
    return data


def load_obligation_from_compliance_ledger(path: Path, obligation_id: str) -> dict[str, object]:
    """Return one obligation record from the compliance ledger."""
    ledger = load_compliance_ledger(path)
    obligations = ledger.get("obligations")
    assert isinstance(obligations, list)
    for raw_obligation in obligations:
        if not isinstance(raw_obligation, dict):
            continue
        if raw_obligation.get("id") == obligation_id:
            return raw_obligation
    raise BarLedgerError(f"obligation {obligation_id!r} not found in compliance ledger {path}")
