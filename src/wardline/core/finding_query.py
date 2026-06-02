# src/wardline/core/finding_query.py
"""Server-side finding filtering — a pure, conjunctive read-lens over a scan's
findings. Shared by the MCP `scan` tool (`where`) and the CLI `wardline findings`
verb so the query capability is identical across surfaces. Filters the findings
list only; a scan's summary/gate remain whole-project facts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from fnmatch import fnmatch
from typing import Any

from wardline.core.finding import Finding

# Property keys that carry a trust-tier value across the rule set: 101/109 ->
# actual_return/declared_return; 106/107/108 -> tier/arg_taint; 104/105 ->
# body_taint/return_taint. A `tier` predicate matches a finding touching that
# tier on ANY of these.
_TIER_KEYS = ("actual_return", "declared_return", "tier", "arg_taint", "body_taint", "return_taint")

_ALLOWED = frozenset({"rule_id", "qualname", "severity", "suppression", "kind", "path_glob", "sink", "tier"})


def _matches(f: Finding, where: Mapping[str, Any]) -> bool:
    if (v := where.get("rule_id")) is not None and f.rule_id != v:
        return False
    if (v := where.get("qualname")) is not None and f.qualname != v:
        return False
    if (v := where.get("severity")) is not None and f.severity.value != v:
        return False
    if (v := where.get("suppression")) is not None and f.suppressed.value != v:
        return False
    if (v := where.get("kind")) is not None and f.kind.value != v:
        return False
    if (v := where.get("path_glob")) is not None and not fnmatch(f.location.path, v):
        return False
    if (v := where.get("sink")) is not None and f.properties.get("sink") != v:
        return False
    return not ((v := where.get("tier")) is not None and not any(f.properties.get(k) == v for k in _TIER_KEYS))


def filter_findings(findings: Sequence[Finding], where: Mapping[str, Any] | None) -> list[Finding]:
    """Return findings matching every predicate in `where` (conjunction). A falsy
    `where` returns all. An unknown key is agent-actionable -> ValueError."""
    if not where:
        return list(findings)
    unknown = set(where) - _ALLOWED
    if unknown:
        raise ValueError(f"unknown filter key(s): {sorted(unknown)}; allowed: {sorted(_ALLOWED)}")
    return [f for f in findings if _matches(f, where)]
