# src/wardline/core/finding_query.py
"""Server-side finding filtering — a pure, conjunctive read-lens over a scan's
findings. Shared by the MCP `scan` tool (`where`) and the CLI `wardline findings`
verb so the query capability is identical across surfaces. Filters the findings
list only; a scan's summary/gate remain whole-project facts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from fnmatch import fnmatch
from typing import Any

from wardline.core.finding import Finding, Kind, Severity, SuppressionState

# Property keys that carry a trust-tier value across the rule set: 101/109 ->
# actual_return/declared_return; 106/107/108 -> tier/arg_taint; 104/105 ->
# body_taint/return_taint. A `tier` predicate matches a finding touching that
# tier on ANY of these.
_TIER_KEYS = ("actual_return", "declared_return", "tier", "arg_taint", "body_taint", "return_taint")

_ALLOWED = frozenset({"rule_id", "qualname", "severity", "suppression", "kind", "path_glob", "sink", "tier"})

# Closed-vocabulary predicate keys (N-5, wardline-dc6f44707d): their values come
# from an enum, so a wrong-case or out-of-domain value can NEVER match — a silent
# empty result there is a bad-error an agent cannot diagnose (filigree's lowercase
# severity habit was the live trip). Normalize case-insensitively to the canonical
# casing; reject anything outside the domain loudly, naming the vocabulary.
# rule_id/qualname/sink/tier stay OPEN (packs can extend tiers; rule ids are data).
_CLOSED_VOCAB: dict[str, tuple[str, ...]] = {
    "severity": tuple(s.value for s in Severity),
    "suppression": tuple(s.value for s in SuppressionState),
    "kind": tuple(k.value for k in Kind),
}


def _normalize_closed_vocab(where: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(where)
    for key, allowed in _CLOSED_VOCAB.items():
        value = normalized.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValueError(f"filter {key!r} must be a string; allowed (case-insensitive): {list(allowed)}")
        canonical = next((a for a in allowed if a.lower() == value.lower()), None)
        if canonical is None:
            raise ValueError(f"unknown {key} {value!r}; allowed (case-insensitive): {list(allowed)}")
        normalized[key] = canonical
    return normalized


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
    where = _normalize_closed_vocab(where)
    return [f for f in findings if _matches(f, where)]
