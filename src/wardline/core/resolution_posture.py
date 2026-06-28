"""Scan-level enforcement posture — is this scan's taint gate actually enforcing?

wardline is an ANNOTATION-DRIVEN trust-boundary checker: a PY-WL defect fires only
when untrusted data violates a DECLARED trust tier (``@trusted`` / ``@external_boundary``
/ ``@trust_boundary``, builtin or pack-defined). A codebase with ZERO recognized trust
boundaries therefore produces ZERO defects no matter what it does — a
``wardline scan . --fail-on ERROR`` gate over it passes GREEN while checking nothing.
That false-assurance is invisible today: the only hint is INFO-severity
``WLN-L3-LOW-RESOLUTION`` noise, exactly the severity an agent filters out.

This module folds the engine's own run metrics into one scan-level verdict the
surface layers (CLI banner, agent-summary, MCP) render loudly. It reads only the
``WLN-ENGINE-METRICS`` finding the engine already emits — its ``taint_source_counts``
is a per-function provenance histogram whose ``anchored`` / ``config`` buckets count
functions seeded from a recognized boundary or configured source, and whose total is
the number of functions analyzed. No engine change, no analysis cost.

A scan is INERT when it recognized ZERO trust boundaries over a non-trivial amount of
code. That fires on a framework app carrying no wardline annotations (anchored=0 over
thousands of functions) and stays quiet on any annotated codebase (the corpus:
anchored=43). A tiny temp-dir exploration (below the function floor) is exempt. ``low_resolution_ratio``
is reported alongside as a secondary health number but does not, by itself, drive the
verdict — a framework-heavy app legitimately resolves few of its library calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from wardline.core.finding import Finding

_LOW_RESOLUTION_RULE = "WLN-L3-LOW-RESOLUTION"
_METRICS_RULE = "WLN-ENGINE-METRICS"

# Provenance buckets that mean "a recognized trust boundary / configured source touched
# this function" — i.e. the gate has something to enforce here. ``anchored`` = a
# boundary-decorated function (or a pack-defined marker); ``config`` = a configured
# untrusted source. ``fallback`` / ``module_default`` / ``callgraph`` do NOT indicate a
# declared boundary.
_RECOGNIZED_BOUNDARY_BUCKETS = ("anchored", "config")

# Below this many analyzed functions a scan is an exploration (a single crafted temp
# file), not a gate — do not call it inert.
_MIN_FUNCTIONS = 5


@dataclass(frozen=True, slots=True)
class ResolutionPosture:
    """A scan's enforcement health, derived from the engine's run metrics."""

    functions_analyzed: int
    recognized_boundaries: int
    low_resolution_functions: int
    inert: bool
    reason: str | None

    @property
    def low_resolution_ratio(self) -> float:
        if self.functions_analyzed <= 0:
            return 0.0
        return self.low_resolution_functions / self.functions_analyzed

    def to_dict(self) -> dict[str, object]:
        return {
            "inert": self.inert,
            "functions_analyzed": self.functions_analyzed,
            "recognized_boundaries": self.recognized_boundaries,
            "low_resolution_functions": self.low_resolution_functions,
            "low_resolution_ratio": round(self.low_resolution_ratio, 4),
            "reason": self.reason,
        }


def compute_resolution_posture(findings: Iterable[Finding]) -> ResolutionPosture:
    """Derive the scan-level :class:`ResolutionPosture` from a finding stream."""
    low_resolution = 0
    functions_analyzed = 0
    recognized_boundaries = 0
    for finding in findings:
        if finding.rule_id == _LOW_RESOLUTION_RULE:
            low_resolution += 1
        elif finding.rule_id == _METRICS_RULE:
            # One metrics finding per scan (stable fingerprint dedupes it). Its
            # taint_source_counts provenance histogram sums to the function count; the
            # anchored/config buckets count functions with a recognized boundary/source.
            counts = finding.properties.get("taint_source_counts") or {}
            if isinstance(counts, dict):
                total = sum(int(v) for v in counts.values())
                functions_analyzed = max(functions_analyzed, total)
                recognized_boundaries += sum(int(counts.get(b, 0)) for b in _RECOGNIZED_BOUNDARY_BUCKETS)

    inert = recognized_boundaries == 0 and functions_analyzed >= _MIN_FUNCTIONS
    reason: str | None = None
    if inert:
        reason = (
            f"taint gate INERT: 0 trust boundaries recognized across {functions_analyzed} "
            "analyzed functions. wardline only fires when untrusted data crosses a DECLARED "
            "trust boundary (@trusted / @external_boundary / @trust_boundary, builtin or "
            "pack-defined); with none declared it enforces nothing — this gate passes green "
            "while checking nothing. Annotate boundaries, or bind your own trust vocabulary "
            "with a wardline pack."
        )
    return ResolutionPosture(
        functions_analyzed=functions_analyzed,
        recognized_boundaries=recognized_boundaries,
        low_resolution_functions=low_resolution,
        inert=inert,
        reason=reason,
    )
