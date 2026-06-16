# src/wardline/scanner/taint/resolver_metadata.py
"""Return-shape carriers for the project resolver.

Slimmed from ``.old``: no SARIF SummaryProvenance, no cache-mode/analysis-level
fields (SP1e/SP1f concerns), no ``deep_immutability`` (discarded per spec §4.5).
Inner collections are wrapped in ``MappingProxyType`` at construction so
downstream stages receive immutable views. Kernel diagnostics ride as plain
``(code, message)`` tuples — SP1f maps them to ``Finding``s.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.core.taints import TaintState
    from wardline.scanner.taint.propagation import TaintProvenance


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolverRunMetadata:
    """Run-level metrics (SP1f promotes these to engine ``kind=metric`` findings).

    ``scc_size_distribution`` and the convergence histograms describe only the
    SCCs that underwent fixed-point *work*: the kernel skips all-anchored SCCs
    (they cannot change), so those components do not appear here. This is a
    convergence-work distribution, not the full project SCC structure. (Dormant
    in SP1 — the default provider anchors nothing — but live once SP2's provider
    pins functions.)
    """

    scc_size_distribution: tuple[tuple[int, int], ...]
    convergence_iterations_max: int
    convergence_iterations_histogram: tuple[tuple[int, int], ...]
    taint_source_counts: Mapping[str, int]

    def __post_init__(self) -> None:
        if self.convergence_iterations_max < 0:
            raise ValueError(f"convergence_iterations_max must be >= 0, got {self.convergence_iterations_max}")
        for name, hist in (
            ("scc_size_distribution", self.scc_size_distribution),
            ("convergence_iterations_histogram", self.convergence_iterations_histogram),
        ):
            if hist and tuple(sorted(hist)) != hist:
                raise ValueError(f"{name} must be sorted ascending; got {hist!r}")
            for _bucket, count in hist:
                if count < 1:
                    raise ValueError(f"{name} counts must be >= 1; got {count}")
        object.__setattr__(self, "taint_source_counts", MappingProxyType(dict(self.taint_source_counts)))


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolverResult:
    """Project-scope resolution output.

    ``taint_map`` is the L3-refined *body* taint per function. ``return_taint_map``
    is the *effective return* taint: for anchored functions, the provider's
    declared return tier (never refined — anchored taints are fixed); for
    non-anchored functions, the refined body taint (``body == return`` holds for
    them). Callers building call-resolution maps want ``return_taint_map`` (a
    caller observes a callee's *return*, not its body); rules wanting a function's
    own operating tier want ``taint_map``.
    """

    taint_map: Mapping[str, TaintState]
    return_taint_map: Mapping[str, TaintState]
    project_edges: Mapping[str, frozenset[str]]
    call_site_callees: Mapping[int, str]
    taint_provenance: Mapping[str, TaintProvenance]
    diagnostics: tuple[tuple[str, str], ...]
    metadata: ResolverRunMetadata
    call_site_implicit_receivers: Mapping[int, str] = field(default_factory=dict)
    call_site_candidate_callees: Mapping[int, frozenset[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "taint_map", MappingProxyType(dict(self.taint_map)))
        object.__setattr__(self, "return_taint_map", MappingProxyType(dict(self.return_taint_map)))
        object.__setattr__(self, "project_edges", MappingProxyType(dict(self.project_edges)))
        object.__setattr__(self, "call_site_callees", MappingProxyType(dict(self.call_site_callees)))
        object.__setattr__(
            self,
            "call_site_implicit_receivers",
            MappingProxyType(dict(self.call_site_implicit_receivers)),
        )
        object.__setattr__(
            self,
            "call_site_candidate_callees",
            MappingProxyType(dict(self.call_site_candidate_callees)),
        )
        object.__setattr__(self, "taint_provenance", MappingProxyType(dict(self.taint_provenance)))
