from __future__ import annotations

from types import MappingProxyType

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.propagation import TaintProvenance
from wardline.scanner.taint.resolver_metadata import ResolverResult, ResolverRunMetadata


def _meta(**over) -> ResolverRunMetadata:
    base = dict(
        scc_size_distribution=((1, 3),),
        convergence_iterations_max=2,
        convergence_iterations_histogram=((1, 2), (2, 1)),
        taint_source_counts={"anchored": 1, "module_default": 0, "fallback": 2},
    )
    base.update(over)
    return ResolverRunMetadata(**base)


def test_metadata_valid() -> None:
    m = _meta()
    assert m.convergence_iterations_max == 2
    assert isinstance(m.taint_source_counts, MappingProxyType)


def test_metadata_rejects_unsorted_histogram() -> None:
    with pytest.raises(ValueError, match="sorted"):
        _meta(convergence_iterations_histogram=((2, 1), (1, 2)))


def test_metadata_rejects_negative_max() -> None:
    with pytest.raises(ValueError, match="convergence_iterations_max"):
        _meta(convergence_iterations_max=-1)


def test_metadata_rejects_nonpositive_histogram_count() -> None:
    # A histogram bucket count must be >= 1 (a bucket with zero entries is meaningless
    # — it should simply be absent). A count of 0 must raise.
    with pytest.raises(ValueError, match="counts must be >= 1"):
        _meta(convergence_iterations_histogram=((1, 0),))


def test_result_wraps_mappings_immutably() -> None:
    res = ResolverResult(
        taint_map={"m.f": T.UNKNOWN_RAW},
        return_taint_map={"m.f": T.UNKNOWN_RAW},
        project_edges={"m.f": frozenset()},
        taint_provenance={"m.f": TaintProvenance(source="fallback")},
        diagnostics=(("L3_LOW_RESOLUTION", "m.f has 80% unresolved"),),
        metadata=_meta(),
    )
    assert isinstance(res.taint_map, MappingProxyType)
    assert isinstance(res.project_edges, MappingProxyType)
    assert isinstance(res.taint_provenance, MappingProxyType)
    assert res.diagnostics[0][0] == "L3_LOW_RESOLUTION"
    with pytest.raises(TypeError):
        res.taint_map["m.g"] = T.INTEGRAL  # type: ignore[index]
