from __future__ import annotations

from wardline.scanner.taint.reverse_edge_index import ReverseModuleIndex


def _idx(forward, fqn_to_module) -> ReverseModuleIndex:
    return ReverseModuleIndex.from_forward_edges(forward, fqn_to_module=fqn_to_module)


def test_single_hop() -> None:
    idx = _idx({"a.f": {"b.g"}, "b.g": set()}, {"a.f": "a", "b.g": "b"})
    assert idx.callers_of("b") == frozenset({"a"})
    assert idx.transitive_callers(frozenset({"b"})) == frozenset({"b", "a"})


def test_multi_hop_transitive() -> None:
    idx = _idx(
        {"a.f": {"b.g"}, "b.g": {"c.h"}, "c.h": set()},
        {"a.f": "a", "b.g": "b", "c.h": "c"},
    )
    assert idx.transitive_callers(frozenset({"c"})) == frozenset({"a", "b", "c"})


def test_cycle_terminates() -> None:
    idx = _idx({"a.f": {"b.g"}, "b.g": {"a.f"}}, {"a.f": "a", "b.g": "b"})
    assert idx.transitive_callers(frozenset({"a"})) == frozenset({"a", "b"})


def test_diamond() -> None:
    idx = _idx(
        {"a.f": {"b.g", "c.h"}, "b.g": {"d.k"}, "c.h": {"d.k"}, "d.k": set()},
        {"a.f": "a", "b.g": "b", "c.h": "c", "d.k": "d"},
    )
    assert idx.transitive_callers(frozenset({"d"})) == frozenset({"a", "b", "c", "d"})


def test_intra_module_edges_skipped() -> None:
    # a.f -> a.g is intra-module: no reverse entry (a changed => a is its own seed).
    idx = _idx({"a.f": {"a.g"}, "a.g": set()}, {"a.f": "a", "a.g": "a"})
    assert idx.callers_of("a") == frozenset()
    assert idx.transitive_callers(frozenset({"a"})) == frozenset({"a"})


def test_class_method_caller_keyed_by_module_not_class() -> None:
    # The .old _module_of bug: pkg.h.Handler.process must reverse-key under
    # module 'pkg.h', NOT class 'pkg.h.Handler'.
    idx = _idx(
        {"pkg.h.Handler.process": {"pkg.s.fetch"}, "pkg.s.fetch": set()},
        {"pkg.h.Handler.process": "pkg.h", "pkg.s.fetch": "pkg.s"},
    )
    assert idx.callers_of("pkg.s") == frozenset({"pkg.h"})
    assert idx.transitive_callers(frozenset({"pkg.s"})) == frozenset({"pkg.h", "pkg.s"})


def test_seed_not_in_graph_returns_seed() -> None:
    idx = _idx({"a.f": {"b.g"}, "b.g": set()}, {"a.f": "a", "b.g": "b"})
    assert idx.transitive_callers(frozenset({"z"})) == frozenset({"z"})


def test_empty_seeds() -> None:
    idx = _idx({"a.f": {"b.g"}, "b.g": set()}, {"a.f": "a", "b.g": "b"})
    assert idx.transitive_callers(frozenset()) == frozenset()
