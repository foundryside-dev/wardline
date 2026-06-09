"""WP0: the NodeId keying authority (spec §5).

These pin the *single keying authority* contract that WP4 (dataflow) and WP5
(rules) depend on: one parse tree, ids minted once in deterministic pre-order,
looked up by passing the ``Node`` (never a raw id). The WP2 cross-pass agreement
test builds on this; here we pin minting in isolation.

Ordering and determinism are checked against an **independent oracle** —
tree-sitter's own ``TreeCursor`` (``_cursor_preorder``), a different traversal
algorithm from ``mint_node_ids``'s explicit stack — so a pre-order regression in
mint cannot hide behind a clone of its own walk.
"""

from __future__ import annotations

import gc
from typing import TYPE_CHECKING

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.node_id import NodeId  # noqa: E402
from wardline.rust._tree_sitter import require_rust  # noqa: E402
from wardline.rust.nodeid import mint_node_ids  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tree_sitter import Node, Tree


def _parse(source: bytes) -> Tree:
    _, parser = require_rust()
    return parser.parse(source)


def _cursor_preorder(tree: Tree) -> Iterator[Node]:
    """An INDEPENDENT pre-order walk via tree-sitter's ``TreeCursor`` — a
    different algorithm than ``mint_node_ids``'s reversed-stack, so it is a real
    oracle for "did mint visit nodes parent-before-child, leftmost-first?"."""
    cursor = tree.walk()
    while True:
        node = cursor.node
        assert node is not None  # the cursor is always positioned on a real node here
        yield node
        if cursor.goto_first_child():
            continue
        if cursor.goto_next_sibling():
            continue
        while True:
            if not cursor.goto_parent():
                return
            if cursor.goto_next_sibling():
                break


def test_mint_is_dense_and_total() -> None:
    # Every node in the tree is minted exactly once; the ids are exactly {0..n-1}.
    tree = _parse(b"fn main(){ let x = 1; }")
    nmap = mint_node_ids(tree)
    nodes = list(_cursor_preorder(tree))
    ids = [int(nmap.node_id(node)) for node in nodes]
    assert sorted(ids) == list(range(len(nodes)))
    assert len(nmap) == len(nodes)


def test_mint_order_matches_an_independent_cursor_oracle() -> None:
    # The discriminating order check: mint's indices, read out in the cursor's
    # independent pre-order, must be the strictly increasing 0,1,2,... — which only
    # holds if mint is genuinely pre-order (a post-order mint would NOT be monotone).
    tree = _parse(b"fn main(){ let x = foo(1); }")
    nmap = mint_node_ids(tree)
    ids = [int(nmap.node_id(node)) for node in _cursor_preorder(tree)]
    assert ids == list(range(len(ids)))


def test_mint_is_deterministic_across_separate_parses() -> None:
    # Two independent parses of the same source yield the same (index, node.type)
    # sequence — pins the docstring's "deterministic across runs" claim, which
    # re-minting one Tree object cannot.
    src = b"fn a(){ let x = 1; } fn b(){ bar(); }"
    t1, t2 = _parse(src), _parse(src)
    m1, m2 = mint_node_ids(t1), mint_node_ids(t2)
    seq1 = [(int(m1.node_id(n)), n.type) for n in _cursor_preorder(t1)]
    seq2 = [(int(m2.node_id(n)), n.type) for n in _cursor_preorder(t2)]
    assert seq1 == seq2


def test_root_is_first_in_preorder() -> None:
    tree = _parse(b"fn main(){}")
    nmap = mint_node_ids(tree)
    assert nmap.node_id(tree.root_node) == NodeId(0)


def test_same_node_via_renavigation_resolves_to_same_id() -> None:
    tree = _parse(b"fn main(){}")
    nmap = mint_node_ids(tree)
    fn_a = tree.root_node.named_children[0]
    fn_b = tree.root_node.named_children[0]
    assert nmap.node_id(fn_a) == nmap.node_id(fn_b)


def test_membership_and_get() -> None:
    tree = _parse(b"fn main(){}")
    nmap = mint_node_ids(tree)
    assert tree.root_node in nmap
    assert nmap.get(tree.root_node) == NodeId(0)


def test_lookup_of_a_foreign_node_raises_keyerror() -> None:
    # Looking a node up in a map minted over a *different* (live) tree is a bug,
    # not a silent miss — the keying authority must refuse it loudly.
    tree = _parse(b"fn main(){}")
    foreign = _parse(b"fn other(){}")
    nmap = mint_node_ids(tree)
    assert foreign.root_node not in nmap
    with pytest.raises(KeyError):
        nmap.node_id(foreign.root_node)


def test_map_outliving_its_source_tree_refuses_foreign_lookups() -> None:
    # The §5 fail-quiet hazard: node.id is a pointer tree-sitter reuses once a tree
    # is freed. The map PINS its source tree, so the keyspace stays valid for the
    # map's whole life and foreign (live) nodes never false-hit a stored key.
    # Without the pin this loops to a non-zero hit count (empirically reproduced).
    nmap = mint_node_ids(_parse(b"fn outer(){ let c = mk(); c.run(); }"))
    # the map is now the ONLY reference keeping the source tree alive
    gc.collect()
    foreign_hits = 0
    for i in range(500):
        foreign = _parse(b"fn f%d(){ let x = 1; }" % i)
        for node in _cursor_preorder(foreign):
            if node in nmap:
                foreign_hits += 1
    assert foreign_hits == 0


def test_nodeidmap_pins_its_source_tree() -> None:
    # Deterministic white-box guard for the §5 Tree-pin: the behavioral freed-tree
    # test above is allocator-probabilistic (a lucky run could pass with the pin
    # removed); this fails the instant someone drops `_tree` from NodeIdMap.
    tree = _parse(b"fn main(){}")
    nmap = mint_node_ids(tree)
    assert nmap._tree is tree  # noqa: SLF001 — white-box on the keystone keyspace-lifetime invariant


def test_mint_over_empty_source_is_total() -> None:
    tree = _parse(b"")
    nmap = mint_node_ids(tree)
    assert len(nmap) == len(list(_cursor_preorder(tree)))
    assert nmap.node_id(tree.root_node) == NodeId(0)


def test_mint_over_malformed_source_is_total_including_error_nodes() -> None:
    # ERROR / MISSING nodes are ordinary node.children entries — they must be
    # minted like any other node, and mint must not raise on a broken parse.
    tree = _parse(b"fn (")
    nmap = mint_node_ids(tree)
    nodes = list(_cursor_preorder(tree))
    assert all(node in nmap for node in nodes)
    assert len(nmap) == len(nodes)


def test_mint_survives_a_tree_deeper_than_the_recursion_limit() -> None:
    # The explicit stack (not recursion) must handle a tree deeper than Python's
    # default recursion limit without a RecursionError.
    depth = 2000
    src = b"fn f(){ let _x = " + b"(" * depth + b"1" + b")" * depth + b"; }"
    nmap = mint_node_ids(_parse(src))
    assert len(nmap) > depth
