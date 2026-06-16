"""The ``NodeId`` keying authority for the Rust frontend (spec §5).

``mint_node_ids(tree)`` walks one tree-sitter parse tree in pre-order and assigns
every CST node (named *and* anonymous) a deterministic ``NodeId`` — its 0-based
pre-order index. The returned ``NodeIdMap`` is the *single* authority that later
passes (dataflow WP4, rules WP5) use to identify a node: they share the one parse
tree and look up through this map, never re-deriving an id. That is what makes
the callgraph↔dataflow↔rule correlation agree instead of failing quietly.

Lookups key on ``node.id`` — the tree-sitter node identity, stable and unique for
the life of the parse tree. The *value* returned is the reproducible pre-order
index, which ``node.id`` (a process-local pointer value) is not: ids are
correlation-stable within a scan, the index is deterministic across runs.

The tree-sitter types appear only under ``TYPE_CHECKING`` so importing this module
never pulls the ``wardline[rust]`` extra.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.node_id import NodeId

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

__all__ = ["NodeIdMap", "mint_node_ids"]


class NodeIdMap:
    """Maps tree-sitter CST nodes to their stable pre-order ``NodeId``s.

    Constructed only by :func:`mint_node_ids`. Callers pass the ``Node`` (never a
    raw id), so the keying scheme stays encapsulated here — the single authority.

    The map **pins its source ``Tree``**. ``node.id`` is a process-local pointer
    value that tree-sitter *reuses* once a tree is freed, so a map keyed on bare
    ids that outlived its tree would return a *wrong* ``NodeId`` for a node from a
    later tree instead of raising — the silent correlation failure (spec §5's
    "NodeId hazard") this type exists to make loud. Holding the ``Tree`` keeps the
    keyspace valid for the map's whole lifetime, so a foreign-tree lookup is
    always a clean ``KeyError`` (distinct live pointers), never a false hit.
    """

    __slots__ = ("_by_node", "_tree")

    def __init__(self, by_node: dict[int, NodeId], tree: Tree) -> None:
        self._by_node = by_node
        self._tree = tree  # pin the source tree so node.id keys stay valid (see docstring)

    def node_id(self, node: Node) -> NodeId:
        """The ``NodeId`` minted for ``node``.

        Raises ``KeyError`` if ``node`` did not come from the tree this map was
        minted over — a cross-tree lookup is a bug, surfaced loudly rather than
        as a silent miss.
        """
        return self._by_node[node.id]

    def get(self, node: Node) -> NodeId | None:
        """The ``NodeId`` for ``node``, or ``None`` if it is not in this map."""
        return self._by_node.get(node.id)

    def __contains__(self, node: Node) -> bool:
        return node.id in self._by_node

    def __len__(self) -> int:
        return len(self._by_node)


def mint_node_ids(tree: Tree) -> NodeIdMap:
    """Assign every node in ``tree`` a 0-based pre-order ``NodeId``.

    Iterative (explicit stack) so a deeply nested expression cannot exhaust the
    Python recursion limit. Children are pushed reversed so the leftmost child is
    visited next — i.e. classic pre-order, matching a tree-cursor walk.
    """
    by_node: dict[int, NodeId] = {}
    stack: list[Node] = [tree.root_node]
    index = 0
    while stack:
        node = stack.pop()
        by_node[node.id] = NodeId(index)
        index += 1
        stack.extend(reversed(node.children))
    return NodeIdMap(by_node, tree)
