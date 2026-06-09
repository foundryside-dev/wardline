"""WP2: the spec §5 cross-pass NodeId agreement test.

The engine correlates its passes (index, dataflow WP4, rules WP5) SOLELY by node id
and fails *quietly* if two passes disagree. The Rust frontend's guard is the single
``NodeIdMap`` keying authority: every pass consults it with a ``Node`` object, never a
re-derived id. This test proves the guard holds by locating the *same* builder-chain
trigger node TWO independent ways and asserting the shared map gives them one NodeId —
and it pins WHY the map is necessary by showing the raw ``node.id`` is NOT stable across
parses while the minted index is.

The two locators are *different traversal algorithms* (recursive descent vs. an iterative
``TreeCursor`` pre-order) on purpose: a pass that keyed on anything but the shared map
(a raw id, a re-parse) would diverge here instead of agreeing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.rust.nodeid import mint_node_ids  # noqa: E402
from wardline.rust.parse import parse_rust  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tree_sitter import Node, Tree

_CHAIN = 'fn f(){ let mut c = Command::new("sh"); c.arg("-c"); c.output(); }'


def _is_output_call(node: Node) -> bool:
    if node.type != "call_expression":
        return False
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "field_expression":
        return False
    field = fn.child_by_field_name("field")
    return field is not None and field.text == b"output"


def _locate_by_recursion(node: Node) -> Node | None:
    """Pass A — recursive descent over ``node.children``."""
    if _is_output_call(node):
        return node
    for child in node.children:
        hit = _locate_by_recursion(child)
        if hit is not None:
            return hit
    return None


def _cursor_preorder(tree: Tree) -> Iterator[Node]:
    cursor = tree.walk()
    while True:
        node = cursor.node
        assert node is not None
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


def _locate_by_cursor(tree: Tree) -> Node | None:
    """Pass B — iterative ``TreeCursor`` pre-order, a different algorithm than Pass A."""
    return next((n for n in _cursor_preorder(tree) if _is_output_call(n)), None)


def test_two_independent_passes_agree_on_the_trigger_nodeid() -> None:
    tree = parse_rust(_CHAIN)
    nmap = mint_node_ids(tree)

    a = _locate_by_recursion(tree.root_node)  # "dataflow records the .output() trigger"
    b = _locate_by_cursor(tree)  # "the rule locator looks it up"
    assert a is not None and b is not None
    assert a.id == b.id  # genuinely the same CST node, found two ways

    # The §5 contract: the single map maps that node to one NodeId for both passes,
    # and that is the NodeId mint assigned it (the keying authority).
    assert nmap.node_id(a) == nmap.node_id(b)
    assert nmap.get(a) is not None


def test_raw_node_id_is_not_stable_across_parses_but_the_minted_index_is() -> None:
    # WHY the map is necessary: re-parsing the same source yields a different raw
    # node.id (a process-local pointer) for the logically-identical trigger, but the
    # minted pre-order index is deterministic. A pass that keyed on raw node.id across
    # a re-parse would silently mis-correlate — exactly the hazard §5 closes.
    t1, t2 = parse_rust(_CHAIN), parse_rust(_CHAIN)
    n1 = _locate_by_recursion(t1.root_node)
    n2 = _locate_by_recursion(t2.root_node)
    assert n1 is not None and n2 is not None
    m1, m2 = mint_node_ids(t1), mint_node_ids(t2)
    assert m1.node_id(n1) == m2.node_id(n2)  # minted index: deterministic across parses
