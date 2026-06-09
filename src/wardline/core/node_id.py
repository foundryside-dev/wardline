"""The shared ``NodeId`` contract (spec §5).

A ``NodeId`` is a deterministic, per-file pre-order index identifying one syntax
node. It is the single correlation key shared across analysis passes
(callgraph ↔ variable-level ↔ rules): if two passes disagree on a node's
``NodeId``, correlation fails *quietly*, so every pass must obtain ids from one
authority over one parse and never re-derive them.

The type lives here — neutral to any one frontend — so the Rust frontend
(``wardline.rust.nodeid.NodeIdMap``) and, at SP1, the Python frontend share it.
Python currently keys its call-site maps on CPython ``id(node)`` ints directly
(``scanner/taint/callgraph.py``); migrating those annotations to ``NodeId`` is
SP1's unification work, *not* WP0's: ``NewType`` is invariant, so annotating the
write sites alone would cascade type errors through every reader of those maps.
Defining the type here establishes the shared contract without that churn.
"""

from __future__ import annotations

from typing import NewType

NodeId = NewType("NodeId", int)

__all__ = ["NodeId"]
