"""The opt-in Rust language frontend (preview, Tier-A: command-injection slice).

Everything here is behind the ``wardline[rust]`` extra. The base package and the
``scanner`` extra never import this package, so they stay zero-dependency;
``tree_sitter`` / ``tree_sitter_rust`` are imported lazily through
``wardline.rust._tree_sitter.require_rust`` (mirrors ``loomweave.require_blake3``).
Importing ``wardline.rust`` and its submodules for type-checking or wiring does
not require the extra — only calling ``require_rust`` does.
"""

from __future__ import annotations
