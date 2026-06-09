"""The Rust trust provider — ``/// @trusted(level=...)`` doc-comment markers.

Rust attributes are compile errors on stable when applied as trust markers, so the
declared-trust signal rides an *outer doc comment* (``///``) instead: ``/// @trusted(
level=ASSURED)`` on a fn declares its body trusted at that tier. An unmarked fn yields
no opinion (``None``), which the L1 seeder turns into the fail-closed ``UNKNOWN_RAW``
default. The provider fingerprint embeds ``RUST_TAINT_VERSION`` so a vocab bump
invalidates dependent summaries (the cache-version gap — a per-file source hash cannot
observe an out-of-source vocab edit).

tree-sitter types appear only under ``TYPE_CHECKING`` so importing this module never
pulls the ``wardline[rust]`` extra.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from wardline.core.taints import TaintState
from wardline.rust import vocabulary
from wardline.scanner.taint.provider import FunctionTaint

if TYPE_CHECKING:
    from tree_sitter import Node

__all__ = ["RustTrustProvider", "rust_provider_fingerprint"]

# A trust marker may only declare a *trusted* tier (ASSURED/GUARDED); raw/unknown tiers
# are the fail-closed default, not something you declare.
_TRUSTED_TIERS: dict[str, TaintState] = {
    "ASSURED": TaintState.ASSURED,
    "GUARDED": TaintState.GUARDED,
}
# Anchored to the START of the doc text (`re.match` + leading `\s*` for the `/// ` space):
# only a directive that LEADS the doc-comment line declares trust. A `search` would also match
# the directive mentioned in prose ("do not use @trusted(level=ASSURED) here"), falsely seeding
# trust and spuriously un-suppressing the fn's findings.
_MARKER = re.compile(r"\s*@trusted\s*\(\s*level\s*=\s*(\w+)\s*\)")


def rust_provider_fingerprint(version: int) -> str:
    """The provider's declaration-surface fingerprint for a given vocab version."""
    return f"rust-vocab:{version}"


class RustTrustProvider:
    """Seeds a function's declared taint from its ``/// @trusted(level=...)`` marker."""

    def taint_for(self, fn_node: Node) -> FunctionTaint | None:
        """The declared :class:`FunctionTaint` for ``fn_node``, or ``None`` (no opinion).

        Raises ``ValueError`` if a ``@trusted`` marker is present but names a level that
        is not a trusted tier — a typo'd marker is surfaced, not silently ignored.
        """
        level = self._declared_level(fn_node)
        if level is None:
            return None
        return FunctionTaint(body_taint=level, return_taint=level)

    def fingerprint(self) -> str:
        return rust_provider_fingerprint(vocabulary.RUST_TAINT_VERSION)

    def _declared_level(self, fn_node: Node) -> TaintState | None:
        # Outer doc comments and attributes are preceding siblings of the fn; walk back
        # through the contiguous run of them looking for the marker.
        node = fn_node.prev_named_sibling
        while node is not None and node.type in ("line_comment", "attribute_item"):
            if node.type == "line_comment":
                outer = node.child_by_field_name("outer")
                doc = node.child_by_field_name("doc")
                if outer is not None and doc is not None and doc.text is not None:
                    match = _MARKER.match(doc.text.decode("utf-8"))
                    if match is not None:
                        word = match.group(1)
                        if word not in _TRUSTED_TIERS:
                            raise ValueError(
                                f"@trusted marker has an invalid level {word!r}; "
                                f"expected one of {sorted(_TRUSTED_TIERS)}"
                            )
                        return _TRUSTED_TIERS[word]
            node = node.prev_named_sibling
        return None
