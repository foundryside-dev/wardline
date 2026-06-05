# src/wardline/loomweave/__init__.py
"""SP9: the opt-in Loomweave-backed taint store integration.

Everything here is behind the ``wardline[loomweave]`` extra. The base package and
the ``scanner`` extra never import this package, so they stay zero-dependency;
``blake3`` (the only new dependency) is imported lazily through ``require_blake3``.
"""

from __future__ import annotations

from types import ModuleType

from wardline.core.errors import LoomweaveError


def require_blake3() -> ModuleType:
    """Import and return the ``blake3`` module, or raise an actionable error.

    Called lazily on the only path that hashes files. Keeping the import here
    (not at module top) is what lets the rest of ``wardline.loomweave`` be imported
    for type-checking / wiring without the extra installed."""
    try:
        import blake3
    except ModuleNotFoundError as exc:
        raise LoomweaveError(
            "the Loomweave integration needs blake3 — install it with: pip install 'wardline[loomweave]'"
        ) from exc
    return blake3
