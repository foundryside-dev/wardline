# src/wardline/scanner/taint/summary.py
"""Slim per-function taint summary + deterministic cache key.

A ``FunctionSummary`` is the cacheable unit SP1e will store and the cold-path
intermediate the project resolver assembles into the kernel's input maps. It
carries exactly what the kernel needs per function (body/return taint, the
3-valued taint-source class, the unresolved-call count) plus a content-addressed
``cache_key``.

The cache key binds source bytes + schema version + resolver version + the
provider's declaration fingerprint. It deliberately omits any import-topology
hash: that would be redundant with ``source_bytes`` for a single module, and
cross-module invalidation is NOT the key's job — it is SP1e's reverse-edge
dirty-closure. Do not re-add a topology hash here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from wardline.core.taints import TaintState  # noqa: TC001  # runtime: dataclass field type

if TYPE_CHECKING:
    from hashlib import _Hash

SUMMARY_SCHEMA_VERSION = 1
"""Bumped whenever FunctionSummary's structural shape changes (purges cache)."""

TaintSourceClass = Literal["anchored", "module_default", "fallback"]


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """A function's taint contract for the L3 resolver / SP1e cache."""

    fqn: str
    body_taint: TaintState
    return_taint: TaintState
    taint_source: TaintSourceClass
    unresolved_calls: int
    schema_version: int
    cache_key: str

    def __post_init__(self) -> None:
        if self.schema_version != SUMMARY_SCHEMA_VERSION:
            raise ValueError(
                f"FunctionSummary schema_version={self.schema_version} != "
                f"SUMMARY_SCHEMA_VERSION={SUMMARY_SCHEMA_VERSION} — purge cache or upgrade"
            )
        if self.unresolved_calls < 0:
            raise ValueError(f"unresolved_calls must be non-negative, got {self.unresolved_calls}")


def compute_cache_key(
    *,
    module_path: str,
    source_bytes: bytes,
    schema_version: int,
    resolver_version: str,
    provider_fingerprint: str,
) -> str:
    """Content-addressed cache key for a module's summaries.

    Binds ``module_path`` as well as content: the key is the *store* key for a
    module's summary tuple, so it must carry module identity. Two distinct
    modules with byte-identical source (boilerplate, re-export shims, generated
    stubs) would otherwise collide on one key, and a cache lookup for the second
    would serve the first's summaries — dropping the second module's functions
    from the taint map (silent under-taint). Module identity, NOT call topology,
    is what is added here: cross-module *dependency* changes are still handled by
    always recomputing the call graph fresh, never by this key.

    Each component is length-prefixed before hashing so distinct inputs cannot
    collide (without it, ``(b"ab", "c")`` and ``(b"a", "bc")`` would hash alike).
    CRLF in ``source_bytes`` is rejected so Linux/Windows checkouts of the same
    commit produce identical keys.
    """
    if source_bytes.find(b"\r\n") != -1:
        raise ValueError("CRLF bytes in source — normalise to LF before hashing")
    hasher = hashlib.sha256()
    _write_len_prefixed(hasher, module_path.encode("utf-8"))
    _write_len_prefixed(hasher, source_bytes)
    _write_len_prefixed(hasher, str(schema_version).encode("ascii"))
    _write_len_prefixed(hasher, resolver_version.encode("utf-8"))
    _write_len_prefixed(hasher, provider_fingerprint.encode("utf-8"))
    return hasher.hexdigest()


def _write_len_prefixed(hasher: _Hash, value: bytes) -> None:
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)
