# src/wardline/scanner/taint/summary_cache.py
"""In-memory summary cache for L3 project-scope transitive taint.

Keyed on the SP1d module ``cache_key`` (every FunctionSummary in a module shares
one key), so the store maps ``cache_key -> tuple[FunctionSummary, ...]``.

In-memory only: disk persistence (and any ``--cache-dir`` surface) is sequenced
to SP1f, which owns the CLI. ``.old``'s governance (CI attestation,
GOVERNANCE-CACHE-UNATTESTED) is discarded outright. The 64-char hex key
validation is retained: it is cheap and guards the eventual persistent-cache
file path against traversal.

Correctness note: this cache memoizes only the source-determined taint contract
(body/return/source), which ``cache_key`` fully captures. The resolver always
recomputes edges + call counts fresh, so a cache hit can never serve stale
taint — see project_resolver's module docstring.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION

if TYPE_CHECKING:
    from wardline.scanner.taint.summary import FunctionSummary


class SummaryCache:
    """Process-local, default-empty cache keyed on FunctionSummary.cache_key."""

    # Cache keys are SHA-256 hex digests (64 lowercase hex). Validated at put()
    # so the future persistent variant cannot be tricked into writing outside
    # its directory via a crafted key.
    _CACHE_KEY_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

    def __init__(self) -> None:
        self._entries: dict[str, tuple[FunctionSummary, ...]] = {}
        self._hits: int = 0
        self._misses: int = 0

    @property
    def schema_version(self) -> int:
        return SUMMARY_SCHEMA_VERSION

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    def hit_rate(self) -> float:
        """Hit rate in ``[0, 1]``; ``0.0`` when no ``get()`` has been called."""
        total = self._hits + self._misses
        if total == 0:
            return 0.0
        return self._hits / total

    def get(self, cache_key: str) -> tuple[FunctionSummary, ...] | None:
        """Return cached summaries for ``cache_key`` or None. A stale-schema
        entry is evicted and counted as a miss."""
        entry = self._entries.get(cache_key)
        if entry is None:
            self._misses += 1
            return None
        if any(s.schema_version != SUMMARY_SCHEMA_VERSION for s in entry):
            del self._entries[cache_key]
            self._misses += 1
            return None
        self._hits += 1
        return entry

    def put(self, cache_key: str, summaries: tuple[FunctionSummary, ...]) -> None:
        """Store ``summaries`` under ``cache_key``.

        Raises ValueError if ``cache_key`` is not a 64-char lowercase hex
        sha256 digest, or if any summary has a stale ``schema_version``.
        """
        if not self._CACHE_KEY_PATTERN.fullmatch(cache_key):
            raise ValueError(
                f"SummaryCache.put rejected cache_key={cache_key!r} — expected "
                f"64-char lowercase hex sha256 digest"
            )
        for s in summaries:
            if s.schema_version != SUMMARY_SCHEMA_VERSION:
                raise ValueError(
                    f"SummaryCache.put rejected a summary with "
                    f"schema_version={s.schema_version} (current: "
                    f"{SUMMARY_SCHEMA_VERSION})"
                )
        self._entries[cache_key] = summaries

    def invalidate(self, cache_key: str) -> None:
        """Remove ``cache_key``. Missing keys are a no-op."""
        if cache_key in self._entries:
            del self._entries[cache_key]

    def clear(self) -> None:
        """Remove all entries. Does NOT reset hit/miss counters."""
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
