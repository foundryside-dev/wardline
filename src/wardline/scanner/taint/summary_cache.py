# src/wardline/scanner/taint/summary_cache.py
"""In-memory (+ optional disk) summary cache for L3 project-scope transitive taint.

Keyed on the SP1d module ``cache_key`` (every FunctionSummary in a module shares
one key), so the store maps ``cache_key -> tuple[FunctionSummary, ...]``.

Disk persistence: construct with ``cache_dir=Path(...)`` then call ``load()``
before analysis and ``save()`` after. Malformed / stale-schema / non-hex-stem
files are silently dropped on load (cold-cache fallback). Atomic write-then-
replace so a crash leaves the prior file or none — never a partial file.

No governance: ``.old``'s CI-attestation / GOVERNANCE-CACHE-UNATTESTED path is
discarded outright. The 64-char hex key validation is retained: it is cheap and
guards the persistent-cache file path against traversal.

Correctness note: this cache memoizes only the source-determined taint contract
(body/return/source), which ``cache_key`` fully captures. The resolver always
recomputes edges + call counts fresh, so a cache hit can never serve stale
taint — see project_resolver's module docstring.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from wardline.core.taints import TaintState  # noqa: TC001  # runtime: deserialise
from wardline.scanner.taint.summary import (  # noqa: TC001  # runtime: deserialise
    SUMMARY_SCHEMA_VERSION,
    FunctionSummary,
)

if TYPE_CHECKING:
    pass

_logger = logging.getLogger(__name__)

# The full reachable taint set for an analyzed function's cached body/return
# taint. Unlike the stdlib table, a cached summary CAN be INTEGRAL (a @trusted
# function produces INTEGRAL), so INTEGRAL is legal here. What must never be
# rehydrated is the unreachable trio {MIXED_RAW, UNKNOWN_GUARDED,
# UNKNOWN_ASSURED}: those are valid TaintState strings, so the "malformed file
# silently dropped" guard in load() does NOT catch them, yet they are never
# produced by any sound analysis. A hand-edited or corrupted on-disk cache file
# carrying one would inject an otherwise-unreachable state into the pipeline.
# See docs/concepts/taint-algebra.md and the taint-combination audit (F5).
_CACHE_LEGAL_TAINT: frozenset[TaintState] = frozenset(
    {
        TaintState.INTEGRAL,
        TaintState.ASSURED,
        TaintState.GUARDED,
        TaintState.EXTERNAL_RAW,
        TaintState.UNKNOWN_RAW,
    }
)


def _parse_cache_taint(raw: str, field: str) -> TaintState:
    """Parse a cached taint string, rejecting the unreachable trio.

    Raises ValueError on a valid-but-unreachable state (MIXED_RAW /
    UNKNOWN_GUARDED / UNKNOWN_ASSURED). load() catches ValueError and drops the
    poisoned file with a warning (cold-cache fallback), so an enforced invariant
    here cannot crash a scan.
    """
    from wardline.core.taints import _PROVENANCE_CLASH

    state = TaintState(raw)  # may raise ValueError on a non-canonical string
    if state == TaintState.MIXED_RAW and _PROVENANCE_CLASH.get():
        return state

    if state not in _CACHE_LEGAL_TAINT:
        raise ValueError(
            f"cached {field}={raw!r} is the unreachable taint state {raw!r}; no "
            f"sound analysis produces {{MIXED_RAW, UNKNOWN_GUARDED, "
            f"UNKNOWN_ASSURED}}, so a cache file holding one is corrupt or "
            f"tampered (see docs/concepts/taint-algebra.md, audit F5)"
        )
    return state


class SummaryCache:
    """Process-local, default-empty cache keyed on FunctionSummary.cache_key."""

    # Cache keys are SHA-256 hex digests (64 lowercase hex). Validated at put()
    # so the future persistent variant cannot be tricked into writing outside
    # its directory via a crafted key.
    _CACHE_KEY_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

    def __init__(self, *, cache_dir: Path | None = None) -> None:
        self._entries: dict[str, tuple[FunctionSummary, ...]] = {}
        self._hits: int = 0
        self._misses: int = 0
        self._cache_dir: Path | None = cache_dir

    @property
    def cache_dir(self) -> Path | None:
        return self._cache_dir

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
                f"SummaryCache.put rejected cache_key={cache_key!r} — expected 64-char lowercase hex sha256 digest"
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

    def save(self) -> None:
        """Atomically write every in-memory entry to ``<cache_dir>/<key>.json``.

        Write-temp-then-os.replace, so a crash leaves the prior file or none —
        never a partial file. Raises ValueError if no cache_dir was set.
        """
        if self._cache_dir is None:
            raise ValueError("SummaryCache.save() requires cache_dir")
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        for cache_key, summaries in self._entries.items():
            target = self._cache_dir / f"{cache_key}.json"
            payload = [_serialise_summary(s) for s in summaries]
            # Opened outside a `with` so temp_path is known for cleanup-on-failure;
            # the `with tf:` below is the actual context manager. (SIM115)
            tf = tempfile.NamedTemporaryFile(  # noqa: SIM115
                mode="w",
                encoding="utf-8",
                dir=self._cache_dir,
                delete=False,
                suffix=".tmp",
            )
            temp_path = Path(tf.name)
            try:
                with tf:
                    json.dump(payload, tf)
                os.replace(temp_path, target)
            except (OSError, ValueError, TypeError):
                # Clean up the temp file on ANY failure (dump or replace) so the
                # cache dir doesn't accrete orphan .tmp litter; re-raise.
                with contextlib.suppress(OSError):
                    temp_path.unlink(missing_ok=True)
                raise

    def load(self) -> None:
        """Populate the store from ``<cache_dir>/*.json``. Malformed / stale /
        non-hex-stem files are silently dropped (cold-cache fallback). Raises
        ValueError if no cache_dir was set."""
        if self._cache_dir is None:
            raise ValueError("SummaryCache.load() requires cache_dir")
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(self._cache_dir.iterdir()):
            if path.suffix != ".json":
                continue
            cache_key = path.stem
            if not self._CACHE_KEY_PATTERN.fullmatch(cache_key):
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                summaries = tuple(_deserialise_summary(d) for d in payload)
            except (json.JSONDecodeError, ValueError, KeyError, TypeError) as exc:
                _logger.warning("SummaryCache.load: dropping malformed entry %s: %s", path, exc)
                continue
            # Defensive second schema gate. Unreachable in practice: FunctionSummary's
            # __post_init__ raises when schema_version != SUMMARY_SCHEMA_VERSION, so a
            # stale-schema file is already rejected by _deserialise_summary above and
            # dropped via the malformed-entry handler — every summary reaching here has
            # the current schema. Kept as an explicit invariant for structural parity.
            if any(s.schema_version != SUMMARY_SCHEMA_VERSION for s in summaries):  # pragma: no cover
                continue
            self._entries[cache_key] = summaries


def _serialise_summary(s: FunctionSummary) -> dict[str, object]:
    return {
        "fqn": s.fqn,
        "body_taint": s.body_taint.value,
        "return_taint": s.return_taint.value,
        "taint_source": s.taint_source,
        "unresolved_calls": s.unresolved_calls,
        "schema_version": s.schema_version,
        "cache_key": s.cache_key,
    }


def _deserialise_summary(d: dict[str, object]) -> FunctionSummary:
    taint_source = d["taint_source"]
    if taint_source not in ("anchored", "module_default", "fallback"):
        raise ValueError(f"invalid taint_source: {taint_source!r}")
    return FunctionSummary(
        fqn=str(d["fqn"]),
        body_taint=_parse_cache_taint(cast("str", d["body_taint"]), "body_taint"),
        return_taint=_parse_cache_taint(cast("str", d["return_taint"]), "return_taint"),
        taint_source=taint_source,
        unresolved_calls=int(cast("int", d["unresolved_calls"])),
        schema_version=int(cast("int", d["schema_version"])),
        cache_key=str(d["cache_key"]),
    )
