# SP1e — Summary Cache + Reverse-Edge Dirty-Set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-memory summary cache (keyed on the SP1d `cache_key`) and a module-granular reverse-edge dirty-set closure, then re-thread the cache seam through `project_resolver` so a warm run reuses unchanged modules' summaries — provably identical to a cold run.

**Architecture:** Two new small modules + a wiring change. The cache memoizes only the **source-determined** taint contract (`body_taint`/`return_taint`/`taint_source`), which the SP1d `cache_key` fully captures. The resolver **already recomputes the full callgraph (edges + resolved/unresolved counts) fresh every run** and feeds those fresh counts to the kernel — it never reads `summary.unresolved_calls` into the taint path. Therefore **cached ≡ cold holds by construction**, with no import-topology hash needed. The reverse-edge closure is a **performance over-approximation that bounds which modules' providers get re-invoked — it is NOT a correctness gate.**

**Tech Stack:** Python 3.12, stdlib only (`re`, `dataclasses`, `types.MappingProxyType`). Gate: `.venv/bin/python -m pytest -q` (1 expected xfail in `test_self_hosting.py` stays xfail), `.venv/bin/ruff check src tests`, `.venv/bin/mypy src`.

---

## Context for the implementer

SP1a–d are merged and green (393 passed, 1 xfailed). You build directly on SP1d:

- `src/wardline/scanner/taint/summary.py` — `FunctionSummary(fqn, body_taint, return_taint, taint_source, unresolved_calls, schema_version, cache_key)`, `SUMMARY_SCHEMA_VERSION = 1`, `TaintSourceClass = Literal["anchored","module_default","fallback"]`, `compute_cache_key(*, source_bytes, schema_version, resolver_version, provider_fingerprint)` (returns a 64-char lowercase hex sha256).
- `src/wardline/scanner/taint/project_resolver.py` — `ModuleInput(module_path, entities, class_qualnames, alias_map, seeds, source_bytes)` + `resolve_project_taints(*, modules, provider_fingerprint) -> ResolverResult`. **Currently cold-path only** — no cache params. It builds `edges` (fresh callgraph), computes `unresolved_counts` fresh, builds summaries via `summarise_module`, runs `propagate_callgraph_taints`, returns `ResolverResult`. Read it before Task 3.
- `src/wardline/scanner/taint/module_summariser.py` — `summarise_module(*, seeds, unresolved_counts, source_bytes, resolver_version, provider_fingerprint) -> tuple[FunctionSummary, ...]` (all functions in a module share one `cache_key`).
- `ResolverResult(taint_map, project_edges, taint_provenance, diagnostics, metadata)` from `resolver_metadata.py`.

### The correctness model (read this — it shapes the tests)

The cache stores `tuple[FunctionSummary, ...]` per `cache_key` at **module granularity** (every function in a module shares the key). The kernel's inputs split into two kinds:

- **Source-determined** — `taint_map` (from `body_taint`), `return_taint_map` (from `return_taint`), `taint_sources` (from `taint_source`). A cache hit means the `cache_key` matched, which means identical `source_bytes + schema + resolver_version + provider_fingerprint`, which means these three fields are **byte-identical to fresh**. Reusing them is identity.
- **Topology-dependent** — `edges`, `resolved_counts`, `unresolved_counts`. These are **always recomputed fresh** from the callgraph every `resolve` call and passed to the kernel directly. The cached `summary.unresolved_calls` field is **never** read into the kernel.

⟹ `cached run ≡ cold run` is true **by construction**. The `cache_key` is the correctness gate. The reverse-edge dirty closure does **not** affect taint/diagnostic correctness — it only decides which clean modules skip provider re-invocation. **Do not describe a closure bug as "serving stale taint" — under this architecture that cannot happen.** A closure that wrongly *omits* a module just forces (or fails to force) a redundant recompute whose result is identical anyway.

**Consequence for testing (critical):** an end-to-end "edit B → A recomputed" test will pass *even if `transitive_callers` is completely broken*, because A's cached summary equals fresh regardless and edges are always recomputed. So the closure MUST be verified **directly as a pure graph function** (Task 1) with exact expected outputs. The resolver-level cache tests (Task 3) verify the `cache_key` gating and the `cached ≡ cold` property; they are not a test of the closure.

### Scope boundaries (do NOT exceed)

- **In-memory cache only.** No disk persistence, no `save()`/`load()`, no `cache_dir`. Disk persistence is sequenced to **SP1f** (it needs the `--cache-dir` CLI surface that lands there, and we will not freeze a serialization format before its consumer exists). This is sequencing, not deferral.
- **No governance.** Discard `.old`'s `load_for_ci`, attestation, and `GOVERNANCE-CACHE-UNATTESTED` Finding entirely. No `Finding`/`Severity`/`RuleId` imports.
- **No `Finding` emission** from the resolver (still SP1f).

**Gate commands (repo root; `.venv/bin/python`, never bare `python`):**
```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests
.venv/bin/mypy src
```

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `src/wardline/scanner/taint/reverse_edge_index.py` (create) | `ReverseModuleIndex` — module-granular reverse closure | 1 |
| `src/wardline/scanner/taint/summary_cache.py` (create) | in-memory `SummaryCache` (get/put/hit_rate) | 2 |
| `src/wardline/scanner/taint/project_resolver.py` (modify) | thread `summary_cache`/`dirty_modules` seam | 3 |

---

## Task 1: `reverse_edge_index.py` — module-granular reverse closure

**Files:**
- Create: `src/wardline/scanner/taint/reverse_edge_index.py`
- Test: `tests/unit/scanner/taint/test_reverse_edge_index.py`

**Why:** Given the project's forward call edges, invert them at **module** granularity and support a transitive closure over a seed set of dirty modules. Built from a real `fqn → module` map (NOT `.old`'s string-surgery `_module_of`, which collapses `pkg.a.Cls.method` → `pkg.a.Cls` — the class, not the module — and would mis-key a module-granular dirty-set). This is the only place the closure logic is verified, so the tests assert exact outputs on crafted graphs.

- [ ] **Step 1: Write the failing tests** (every expected value was REPL-verified)

```python
from __future__ import annotations

from wardline.scanner.taint.reverse_edge_index import ReverseModuleIndex


def _idx(forward, fqn_to_module) -> ReverseModuleIndex:
    return ReverseModuleIndex.from_forward_edges(forward, fqn_to_module=fqn_to_module)


def test_single_hop() -> None:
    idx = _idx({"a.f": {"b.g"}, "b.g": set()}, {"a.f": "a", "b.g": "b"})
    assert idx.callers_of("b") == frozenset({"a"})
    assert idx.transitive_callers(frozenset({"b"})) == frozenset({"b", "a"})


def test_multi_hop_transitive() -> None:
    idx = _idx(
        {"a.f": {"b.g"}, "b.g": {"c.h"}, "c.h": set()},
        {"a.f": "a", "b.g": "b", "c.h": "c"},
    )
    assert idx.transitive_callers(frozenset({"c"})) == frozenset({"a", "b", "c"})


def test_cycle_terminates() -> None:
    idx = _idx({"a.f": {"b.g"}, "b.g": {"a.f"}}, {"a.f": "a", "b.g": "b"})
    assert idx.transitive_callers(frozenset({"a"})) == frozenset({"a", "b"})


def test_diamond() -> None:
    idx = _idx(
        {"a.f": {"b.g", "c.h"}, "b.g": {"d.k"}, "c.h": {"d.k"}, "d.k": set()},
        {"a.f": "a", "b.g": "b", "c.h": "c", "d.k": "d"},
    )
    assert idx.transitive_callers(frozenset({"d"})) == frozenset({"a", "b", "c", "d"})


def test_intra_module_edges_skipped() -> None:
    # a.f -> a.g is intra-module: no reverse entry (a changed => a is its own seed).
    idx = _idx({"a.f": {"a.g"}, "a.g": set()}, {"a.f": "a", "a.g": "a"})
    assert idx.callers_of("a") == frozenset()
    assert idx.transitive_callers(frozenset({"a"})) == frozenset({"a"})


def test_class_method_caller_keyed_by_module_not_class() -> None:
    # The .old _module_of bug: pkg.h.Handler.process must reverse-key under
    # module 'pkg.h', NOT class 'pkg.h.Handler'.
    idx = _idx(
        {"pkg.h.Handler.process": {"pkg.s.fetch"}, "pkg.s.fetch": set()},
        {"pkg.h.Handler.process": "pkg.h", "pkg.s.fetch": "pkg.s"},
    )
    assert idx.callers_of("pkg.s") == frozenset({"pkg.h"})
    assert idx.transitive_callers(frozenset({"pkg.s"})) == frozenset({"pkg.h", "pkg.s"})


def test_seed_not_in_graph_returns_seed() -> None:
    idx = _idx({"a.f": {"b.g"}, "b.g": set()}, {"a.f": "a", "b.g": "b"})
    assert idx.transitive_callers(frozenset({"z"})) == frozenset({"z"})


def test_empty_seeds() -> None:
    idx = _idx({"a.f": {"b.g"}, "b.g": set()}, {"a.f": "a", "b.g": "b"})
    assert idx.transitive_callers(frozenset()) == frozenset()
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_reverse_edge_index.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `reverse_edge_index.py`**

```python
# src/wardline/scanner/taint/reverse_edge_index.py
"""Module-granular reverse-edge index for incremental dirty-set propagation.

Inverts the project's forward call graph at MODULE granularity (aligned with
the module-level summary cache_key) and supports a transitive closure over a
seed set of dirty modules: ``transitive_callers(dirty)`` returns ``dirty`` plus
every module that reaches a dirty module via reverse edges.

The index is built from an explicit ``fqn -> module`` map (which the resolver
already knows), NOT by string surgery on the FQN — a method FQN like
``pkg.a.Cls.method`` must reverse-key under module ``pkg.a``, not class
``pkg.a.Cls``.

Role note: in Wardline's resolver the forward edges and call counts are
recomputed fresh on every run, and the cache stores only source-determined
taint. So this closure is a PERFORMANCE over-approximation that bounds which
clean modules skip provider re-invocation — it is NOT a taint-correctness gate.
``cache_key`` is the correctness gate.
"""

from __future__ import annotations

from collections.abc import Mapping, Set
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReverseModuleIndex:
    """Module-granularity reverse index derived from FQN-level forward edges.

    Intra-module edges are dropped: a module is always in its own dirty seed,
    so a self-reverse entry would be uninformative.
    """

    _reverse: Mapping[str, frozenset[str]]

    @classmethod
    def from_forward_edges(
        cls,
        forward: Mapping[str, Set[str]],
        *,
        fqn_to_module: Mapping[str, str],
    ) -> ReverseModuleIndex:
        """Build the reverse index. ``forward`` is ``{caller_fqn: {callee_fqn}}``;
        ``fqn_to_module`` maps every FQN appearing in ``forward`` to its module."""
        rev: dict[str, set[str]] = {}
        for caller_fqn, callee_fqns in forward.items():
            caller_mod = fqn_to_module[caller_fqn]
            for callee_fqn in callee_fqns:
                callee_mod = fqn_to_module[callee_fqn]
                if caller_mod == callee_mod:
                    continue  # intra-module — skip
                try:
                    rev[callee_mod].add(caller_mod)
                except KeyError:
                    rev[callee_mod] = {caller_mod}
        return cls(_reverse={k: frozenset(v) for k, v in rev.items()})

    def callers_of(self, callee_module: str) -> frozenset[str]:
        """Modules that call INTO ``callee_module`` (one reverse hop)."""
        try:
            return self._reverse[callee_module]
        except KeyError:
            return frozenset()

    def transitive_callers(self, seeds: frozenset[str]) -> frozenset[str]:
        """``seeds`` plus every transitively-reverse-reachable module."""
        closure: set[str] = set(seeds)
        frontier: set[str] = set(seeds)
        while frontier:
            next_frontier: set[str] = set()
            for mod in frontier:
                if mod not in self._reverse:
                    continue
                for caller_mod in self._reverse[mod]:
                    if caller_mod not in closure:
                        closure.add(caller_mod)
                        next_frontier.add(caller_mod)
            frontier = next_frontier
        return frozenset(closure)
```

- [ ] **Step 4: Run to verify it passes + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_reverse_edge_index.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/reverse_edge_index.py tests/unit/scanner/taint/test_reverse_edge_index.py
git commit -m "feat(sp1e): module-granular reverse-edge dirty-set closure"
```

---

## Task 2: `summary_cache.py` — in-memory summary cache

**Files:**
- Create: `src/wardline/scanner/taint/summary_cache.py`
- Test: `tests/unit/scanner/taint/test_summary_cache.py`

**Why:** Store/retrieve `tuple[FunctionSummary, ...]` keyed on the 64-hex `cache_key`, with hit/miss accounting for the metrics. In-memory only (disk → SP1f). The 64-hex key validation is kept (it is cheap and guards the future persistent-cache path against traversal); everything governance/disk in `.old` is discarded.

- [ ] **Step 1: Write the failing tests**

```python
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION, FunctionSummary
from wardline.scanner.taint.summary_cache import SummaryCache

_KEY = "a" * 64
_KEY2 = "b" * 64


def _summary(fqn: str, *, schema: int = SUMMARY_SCHEMA_VERSION, key: str = _KEY) -> FunctionSummary:
    return FunctionSummary(
        fqn=fqn, body_taint=T.UNKNOWN_RAW, return_taint=T.UNKNOWN_RAW,
        taint_source="fallback", unresolved_calls=0, schema_version=schema, cache_key=key,
    )


def test_put_then_get_hits() -> None:
    c = SummaryCache()
    summaries = (_summary("m.a"), _summary("m.b"))
    c.put(_KEY, summaries)
    assert c.get(_KEY) == summaries
    assert c.hits == 1 and c.misses == 0


def test_get_miss() -> None:
    c = SummaryCache()
    assert c.get(_KEY) is None
    assert c.misses == 1 and c.hits == 0


def test_hit_rate_zero_when_no_activity() -> None:
    assert SummaryCache().hit_rate() == 0.0


def test_hit_rate_fraction() -> None:
    c = SummaryCache()
    c.put(_KEY, (_summary("m.a"),))
    c.get(_KEY)        # hit
    c.get(_KEY2)       # miss
    assert c.hit_rate() == 0.5


def test_put_rejects_non_hex_key() -> None:
    c = SummaryCache()
    with pytest.raises(ValueError, match="cache_key"):
        c.put("../escape", (_summary("m.a", key="../escape"),))


def test_get_drops_stale_schema_entry() -> None:
    c = SummaryCache()
    # Construct a stale-schema summary by bypassing FunctionSummary's guard:
    # put() also guards, so build the stale entry via object.__setattr__ on a
    # valid instance to simulate a rehydrated stale entry reaching the store.
    good = _summary("m.a")
    object.__setattr__(good, "schema_version", SUMMARY_SCHEMA_VERSION + 99)
    c._entries[_KEY] = (good,)  # type: ignore[attr-defined]  # simulate stale store
    assert c.get(_KEY) is None
    assert c.misses == 1
    assert len(c) == 0  # stale entry evicted


def test_put_rejects_stale_schema_summary() -> None:
    c = SummaryCache()
    good = _summary("m.a")
    object.__setattr__(good, "schema_version", SUMMARY_SCHEMA_VERSION + 1)
    with pytest.raises(ValueError, match="schema_version"):
        c.put(_KEY, (good,))


def test_invalidate_and_clear() -> None:
    c = SummaryCache()
    c.put(_KEY, (_summary("m.a"),))
    c.invalidate(_KEY)
    assert c.get(_KEY) is None
    c.put(_KEY, (_summary("m.a"),))
    c.put(_KEY2, (_summary("n.a", key=_KEY2),))
    assert len(c) == 2
    c.clear()
    assert len(c) == 0


def test_invalidate_missing_key_is_noop() -> None:
    SummaryCache().invalidate(_KEY)  # no exception


def test_schema_version_property() -> None:
    assert SummaryCache().schema_version == SUMMARY_SCHEMA_VERSION
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_summary_cache.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `summary_cache.py`**

```python
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
```

- [ ] **Step 4: Run to verify it passes + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_summary_cache.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/summary_cache.py tests/unit/scanner/taint/test_summary_cache.py
git commit -m "feat(sp1e): in-memory summary cache (get/put/hit_rate)"
```

---

## Task 3: thread the cache seam through `project_resolver`

**Files:**
- Modify: `src/wardline/scanner/taint/project_resolver.py`
- Test: `tests/unit/scanner/taint/test_project_resolver.py` (append)

**Why:** Re-add the `summary_cache`/`dirty_modules` parameters (cold-path-only since SP1d), with the consistency guard. For each module: if it is in the transitive dirty frontier OR misses the cache, compute fresh summaries (and write them back); otherwise reuse the cached summaries. Because only source-determined fields are cached and counts are always fresh, a warm run is provably identical to cold.

- [ ] **Step 1: Write the failing tests** (append to `tests/unit/scanner/taint/test_project_resolver.py`)

Use the existing `_module_input` / `_RawLeafProvider` / `_IO`/`_SERVICE`/`_HANDLER` fixtures already at the top of that file.

```python
import pytest

from wardline.scanner.taint.summary_cache import SummaryCache


def _inputs(provider):
    return [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", _SERVICE, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]


def test_cache_and_dirty_must_be_supplied_together() -> None:
    provider = _RawLeafProvider()
    inputs = _inputs(provider)
    with pytest.raises(ValueError, match="together"):
        resolve_project_taints(
            modules=inputs, provider_fingerprint=provider.fingerprint(),
            summary_cache=SummaryCache(),  # dirty_modules omitted
        )
    with pytest.raises(ValueError, match="together"):
        resolve_project_taints(
            modules=inputs, provider_fingerprint=provider.fingerprint(),
            dirty_modules=frozenset(),  # summary_cache omitted
        )


def test_warm_run_equals_cold_run() -> None:
    provider = _RawLeafProvider()
    inputs = _inputs(provider)
    fp = provider.fingerprint()

    cold = resolve_project_taints(modules=inputs, provider_fingerprint=fp)

    cache = SummaryCache()
    run1 = resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )
    run2 = resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )

    # cached ≡ cold, byte-for-byte on taint and provenance
    assert dict(run1.taint_map) == dict(cold.taint_map)
    assert dict(run2.taint_map) == dict(cold.taint_map)
    assert {k: v.source for k, v in run2.taint_provenance.items()} == {
        k: v.source for k, v in cold.taint_provenance.items()
    }
    # run2 served entirely from cache
    assert cache.hit_rate() > 0.0


def test_dirty_frontier_recompute_still_equals_cold() -> None:
    # Behavioural end-to-end check. NOTE: this passes regardless of whether
    # transitive_callers is correct (cached summaries equal fresh, edges are
    # always recomputed) — the closure itself is verified directly in
    # test_reverse_edge_index.py. This guards the wiring, not the closure.
    provider = _RawLeafProvider()
    inputs = _inputs(provider)
    fp = provider.fingerprint()
    cold = resolve_project_taints(modules=inputs, provider_fingerprint=fp)

    cache = SummaryCache()
    resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset({"pkg.io_layer"}),
    )
    # Mark the leaf's module dirty; its callers are in the frontier.
    warm = resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset({"pkg.io_layer"}),
    )
    assert dict(warm.taint_map) == dict(cold.taint_map)


def test_cache_miss_on_changed_source_recomputes() -> None:
    # A module whose source changes gets a different cache_key -> miss ->
    # fresh summary, even if the caller forgets to mark it dirty.
    provider = _RawLeafProvider()
    fp = provider.fingerprint()
    cache = SummaryCache()

    inputs_v1 = _inputs(provider)
    resolve_project_taints(
        modules=inputs_v1, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )
    len_after_v1 = len(cache)

    # Change pkg.service's source (add a comment) -> new cache_key.
    service_v2 = "# changed\n" + _SERVICE
    inputs_v2 = [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", service_v2, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]
    warm = resolve_project_taints(
        modules=inputs_v2, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )
    cold_v2 = resolve_project_taints(modules=inputs_v2, provider_fingerprint=fp)
    assert dict(warm.taint_map) == dict(cold_v2.taint_map)
    # The changed module added a new key (old one is still present, unused).
    assert len(cache) == len_after_v1 + 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_project_resolver.py -q`
Expected: FAIL (`TypeError` for unexpected `summary_cache` kwarg / `ImportError`).

- [ ] **Step 3: Modify `project_resolver.py`**

Apply these changes:

**(a) Module docstring** — replace the "cold path only" framing:

```python
"""Project-scope L3 resolver.

Assembles per-module parsed data + L1 seeds into the inter-module call graph,
runs the SCC fixed-point kernel, and returns a ``ResolverResult``. Diagnostics
ride on the result as ``(code, message)`` data (SP1f maps them to Findings);
the resolver emits no ``Finding`` itself.

An optional in-memory ``SummaryCache`` memoizes per-module summaries across
calls. The call graph (edges + resolved/unresolved counts) is ALWAYS recomputed
fresh and fed to the kernel; the cache stores only the source-determined taint
contract (body/return/source), which ``cache_key`` fully captures. Therefore a
warm run is byte-identical to a cold run — the ``cache_key`` is the correctness
gate, and the reverse-edge dirty frontier is a performance over-approximation
that only bounds which clean modules skip provider re-invocation (it cannot
affect taint correctness). Star imports are not yet materialised for edge
resolution (deferred).
"""
```

**(b) Imports** — add:

```python
from wardline.scanner.taint.reverse_edge_index import ReverseModuleIndex
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION, TaintSourceClass, compute_cache_key
from wardline.scanner.taint.summary_cache import SummaryCache
```

(Keep the existing `from wardline.scanner.taint.summary import TaintSourceClass` — merge it into the line above so `TaintSourceClass` is imported once alongside `SUMMARY_SCHEMA_VERSION` and `compute_cache_key`.)

**(c) Signature + consistency guard + cache logic** — replace the summary-building section. The new `resolve_project_taints`:

```python
def resolve_project_taints(
    *,
    modules: Sequence[ModuleInput],
    provider_fingerprint: str,
    summary_cache: SummaryCache | None = None,
    dirty_modules: frozenset[str] | None = None,
) -> ResolverResult:
    """Run whole-project transitive taint resolution over ``modules``.

    When ``summary_cache`` is supplied, ``dirty_modules`` MUST also be supplied
    (pass ``frozenset()`` for "nothing declared dirty"); the cache reuses
    summaries for clean, cache-hit modules and recomputes the rest. The result
    is identical to a cold run regardless — the cache only saves provider
    re-invocation.
    """
    if (summary_cache is None) != (dirty_modules is None):
        raise ValueError(
            "summary_cache and dirty_modules must be supplied together; pass "
            "dirty_modules=frozenset() explicitly if nothing has changed"
        )

    project_fqns = frozenset(e.qualname for m in modules for e in m.entities)
    all_classes = frozenset(c for m in modules for c in m.class_qualnames)

    edges: dict[str, frozenset[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}
    for m in modules:
        m_edges, m_resolved, m_unresolved = build_call_edges(
            entities=m.entities,
            class_qualnames=all_classes,
            alias_map=m.alias_map,
            module_prefix=m.module_path,
            project_fqns=project_fqns,
        )
        edges.update(m_edges)
        resolved_counts.update(m_resolved)
        unresolved_counts.update(m_unresolved)

    # Transitive dirty frontier (performance over-approximation — bounds which
    # clean modules skip provider re-invocation; NOT a correctness gate).
    if summary_cache is not None and dirty_modules is not None:
        fqn_to_module = {e.qualname: m.module_path for m in modules for e in m.entities}
        frontier = ReverseModuleIndex.from_forward_edges(
            {k: set(v) for k, v in edges.items()},
            fqn_to_module=fqn_to_module,
        ).transitive_callers(dirty_modules)
    else:
        frontier = frozenset()

    # Per-module summaries: reuse cached for clean cache-hit modules, else fresh.
    summaries: list[FunctionSummary] = []
    for m in modules:
        cache_key = compute_cache_key(
            source_bytes=m.source_bytes,
            schema_version=SUMMARY_SCHEMA_VERSION,
            resolver_version=_RESOLVER_VERSION,
            provider_fingerprint=provider_fingerprint,
        )
        cached: tuple[FunctionSummary, ...] | None = None
        if summary_cache is not None and m.module_path not in frontier:
            cached = summary_cache.get(cache_key)
        if cached is not None:
            summaries.extend(cached)
            continue
        fresh = summarise_module(
            seeds=m.seeds,
            unresolved_counts=unresolved_counts,
            source_bytes=m.source_bytes,
            resolver_version=_RESOLVER_VERSION,
            provider_fingerprint=provider_fingerprint,
        )
        summaries.extend(fresh)
        if summary_cache is not None:
            summary_cache.put(cache_key, fresh)

    taint_map: dict[str, TaintState] = {s.fqn: s.body_taint for s in summaries}
    return_taint_map: dict[str, TaintState] = {s.fqn: s.return_taint for s in summaries}
    taint_sources: dict[str, TaintSourceClass] = {s.fqn: s.taint_source for s in summaries}
```

Leave the rest of the function (the `propagate_callgraph_taints` call with the fresh `resolved_counts`/`unresolved_counts`, the metadata aggregation, and the `ResolverResult` construction) UNCHANGED.

Add `FunctionSummary` to the `TYPE_CHECKING` import block (it is now referenced in an annotation):
```python
    from wardline.scanner.taint.summary import FunctionSummary
```
(`SummaryCache` is imported at runtime above for the parameter type; that is fine — it has no heavy deps.)

> **Implementer note:** Do NOT change how `unresolved_counts` reaches the kernel — it stays the fresh callgraph value. The cached summaries' `unresolved_calls` field is intentionally never read into the taint path; that is precisely what makes warm ≡ cold without a topology hash.

- [ ] **Step 4: Run to verify it passes + FULL gate**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS (1 expected xfail in `test_self_hosting.py` stays xfail); ruff + mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/project_resolver.py tests/unit/scanner/taint/test_project_resolver.py
git commit -m "feat(sp1e): thread summary-cache + dirty-set seam through project resolver"
```

---

## Final review

After all 3 tasks: dispatch a final code-reviewer over the SP1e diff (focus: the cache-gating logic in the resolver, and that no governance/disk crept in), then use `superpowers:finishing-a-development-branch` to merge `sp1e-summary-cache` → `main` (`--no-ff`), verify green on the merge, delete the branch, and update `memory/project_generic_rebuild.md` (mark SP1e done; record that disk persistence is sequenced to SP1f; note the closure is a perf over-approximation, not a correctness gate; cached ≡ cold holds by construction).

## Self-review notes (author)

- **Spec coverage:** SP1e row of §6 — `summary_cache` (Task 2) + `reverse_edge_index` (Task 1, incremental dirty-set); cache hit/miss + dirty-set invalidation tests (Tasks 1–3); cached run ≡ cold run (Task 3 `test_warm_run_equals_cold_run` + `test_cache_miss_on_changed_source_recomputes`). ✓
- **Soundness reframing:** correctness rests on `cache_key`; the closure is verified DIRECTLY (Task 1) because the resolver-level tests pass regardless of closure correctness. Stated in code docstrings + test comments. ✓
- **Scope discipline:** in-memory only; disk → SP1f; all `.old` governance discarded. ✓
- **Type consistency:** `ReverseModuleIndex.from_forward_edges(forward, *, fqn_to_module)`; `SummaryCache.get/put` take/return `tuple[FunctionSummary, ...]`; resolver new params `summary_cache: SummaryCache | None`, `dirty_modules: frozenset[str] | None`. ✓
- **Ground truth:** every `transitive_callers` expected value REPL-verified before the assertion was written. ✓
