# SP1b — Taint Lattice + L1 Seeding (via pluggable TaintSourceProvider) + stdlib_taint (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **GIT PROHIBITION (controller-enforced):** Implementer/reviewer subagents MUST NEVER run any git command — no `git add/commit/stash/checkout/restore/reset/rm/branch/switch`. They write files, run tests, and report. **The controller does every commit.** This overrides the skill's "implementer commits" step.

**Goal:** Land the taint domain (`core/taints.py`: the 8-state lattice, `TRUST_RANK`, and the two distinct combination operators) and L1 function-level seeding behind a pluggable `TaintSourceProvider` seam (with a trivial default provider), plus the curated `stdlib_taint` table — the data/loader foundation downstream stages consume.

**Architecture:** `core/taints.py` is stdlib-only and ports two `.old` modules' irreducible cores. The crucial subtlety: `.old` has **two** combination operators that must both be ported and kept distinct — `taint_join` (provenance compatibility; mostly absorbs to `MIXED_RAW`) and `least_trusted` (pure `TRUST_RANK` demotion for L3 monotonicity). L1 seeding (`scanner/taint/function_level.py`) does NOT port `.old`'s decorator/manifest-coupled `assign_function_taints`; instead it asks a `TaintSourceProvider` (seam in `scanner/taint/provider.py`) per function, falling back to `UNKNOWN_RAW`. `stdlib_taint` ships as loader + YAML data + tests; it is a call-RETURN reference consumed in SP1c/SP1d, NOT an L1 input.

**Tech Stack:** Python 3.12; `core/taints.py` stdlib-only; `scanner/taint/*` may use `pyyaml` (already the `scanner` optional extra, like `core/config.py`). pytest, ruff, mypy strict.

**Source engine:** `.old` `core/taints.py` (TaintState + taint_join), `.old` `scanner/taint/callgraph.py` lines 15-33 (TRUST_RANK + least_trusted), `.old` `scanner/taint/stdlib_taint.py` + `src/wardline/stdlib_taint.yaml`.

**SP1 design spec:** `docs/superpowers/specs/2026-05-29-wardline-sp1-analyzer-core-design.md` §2 (taint model), §4.2 (pluggable taint source), §4.5 (discards), §6 (SP1b row). **Layout note:** this plan adds `scanner/taint/provider.py` (the seam), which the spec §3 layout did not separately list — it keeps `function_level.py` free of the seam's type definitions.

**Branch:** `sp1b-taint-lattice-l1` (already created off `main`).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/wardline/core/taints.py` (create) | `TaintState`, `TRUST_RANK`, `taint_join`, `least_trusted` — stdlib-only |
| `src/wardline/scanner/taint/__init__.py` (create) | regular package marker (required so `importlib.resources` resolves the YAML) |
| `src/wardline/scanner/taint/provider.py` (create) | `SeedContext`, `FunctionTaint`, `TaintSourceProvider` (Protocol), `DefaultTaintSourceProvider` |
| `src/wardline/scanner/taint/function_level.py` (create) | `FunctionSeed` + `seed_function_taints` — the L1 driver |
| `src/wardline/scanner/taint/stdlib_taint.py` (create) | loader + `StdlibTaintEntry` + `_build_table` (testable) + `load_stdlib_taint` + `stdlib_taint_keys` |
| `src/wardline/scanner/taint/stdlib_taint.yaml` (create) | curated `(package, function) -> returns_taint` table |
| `pyproject.toml` (modify) | force-include the YAML in the wheel |
| `tests/unit/core/test_taints.py` (create) | exhaustive 64-pair join gate + TRUST_RANK + least_trusted |
| `tests/unit/scanner/taint/test_provider.py` (create) | seam tests |
| `tests/unit/scanner/taint/test_function_level.py` (create) | L1 seeding tests |
| `tests/unit/scanner/taint/test_stdlib_taint.py` (create) | loader + validation tests |

**Do NOT port (scope guard, mirrors SP1a):** `.old`'s `assign_function_taints` and its `BODY_EVAL_TAINT`/`RETURN_TAINT` tables + `authority.py` decorator vocabulary (that's SP2's provider), `anchor_resolver.py` (the single-provider L1 driver IS the resolution here; a shared resolver arrives when stdlib joins at call-resolution in SP1c/d), `restoration.py`, `TAINT_CONTEXT` (codegen), `TAINT_STATE_LABELS` (SARIF → SP4), and manifest/`module_tiers`/`TaintConflict`/`RestorationOverclaim` machinery.

---

## Task 1: `core/taints.py` — lattice + join + TRUST_RANK + least_trusted

**Files:**
- Create: `src/wardline/core/taints.py`
- Test: `tests/unit/core/test_taints.py`

- [ ] **Step 1: Write the failing test (the SP1b correctness gate)**

```python
# tests/unit/core/test_taints.py
from __future__ import annotations

import pytest

from wardline.core.taints import TRUST_RANK, TaintState, least_trusted, taint_join

_UA = TaintState.UNKNOWN_ASSURED
_UG = TaintState.UNKNOWN_GUARDED
_UR = TaintState.UNKNOWN_RAW
_MIXED = TaintState.MIXED_RAW

# Independent restatement of the join rule — deliberately NOT a copy of the
# implementation's _JOIN_TABLE, so any edit to the table fails this gate.
_SPECIAL: dict[frozenset[TaintState], TaintState] = {
    frozenset({_UA, _UR}): _UR,
    frozenset({_UG, _UR}): _UR,
    frozenset({_UA, _UG}): _UG,
}


def _expected_join(a: TaintState, b: TaintState) -> TaintState:
    if a == b:
        return a
    if a == _MIXED or b == _MIXED:
        return _MIXED
    return _SPECIAL.get(frozenset({a, b}), _MIXED)


@pytest.mark.parametrize("a", list(TaintState))
@pytest.mark.parametrize("b", list(TaintState))
def test_taint_join_exhaustive(a: TaintState, b: TaintState) -> None:
    assert taint_join(a, b) == _expected_join(a, b)


@pytest.mark.parametrize("a", list(TaintState))
@pytest.mark.parametrize("b", list(TaintState))
def test_taint_join_commutative(a: TaintState, b: TaintState) -> None:
    assert taint_join(a, b) == taint_join(b, a)


def test_mixed_raw_is_absorbing() -> None:
    for s in TaintState:
        assert taint_join(_MIXED, s) == _MIXED
        assert taint_join(s, _MIXED) == _MIXED


def test_taint_state_values_are_uppercase_names() -> None:
    for s in TaintState:
        assert s.value == s.name
        assert s.value.isupper()


def test_trust_rank_total_order() -> None:
    assert sorted(TaintState, key=lambda s: TRUST_RANK[s]) == [
        TaintState.INTEGRAL,
        TaintState.ASSURED,
        TaintState.GUARDED,
        TaintState.UNKNOWN_ASSURED,
        TaintState.UNKNOWN_GUARDED,
        TaintState.EXTERNAL_RAW,
        TaintState.UNKNOWN_RAW,
        TaintState.MIXED_RAW,
    ]
    assert set(TRUST_RANK.values()) == set(range(8))


@pytest.mark.parametrize("a", list(TaintState))
@pytest.mark.parametrize("b", list(TaintState))
def test_least_trusted_picks_higher_rank(a: TaintState, b: TaintState) -> None:
    assert TRUST_RANK[least_trusted(a, b)] == max(TRUST_RANK[a], TRUST_RANK[b])


def test_join_and_least_trusted_diverge_across_families() -> None:
    # The whole point of having both operators: same inputs, different outputs.
    assert taint_join(TaintState.INTEGRAL, TaintState.ASSURED) == _MIXED
    assert least_trusted(TaintState.INTEGRAL, TaintState.ASSURED) == TaintState.ASSURED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/core/test_taints.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.core.taints'`

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/core/taints.py
"""The taint-state lattice: 8 canonical states, their trust ranking, and the
two combination operators. Stdlib-only — no project or third-party imports.

Ported from ``wardline.old``: ``core/taints.py`` (``TaintState`` + ``taint_join``)
and ``scanner/taint/callgraph.py`` (``TRUST_RANK`` + ``least_trusted``). The
SARIF label table and codegen vocabulary (``TAINT_STATE_LABELS``,
``TAINT_CONTEXT``) are intentionally NOT ported — labels arrive with SARIF in
SP4; the codegen map is unused here.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType


class TaintState(StrEnum):
    """The 8 canonical taint states.

    Values are explicit uppercase strings (never ``auto()``, which lowercases),
    so serialized findings, cache keys, and conformance fixtures stay stable.
    """

    INTEGRAL = "INTEGRAL"
    ASSURED = "ASSURED"
    GUARDED = "GUARDED"
    EXTERNAL_RAW = "EXTERNAL_RAW"
    UNKNOWN_RAW = "UNKNOWN_RAW"
    UNKNOWN_GUARDED = "UNKNOWN_GUARDED"
    UNKNOWN_ASSURED = "UNKNOWN_ASSURED"
    MIXED_RAW = "MIXED_RAW"


# Trust ordering: 0 = most trusted ... 7 = least trusted / absorbing top.
TRUST_RANK: MappingProxyType[TaintState, int] = MappingProxyType(
    {
        TaintState.INTEGRAL: 0,
        TaintState.ASSURED: 1,
        TaintState.GUARDED: 2,
        TaintState.UNKNOWN_ASSURED: 3,
        TaintState.UNKNOWN_GUARDED: 4,
        TaintState.EXTERNAL_RAW: 5,
        TaintState.UNKNOWN_RAW: 6,
        TaintState.MIXED_RAW: 7,
    }
)


# Non-trivial ``taint_join`` pairs, keys normalized to (min, max) by ``.value``.
# Self-joins are identity; any pair touching MIXED_RAW yields MIXED_RAW; every
# other distinct pair NOT listed here collapses to MIXED_RAW. Within the
# UNKNOWN_* family the join demotes to the weaker validation.
_UR = TaintState.UNKNOWN_RAW
_UG = TaintState.UNKNOWN_GUARDED
_UA = TaintState.UNKNOWN_ASSURED

_JOIN_TABLE: dict[tuple[TaintState, TaintState], TaintState] = {
    (_UA, _UR): _UR,
    (_UG, _UR): _UR,
    (_UA, _UG): _UG,
}


def taint_join(a: TaintState, b: TaintState) -> TaintState:
    """Provenance-combination join (commutative; ``MIXED_RAW`` absorbing).

    Models *provenance compatibility*: combining values within one family
    yields that family's weaker member; combining values of DIFFERENT families
    is a provenance clash and yields ``MIXED_RAW``.

    This is DELIBERATELY NOT the trust-rank meet — see :func:`least_trusted` for
    pure rank demotion. The two operators agree only on self-joins, anything
    touching ``MIXED_RAW``, and within the ``UNKNOWN_*`` family; they diverge on
    every other cross-family pair (e.g. ``taint_join(INTEGRAL, ASSURED)`` is
    ``MIXED_RAW`` whereas ``least_trusted(INTEGRAL, ASSURED)`` is ``ASSURED``).
    Do not "simplify" one into the other.
    """
    if a == b:
        return a
    if a == TaintState.MIXED_RAW or b == TaintState.MIXED_RAW:
        return TaintState.MIXED_RAW
    key = (min(a, b, key=lambda x: x.value), max(a, b, key=lambda x: x.value))
    return _JOIN_TABLE.get(key, TaintState.MIXED_RAW)


def least_trusted(a: TaintState, b: TaintState) -> TaintState:
    """Return the less-trusted (higher ``TRUST_RANK``) of two states.

    Pure rank demotion, used by the L3 fixed-point's monotone propagation
    (non-anchored functions only ever move toward less-trusted). Distinct from
    :func:`taint_join` — see that docstring.
    """
    return a if TRUST_RANK[a] >= TRUST_RANK[b] else b
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/core/test_taints.py -q`
Expected: PASS (64 join pairs ×2 + the scalar tests)

- [ ] **Step 5: Controller commits** (`feat(sp1b): taint lattice — TaintState, TRUST_RANK, taint_join, least_trusted`).

---

## Task 2: `scanner/taint/provider.py` — the pluggable seam

**Files:**
- Create: `src/wardline/scanner/taint/__init__.py` (regular package — needed for `importlib.resources` in Task 4)
- Create: `src/wardline/scanner/taint/provider.py`
- Test: `tests/unit/scanner/taint/test_provider.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/scanner/taint/test_provider.py
from __future__ import annotations

import ast
import dataclasses

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.index import discover_file_entities
from wardline.scanner.taint.provider import (
    DefaultTaintSourceProvider,
    FunctionTaint,
    SeedContext,
    TaintSourceProvider,
)


def _entity() -> object:
    tree = ast.parse("def f():\n    pass\n")
    return discover_file_entities(tree, module="demo", path="demo.py")[0]


def test_default_provider_has_no_opinion() -> None:
    provider = DefaultTaintSourceProvider()
    assert provider.taint_for(_entity(), SeedContext(module="demo")) is None  # type: ignore[arg-type]


def test_default_provider_satisfies_protocol() -> None:
    assert isinstance(DefaultTaintSourceProvider(), TaintSourceProvider)


def test_function_taint_is_frozen() -> None:
    taint = FunctionTaint(
        body_taint=TaintState.EXTERNAL_RAW, return_taint=TaintState.GUARDED
    )
    assert taint.body_taint == TaintState.EXTERNAL_RAW
    assert taint.return_taint == TaintState.GUARDED
    with pytest.raises(dataclasses.FrozenInstanceError):
        taint.body_taint = TaintState.INTEGRAL  # type: ignore[misc]


def test_seed_context_carries_module() -> None:
    assert SeedContext(module="pkg.sub").module == "pkg.sub"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_provider.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.scanner.taint'`

- [ ] **Step 3: Write the implementation**

`src/wardline/scanner/taint/__init__.py`:

```python
"""Taint engine: lattice consumers, L1 seeding, and the stdlib taint table."""
```

`src/wardline/scanner/taint/provider.py`:

```python
# src/wardline/scanner/taint/provider.py
"""The pluggable taint-source seam consumed by L1 function seeding.

A ``TaintSourceProvider`` answers one question: what taint did the author
*declare* for this function (via decorators, annotations, or config)? SP1 ships
only the trivial ``DefaultTaintSourceProvider`` (no opinion on anything, so
callers fall back to ``UNKNOWN_RAW``). SP2 supplies the real
decorator-vocabulary provider via the rule registry.

The seam is intentionally extensible: SP2 may add fields to ``SeedContext`` and
``FunctionTaint`` without reshaping ``taint_for``. ``SeedContext`` is kept
minimal here (module name only) — fields like an import-alias map are added when
a provider actually consumes them, not speculatively.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from wardline.core.taints import TaintState
from wardline.scanner.index import Entity


@dataclass(frozen=True, slots=True)
class SeedContext:
    """Per-file context handed to a provider for each entity in that file."""

    module: str


@dataclass(frozen=True, slots=True)
class FunctionTaint:
    """A provider's declared taint for one function: the taint observed INSIDE
    the body (input tier) and the taint of its return value (output tier)."""

    body_taint: TaintState
    return_taint: TaintState


@runtime_checkable
class TaintSourceProvider(Protocol):
    """Maps a function entity to its declared taint, or ``None`` for 'no opinion'."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None: ...


class DefaultTaintSourceProvider:
    """The trivial provider: declares nothing. With no decorator vocabulary in
    SP1, every function falls back to ``UNKNOWN_RAW`` (fail-closed)."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None:
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_provider.py -q`
Expected: PASS

- [ ] **Step 5: Controller commits** (`feat(sp1b): pluggable TaintSourceProvider seam + default provider`).

---

## Task 3: `scanner/taint/function_level.py` — L1 seeding driver

**Files:**
- Create: `src/wardline/scanner/taint/function_level.py`
- Test: `tests/unit/scanner/taint/test_function_level.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/scanner/taint/test_function_level.py
from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.index import Entity, discover_file_entities
from wardline.scanner.taint.function_level import FunctionSeed, seed_function_taints
from wardline.scanner.taint.provider import (
    DefaultTaintSourceProvider,
    FunctionTaint,
    SeedContext,
)


def _entities(src: str) -> list[Entity]:
    return discover_file_entities(ast.parse(src), module="demo", path="demo.py")


def test_default_provider_seeds_all_unknown_raw() -> None:
    entities = _entities("def a():\n    pass\ndef b():\n    pass\n")
    seeds = seed_function_taints(
        entities, ctx=SeedContext(module="demo"), provider=DefaultTaintSourceProvider()
    )
    assert set(seeds) == {"demo.a", "demo.b"}
    for seed in seeds.values():
        assert seed.body_taint == TaintState.UNKNOWN_RAW
        assert seed.return_taint == TaintState.UNKNOWN_RAW
        assert seed.source == "default"


class _StubProvider:
    """Opines on demo.a only; silent (None) on everything else."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None:
        if entity.qualname == "demo.a":
            return FunctionTaint(
                body_taint=TaintState.EXTERNAL_RAW, return_taint=TaintState.GUARDED
            )
        return None


def test_provider_opinion_used_else_fallback() -> None:
    entities = _entities("def a():\n    pass\ndef b():\n    pass\n")
    seeds = seed_function_taints(
        entities, ctx=SeedContext(module="demo"), provider=_StubProvider()
    )
    assert seeds["demo.a"] == FunctionSeed(
        qualname="demo.a",
        body_taint=TaintState.EXTERNAL_RAW,
        return_taint=TaintState.GUARDED,
        source="provider",
    )
    assert seeds["demo.b"].source == "default"
    assert seeds["demo.b"].body_taint == TaintState.UNKNOWN_RAW


def test_empty_entity_list() -> None:
    seeds = seed_function_taints(
        [], ctx=SeedContext(module="demo"), provider=DefaultTaintSourceProvider()
    )
    assert seeds == {}


def test_methods_and_closures_all_seeded() -> None:
    src = "class C:\n    def m(self):\n        def inner():\n            pass\n"
    entities = _entities(src)
    seeds = seed_function_taints(
        entities, ctx=SeedContext(module="demo"), provider=DefaultTaintSourceProvider()
    )
    assert set(seeds) == {"demo.C.m", "demo.C.m.<locals>.inner"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_function_level.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.scanner.taint.function_level'`

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/scanner/taint/function_level.py
"""L1 (function-level) taint seeding.

For each discovered function entity, ask the ``TaintSourceProvider`` for a
declared taint; when the provider has no opinion, fall back to ``UNKNOWN_RAW``
(fail-closed). That is the ENTIRE L1 precedence: ``provider > UNKNOWN_RAW``.

The stdlib taint table is a call-RETURN reference consumed downstream at call
resolution (SP1c/SP1d), NOT a function-body seeding input, so it is deliberately
absent here (matching ``.old``, whose ``function_level`` does not import it).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from wardline.core.taints import TaintState
from wardline.scanner.index import Entity
from wardline.scanner.taint.provider import SeedContext, TaintSourceProvider

_FALLBACK = TaintState.UNKNOWN_RAW


@dataclass(frozen=True, slots=True)
class FunctionSeed:
    """The L1 result for one function: its seeded body/return taint and the
    origin of that taint (``"provider"`` when declared, ``"default"`` when the
    provider was silent and the fail-closed fallback applied)."""

    qualname: str
    body_taint: TaintState
    return_taint: TaintState
    source: Literal["provider", "default"]


def seed_function_taints(
    entities: Sequence[Entity],
    *,
    ctx: SeedContext,
    provider: TaintSourceProvider,
) -> dict[str, FunctionSeed]:
    """Seed each entity's L1 taint, keyed by qualname.

    Entities are assumed already deduplicated by qualname (SP1a's
    ``discover_file_entities`` guarantees this); on any residual collision the
    last write wins, which is harmless because the seeds are identical inputs.
    """
    seeds: dict[str, FunctionSeed] = {}
    for entity in entities:
        declared = provider.taint_for(entity, ctx)
        if declared is None:
            seeds[entity.qualname] = FunctionSeed(
                qualname=entity.qualname,
                body_taint=_FALLBACK,
                return_taint=_FALLBACK,
                source="default",
            )
        else:
            seeds[entity.qualname] = FunctionSeed(
                qualname=entity.qualname,
                body_taint=declared.body_taint,
                return_taint=declared.return_taint,
                source="provider",
            )
    return seeds
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_function_level.py -q`
Expected: PASS

- [ ] **Step 5: Controller commits** (`feat(sp1b): L1 function-level seeding driver`).

---

## Task 4: `scanner/taint/stdlib_taint.py` + YAML + packaging

**Files:**
- Create: `src/wardline/scanner/taint/stdlib_taint.py`
- Create: `src/wardline/scanner/taint/stdlib_taint.yaml`
- Modify: `pyproject.toml` (force-include the YAML in the wheel)
- Test: `tests/unit/scanner/taint/test_stdlib_taint.py`

- [ ] **Step 1: Write the YAML data file**

```yaml
# src/wardline/scanner/taint/stdlib_taint.yaml
# Curated stdlib taint fallback table.
#
# Each entry claims the taint of the value RETURNED by a stdlib call, so that
# common unresolved cross-module calls do not inflate UNKNOWN_RAW rates. Applied
# at call resolution (SP1c/SP1d), not in L1 function seeding. Documented here so
# the rates stay explainable and the table is auditable.
#
# `version` is bumped when the shape/semantics change — folded into the SP1e
# summary cache key so changes invalidate dependent summaries.

version: 1

entries:
  # Filesystem / OS
  - package: builtins
    function: open
    returns_taint: EXTERNAL_RAW
    rationale: Opens an external file; contents are raw bytes from disk.

  - package: pathlib
    function: Path.read_text
    returns_taint: EXTERNAL_RAW
    rationale: External file contents; unvalidated.

  - package: pathlib
    function: Path.read_bytes
    returns_taint: EXTERNAL_RAW
    rationale: External file bytes; unvalidated.

  - package: os
    function: environ.get
    returns_taint: EXTERNAL_RAW
    rationale: Environment variable; externally controlled.

  # Subprocess
  - package: subprocess
    function: check_output
    returns_taint: EXTERNAL_RAW
    rationale: Output of an external process.

  - package: subprocess
    function: run
    returns_taint: EXTERNAL_RAW
    rationale: CompletedProcess.stdout is external.

  # Networking
  - package: urllib.request
    function: urlopen
    returns_taint: EXTERNAL_RAW
    rationale: Remote resource contents.

  # Parsing (returns shape-validated container — GUARDED, not ASSURED)
  - package: json
    function: loads
    returns_taint: GUARDED
    rationale: Shape-validated by the parser but semantics unchecked.

  - package: json
    function: load
    returns_taint: GUARDED
    rationale: Same as json.loads from a file handle.

  - package: ast
    function: literal_eval
    returns_taint: GUARDED
    rationale: Safe literal parser; shape is validated, semantics are the literal.
```

- [ ] **Step 2: Write the failing test**

```python
# tests/unit/scanner/taint/test_stdlib_taint.py
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.taint.stdlib_taint import (
    STDLIB_TAINT_VERSION,
    StdlibTaintEntry,
    _build_table,
    load_stdlib_taint,
    stdlib_taint_keys,
)


def test_known_entries_present() -> None:
    table = load_stdlib_taint()
    assert table[("json", "loads")].taint == TaintState.GUARDED
    assert table[("builtins", "open")].taint == TaintState.EXTERNAL_RAW
    assert table[("os", "environ.get")].taint == TaintState.EXTERNAL_RAW
    assert table[("ast", "literal_eval")].taint == TaintState.GUARDED


def test_every_entry_has_rationale() -> None:
    for entry in load_stdlib_taint().values():
        assert isinstance(entry, StdlibTaintEntry)
        assert entry.rationale


def test_table_is_immutable() -> None:
    table = load_stdlib_taint()
    with pytest.raises(TypeError):
        table[("x", "y")] = StdlibTaintEntry(TaintState.GUARDED, "x")  # type: ignore[index]


def test_keys_membership() -> None:
    keys = stdlib_taint_keys()
    assert ("json", "loads") in keys
    assert ("definitely", "missing") not in keys


def test_version_mismatch_raises() -> None:
    with pytest.raises(ValueError, match="version mismatch"):
        _build_table({"version": 999, "entries": []})


def test_entries_must_be_a_list() -> None:
    with pytest.raises(ValueError, match="entries"):
        _build_table({"version": STDLIB_TAINT_VERSION, "entries": "nope"})


def test_non_canonical_taint_token_raises() -> None:
    with pytest.raises(ValueError, match="canonical TaintState"):
        _build_table(
            {
                "version": STDLIB_TAINT_VERSION,
                "entries": [
                    {"package": "p", "function": "f", "returns_taint": "BOGUS"}
                ],
            }
        )


def test_valid_build_round_trips() -> None:
    table = _build_table(
        {
            "version": STDLIB_TAINT_VERSION,
            "entries": [
                {
                    "package": "p",
                    "function": "f",
                    "returns_taint": "GUARDED",
                    "rationale": "x",
                }
            ],
        }
    )
    assert table[("p", "f")] == StdlibTaintEntry(TaintState.GUARDED, "x")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_stdlib_taint.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.scanner.taint.stdlib_taint'`

- [ ] **Step 4: Write the implementation** (ported from `.old/scanner/taint/stdlib_taint.py`; the resource path is updated to `wardline.scanner.taint`, and validation is split into a testable `_build_table`)

```python
# src/wardline/scanner/taint/stdlib_taint.py
"""Loader for the bundled stdlib taint fallback table.

Curated ``(package, function) -> returned-value taint`` so common stdlib calls
do not inflate ``UNKNOWN_RAW`` rates. Consumed at call resolution (SP1c/SP1d),
not in L1 seeding. Source data + rationale live in ``stdlib_taint.yaml`` (same
package directory), loaded via ``importlib.resources``.
"""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003  # runtime import for typing reflection
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from types import MappingProxyType
from typing import Any

import yaml

from wardline.core.taints import TaintState

STDLIB_TAINT_VERSION: int = 1
"""Bumped when the table's shape or entries change materially; folded into the
SP1e summary cache key so changes invalidate dependent summaries."""


@dataclass(frozen=True)
class StdlibTaintEntry:
    """A single curated stdlib call's taint assumption."""

    taint: TaintState
    rationale: str


StdlibTaintTable = Mapping[tuple[str, str], StdlibTaintEntry]


def _build_table(raw: Any) -> StdlibTaintTable:
    """Validate parsed YAML into the immutable table.

    Separated from IO so the validation paths are unit-testable without a
    fixture file on disk.
    """
    if not isinstance(raw, dict) or raw.get("version") != STDLIB_TAINT_VERSION:
        got = raw.get("version") if isinstance(raw, dict) else raw
        raise ValueError(
            f"stdlib_taint.yaml version mismatch: expected {STDLIB_TAINT_VERSION}, got {got!r}"
        )
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise ValueError("stdlib_taint.yaml: 'entries' must be a list")

    table: dict[tuple[str, str], StdlibTaintEntry] = {}
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"stdlib_taint.yaml entries[{idx}] must be a mapping")
        package = entry.get("package")
        function = entry.get("function")
        returns_taint_raw = entry.get("returns_taint")
        rationale = entry.get("rationale", "")
        if not isinstance(package, str) or not package:
            raise ValueError(f"stdlib_taint.yaml entries[{idx}].package must be a non-empty string")
        if not isinstance(function, str) or not function:
            raise ValueError(f"stdlib_taint.yaml entries[{idx}].function must be a non-empty string")
        if not isinstance(returns_taint_raw, str):
            raise ValueError(f"stdlib_taint.yaml entries[{idx}].returns_taint must be a string")
        try:
            taint = TaintState(returns_taint_raw)
        except ValueError as exc:
            raise ValueError(
                f"stdlib_taint.yaml entries[{idx}].returns_taint={returns_taint_raw!r} "
                f"is not a canonical TaintState"
            ) from exc
        if not isinstance(rationale, str):
            raise ValueError(f"stdlib_taint.yaml entries[{idx}].rationale must be a string")
        table[(package, function)] = StdlibTaintEntry(taint=taint, rationale=rationale)

    return MappingProxyType(table)


@lru_cache(maxsize=1)
def load_stdlib_taint() -> StdlibTaintTable:
    """Return the bundled ``(package, function) -> StdlibTaintEntry`` table.

    Immutable (``MappingProxyType``) and cached once per process.
    """
    yaml_path = files("wardline.scanner.taint").joinpath("stdlib_taint.yaml")
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    return _build_table(raw)


@lru_cache(maxsize=1)
def stdlib_taint_keys() -> frozenset[tuple[str, str]]:
    """Cached ``(package, function)`` key set over the table."""
    return frozenset(load_stdlib_taint().keys())
```

- [ ] **Step 5: Modify `pyproject.toml` to ship the YAML in the wheel**

Add this block (after the existing `[tool.hatch.build.targets.wheel]` block):

```toml
[tool.hatch.build.targets.wheel.force-include]
"src/wardline/scanner/taint/stdlib_taint.yaml" = "wardline/scanner/taint/stdlib_taint.yaml"
```

- [ ] **Step 6: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_stdlib_taint.py -q`
Expected: PASS

- [ ] **Step 7: Controller commits** (`feat(sp1b): stdlib taint table loader + curated data + wheel packaging`).

---

## Final Gate (controller runs after all tasks)

- [ ] Full suite green: `.venv/bin/python -m pytest -q` (SP0 + SP1a + SP1b; the self-hosting xfail must still xfail).
- [ ] Lint clean: `.venv/bin/python -m ruff check src tests`
- [ ] Types clean: `.venv/bin/python -m mypy src` (strict).
- [ ] **Wheel ships the YAML:** `.venv/bin/python -m build --wheel 2>/dev/null && python -c "import zipfile,glob; w=sorted(glob.glob('dist/*.whl'))[-1]; assert 'wardline/scanner/taint/stdlib_taint.yaml' in zipfile.ZipFile(w).namelist(), 'YAML missing from wheel'; print('YAML present in', w)"` — if `build` is unavailable, instead confirm `importlib.resources.files('wardline.scanner.taint').joinpath('stdlib_taint.yaml').is_file()` is True. (Clean up `dist/`/`build/` artifacts afterward; do not commit them.)
- [ ] Dispatch a final code reviewer over the whole SP1b diff.
- [ ] Use superpowers:finishing-a-development-branch to merge `sp1b-taint-lattice-l1` back to `main`.

---

## Self-Review (controller checklist before execution)

1. **Spec coverage:** SP1 spec §6 SP1b row = "`core/taints.py` (lattice+join) + L1 `function_level` seeding via `TaintSourceProvider` (default provider) + `stdlib_taint`" → Task 1 (lattice+join+rank), Tasks 2-3 (seam + L1 driver), Task 4 (stdlib_taint). Acceptance "join-table tests; L1 seeds correct for fixtures; provider seam documented" → Task 1 exhaustive gate, Task 3 fixtures, Task 2 documented seam. ✓
2. **No placeholders:** every code step shows full code; no TBDs. ✓
3. **Type consistency:** `SeedContext(module)`, `FunctionTaint(body_taint, return_taint)`, `FunctionSeed(qualname, body_taint, return_taint, source)`, `taint_for(entity, ctx) -> FunctionTaint | None`, `seed_function_taints(entities, *, ctx, provider) -> dict[str, FunctionSeed]` consistent across impl + tests. `StdlibTaintEntry(taint, rationale)` consistent. ✓
4. **Contract fidelity / scope guard:** `taint_join` and `least_trusted` ported as DISTINCT operators with the divergence documented and gated; `TRUST_RANK` order matches spec §2 (verified vs `.old` `callgraph.py`); L1 precedence is `provider > UNKNOWN_RAW` with stdlib deliberately NOT wired in; no decorator vocabulary / manifest / anchor_resolver / SARIF labels ported. ✓
5. **Layering:** `core/taints.py` stdlib-only; `scanner/taint/*` may use yaml (scanner extra). `provider.py` imports `Entity` (scanner) so it lives in `scanner/taint`, not `core`. ✓
