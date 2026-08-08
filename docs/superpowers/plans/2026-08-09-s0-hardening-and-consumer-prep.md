# S0 — Hardening + Consumer-First Cross-Product Prep — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Git discipline (non-negotiable):** subagents NEVER run git — no `git add/commit/stash/checkout/restore/reset/diff/status`, nothing. Every "Commit" step is executed by the orchestrator session. Cross-repo tasks (15–18) touch `/home/john/loomweave`, `/home/john/warpline`, `/home/john/legis`: the orchestrator checks `git status` there first and stages ONLY the files this plan names (shared trees — explicit `git add`, never `-A`).

**Goal:** Ship stage S0 of the declaration-surface-v2 program: fix the live false green `wardline-4928b75782` (PY-WL-130 + `WLN-ENGINE-UNKNOWN-MARKER`), land the §4.2 ArgKind registry grammar, close QE prerequisites P1–P13, and stage the consumer-first cross-product prep (loomweave `generic-3` dual-accept, `wardline-attest-3` contract + vectors + verifier/warpline dual-accept, legis tolerance pin) — all before any new marker vocabulary exists.

**Architecture:** Detection rides the existing engine seams: PY-WL-130 is a new rule class mirroring PY-WL-114 (AST + alias maps + the engine's own seeding predicates, promoted to a shared public reader module), so seeds never change and every byte-identity golden stays frozen. The unknown-marker FACT rides the `SeedResult → FunctionSeed → pipeline` channel exactly like `WLN-ENGINE-UNPROVABLE-BOUNDARY`. Cross-product changes are consumer-side only: wardline still emits `wardline-generic-2` and `wardline-attest-2` after S0.

**Tech Stack:** Python 3.12, pytest via `uv run pytest`, ruff, mypy, import-linter. Spec: `docs/superpowers/specs/2026-08-09-declaration-surface-v2-design.md`. Tickets: `wardline-5a795253f1` (S0), `wardline-4928b75782` (bug, closed by Tasks 3–4).

## Global Constraints

- **Zero golden drift.** After every wardline task the full default suite is green with NO regeneration of: `tests/grammar/golden/` (byte oracle over `tests/corpus/fixtures`), `tests/golden/identity/corpus/*.json`, `tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml`, `src/wardline/core/vocabulary.yaml`. New rule ids fire on no existing fixture, so nothing regenerates. If a golden test goes red, the change is wrong — stop and fix the change, never the golden.
- **`REGISTRY_VERSION` stays `"wardline-generic-2"`** (`src/wardline/core/registry.py:22`) and **`ATTEST_SCHEMA` stays `"wardline-attest-2"`** (`src/wardline/core/attest.py:63`) throughout S0. The `generic-3`/`attest-3` bumps are S1, after these consumer-side tasks land.
- **`src/wardline/core/descriptor.py` output is untouched** — new `RegistryEntry` fields are NOT serialised into the vocabulary descriptor in S0.
- **The three shipped markers' signatures are frozen** — no edits to `src/wardline/decorators/` at all.
- New rule id is exactly **`PY-WL-130`**; new FACT id is exactly **`WLN-ENGINE-UNKNOWN-MARKER`** (ids reserved by the spec; next free id after this plan is 131).
- Severity/kind conventions: FACTs are `Severity.NONE` + `Kind.FACT`; PY-WL-130 is `Severity.ERROR` + `Kind.DEFECT`, `maturity=STABLE`, `multi_emit=True`.
- Test commands run from `/home/john/wardline` unless a task names another repo. Full suite = `uv run pytest -q`; targeted runs are given per step.
- Commit messages follow the repo convention `feat(scope):` / `fix(scope):` / `test(scope):` / `docs(scope):`, on branch `release/1.5.0` (wardline). Other repos: current checked-out branch, orchestrator verifies cleanliness first.

## Task dependency order

Task 1 → 2 → 3; Task 2 → 4 → 5. Tasks 6–14 are independent of each other (Task 10 needs Task 3; Task 11–14 independent). Tasks 15–18 are independent of each other and of 1–14. Recommended execution order is numeric.

---

### Task 1: `ArgKind` + `RegistryEntry.kwargs` / `ignored_kwargs` / `arg_kinds` (P14, registry half)

**Files:**
- Modify: `src/wardline/core/registry.py`
- Modify: `src/wardline/scanner/taint/decorator_provider.py:404` (registry-driven `ignored_args`)
- Test: `tests/unit/core/test_registry.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `wardline.core.registry.ArgKind` (StrEnum: `LEVEL`, `TOKEN_SET`, `REF`); `RegistryEntry.kwargs: frozenset[str]`, `RegistryEntry.ignored_kwargs: frozenset[str]`, `RegistryEntry.arg_kinds: Mapping[str, ArgKind]`. Task 3 reads `kwargs | ignored_kwargs` to decide what PY-WL-130 tolerates. S2/S3 will attach `TOKEN_SET`/`REF` readers; S0 only declares the kinds.

- [ ] **Step 1: Write the failing tests** — append to `tests/unit/core/test_registry.py`:

```python
from wardline.core.registry import REGISTRY, ArgKind


def test_registry_declares_marker_kwargs() -> None:
    assert REGISTRY["external_boundary"].kwargs == frozenset()
    assert REGISTRY["trust_boundary"].kwargs == frozenset({"to_level"})
    assert REGISTRY["trusted"].kwargs == frozenset({"level"})
    # Legacy-inert compat kwarg the provider tolerates without reading
    # (decorator_provider._match) — declared HERE so PY-WL-130 and the
    # provider share one source of truth.
    assert REGISTRY["trusted"].ignored_kwargs == frozenset({"to_level"})
    assert REGISTRY["external_boundary"].ignored_kwargs == frozenset()
    assert REGISTRY["trust_boundary"].ignored_kwargs == frozenset()


def test_registry_arg_kinds_cover_the_level_args() -> None:
    assert dict(REGISTRY["trusted"].arg_kinds) == {"level": ArgKind.LEVEL}
    assert dict(REGISTRY["trust_boundary"].arg_kinds) == {"to_level": ArgKind.LEVEL}
    assert dict(REGISTRY["external_boundary"].arg_kinds) == {}


def test_registry_kwarg_invariants() -> None:
    for entry in REGISTRY.values():
        assert set(entry.arg_kinds) <= entry.kwargs, entry.canonical_name
        assert entry.kwargs.isdisjoint(entry.ignored_kwargs), entry.canonical_name


def test_registry_arg_kinds_are_immutable() -> None:
    import pytest

    with pytest.raises(TypeError):
        REGISTRY["trusted"].arg_kinds["level"] = ArgKind.REF  # type: ignore[index]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/core/test_registry.py -v`
Expected: FAIL — `ImportError: cannot import name 'ArgKind'`.

- [ ] **Step 3: Implement in `src/wardline/core/registry.py`.** Add `from enum import StrEnum` and `field` to the dataclass import. Insert after `REGISTRY_VERSION`:

```python
class ArgKind(StrEnum):
    """The marker-argument grammar (declaration-surface-v2 §4.2, P14).

    Declares how the engine READS each keyword argument of a registered marker.
    S0 ships only ``LEVEL`` consumers; ``TOKEN_SET`` (tuples of value tokens,
    e.g. ``evidence=``/``marks=``) and ``REF`` (module-level declaration
    references, e.g. ``contract=``) get their readers in S2/S3. Every kind is
    fail-closed on any deviation from its form.
    """

    LEVEL = "level"
    TOKEN_SET = "token_set"
    REF = "ref"
```

Replace `RegistryEntry` with:

```python
@dataclass(frozen=True)
class RegistryEntry:
    """A registered trust decorator and its expected ``_wardline_*`` attributes.

    ``attrs`` maps each stamped attribute name to its expected value *type*.
    ``kwargs`` is the declared keyword set the marker's call form accepts;
    ``ignored_kwargs`` are legacy-inert keywords the engine tolerates without
    reading (never new vocabulary — compat only); ``arg_kinds`` maps declared
    keywords to their :class:`ArgKind` reading discipline. All mappings are
    wrapped in ``MappingProxyType`` at construction for deep immutability.
    """

    canonical_name: str
    group: int
    attrs: Mapping[str, type]
    kwargs: frozenset[str] = frozenset()
    ignored_kwargs: frozenset[str] = frozenset()
    arg_kinds: Mapping[str, ArgKind] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))
        object.__setattr__(self, "arg_kinds", MappingProxyType(dict(self.arg_kinds)))
        if not set(self.arg_kinds) <= self.kwargs:
            raise ValueError(f"{self.canonical_name}: arg_kinds keys must be declared in kwargs")
        if not self.kwargs.isdisjoint(self.ignored_kwargs):
            raise ValueError(f"{self.canonical_name}: kwargs and ignored_kwargs overlap")
```

Update `_ENTRIES`:

```python
_ENTRIES: dict[str, RegistryEntry] = {
    "external_boundary": RegistryEntry(canonical_name="external_boundary", group=1, attrs={}),
    "trust_boundary": RegistryEntry(
        canonical_name="trust_boundary",
        group=1,
        attrs={"_wardline_to_level": TaintState},
        kwargs=frozenset({"to_level"}),
        arg_kinds={"to_level": ArgKind.LEVEL},
    ),
    "trusted": RegistryEntry(
        canonical_name="trusted",
        group=1,
        attrs={"_wardline_level": TaintState},
        kwargs=frozenset({"level"}),
        ignored_kwargs=frozenset({"to_level"}),
        arg_kinds={"level": ArgKind.LEVEL},
    ),
}
```

- [ ] **Step 4: Make the provider registry-driven.** In `src/wardline/scanner/taint/decorator_provider.py` `_match` (line 399–412), replace:

```python
                # Legacy review fixtures and older sample code sometimes supplied
                # ``to_level`` on ``@trusted``. Treat it as inert compatibility
                # only when the real ``level`` argument remains statically readable;
                # genuinely unknown kwargs still fail closed.
                ignored = frozenset({"to_level"}) if bt.canonical_name == "trusted" else frozenset()
```

with:

```python
                # Legacy-inert compat kwargs come from the registry (one source of
                # truth with PY-WL-130): tolerated only when the real level args
                # stay statically readable; genuinely unknown kwargs fail closed.
                entry = REGISTRY.get(bt.canonical_name)
                ignored = entry.ignored_kwargs if entry is not None else frozenset()
```

(`REGISTRY` is already imported at line 19.)

- [ ] **Step 5: Run tests to verify they pass, and prove zero drift**

Run: `uv run pytest tests/unit/core/test_registry.py tests/unit/core/test_descriptor.py tests/unit/scanner/taint/test_decorator_provider.py tests/unit/scanner/taint/test_review_fixups_engine.py tests/grammar tests/conformance/test_vocabulary_descriptor_wire_golden.py -q`
Expected: all PASS. `test_committed_vocabulary_yaml_matches_registry` proves the descriptor bytes did not move.

- [ ] **Step 6: Commit** — `feat(registry): ArgKind grammar + declared/ignored kwarg sets on RegistryEntry (S0, P14)`

---

### Task 2: Shared marker-reader engine-floor module (P9)

**Files:**
- Create: `src/wardline/scanner/marker_reader.py`
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (delete moved functions, import instead)
- Modify: `src/wardline/scanner/rules/invalid_decorator_level.py` (drop the loose local reader)
- Test: `tests/unit/scanner/test_marker_reader_agreement.py` (new)

**Interfaces:**
- Consumes: `BUILTIN_BOUNDARY_TYPES` from `wardline.scanner.boundary_types`, `TaintState` from `wardline.core.taints`, `REGISTRY` from `wardline.core.registry`.
- Produces (all public, exact signatures — Tasks 3 and 4 import these):
  - `dotted_name(node: ast.expr) -> str | None`
  - `resolve_dotted_fqn(node: ast.expr, alias_map: Mapping[str, str]) -> str | None`
  - `resolve_decorator_fqn(deco: ast.expr, alias_map: Mapping[str, str]) -> str | None`
  - `level_token(value: ast.expr, alias_map: Mapping[str, str]) -> str | None`
  - `read_level(deco, arg, *, allowed, default, alias_map, ignored_args=frozenset()) -> TaintState | None`
  - `is_builtin_decorator_fqn(fqn: str, canonical_name: str, module_prefix: str) -> bool`
  - `shadowed_builtin_roots(project_modules: frozenset[str]) -> frozenset[str]`
  - Constants `VOCAB_PREFIX = "wardline.decorators"`, `WEFT_MARKERS_PREFIX = "weft_markers"`, `BUILTIN_MARKER_ROOTS`

- [ ] **Step 1: Create `src/wardline/scanner/marker_reader.py`.** Move (verbatim bodies, public names, docstrings intact) these from `decorator_provider.py`: `_dotted_name`, `_resolve_dotted_fqn`, `_resolve_decorator_fqn`, `_level_token`, `_read_level`, `_is_builtin_decorator_fqn`, `_shadowed_builtin_roots`, and the constants `_VOCAB_PREFIX`/`_WEFT_MARKERS_PREFIX`/`_TAINTSTATE_FQN`/`_BUILTIN_MARKER_ROOTS` (public: `VOCAB_PREFIX`, `WEFT_MARKERS_PREFIX`, `_TAINTSTATE_FQN` may stay private, `BUILTIN_MARKER_ROOTS`). Module docstring:

```python
# src/wardline/scanner/marker_reader.py
"""The ONE marker-reading grammar (engine floor, declaration-surface-v2 P9).

Every consumer of a trust-marker AST — the L1 seeding provider AND every
validation rule (PY-WL-114, PY-WL-130, the S2+ declaration validators) — reads
through these primitives, so a rule can never recognise or read a marker
differently than seeding does (the recogniser-agreement property,
wardline-09c09f14df). Fail-closed everywhere: an unreadable value is ``None``,
never a guess.

Imports only ``boundary_types`` + ``core`` (the same acyclic-floor rule that
module documents): rules and the provider both import THIS, neither reaches
into the other.
"""
```

- [ ] **Step 2: Rewire `decorator_provider.py`.** Delete the moved definitions; add:

```python
from wardline.scanner.marker_reader import (
    BUILTIN_MARKER_ROOTS as _BUILTIN_MARKER_ROOTS,
    is_builtin_decorator_fqn as _is_builtin_decorator_fqn,
    level_token as _level_token,
    read_level as _read_level,
    resolve_decorator_fqn as _resolve_decorator_fqn,
    resolve_dotted_fqn as _resolve_dotted_fqn,
    shadowed_builtin_roots as _shadowed_builtin_roots,
)
```

Keep `vocabulary_star_exports`, the fingerprint/identity helpers, and the provider class in place (only the reading primitives move). Keep the module-level `_VOCAB_PREFIX`/`_WEFT_MARKERS_PREFIX` constants as re-imports (`from wardline.scanner.marker_reader import VOCAB_PREFIX as _VOCAB_PREFIX, ...`) — `vocabulary_star_exports` uses them.

- [ ] **Step 3: Unify PY-WL-114 onto the shared reader.** In `src/wardline/scanner/rules/invalid_decorator_level.py`: delete the local `_dotted_name` (:63-70), `_level_token` (:73-81), `_resolve_decorator_fqn` (:84-94). Replace the import at line 20 with:

```python
from wardline.scanner.marker_reader import (
    is_builtin_decorator_fqn as _is_builtin_decorator_fqn,
    level_token as _level_token,
    resolve_decorator_fqn as _resolve_decorator_fqn,
    shadowed_builtin_roots as _shadowed_builtin_roots,
)
```

At the call site (line 162) pass the alias map: `token = _level_token(kw.value, alias_map)`. **Behaviour delta (deliberate, pin it):** the old loose reader accepted any `*.TaintState.X` attribute without alias resolution; the shared strict reader accepts only a receiver that alias-resolves to `wardline.core.taints.TaintState`. A typo'd level behind a RE-EXPORTED `TaintState` now reads as unreadable → PY-WL-114 goes silent there, exactly as the provider's seeding does (one reader, one verdict). Append to `METADATA.examples_clean`:

```python
        # A TaintState reached through a re-export is not the reader's exact known
        # export — unreadable for seeding AND for this rule (shared reader, P9).
        "from myapp.shim import TaintState\n@trusted(level=TaintState.ASURED)\ndef f(p):\n    return p",
```

- [ ] **Step 4: Write the agreement tests** — `tests/unit/scanner/test_marker_reader_agreement.py`:

```python
"""P9 — one marker-reading grammar: the rule-side reader IS the provider-side reader."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from wardline.core.run import run_scan
from wardline.scanner.marker_reader import level_token

CASES = [
    ("'ASSURED'", {}, "ASSURED"),
    ("TaintState.ASSURED", {"TaintState": "wardline.core.taints.TaintState"}, "ASSURED"),
    ("taints.TaintState.ASSURED", {"taints": "wardline.core.taints"}, "ASSURED"),
    # Re-exported TaintState: NOT the exact known export — unreadable (fail-closed).
    ("shim.TaintState.ASSURED", {"shim": "myapp.shim"}, None),
    ("LEVEL", {}, None),
    ("get_level()", {}, None),
    ("f'{x}'", {}, None),
    ("cfg.ASSURED", {"cfg": "myapp.cfg"}, None),
]


@pytest.mark.parametrize(("expr", "alias_map", "expected"), CASES)
def test_level_token_is_the_single_reader(expr: str, alias_map: dict, expected: str | None) -> None:
    value = ast.parse(expr, mode="eval").body
    assert level_token(value, alias_map) == expected


def test_rule_and_provider_agree_on_reexported_taintstate(tmp_path: Path) -> None:
    # A typo'd level behind a re-export: the provider cannot read it (no seed) and
    # PY-WL-114 must not claim to have read it either — consistent silence, pinned.
    src = (
        "from myapp.shim import TaintState\n"
        "from wardline.decorators import trusted\n"
        "@trusted(level=TaintState.ASURED)\n"
        "def f(p):\n"
        "    return p\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    result = run_scan(proj)
    assert not [f for f in result.findings if f.rule_id == "PY-WL-114"]
    ctx = result.context
    assert ctx is not None
    assert "svc.f" not in ctx.declared_qualnames  # provider dropped the seed too
```

- [ ] **Step 5: Run the affected suites**

Run: `uv run pytest tests/unit/scanner/test_marker_reader_agreement.py tests/unit/scanner/rules/test_invalid_decorator_level.py tests/unit/scanner/rules/test_invalid_decorator_level_recognizer.py tests/unit/scanner/taint/test_decorator_provider.py tests/grammar -q && uv run lint-imports`
Expected: PASS (fix any test that imported the moved privates from `decorator_provider` by pointing it at `marker_reader` — `grep -rn "from wardline.scanner.taint.decorator_provider import" tests/ src/` and update each hit). `lint-imports` proves the layering contracts still hold.

- [ ] **Step 6: Run the full suite** — `uv run pytest -q`. Expected: PASS, zero golden drift.

- [ ] **Step 7: Commit** — `refactor(scanner): promote the marker-reading grammar to a shared engine-floor module (S0, P9)`

---

### Task 3: PY-WL-130 — malformed builtin-marker call (the false-green fix, rule half)

**Files:**
- Create: `src/wardline/scanner/rules/malformed_marker_call.py`
- Modify: `src/wardline/scanner/rules/__init__.py` (register; append to `_ALL_RULE_CLASSES`)
- Test: `tests/unit/scanner/rules/test_malformed_marker_call.py` (new)

**Interfaces:**
- Consumes: `REGISTRY` + `RegistryEntry.kwargs`/`.ignored_kwargs` (Task 1); `resolve_decorator_fqn`, `is_builtin_decorator_fqn`, `shadowed_builtin_roots` (Task 2); `BUILTIN_BOUNDARY_TYPES`; `RuleMetadata`; `Finding`/`compute_finding_fingerprint`.
- Produces: rule class `MalformedMarkerCall` with `rule_id = "PY-WL-130"`, `metadata`, `check(context) -> list[Finding]`. Findings carry `properties={"decorator": name, "offender": <kwarg or "<positional>" or "<**splat>">, "reason": <"undeclared_kwarg"|"positional_args"|"unreadable_splat">}` and fingerprint `taint_path=f"{name}:{offender}#{deco_ordinal}.{offence_ordinal}"`.

- [ ] **Step 1: Write the failing tests** — `tests/unit/scanner/rules/test_malformed_marker_call.py`:

```python
"""PY-WL-130 — a malformed builtin-marker call must be a loud ERROR DEFECT.

The engine silently drops the seed for these shapes (wardline-4928b75782): the
function falls out of declared_qualnames and every tier-modulated rule goes
quiet — the scan gets GREENER on a typo. This suite pins the rule that makes
that shape red, and pins where it must stay silent (well-formed calls, the
legacy ignored kwarg, foreign/custom/shadowed markers).
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan


def _scan(tmp_path: Path, src: str):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    return run_scan(proj)


def _hits(result, rule_id: str = "PY-WL-130"):
    return [f for f in result.findings if f.rule_id == rule_id]


def test_undeclared_kwarg_on_trusted_fires_error(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.severity is Severity.ERROR
    assert hit.kind is Kind.DEFECT
    assert hit.properties["decorator"] == "trusted"
    assert hit.properties["offender"] == "audit"
    assert hit.properties["reason"] == "undeclared_kwarg"
    # The seed is still dropped (rule observes, never repairs) — the function
    # is undeclared AND the defect is loud: no more false green.
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_positional_arg_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted('INTEGRAL')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties["reason"] == "positional_args"


def test_external_boundary_kwarg_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import external_boundary\n"
        "@external_boundary(source='http')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "external_boundary", "offender": "source", "reason": "undeclared_kwarg"}


def test_aliased_builtin_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted as t\n"
        "@t(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert len(_hits(result)) == 1


def test_legacy_to_level_on_trusted_is_tolerated(tmp_path: Path) -> None:
    # The provider seeds this shape (registry ignored_kwargs) — the rule shares
    # that tolerance: fire exactly where the seed drops, nowhere else.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', to_level='ASSURED')\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert not _hits(result)
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames


def test_foreign_and_custom_markers_are_not_this_rules_concern(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import other_pkg\n"
        "@other_pkg.trusted(level='X', extra=1)\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert not _hits(result)


def test_shadowed_root_stays_silent(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "wardline" / "decorators").mkdir(parents=True)
    (proj / "wardline" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "wardline" / "decorators" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert not _hits(result)


def test_stacked_malformed_markers_get_distinct_fingerprints(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted, external_boundary\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "@external_boundary(source='http')\n"
        "def f(p):\n"
        "    return p\n",
    )
    hits = _hits(result)
    assert len(hits) == 2
    assert len({h.fingerprint for h in hits}) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/rules/test_malformed_marker_call.py -v`
Expected: FAIL — no `PY-WL-130` findings (rule doesn't exist).

- [ ] **Step 3: Implement `src/wardline/scanner/rules/malformed_marker_call.py`:**

```python
# src/wardline/scanner/rules/malformed_marker_call.py
"""PY-WL-130 — builtin trust marker called with a malformed argument shape.

A builtin marker call carrying an undeclared keyword or any positional argument
is silently UN-DECLARED by the engine: ``read_level`` fails closed, the seed
drops, the function falls out of ``declared_qualnames``, and every
tier-modulated rule goes quiet (wardline-4928b75782). The scan gets GREENER
with no diagnostic — the version-skew false green (new weft-markers kwargs, old
wardline). This rule makes that shape a loud ERROR DEFECT.

Deliberately NOT silenced by the builtin-stays-quiet convention: that
convention preserves the byte-identity oracle, and a NEW rule id appears in no
frozen golden, so emitting it cannot drift a pinned stream. Recognition and
tolerance use the engine's own predicates (shared reader P9; registry
``kwargs``/``ignored_kwargs``) so the rule fires exactly where the seed drops —
the legacy ``to_level=`` on ``@trusted`` the provider tolerates is tolerated
here too.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.registry import REGISTRY
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES
from wardline.scanner.marker_reader import (
    is_builtin_decorator_fqn,
    resolve_decorator_fqn,
    shadowed_builtin_roots,
)
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-130",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "A builtin trust marker (@external_boundary/@trust_boundary/@trusted) is "
        "called with a positional argument or an undeclared keyword; the engine "
        "silently drops the declaration, disabling every tier-modulated rule on "
        "the function."
    ),
    examples_violation=(
        "@trusted(level='INTEGRAL', audit=True)\ndef f(p):\n    return p",
        "@trusted('INTEGRAL')\ndef g(p):\n    return p",
        "@trust_boundary(to_level='ASSURED', reason='api')\ndef h(p):\n    if not p: raise ValueError\n    return p",
        "@external_boundary(source='http')\ndef r(p):\n    return p",
    ),
    examples_clean=(
        "@trusted(level='INTEGRAL')\ndef f(p):\n    return p",
        "@trusted\ndef g(p):\n    return p",
        # Legacy-inert compat kwarg the provider tolerates (registry ignored_kwargs)
        "@trusted(level='ASSURED', to_level='ASSURED')\ndef legacy(p):\n    return p",
        # A foreign decorator merely spelled like a marker is not the builtin
        "import other_pkg\n@other_pkg.trusted(level='X', extra=1)\ndef f(p):\n    return p",
    ),
)


def _builtin_marker(deco: ast.expr, alias_map: Mapping[str, str], shadowed_roots: frozenset[str]) -> str | None:
    """The canonical name iff *deco* resolves to a builtin marker seeding would honour."""
    fqn = resolve_decorator_fqn(deco, alias_map)
    if fqn is None:
        return None
    for bt in BUILTIN_BOUNDARY_TYPES:
        if not bt.builtin:
            continue
        if bt.module_prefix.split(".")[0] in shadowed_roots:
            continue
        if is_builtin_decorator_fqn(fqn, bt.canonical_name, bt.module_prefix):
            return bt.canonical_name
    return None


def _offences(deco: ast.Call, declared: frozenset[str]) -> list[tuple[str, str]]:
    """Every (offender, reason) pair in one marker call, in source order."""
    out: list[tuple[str, str]] = []
    if deco.args:
        out.append(("<positional>", "positional_args"))
    for kw in deco.keywords:
        if kw.arg is None:
            if not isinstance(kw.value, ast.Dict):
                out.append(("<**splat>", "unreadable_splat"))
                continue
            for key in kw.value.keys:
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    out.append(("<**splat>", "unreadable_splat"))
                elif key.value not in declared:
                    out.append((key.value, "undeclared_kwarg"))
            continue
        if kw.arg not in declared:
            out.append((kw.arg, "undeclared_kwarg"))
    return out


class MalformedMarkerCall:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        modules = list(context.alias_maps.keys())
        shadowed = shadowed_builtin_roots(frozenset(modules))
        for qualname, entity in context.entities.items():
            mod_name = next(
                (m for m in sorted(modules, key=len, reverse=True) if qualname == m or qualname.startswith(m + ".")),
                None,
            )
            alias_map = (context.alias_maps.get(mod_name) if mod_name is not None else None) or {}
            for deco_ordinal, deco in enumerate(entity.node.decorator_list):
                if not isinstance(deco, ast.Call):
                    continue
                name = _builtin_marker(deco, alias_map, shadowed)
                if name is None:
                    continue
                entry = REGISTRY[name]
                declared = entry.kwargs | entry.ignored_kwargs
                for offence_ordinal, (offender, reason) in enumerate(_offences(deco, declared)):
                    detail = {
                        "positional_args": "a positional argument",
                        "undeclared_kwarg": f"undeclared keyword {offender!r}",
                        "unreadable_splat": "an unreadable ** splat",
                    }[reason]
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            message=(
                                f"{qualname}: builtin marker @{name} called with {detail} — "
                                f"the engine silently drops this declaration (no seed; every "
                                f"tier-modulated rule is disabled on this function)"
                            ),
                            severity=self.base_severity,
                            kind=Kind.DEFECT,
                            location=entity.location,
                            fingerprint=_fp(
                                rule_id=self.rule_id,
                                path=entity.location.path,
                                qualname=qualname,
                                # Same discriminator discipline as PY-WL-114 (wardline-377b896a87):
                                # position must come entirely from within-def ordinals (move-stable).
                                # offence_ordinal disambiguates two ** splats carrying the same key.
                                taint_path=f"{name}:{offender}#{deco_ordinal}.{offence_ordinal}",
                            ),
                            taint_path_v0=f"{name}:{offender}#{deco_ordinal}.{offence_ordinal}",
                            qualname=qualname,
                            properties={"decorator": name, "offender": offender, "reason": reason},
                        )
                    )
        return findings
```

- [ ] **Step 4: Register the rule.** In `src/wardline/scanner/rules/__init__.py`: add `from wardline.scanner.rules.malformed_marker_call import MalformedMarkerCall` alongside the sibling imports, and append `MalformedMarkerCall,` as the LAST entry of `_ALL_RULE_CLASSES` (registration order = emission order — appending preserves every frozen ordering).

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/scanner/rules/test_malformed_marker_call.py -v`
Expected: PASS.

- [ ] **Step 6: Prove zero drift + waiver/corpus interaction**

Run: `uv run pytest tests/grammar tests/corpus tests/golden -q`
Expected: PASS untouched — no existing fixture carries a malformed marker call, so the byte oracle, identity corpus, FP reconciliation, and determinism stream are all unchanged. (`tests/corpus/test_waiver_discipline.py` still passes: the ceiling is rule-count until Task 12.)

- [ ] **Step 7: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 8: Commit** — `feat(rules): PY-WL-130 malformed builtin-marker call is a loud ERROR (fixes wardline-4928b75782 rule half)`

---

### Task 4: `WLN-ENGINE-UNKNOWN-MARKER` FACT (the false-green fix, observability half; P11)

**Files:**
- Modify: `src/wardline/scanner/marker_reader.py` (add `unknown_vocabulary_marker`)
- Modify: `src/wardline/scanner/taint/provider.py:55-73` (`SeedResult.unknown_markers`)
- Modify: `src/wardline/scanner/taint/decorator_provider.py:306-335` (`taint_for` collects unknowns)
- Modify: `src/wardline/scanner/taint/function_level.py:26-76` (`FunctionSeed.unknown_markers` + threading)
- Modify: `src/wardline/scanner/pipeline.py:261-280` (FACT emission after the UNPROVABLE-BOUNDARY loop)
- Test: `tests/grammar/test_unknown_marker.py` (new)

**Interfaces:**
- Consumes: Task 2's `resolve_decorator_fqn`/`is_builtin_decorator_fqn`; `REGISTRY`.
- Produces: `marker_reader.unknown_vocabulary_marker(deco, alias_map, shadowed_roots) -> str | None`; `SeedResult.unknown_markers: tuple[str, ...] = ()`; `FunctionSeed.unknown_markers: tuple[str, ...] = ()`; findings `rule_id="WLN-ENGINE-UNKNOWN-MARKER"`, `Severity.NONE`, `Kind.FACT`, `properties={"marker": <fqn>, "reason": "unrecognised_vocabulary"}`. Task 5 counts these by rule_id.

- [ ] **Step 1: Write the failing tests** — `tests/grammar/test_unknown_marker.py`:

```python
"""WLN-ENGINE-UNKNOWN-MARKER — new-markers-old-wardline is observable, never a crash.

P11 (cross-version conformance): a decorator rooted in the Wardline vocabulary
(``wardline.decorators`` / ``weft_markers``) that THIS engine does not recognise
takes no opinion (fail-closed UNKNOWN_RAW fallback), never crashes, and leaves a
FACT — so an app that upgrades weft-markers ahead of wardline sees WHY its new
declarations are inert instead of a silently greener scan.
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan

FACT_ID = "WLN-ENGINE-UNKNOWN-MARKER"


def _scan(tmp_path: Path, src: str):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    return run_scan(proj)


def _facts(result):
    return [f for f in result.findings if f.rule_id == FACT_ID]


def test_unknown_marker_is_no_opinion_never_a_crash(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import weft_markers\n"
        "@weft_markers.audit_record\n"
        "def write_event(e):\n"
        "    return e\n",
    )
    (fact,) = _facts(result)
    assert fact.severity is Severity.NONE
    assert fact.kind is Kind.FACT
    assert fact.properties == {"marker": "weft_markers.audit_record", "reason": "unrecognised_vocabulary"}
    # No opinion: the function seeds default (fail-closed), not provider.
    assert result.context is not None
    assert "svc.write_event" not in result.context.declared_qualnames
    # And no DEFECT was invented for it.
    assert not [f for f in result.findings if f.kind is Kind.DEFECT]


def test_from_import_form_is_detected(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from weft_markers import audit_record\n"
        "@audit_record\n"
        "def write_event(e):\n"
        "    return e\n",
    )
    (fact,) = _facts(result)
    assert fact.properties["marker"] == "weft_markers.audit_record"


def test_nested_vocabulary_path_is_observable(tmp_path: Path) -> None:
    # ``wardline.decorators.evil.trusted`` is seeded by nothing (exact-export
    # rule) — previously invisible; now the FACT names it.
    result = _scan(
        tmp_path,
        "import wardline.decorators.evil\n"
        "@wardline.decorators.evil.trusted(level='INTEGRAL')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (fact,) = _facts(result)
    assert fact.properties["marker"] == "wardline.decorators.evil.trusted"


def test_known_marker_malformed_call_is_not_unknown(tmp_path: Path) -> None:
    # A recognised export with a malformed CALL is PY-WL-130's DEFECT, not this FACT.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert not _facts(result)
    assert [f for f in result.findings if f.rule_id == "PY-WL-130"]


def test_shadowed_root_emits_no_fact(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "weft_markers").mkdir(parents=True)
    (proj / "weft_markers" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        "import weft_markers\n@weft_markers.audit_record\ndef f(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert not _facts(result)


def test_foreign_decorator_emits_no_fact(tmp_path: Path) -> None:
    result = _scan(tmp_path, "import functools\n@functools.cache\ndef f(p):\n    return p\n")
    assert not _facts(result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/grammar/test_unknown_marker.py -v`
Expected: FAIL — no FACT emitted.

- [ ] **Step 3: Add the detector to `marker_reader.py`:**

```python
_VOCAB_PREFIXES: tuple[str, ...] = (VOCAB_PREFIX, WEFT_MARKERS_PREFIX)


def unknown_vocabulary_marker(
    deco: ast.expr,
    alias_map: Mapping[str, str],
    shadowed_roots: frozenset[str],
) -> str | None:
    """The resolved FQN iff *deco* is vocabulary-rooted but not a recognised export.

    Vocabulary-rooted = the FQN sits strictly under ``wardline.decorators`` or
    ``weft_markers``. Exact known exports (the REGISTRY names) are excluded —
    those are recognised markers whose malformed CALLS are PY-WL-130's concern.
    Shadow-rejected roots are excluded (builtin matching is off wholesale under
    a shadow, and the shadow has its own diagnostics). This is the
    new-markers-old-wardline observability hook (WLN-ENGINE-UNKNOWN-MARKER):
    ``@weft_markers.audit_record`` on a wardline that predates facets resolves
    here instead of vanishing. Known FN, by design: a name arriving via
    ``from weft_markers import *`` that is NOT a current REGISTRY key stays
    unresolved in the alias map (``vocabulary_star_exports`` maps only known
    names) and cannot be attributed to the vocabulary.
    """
    fqn = resolve_decorator_fqn(deco, alias_map)
    if fqn is None:
        return None
    if fqn.split(".")[0] in shadowed_roots:
        return None
    if not any(fqn.startswith(prefix + ".") for prefix in _VOCAB_PREFIXES):
        return None
    for name in REGISTRY:
        for prefix in _VOCAB_PREFIXES:
            if is_builtin_decorator_fqn(fqn, name, prefix):
                return None
    return fqn
```

(Add `from wardline.core.registry import REGISTRY` to `marker_reader.py` imports.)

- [ ] **Step 4: Thread the channel.**
  1. `provider.py` — add to `SeedResult` after `unprovable_boundaries` (and extend the docstring with one sentence: "``unknown_markers`` carries the resolved FQNs of vocabulary-rooted decorators this engine does not recognise — surfaced as ``WLN-ENGINE-UNKNOWN-MARKER`` FACTs."):

```python
    unknown_markers: tuple[str, ...] = ()
```

  2. `decorator_provider.py` `taint_for` — collect unknowns in the decorator loop and carry them out on BOTH return paths:

```python
    def taint_for(self, entity: Entity, ctx: SeedContext) -> SeedResult:
        candidates: list[FunctionTaint] = []
        unprovable: list[str] = []
        unknown: list[str] = []
        shadowed_roots = _shadowed_builtin_roots(ctx.project_modules)
        for deco in entity.node.decorator_list:
            ft, unprov = self._match(deco, ctx.alias_map, shadowed_roots)
            if ft is not None:
                candidates.append(ft)
            elif unprov is not None:
                unprovable.append(unprov)
            else:
                marker = unknown_vocabulary_marker(deco, ctx.alias_map, shadowed_roots)
                if marker is not None:
                    unknown.append(marker)
```

     …and add `unknown_markers=tuple(unknown)` to both `SeedResult(...)` constructions (lines 320 and 335). Import `unknown_vocabulary_marker` from `marker_reader`.
  3. `function_level.py` — add `unknown_markers: tuple[str, ...] = ()` to `FunctionSeed` (docstring: same sentence as SeedResult) and `unknown_markers=res.unknown_markers,` to both `FunctionSeed(...)` constructions in `seed_function_taints`.
  4. `pipeline.py` — directly after the `unprovable_boundaries` loop (after line 280), same indent:

```python
            for marker in fn_seed.unknown_markers:
                parse_findings.append(
                    Finding(
                        rule_id="WLN-ENGINE-UNKNOWN-MARKER",
                        message=(
                            f"{ent.qualname}: decorator @{marker} is Wardline vocabulary this "
                            f"engine does not recognise — no opinion taken (newer weft-markers "
                            f"than wardline?)"
                        ),
                        severity=Severity.NONE,
                        kind=Kind.FACT,
                        location=ent.location,
                        fingerprint=_fp("WLN-ENGINE-UNKNOWN-MARKER", ent.qualname, marker),
                        qualname=ent.qualname,
                        properties={"marker": marker, "reason": "unrecognised_vocabulary"},
                    )
                )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/grammar/test_unknown_marker.py tests/grammar -q`
Expected: PASS, including the byte oracle and determinism guard (no fixture carries an unknown marker; FACTs are excluded from the identity corpus by construction).

- [ ] **Step 6: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 7: Commit** — `feat(engine): WLN-ENGINE-UNKNOWN-MARKER FACT makes unrecognised vocabulary observable (wardline-4928b75782 observability half, P11)`

---

### Task 5: `decorator_coverage` surfaces the unknown-marker count

**Files:**
- Modify: `src/wardline/core/decorator_coverage.py:116-136,204-241`
- Modify: `src/wardline/mcp/server.py:3185-3193` (`_DECORATOR_COVERAGE_OUTPUT_SCHEMA` summary block)
- Modify: `src/wardline/cli/decorator_coverage.py:72-81` (`_render_human`)
- Test: `tests/unit/core/test_decorator_coverage.py` (extend), `tests/unit/mcp/` decorator-coverage test (extend), `tests/unit/cli/` decorator-coverage test (extend — locate each with `grep -rln "decorator_coverage" tests/unit/`)

**Interfaces:**
- Consumes: Task 4's FACT id (matched by `rule_id == "WLN-ENGINE-UNKNOWN-MARKER"` over `result.findings`).
- Produces: `DecoratorCoverageReport.unknown_marker_count: int = 0`; summary dict gains key `"unknown_markers"` (now six keys: `total, clean, defect, unknown, suppressed, unknown_markers`).

- [ ] **Step 1: Write the failing test** (in the existing core decorator-coverage test module):

```python
def test_summary_counts_unknown_markers(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "import weft_markers\n"
        "from wardline.decorators import trusted\n"
        "@weft_markers.audit_record\n"
        "def new_style(e):\n"
        "    return e\n"
        "@trusted\n"
        "def declared(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    report = build_decorator_coverage(proj)
    assert report.summary["unknown_markers"] == 1
    # Rows are still provider-seeded entities only — the unknown-marker entity
    # has no row; the count is the side-channel that says WHY.
    assert report.summary["total"] == 1
```

- [ ] **Step 2: Run to verify it fails** — `uv run pytest tests/unit/core/test_decorator_coverage.py -v`. Expected: FAIL (`KeyError: 'unknown_markers'`).

- [ ] **Step 3: Implement.**
  1. `core/decorator_coverage.py` — `DecoratorCoverageReport` gains a field and the summary gains a key:

```python
@dataclass(frozen=True, slots=True)
class DecoratorCoverageReport:
    rows: list[DecoratorCoverageRow]
    unknown_marker_count: int = 0

    @property
    def summary(self) -> dict[str, int]:
        total = len(self.rows)
        clean = sum(1 for row in self.rows if row.finding_state == "clean")
        defect = sum(1 for row in self.rows if row.finding_state == "defect")
        unknown = sum(1 for row in self.rows if row.finding_state == "unknown")
        suppressed = sum(1 for row in self.rows if row.finding_state == "suppressed")
        return {
            "total": total,
            "clean": clean,
            "defect": defect,
            "unknown": unknown,
            "suppressed": suppressed,
            "unknown_markers": self.unknown_marker_count,
        }
```

  2. `decorator_coverage_from_scan` (end of function):

```python
    unknown_marker_count = sum(1 for f in result.findings if f.rule_id == "WLN-ENGINE-UNKNOWN-MARKER")
    return DecoratorCoverageReport(rows=rows, unknown_marker_count=unknown_marker_count)
```

  3. `mcp/server.py` `_DECORATOR_COVERAGE_OUTPUT_SCHEMA` summary block: add `"unknown_markers": {"type": "integer"}` to `properties` and `"unknown_markers"` to `required` (the block is `additionalProperties: False` — without this edit the tool's output-schema validation rejects the new key).
  4. `cli/decorator_coverage.py` `_render_human`: extend the summary line to print `unknown_markers=<n>` after `suppressed`, reading `summary["unknown_markers"]`.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/unit/core/test_decorator_coverage.py tests/unit/mcp -k coverage tests/unit/cli -k coverage -q` then fix any exact-summary-dict assertions the new key breaks (update them to include `unknown_markers`).

- [ ] **Step 5: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 6: Commit** — `feat(coverage): decorator_coverage surfaces the unrecognised-vocabulary count (S0)`

---

### Task 6: Corpus harness — manifest `maturity`/`kind`/`interaction` + preview reconciliation + per-kind FP gate (P1, P2, P3)

**Files:**
- Modify: `tests/corpus/harness.py`
- Modify: `tests/corpus/MANIFEST.yaml`
- Modify: `tests/corpus/test_fp_rate.py`

**Interfaces:**
- Consumes: `BUILTIN_RULE_CLASSES` metadata (rule_id → maturity).
- Produces: `Expectation` gains `maturity: str = "stable"`, `kind: str = "core"`, `interaction: str = ""`; `Reconciliation` gains `active_by_kind: dict[str, int]`, `fp_by_kind: dict[str, int]`; `load_manifest` rejects unknown keys and maturity drift. Later stages add manifest entries with `kind: contracts` / `facets` / `restoration` / `sensitivity` / `dependency_taint` and inherit the per-kind gate for free.

- [ ] **Step 1: Write the failing tests** — append to `tests/corpus/test_fp_rate.py`:

```python
def test_manifest_rejects_unknown_keys(tmp_path, monkeypatch):
    bad = tmp_path / "MANIFEST.yaml"
    bad.write_text(
        "fixtures:\n"
        "  x.py:\n"
        '    - {rule_id: PY-WL-101, qualname: "x.f", label: TRUE_POSITIVE, maturty: stable}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="unknown key"):
        harness.load_manifest()


def test_manifest_maturity_must_match_the_rule(tmp_path, monkeypatch):
    bad = tmp_path / "MANIFEST.yaml"
    bad.write_text(
        "fixtures:\n"
        "  x.py:\n"
        '    - {rule_id: PY-WL-118, qualname: "x.f", label: TRUE_POSITIVE, maturity: stable}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="maturity"):
        harness.load_manifest()


def test_preview_findings_are_reconciled():
    # P1: the preview skip is gone — a preview finding over the corpus is either
    # manifested or it fails the gate as unaccounted, same as stable.
    rec = reconcile()
    assert not rec.unaccounted
    assert not rec.stale


def test_per_kind_fp_rate_within_budget():
    # P3: each kind with >=10 defects meets the 5% budget; a smaller kind must be
    # sentinel-gated (at least one FALSE_POSITIVE sentinel of that kind exists).
    rec = reconcile()
    sentinel_kinds = {e.kind for e in load_manifest() if e.label == FALSE_POSITIVE}
    for kind, defects in rec.active_by_kind.items():
        fps = rec.fp_by_kind.get(kind, 0)
        if defects >= 10:
            assert fps / defects <= 0.05, f"kind {kind}: FP rate {fps}/{defects} exceeds 5%"
        else:
            assert kind in sentinel_kinds, f"kind {kind}: <10 defects and no FP sentinel"
```

(Adjust imports at top of the file: `from corpus import harness` plus the existing `from corpus.harness import ...` names, and `FALSE_POSITIVE`, `load_manifest`.)

- [ ] **Step 2: Run to verify failures** — `cd tests && uv run pytest corpus/test_fp_rate.py -v`; expected: new tests FAIL (no strict keys, preview skip still present, no per-kind fields).

- [ ] **Step 3: Implement `harness.py`.**
  1. `Expectation` gains the three fields (defaults `"stable"`, `"core"`, `""`).
  2. `load_manifest` becomes strict and maturity-checked:

```python
_ALLOWED_KEYS = frozenset({"rule_id", "qualname", "label", "note", "maturity", "kind", "interaction"})
_MATURITIES = frozenset({"stable", "preview"})


def _rule_maturities() -> dict[str, str]:
    from wardline.scanner.rules import BUILTIN_RULE_CLASSES

    return {cls.metadata.rule_id: cls.metadata.maturity.value for cls in BUILTIN_RULE_CLASSES}
```

     Inside the entry loop, before constructing `Expectation`:

```python
                unknown = set(entry) - _ALLOWED_KEYS
                if unknown:
                    raise ValueError(f"{path}: unknown key(s) {sorted(unknown)} in manifest entry")
                maturity = entry.get("maturity", "stable")
                if maturity not in _MATURITIES:
                    raise ValueError(f"{path}: bad maturity {maturity!r} (want one of {sorted(_MATURITIES)})")
                actual = _rule_maturities().get(entry["rule_id"])
                if actual is not None and actual != maturity:
                    raise ValueError(
                        f"{path}: {entry['rule_id']} maturity is {actual!r} but the manifest says "
                        f"{maturity!r} — a graduated rule must update its entries"
                    )
```

     …and pass `maturity=maturity, kind=entry.get("kind", "core"), interaction=entry.get("interaction", "")` to `Expectation`.
  3. `reconcile()`: DELETE the preview skip (lines 96–97: `if finding.maturity is Maturity.PREVIEW: continue`) and remove the now-unused `Maturity` import. Add per-kind tallies:

```python
    active_by_kind: dict[str, int] = {}
    fp_by_kind: dict[str, int] = {}
    ...
        active_defects += 1
        key = (finding.location.path, finding.rule_id, finding.qualname or "")
        expectation = by_key.get(key)
        kind = expectation.kind if expectation is not None else "core"
        active_by_kind[kind] = active_by_kind.get(kind, 0) + 1
        if expectation is None:
            unaccounted.append(key)
            continue
        matched_keys.add(key)
        if expectation.label == FALSE_POSITIVE:
            false_positives += 1
            fp_by_kind[kind] = fp_by_kind.get(kind, 0) + 1
```

     `Reconciliation` gains `active_by_kind: dict[str, int]` and `fp_by_kind: dict[str, int]` fields (populate in the return). Update the module docstring: the FP population now includes preview DEFECTs (P1) — the harness no longer has a maturity blind spot.

- [ ] **Step 4: Enumerate the newly counted preview findings.**

Run: `cd tests && uv run python -c "from corpus.harness import reconcile; r = reconcile(); [print(k) for k in r.unaccounted]"`
For EACH `(path, rule_id, qualname)` printed, add a manifest entry under its file with `maturity: preview` and an honest label: `TRUE_POSITIVE` if the fixture genuinely exhibits that preview rule's defect shape at that site, `FALSE_POSITIVE` if the rule wrongly fires (FPs count against the budget — that is the point). Add a `note:` for every entry. Also update the `MANIFEST.yaml` header comment block to document the three new fields and their defaults. The dead PY-WL-118 sentinel entry (`clean_sql_parameterized.py`) gains `maturity: preview` and is now LIVE — if PY-WL-118 fires on it, that is a real FP against the budget.
**Decision gate:** if the resulting global or per-kind FP rate exceeds 5%, STOP — do not relabel findings to pass. Report the failing rate and the offending rule ids to John (spec P1 budgets this red deliberately; triage of the preview rules is a separate decision).

- [ ] **Step 5: Run the corpus suite** — `cd tests && uv run pytest corpus -v`. Expected: PASS (or the documented STOP above).

- [ ] **Step 6: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 7: Commit** — `test(corpus): reconcile preview findings; manifest maturity/kind/interaction; per-kind FP gate (S0 P1-P3)`

---

### Task 7: Determinism guard covers `sentinels/` (P4)

**Files:**
- Modify: `tests/grammar/test_output_determinism.py:27,30-39`

- [ ] **Step 1: Extend the corpus glob.** Replace the single-root constant and collection:

```python
_CORPUS_ROOTS = (
    REPO_ROOT / "tests" / "corpus" / "fixtures",
    REPO_ROOT / "tests" / "corpus" / "sentinels",
)
```

and in `_corpus_findings`: `files = sorted(p for root in _CORPUS_ROOTS for p in root.rglob("*.py"))`. Update the docstring: "…over the fixed corpus (fixtures/ AND sentinels/ — P4: sentinel-shape churn gets the same two-run byte guard)".

- [ ] **Step 2: Run it twice to prove stability** — `uv run pytest tests/grammar/test_output_determinism.py -v && uv run pytest tests/grammar/test_output_determinism.py -v`. Expected: PASS both times.

- [ ] **Step 3: Commit** — `test(determinism): two-run byte guard covers corpus sentinels (S0 P4)`

---

### Task 8: Canonical-orderings pin (P7)

**Files:**
- Create: `tests/conformance/test_canonical_orderings.py`

- [ ] **Step 1: Write the pins** (these should pass immediately — they FREEZE current behaviour so the S1+ serialisation work cannot un-sort anything silently):

```python
"""P7 — canonical orderings pinned at every serialisation seam.

The declaration ledger (S1+) inherits these seams; each is pinned here so an
ordering regression is a named failure, not a byte-drift mystery."""

from __future__ import annotations

import json

from wardline.core.attest import _canonical_bytes
from wardline.core.baseline import build_baseline_document
from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint


def _finding(rule_id: str, path: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="m",
        severity=severity,
        kind=Kind.DEFECT,
        location=Location(path=path, line_start=1),
        fingerprint=compute_finding_fingerprint(rule_id=rule_id, path=path),
    )


def test_finding_jsonl_keys_are_sorted() -> None:
    payload = json.loads(_finding("PY-WL-101", "a.py", Severity.ERROR).to_jsonl())
    assert list(payload) == sorted(payload)


def test_attest_canonical_bytes_are_key_sorted_and_compact() -> None:
    assert _canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}}) == b'{"a":{"c":3,"d":2},"b":1}'


def test_baseline_orders_by_severity_then_rule_then_path_then_fingerprint() -> None:
    findings = [
        _finding("PY-WL-108", "b.py", Severity.ERROR),
        _finding("PY-WL-101", "a.py", Severity.CRITICAL),
        _finding("PY-WL-101", "b.py", Severity.ERROR),
        _finding("PY-WL-101", "a.py", Severity.ERROR),
    ]
    doc = build_baseline_document(findings)
    ordered = [(e["rule_id"], e["path"]) for e in doc["findings"]]
    assert ordered == [
        ("PY-WL-101", "a.py"),  # CRITICAL first
        ("PY-WL-101", "a.py"),
        ("PY-WL-101", "b.py"),
        ("PY-WL-108", "b.py"),
    ]
```

(If `build_baseline_document`'s entry shape differs — check `src/wardline/core/baseline.py:220-245` — adjust the key extraction to the actual entry keys, keeping the four-level ordering assertion intact.)

- [ ] **Step 2: Run** — `uv run pytest tests/conformance/test_canonical_orderings.py -v`. Expected: PASS (fix extraction shape per the note if needed; the ORDER expectations themselves must hold — if one genuinely fails, that is a live bug: stop and report).

- [ ] **Step 3: Commit** — `test(conformance): pin canonical orderings at the serialisation seams (S0 P7)`

---

### Task 9: Provider-fingerprint mutation table + collision pairs + reformat stability (P8)

**Files:**
- Create: `tests/unit/scanner/taint/test_provider_fingerprint_mutations.py`

- [ ] **Step 1: Write the table** (grammar-digest behaviour is existing — these pin it):

```python
"""P8 — the provider fingerprint moves iff the declaration surface moves.

Mutation table: every component of a grammar's identity (name, prefix, group,
level-arg schema, seed body, order) must change the fingerprint. Reformat
stability: cosmetic re-authoring of an identical seed must NOT change it.
The builtin literal is pinned so a REGISTRY_VERSION drift in S0 is loud."""

from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.boundary_types import BoundaryType, LevelArg
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import FunctionTaint

_ALLOWED = frozenset({TaintState.GUARDED, TaintState.ASSURED})


def _seed(levels):
    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])


def _bt(name="sanitized", prefix="myproj.trust", group=1, arg="to_level", allowed=_ALLOWED, default=None, seed=_seed):
    return BoundaryType(name, prefix, group, (LevelArg(arg, allowed, default),), seed)


def _fp(*bts) -> str:
    return DecoratorTaintSourceProvider(boundary_types=tuple(bts)).fingerprint()


BASE = _bt()

MUTATIONS = {
    "canonical_name": _bt(name="cleansed"),
    "module_prefix": _bt(prefix="otherproj.trust"),
    "group": _bt(group=2),
    "arg_name": _bt(arg="level"),
    "allowed_set": _bt(allowed=frozenset({TaintState.ASSURED})),
    "default": _bt(default=TaintState.GUARDED),
}


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_mutation_changes_fingerprint(label: str) -> None:
    assert _fp(BASE) != _fp(MUTATIONS[label]), f"mutating {label} did not move the fingerprint"


def test_seed_body_mutation_changes_fingerprint() -> None:
    def other_seed(levels):
        return FunctionTaint(TaintState.UNKNOWN_RAW, levels["to_level"])

    assert _fp(BASE) != _fp(_bt(seed=other_seed))


def test_boundary_order_changes_fingerprint() -> None:
    a, b = _bt(name="alpha"), _bt(name="beta")
    assert _fp(a, b) != _fp(b, a)


def test_collision_pair_distinct_grammars_never_collide() -> None:
    fps = {_fp(BASE), _fp(MUTATIONS["canonical_name"]), _fp(MUTATIONS["group"]), _fp(_bt(name="alpha"), _bt(name="beta"))}
    assert len(fps) == 4


def test_reformat_stability_of_an_identical_seed() -> None:
    # Same logic, different formatting/comments: co_code/co_consts/co_names equal.
    def seed_v1(levels):
        return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])

    def seed_v2(levels):
        # a comment does not change the code object
        return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])

    assert _fp(_bt(seed=seed_v1)) == _fp(_bt(seed=seed_v2))


def test_builtin_fingerprint_literal_is_pinned_for_s0() -> None:
    # S0 must not move the vocabulary version; the S1 generic-3 bump updates this pin.
    assert DecoratorTaintSourceProvider().fingerprint() == "decorator-vocab:wardline-generic-2"
```

Note: `seed_v1`/`seed_v2` have different `__qualname__`s, which `_seed_identity` folds in — if the reformat test fails on that, both must share a factory (define one `def make(): def seed(levels): ...; return seed` called twice) so the qualnames match; the assertion then holds on identical code objects. Verify which it is by running; fix the TEST construction, not the digest.

- [ ] **Step 2: Run** — `uv run pytest tests/unit/scanner/taint/test_provider_fingerprint_mutations.py -v`. Expected: PASS.

- [ ] **Step 3: Commit** — `test(provider): fingerprint mutation table, collision pairs, reformat stability (S0 P8)`

---

### Task 10: Builtin/custom malformity asymmetry, named pin (P10)

**Files:**
- Create: `tests/grammar/test_malformity_asymmetry.py`

**Interfaces:** Consumes Task 3 (PY-WL-130) and the existing custom-FACT path.

- [ ] **Step 1: Write the named test:**

```python
"""P10 — the malformity asymmetry, pinned by name.

Malformed BUILTIN declarations are ERROR DEFECTs (PY-WL-130 for call shape,
PY-WL-114 for readable-but-invalid levels): the builtin vocabulary is provable,
so malformity gates. Malformed CUSTOM/pack declarations are FACTs
(WLN-ENGINE-UNPROVABLE-BOUNDARY): the custom path is the unprovable one, so it
observes without gating. Neither channel may leak into the other."""

from __future__ import annotations

from pathlib import Path

from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType, LevelArg
from wardline.scanner.taint.provider import FunctionTaint


def test_builtin_malformed_call_is_an_error_defect_and_no_fact(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    hits = [f for f in result.findings if f.rule_id == "PY-WL-130"]
    assert len(hits) == 1 and hits[0].severity is Severity.ERROR and hits[0].kind is Kind.DEFECT
    assert not [f for f in result.findings if f.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]


def test_custom_malformed_marker_is_a_fact_and_never_pywl130(tmp_path: Path) -> None:
    grammar = BUILTIN_BOUNDARY_TYPES + (
        BoundaryType(
            "sanitized",
            "myproj.trust",
            1,
            (LevelArg("to_level", frozenset({TaintState.GUARDED, TaintState.ASSURED}), default=None),),
            lambda levels: FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"]),
        ),
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    src = proj / "svc.py"
    src.write_text(
        "import myproj.trust\n"
        "@myproj.trust.sanitized(to_level=CFG)\n"
        "def f(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    analyzer = WardlineAnalyzer(boundary_types=grammar)
    from wardline.core.config import WardlineConfig

    result = analyzer.analyze([src], WardlineConfig(), root=proj)
    facts = [f for f in result.findings if f.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert len(facts) == 1 and facts[0].severity is Severity.NONE and facts[0].kind is Kind.FACT
    assert not [f for f in result.findings if f.rule_id == "PY-WL-130"]
```

(Match the custom-grammar analyzer construction used in `tests/grammar/test_unprovable_boundary.py:32-48` — reuse its helper if one exists rather than the inline `WardlineAnalyzer(...)` sketch above; the assertions are the contract.)

- [ ] **Step 2: Run** — `uv run pytest tests/grammar/test_malformity_asymmetry.py -v`. Expected: PASS.

- [ ] **Step 3: Commit** — `test(grammar): pin the builtin-DEFECT vs custom-FACT malformity asymmetry (S0 P10)`

---

### Task 11: Invariant split + RAW_ZONE matrix + inertness-denominator pins (P5, P6, P12)

**Files:**
- Modify: `tests/unit/core/test_taint_invariants.py`
- Create: `tests/unit/core/test_raw_zone_matrix.py`
- Create: `tests/unit/core/test_resolution_posture_pins.py`

- [ ] **Step 1: Split the never-produced invariant (P5).** In `tests/unit/core/test_taint_invariants.py`, replace the `UNREACHABLE` definition (lines 29–30) and the trio test (lines 33–41) with:

```python
# P5 (declaration-surface-v2 §8.4): the old "trio" splits into two invariants
# with different lifetimes. MIXED_RAW is the taint_join falsification record —
# NEVER produced, permanently. UNKNOWN_ASSURED/UNKNOWN_GUARDED are reserved for
# witnessed restoration declarations (S3): until restoration ships they are
# equally unproduced, and after it ships they may appear ONLY with a witness.
NEVER_PRODUCED: frozenset[TaintState] = frozenset({TaintState.MIXED_RAW})
RESTORATION_ONLY: frozenset[TaintState] = frozenset(
    {TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED}
)
UNREACHABLE: frozenset[TaintState] = NEVER_PRODUCED | RESTORATION_ONLY


def test_unreachable_set_is_the_two_partitions() -> None:
    assert UNREACHABLE == frozenset(TaintState) - REACHABLE
    assert NEVER_PRODUCED.isdisjoint(RESTORATION_ONLY)
```

Everything else in the file — `REACHABLE`, both closure tests, the `_CORPUS`, and `test_no_unreachable_state_in_scan_output` — stays byte-identical (the pipeline test still asserts `state not in UNREACHABLE`; S3 will narrow it to `NEVER_PRODUCED` + witness checks, not S0).

- [ ] **Step 2: RAW_ZONE × reserved-states matrix (P6)** — `tests/unit/core/test_raw_zone_matrix.py`:

```python
"""P6 — the RAW_ZONE x reserved-states decision matrix, pinned before S3 exists.

Both restoration states sit OUTSIDE RAW_ZONE (they are uplifted, unknown-
provenance states, not raw ones), and the severity model already treats them as
_PARTIAL (one step down) — a deliberate, stated policy the S3 work must not
re-litigate silently."""

from __future__ import annotations

import itertools

import pytest

from wardline.core.finding import Severity
from wardline.core.taints import RAW_ZONE, TaintState
from wardline.scanner.rules.severity_model import modulate

_TRUSTED = {TaintState.INTEGRAL, TaintState.ASSURED}
_PARTIAL = {TaintState.GUARDED, TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED}
_DOWNGRADE = {
    Severity.CRITICAL: Severity.ERROR,
    Severity.ERROR: Severity.WARN,
    Severity.WARN: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


def test_raw_zone_membership_is_pinned() -> None:
    assert RAW_ZONE == frozenset({TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW})
    assert TaintState.UNKNOWN_ASSURED not in RAW_ZONE
    assert TaintState.UNKNOWN_GUARDED not in RAW_ZONE


@pytest.mark.parametrize(
    ("base", "taint"),
    list(itertools.product((Severity.CRITICAL, Severity.ERROR, Severity.WARN, Severity.INFO), TaintState)),
)
def test_modulate_full_matrix(base: Severity, taint: TaintState) -> None:
    expected = base if taint in _TRUSTED else _DOWNGRADE[base] if taint in _PARTIAL else Severity.NONE
    assert modulate(base, taint) is expected
```

(Cross-check `_DOWNGRADE` against `src/wardline/scanner/rules/severity_model.py:39-45` before running — the pin must mirror the shipped map exactly; if it differs, copy the shipped map into the test verbatim.)

- [ ] **Step 3: Inertness-denominator pins (P12)** — `tests/unit/core/test_resolution_posture_pins.py`:

```python
"""P12 — the inertness denominators, decided and pinned (declaration-surface-v2 §11.4).

Decision of record for S0: recognition buckets are ("anchored", "config"); the
non-trivial-scan floor is 5 analyzed functions; the trip is recognized==0 over
a scan at/above the floor. S1's per-group arming EXTENDS this base (one counter
per declaration group; uplift-only groups never de-inert) — it must not move it."""

from __future__ import annotations

from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint
from wardline.core.resolution_posture import _MIN_FUNCTIONS, _RECOGNIZED_BOUNDARY_BUCKETS, compute_resolution_posture


def _metrics(counts: dict[str, int]) -> Finding:
    return Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="m",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path="<engine>"),
        fingerprint=compute_finding_fingerprint(rule_id="WLN-ENGINE-METRICS", path="<engine>"),
        properties={"taint_source_counts": counts},
    )


def test_denominator_constants_are_pinned() -> None:
    assert _MIN_FUNCTIONS == 5
    assert _RECOGNIZED_BOUNDARY_BUCKETS == ("anchored", "config")


def test_inert_iff_zero_recognized_at_or_above_floor() -> None:
    assert compute_resolution_posture([_metrics({"fallback": 5})]).inert is True
    assert compute_resolution_posture([_metrics({"fallback": 4})]).inert is False  # below floor
    assert compute_resolution_posture([_metrics({"fallback": 5, "anchored": 1})]).inert is False
    assert compute_resolution_posture([_metrics({"fallback": 5, "config": 1})]).inert is False
    # callgraph/module_default recognition does NOT clear the trip.
    assert compute_resolution_posture([_metrics({"fallback": 5, "callgraph": 3})]).inert is True
```

- [ ] **Step 4: Run** — `uv run pytest tests/unit/core/test_taint_invariants.py tests/unit/core/test_raw_zone_matrix.py tests/unit/core/test_resolution_posture_pins.py -v`. Expected: PASS.

- [ ] **Step 5: Commit** — `test(core): invariant split (NEVER_PRODUCED vs RESTORATION_ONLY), RAW_ZONE matrix, inertness denominator pins (S0 P5/P6/P12)`

---

### Task 12: Waiver ceiling decoupled from rule count (P13)

**Files:**
- Modify: `tests/corpus/test_waiver_discipline.py:14,41-47`

- [ ] **Step 1: Replace the rule-count coupling.** Delete the `from wardline.scanner.rules import _ALL_RULE_CLASSES` import and replace `test_waiver_count_not_outgrowing_rule_count` with:

```python
# P13: decoupled from rule count. The old `<= len(_ALL_RULE_CLASSES)` ceiling
# silently grew from 4 to 26 as rules shipped — a suppression budget must not
# scale with the detection surface it suppresses. The repo carries ZERO waivers
# today; 5 is headroom for genuinely triaged FPs. Raising this constant is a
# reviewed decision with a stated reason, never a side effect of adding rules
# (and the per-kind self-hosting gate requires ZERO committed suppressions for
# every new declaration kind — spec §12).
_WAIVER_CEILING = 5


def test_waiver_count_within_fixed_ceiling():
    waiver_count = len(_repo_waivers())
    assert waiver_count <= _WAIVER_CEILING, (
        f"waiver count {waiver_count} exceeds the fixed ceiling {_WAIVER_CEILING} — "
        "suppression is outgrowing its reviewed budget (FP-economics breach)"
    )
```

- [ ] **Step 2: Run** — `uv run pytest tests/corpus/test_waiver_discipline.py -v`. Expected: PASS (repo has zero waivers).

- [ ] **Step 3: Commit** — `test(corpus): fix waiver ceiling as a reviewed constant, decoupled from rule count (S0 P13)`

---

### Task 13: CODEOWNERS for the identity corpus + doc truth-up

**Files:**
- Create: `.github/CODEOWNERS`
- Modify: `tests/golden/identity/regen.py:6-8` (docstring), `tests/golden/identity/README.md:55-58`

- [ ] **Step 1: Create `.github/CODEOWNERS`:**

```
# Identity-corpus rekeys require maintainer review — the parity test enforces
# byte-identity; this enforces a human on every deliberate rekey
# (tests/golden/identity/README.md).
/tests/golden/identity/corpus/ @tachyon-beep
```

- [ ] **Step 2: Truth-up the docs.** `regen.py` module docstring currently claims CODEOWNERS enforcement that did not exist — now it does; reword to "the real enforcement is the parity test + the `.github/CODEOWNERS` entry on `tests/golden/identity/corpus/`". `README.md` lines 55–58: change "*Recommended complement* (not yet wired):" to "Wired: `.github/CODEOWNERS` routes `tests/golden/identity/corpus/` to the maintainer."

- [ ] **Step 3: Commit** — `docs(golden): wire CODEOWNERS for the identity corpus; truth-up regen/README claims (S0)`

---

### Task 14: Changelog — S0 entries + version-bump discipline (ticket item e)

**Files:**
- Modify: `CHANGELOG.md` (under `## [Unreleased]`)

- [ ] **Step 1: Add under `### Added`:**

```markdown
- **PY-WL-130 — malformed builtin-marker calls are loud.** A builtin trust
  marker called with a positional argument or an undeclared keyword previously
  UN-DECLARED the function silently (the seed dropped and every tier-modulated
  rule went quiet — the scan got greener on a typo). It is now an ERROR DEFECT,
  and the legacy-inert `to_level=` on `@trusted` remains tolerated exactly as
  seeding tolerates it. Companion FACT `WLN-ENGINE-UNKNOWN-MARKER` surfaces
  vocabulary-rooted decorators this engine does not recognise (the
  new-weft-markers-on-old-wardline skew), counted in `decorator_coverage`'s new
  `unknown_markers` summary key.
- **Marker-argument grammar (ArgKind) on the registry.** `RegistryEntry` now
  declares each marker's keyword set, legacy-ignored keywords, and per-keyword
  `ArgKind` (`level` today; `token_set`/`ref` readers arrive with the
  declaration-surface stages). The vocabulary descriptor and
  `REGISTRY_VERSION` are unchanged.
```

- [ ] **Step 2: Add a `### Development` (or extend `### Added`) discipline note:**

```markdown
- **Vocabulary version-bump discipline (recorded).** Any change to the
  declaration surface bumps `REGISTRY_VERSION`
  (`src/wardline/core/registry.py`) AND `_RESOLVER_VERSION`
  (`src/wardline/scanner/taint/project_resolver.py`) in the same commit — the
  builtin-only provider fingerprint otherwise serves warm pre-upgrade caches
  against new seeding. A `REGISTRY` content change additionally re-vendors, in
  one commit: `src/wardline/core/vocabulary.yaml`, the descriptor golden +
  `UPSTREAM_BLOB_SHA` in
  `tests/conformance/test_vocabulary_descriptor_wire_golden.py`, and (consumer
  side) loomweave's vendored golden + pins. Consumers ship dual-accept BEFORE
  wardline emits a new version (declaration-surface-v2 §13.1).
```

- [ ] **Step 3: Commit** — `docs(changelog): S0 hardening entries + vocabulary bump discipline (ticket 5a795253f1 item e)`

---

### Task 15: Loomweave dual-accept `wardline-generic-2 | wardline-generic-3` (§13.1.1) — repo `/home/john/loomweave`

**Files (all under `/home/john/loomweave`):**
- Modify: `plugins/python/src/loomweave_plugin_python/wardline_descriptor.py:30,146`
- Modify: `plugins/python/plugin.toml:78`
- Modify: `scripts/check-wardline-version-bounds.py:26` (+ its usage sites)
- Create: `plugins/python/tests/fixtures/wardline-vocabulary-descriptor.generic-3.preview.yaml`
- Test: `plugins/python/tests/test_wardline_descriptor.py` (extend)

**Interfaces:**
- Produces: `ACCEPTED_DESCRIPTOR_VERSIONS: frozenset[str] = frozenset({"wardline-generic-2", "wardline-generic-3"})`. Wardline S1 depends on this landing FIRST.

- [ ] **Step 1: Write the failing test** — append to `plugins/python/tests/test_wardline_descriptor.py` (mirror the existing skew-test fixture plumbing at `:217-224`, which copies a descriptor into the project path and drives `load_wardline_descriptor`):

```python
GENERIC_3_FIXTURE = Path(__file__).parent / "fixtures" / "wardline-vocabulary-descriptor.generic-3.preview.yaml"


def test_generic_3_descriptor_is_accepted_not_skew(tmp_path):
    project = _project_with_descriptor(tmp_path, GENERIC_3_FIXTURE.read_text(encoding="utf-8"))
    state = load_wardline_descriptor(project)
    assert state.status == "enabled"
    assert state.descriptor_version == "wardline-generic-3"
    # The v2 schema's new `facets:` section is tolerated (unknown top-level keys ignored).
    assert set(state.vocabulary.entries_by_name) >= {"external_boundary", "trust_boundary", "trusted"}


def test_generic_9_is_still_version_skew(tmp_path):
    # unchanged behaviour: anything outside the accepted set degrades to skew
    ...  # keep/point at the existing generic-9 case — do not delete it
```

(Use the file's existing project-descriptor helper — the name `_project_with_descriptor` above stands for whatever helper the `:217-224` skew test uses; reuse it verbatim.)

- [ ] **Step 2: Author the preview vector** — `plugins/python/tests/fixtures/wardline-vocabulary-descriptor.generic-3.preview.yaml`:

```yaml
# PREVIEW shared vector for wardline-generic-3 (consumer-first, S0 of the
# declaration-surface-v2 program). Hand-authored from spec §4.1/§4.3; wardline's
# S1 producer must reproduce this byte-for-byte, at which point both repos pin
# its blob SHA (the wardline-generic-2 golden discipline).
schema: wardline.vocabulary/v2
version: wardline-generic-3
entries:
- canonical_name: external_boundary
  group: 1
  attrs: {}
- canonical_name: trust_boundary
  group: 1
  attrs:
    _wardline_to_level: TaintState
- canonical_name: trusted
  group: 1
  attrs:
    _wardline_level: TaintState
facets:
- canonical_name: audit_record
  group: 3
```

- [ ] **Step 3: Run to verify failure** — from `/home/john/loomweave`: run the plugin's test command for that file (check the repo's Makefile/pyproject for the invocation; typically `uv run pytest plugins/python/tests/test_wardline_descriptor.py -v`). Expected: new test FAILS with `status == "version_skew"`.

- [ ] **Step 4: Implement dual-accept.** In `wardline_descriptor.py`, replace line 30:

```python
# Consumer-first dual-accept (wardline declaration-surface-v2 §13.1): generic-3
# is accepted BEFORE wardline emits it. EXPECTED_DESCRIPTOR_VERSION remains the
# canonical current version for messages/tooling.
EXPECTED_DESCRIPTOR_VERSION = "wardline-generic-2"
ACCEPTED_DESCRIPTOR_VERSIONS: frozenset[str] = frozenset({"wardline-generic-2", "wardline-generic-3"})
```

and the gate at line 146: `if vocabulary.version not in ACCEPTED_DESCRIPTOR_VERSIONS:` (the degrade-to-`version_skew` body is unchanged). In `plugin.toml:78` replace the single value with:

```toml
expected_descriptor_version = "wardline-generic-2"
accepted_descriptor_versions = ["wardline-generic-2", "wardline-generic-3"]
```

Update `scripts/check-wardline-version-bounds.py` to read the new list key and assert it equals `sorted(ACCEPTED_DESCRIPTOR_VERSIONS)` (keep its `wardline-generic-9` skew exercise).

- [ ] **Step 5: Run the loomweave suite for the touched areas** — descriptor + conformance tests (`test_wardline_vocabulary_descriptor_conformance.py` must stay green: the generic-2 golden byte-pin is untouched). Expected: PASS.

- [ ] **Step 6: Commit (orchestrator, in /home/john/loomweave, current branch, explicit paths only)** — `feat(wardline-descriptor): dual-accept wardline-generic-2|3 with preview generic-3 vector (consumer-first)`

---

### Task 16: `wardline-attest-3` staged — contract doc, shared vector, verifier dual-accept (§13.1.2, wardline side)

**Files:**
- Modify: `src/wardline/core/attest.py:63,331-354,366-374,378-384,398-404,408-413`
- Create: `docs/contracts/wardline-attest-3.md`
- Create: `tests/conformance/fixtures/wardline-attest-3.vector.json`
- Create: `tests/conformance/test_attest_dual_read.py`
- Modify: `tests/conformance/test_attest_contract_freeze.py`
- Modify: `tests/conformance/seam_registry.json:490-507`

**Interfaces:**
- Produces: `ACCEPTED_ATTEST_SCHEMAS: tuple[str, ...] = ("wardline-attest-2", "wardline-attest-3")` in `wardline.core.attest`; `verify_attestation` reports gain key `"schema_recognized": bool`. Warpline (Task 17) vendors the same vector file byte-for-byte.

- [ ] **Step 1: Write the failing tests** — `tests/conformance/test_attest_dual_read.py`:

```python
"""Consumer-first dual-read for wardline-attest-3 (declaration-surface-v2 §13.1.2).

Wardline still EMITS attest-2 (the freeze test pins that). This suite proves the
verifier RECOGNISES attest-3 — schema recognition is split out of
signature_valid so an attest-3 bundle is distinguishable from a bad key or a
tampered payload — and freezes the shared attest-3 vector warpline vendors."""

from __future__ import annotations

import json
from pathlib import Path

from wardline.core.attest import ACCEPTED_ATTEST_SCHEMAS, ATTEST_SCHEMA, _sign, verify_attestation

VECTOR = Path(__file__).parent / "fixtures" / "wardline-attest-3.vector.json"
# Public, test-only key — the vector is a conformance artefact, not a secret.
VECTOR_KEY = "wardline-attest-3-conformance-vector-key"


def test_accepted_schemas_are_pinned() -> None:
    assert ATTEST_SCHEMA == "wardline-attest-2"  # S0 emits v2, unchanged
    assert ACCEPTED_ATTEST_SCHEMAS == ("wardline-attest-2", "wardline-attest-3")


def test_attest_3_vector_signature_is_internally_consistent() -> None:
    bundle = json.loads(VECTOR.read_text(encoding="utf-8"))
    assert bundle["schema"] == "wardline-attest-3"
    expected = _sign(bundle["payload"], VECTOR_KEY, schema="wardline-attest-3")
    assert bundle["signature"]["value"] == expected["value"]


def test_verifier_recognises_and_validates_attest_3() -> None:
    bundle = json.loads(VECTOR.read_text(encoding="utf-8"))
    report = verify_attestation(bundle, VECTOR_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is True


def test_tampered_attest_3_is_recognised_but_invalid() -> None:
    bundle = json.loads(VECTOR.read_text(encoding="utf-8"))
    bundle["payload"]["commit"] = "0" * 40
    report = verify_attestation(bundle, VECTOR_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is False


def test_unknown_schema_is_unrecognised_not_just_invalid() -> None:
    bundle = json.loads(VECTOR.read_text(encoding="utf-8"))
    bundle["schema"] = "wardline-attest-1"
    report = verify_attestation(bundle, VECTOR_KEY)
    assert report["schema_recognized"] is False
    assert report["signature_valid"] is False
```

- [ ] **Step 2: Generate the vector once** (scratch script, then the tests freeze it):

```python
# run: uv run python /tmp/claude-1000/-home-john-wardline/81966b53-975d-415d-b8fd-8253fa23cd41/scratchpad/gen_attest3_vector.py
import json
from pathlib import Path

from wardline.core.attest import _sign

payload = {
    "wardline_version": "1.5.0",
    "attested_at": "2026-08-09",
    "commit": "ed7bfe860d83000000000000000000000000dead",
    "dirty": False,
    "ruleset_hash": "sha256:" + "ab" * 32,
    "posture": {"inert": False, "recognized_boundaries": 3, "functions_analyzed": 12},
    "boundaries": [
        {"qualname": "svc.fetch_order", "sei": None, "content_hash": "blake3:" + "cd" * 16, "verdict": "clean", "tier": "ASSURED"}
    ],
    "sei_source": None,
    "sei_diagnostics": [],
    # attest-3 additions (declaration-surface-v2 §11.2) — representative, not exhaustive:
    "declarations": [
        {
            "declaration_id": "wlds1:" + "ef" * 32,
            "kind": "facet",
            "content_digest": "sha256:" + "12" * 32,
            "verification_class": "machine_verified",
            "subject": "svc.write_audit_event",
        }
    ],
    "declaration_counts": {"contracts": 0, "facets": 1, "restoration": 0, "sensitivity": 0, "dependency_taint": 0},
    "declaration_debt": {"lapsed_expiries": 0, "stale_dependency_pins": 0, "record_only_claims": 0},
    "grants": {"trusted_packs": [], "trust_dependency_taint": False, "strict_defaults": False},
    "dependency_taint_digest": None,
    "authorship_note": "HMAC attests domain-internal integrity, not third-party identity; authorship lives in git.",
}
bundle = {
    "schema": "wardline-attest-3",
    "payload": payload,
    "signature": _sign(payload, "wardline-attest-3-conformance-vector-key", schema="wardline-attest-3"),
}
out = Path("tests/conformance/fixtures/wardline-attest-3.vector.json")
out.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("wrote", out)
```

- [ ] **Step 3: Run tests to verify the dual-read failures** — `uv run pytest tests/conformance/test_attest_dual_read.py -v`. Expected: FAIL on `ACCEPTED_ATTEST_SCHEMAS` import and `schema_recognized`.

- [ ] **Step 4: Implement the verifier split** in `src/wardline/core/attest.py`. After line 63 add:

```python
# Consumer-first dual-read (declaration-surface-v2 §13.1.2): the verifier
# RECOGNISES attest-3 before the builder EMITS it (S1). Order = emission
# preference, oldest first.
ACCEPTED_ATTEST_SCHEMAS: tuple[str, ...] = (ATTEST_SCHEMA, "wardline-attest-3")
```

Replace lines 368–374 with:

```python
    schema_recognized = isinstance(schema, str) and schema in ACCEPTED_ATTEST_SCHEMAS
    signature_valid = (
        isinstance(signature, dict)
        and schema_recognized
        and signature.get("alg") == "HMAC-SHA256"
        and signature.get("key_id") == key_id(key)
        and hmac.compare_digest(expected, str(signature.get("value") or ""))
    )
```

Add `"schema_recognized": schema_recognized,` to ALL THREE return dicts (lines 379-384, 399-404, 408-413). Extend the docstring's signature paragraph: "An unrecognised schema reports `schema_recognized=False` (distinguishable from a wrong key or tamper); a recognised non-current schema (`wardline-attest-3`) signature-verifies against its own recorded tag. `--reproduce` re-derives the CURRENT builder's payload, so a v3 bundle verified before S1 honestly reports the v3-only keys as mismatches (the `sei_diagnostics` precedent)."

- [ ] **Step 5: Author `docs/contracts/wardline-attest-3.md`** with these sections (content from spec §11.2; follow `wardline-attest-2.md`'s structure): **Status** — staged S0, consumers dual-read, wardline emits v3 from S1; **Envelope** — `{schema: "wardline-attest-3", payload, signature}`, HMAC-SHA256 over compact key-sorted JSON of `{"schema", "payload"}`, `key_id` = first 8 hex of sha256(key); **Payload** — everything in attest-2 PLUS `declarations[]` (sorted by `declaration_id`; entries `{declaration_id, kind, content_digest, verification_class, subject, sei?}` with `verification_class ∈ {machine_verified, structurally_verified, recorded_unverified}`), `declaration_counts` (per-kind, zero-filled), `declaration_debt` (`lapsed_expiries`, `stale_dependency_pins`, `record_only_claims`), `grants` (`trusted_packs`, `trust_dependency_taint`, `strict_defaults`), `dependency_taint_digest` (nullable), `authorship_note` (payload-resident HMAC disclaimer, D3); **Shared vector** — `tests/conformance/fixtures/wardline-attest-3.vector.json`, key `wardline-attest-3-conformance-vector-key`, vendored byte-for-byte by warpline; **Migration** — dual-read staged now in wardline's verifier and warpline; attest-2 bundles verify unchanged forever-until-deprecated; the boundary key-set/verdict vocabulary is unchanged from v2.

- [ ] **Step 6: Update the freeze + registry.** `test_attest_contract_freeze.py`: keep `test_attest_schema_tag_frozen` exactly as is (emission is still v2); add `test_accepted_schemas_include_staged_v3` asserting `ACCEPTED_ATTEST_SCHEMAS == ("wardline-attest-2", "wardline-attest-3")` and `test_v3_contract_doc_exists` asserting `docs/contracts/wardline-attest-3.md` exists. `seam_registry.json` attest row (:490-507): append to the `wire` text "; attest-3 STAGED consumer-first (verifier + warpline dual-read, shared vector tests/conformance/fixtures/wardline-attest-3.vector.json); producer emits v3 from S1", add the new doc/vector/test paths to the evidence list, and correct the stale refs (`attest.py:62`→`:63`, `:216-224`→`:187-258`).

- [ ] **Step 7: Run** — `uv run pytest tests/conformance/test_attest_dual_read.py tests/conformance/test_attest_contract_freeze.py tests/conformance/test_seam_registry.py tests/unit/core/test_attest.py -q` then full suite `uv run pytest -q`. Expected: PASS.

- [ ] **Step 8: Commit** — `feat(attest): stage wardline-attest-3 — contract doc, shared vector, verifier dual-read with schema_recognized (S0 §13.1.2)`

---

### Task 17: Warpline dual-accept `attest-2 | attest-3` (§13.1.2, consumer side) — repo `/home/john/warpline`

**Files (all under `/home/john/warpline`):**
- Modify: `src/warpline/_attest.py:44,182-187`
- Create: `tests/fixtures/wardline-attest-3.vector.json` (byte-for-byte copy of wardline's `tests/conformance/fixtures/wardline-attest-3.vector.json`)
- Test: `tests/test_attest.py` (extend)

- [ ] **Step 1: Write the failing tests** — append to `tests/test_attest.py` (reuse its bundle factory at `:47`):

```python
def test_attest_3_schema_is_accepted():
    # Signature (src/warpline/_attest.py:126):
    #   worklist_risk(impact_completeness, *, affected_seis, bundle, current_commit, content_hash_for_sei)
    # Reuse the accepted-path test's exact argument construction from :85 —
    # only the bundle factory's schema changes:
    bundle = _bundle(schema="wardline-attest-3")
    verdict = _accepted_path_worklist_risk(bundle)  # the same helper/inline call the :85 test uses
    assert verdict["reason_code"] != "attestation_schema_unknown"
    assert verdict["source"] == "wardline-attest-3"  # the verdict names what it consumed


# NOTE: the existing attest-1 rejection cases at :137-141 and :277 stay untouched
# and must remain green — attest-1 is still rejected under dual-accept.


def test_vendored_attest_3_vector_parses():
    import json
    from pathlib import Path

    from warpline._attest import parse_attest_bundle

    vector = json.loads((Path(__file__).parent / "fixtures" / "wardline-attest-3.vector.json").read_text())
    parsed = parse_attest_bundle(vector)
    assert parsed["schema"] == "wardline-attest-3"
    assert parsed["by_sei"] is not None
```

(Match the existing accepted-path test's exact `worklist_risk` invocation from `:85`'s test; the assertion contract is "not schema_unknown". Also check the `:85` assertion `verdict["source"] == ATTEST_SCHEMA` — for an attest-3 bundle `source` must report the BUNDLE's schema; if the implementation sets `source` from `parsed["schema"]` this holds automatically; assert `verdict["source"] == "wardline-attest-3"` in the new test if so.)

- [ ] **Step 2: Copy the vector** from `/home/john/wardline/tests/conformance/fixtures/wardline-attest-3.vector.json` to `tests/fixtures/wardline-attest-3.vector.json` (byte-identical — this is the shared-vector discipline; a divergence later is the drift signal).

- [ ] **Step 3: Run to verify failure** — warpline's test command (check its Makefile/pyproject; typically `uv run pytest tests/test_attest.py -v`). Expected: new acceptance test FAILS with `attestation_schema_unknown`.

- [ ] **Step 4: Implement.** In `src/warpline/_attest.py` line 44:

```python
ATTEST_SCHEMA = "wardline-attest-2"
# Dual-accept (wardline declaration-surface-v2 §13.1.2): attest-3 is honored
# BEFORE wardline emits it. attest-1 and anything else stay rejected.
ACCEPTED_ATTEST_SCHEMAS: frozenset[str] = frozenset({"wardline-attest-2", "wardline-attest-3"})
```

and the gate at 182–187:

```python
    if parsed["schema"] not in ACCEPTED_ATTEST_SCHEMAS:
        return _unavailable(
            "attestation_schema_unknown",
            cause=f"attestation schema is {parsed['schema']!r}, not one of {sorted(ACCEPTED_ATTEST_SCHEMAS)}",
            fix="supply a wardline-attest-2 or wardline-attest-3 bundle (other attest schemas are not honored)",
        )
```

`parse_attest_bundle` needs no change (it reads named keys; attest-3's additive keys pass through). If `worklist_risk` derives `source` from the constant rather than `parsed["schema"]`, change it to use `parsed["schema"]` so the verdict names what it actually consumed.

- [ ] **Step 5: Run warpline's attest tests** — expected: PASS, including the untouched attest-1 rejection at `:137-141` and `:277`.

- [ ] **Step 6: Commit (orchestrator, /home/john/warpline, current branch, explicit paths)** — `feat(attest): dual-accept wardline-attest-2|3 with vendored shared vector (consumer-first)`

---

### Task 18: Legis unknown-key tolerance pin (§13.1.3) — repo `/home/john/legis`

**Files (under `/home/john/legis`):**
- Create: `tests/contract/weft/test_unknown_artifact_key_tolerance.py`

- [ ] **Step 1: Write the pin** (reuse the artifact/sign helpers from `tests/contract/weft/test_wardline_scan_artifact_contract.py` — same imports, same signing path):

```python
"""Wardline declaration-surface-v2 §13.1.3 — legis's stated posture, pinned.

Legis accepts unknown top-level keys in the wardline scan artifact today:
``wardline_artifact_fields`` copies every non-signature key (no allowlist) and
``verify_wardline_artifact`` checks only the four provenance fields. Wardline's
S1 additive ``declarations`` member depends on this tolerance, so it is pinned
here — with its one observable side effect: the batch ``scan_digest`` covers
the whole artifact, so an added key SHIFTS the digest (additive, but visible in
the audit record, by design)."""

from __future__ import annotations

from legis.canonical import content_hash
from legis.wardline.ingest import verify_wardline_artifact, wardline_artifact_fields


def test_unknown_top_level_key_is_accepted_and_signature_covered(base_artifact, sign_artifact):
    # base_artifact/sign_artifact = the existing contract-test fixtures/helpers;
    # if they are module-level functions rather than pytest fixtures, call them
    # the same way test_wardline_scan_artifact_contract.py does.
    widened = {**base_artifact, "declarations": []}
    fields = wardline_artifact_fields(widened)
    assert "declarations" in fields
    signed = {**widened, "artifact_signature": sign_artifact(fields)}
    verify_wardline_artifact(signed)  # must not raise


def test_added_key_shifts_the_scan_digest(base_artifact):
    plain = content_hash(wardline_artifact_fields(base_artifact))
    widened = content_hash(wardline_artifact_fields({**base_artifact, "declarations": []}))
    assert plain != widened
```

- [ ] **Step 2: Adapt the helper plumbing.** Open `tests/contract/weft/test_wardline_scan_artifact_contract.py`, copy its exact artifact-construction and signing mechanics (it drives `verify_wardline_artifact` with a real `sign` — mirror that), and make the two tests above run against a real minimal artifact. `content_hash` import path: mirror how `src/legis/service/wardline.py:221` imports it.

- [ ] **Step 3: Run** — from `/home/john/legis`: `uv run pytest tests/contract/weft/test_unknown_artifact_key_tolerance.py -v`. Expected: PASS (this pins EXISTING behaviour; if it fails, legis is NOT tolerant and spec §13.1.3's premise is wrong — STOP and report to John before any S1 work).

- [ ] **Step 4: Commit (orchestrator, /home/john/legis, current branch, explicit paths)** — `test(weft): pin unknown-artifact-key tolerance ahead of wardline's declarations member`

---

## Final verification (after all tasks)

- [ ] Wardline: `uv run pytest -q` (full), `uv run lint-imports`, `uv run mypy src`, `uv run ruff check src tests` — all green.
- [ ] Self-scan gate: `uv run wardline scan src/ --fail-on ERROR` — exit 0 (PY-WL-130 must be green on wardline's own source; if it fires, the marker use it found is a REAL defect — fix the source, never suppress: the self-hosting gate demands zero committed suppressions).
- [ ] End-to-end bug reproduction check (the ticket's scenario): a scratch project with `@trusted(level="INTEGRAL", audit=True)` + a taint sink now exits 1 at `--fail-on ERROR` (was: exit 0, the false green). Record the before/after in the `wardline-4928b75782` close comment.
- [ ] Loomweave / warpline / legis suites for their touched areas — green.
- [ ] Orchestrator: close `wardline-4928b75782` (fixed by Tasks 3–4) and `wardline-5a795253f1` (this plan) with commit refs; note in the epic `wardline-aee6ae068b` that S0 is done and S1 (`wardline-7342234667`) is unblocked pending P0 re-review.

## Self-review notes (spec coverage)

- Ticket item (a) → Tasks 1–3; (b) → Tasks 4–5; (c) P1/P2/P3 → Task 6, P4 → Task 7, P7 → Task 8, P8 → Task 9, P9 → Task 2, P10 → Task 10, P13 → Task 12; (d) → Task 13; (e) → Task 14. Spec §12 P5/P6/P11/P12 (also S0 per §13.2's "P1–P13") → Tasks 11 and 4 (P11). P14 → Tasks 1–3. §13.1.1 → Task 15; §13.1.2 → Tasks 16–17; §13.1.3 → Task 18.
- Deliberately NOT in S0: any weft-markers export, `REGISTRY_VERSION`/`vocabulary.yaml` changes, attest-3 EMISSION, the declarations inventory factory, per-group inertness arming (all S1 — see spec §13.2).
