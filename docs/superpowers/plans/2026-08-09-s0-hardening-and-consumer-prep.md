# S0 — Hardening + Consumer-First Cross-Product Prep — Implementation Plan (rev 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Git discipline (non-negotiable):** subagents NEVER run git — no `git add/commit/stash/checkout/restore/reset/diff/status`, nothing. Every "Commit" step is executed by the orchestrator session. Cross-repo tasks (17–20) touch `/home/john/loomweave`, `/home/john/warpline`, `/home/john/legis`: the orchestrator checks `git status` there first and stages ONLY the files this plan names (shared trees — explicit `git add`, never `-A`). ⚠️ `/home/john/loomweave/.worktrees/integrate-review-fixes/` holds duplicate copies of several loomweave files — never edit the worktree copies.
>
> **Rev 2** (post NO-GO review of `0863d1a9`): the `to_level=` analyzer-only tolerance is REMOVED (the runtime rejects it; spec §4.2 has no ignored-kwargs concept); a shared call-shape validator makes rule and seeding agree by construction; all four rule-inventory pins are edited; the QE tests are rewritten against verified APIs; the MCP verify_attestation surface (outputSchema golden + blob pin) is part of the attest task; the consumer tasks accept (schema, version) pairs and the rollout fence is explicit.

**Goal:** Ship stage S0 of the declaration-surface-v2 program: fix the live false green `wardline-4928b75782` (PY-WL-130 + `WLN-ENGINE-UNKNOWN-MARKER`), land the §4.2 ArgKind registry grammar, close QE prerequisites P1–P13, and stage the consumer-first cross-product prep (loomweave `generic-2|3` dual-accept, `wardline-attest-3` contract + shared vectors + verifier/warpline dual-read, legis tolerance pin + declarations preview vector) — all before any new marker vocabulary exists.

**Architecture:** One marker-reading grammar (`marker_reader`, P9): the L1 provider, PY-WL-110, PY-WL-114, and the new PY-WL-130 all read markers through the same shared module, and a single `call_shape_offences` validator decides "malformed call shape" for BOTH seeding (seed drops) and PY-WL-130 (DEFECT fires) — agreement by construction, not by convention. The unknown-marker FACT rides the `SeedResult → FunctionSeed → pipeline` channel exactly like `WLN-ENGINE-UNPROVABLE-BOUNDARY`. Cross-product changes are consumer-side only: wardline still emits `wardline-generic-2` and `wardline-attest-2` after S0.

**Tech Stack:** Python 3.12, pytest via `uv run pytest`, ruff, mypy, import-linter; Rust/cargo only to re-verify the loomweave manifest parse. Spec: `docs/superpowers/specs/2026-08-09-declaration-surface-v2-design.md`. Tickets: `wardline-5a795253f1` (S0), `wardline-4928b75782` (bug; closed by Tasks 2–6).

## Global Constraints

- **Zero scan-golden drift.** After every wardline task the full default suite is green with NO regeneration of: `tests/grammar/golden/builtin_findings.jsonl` (byte oracle over `tests/corpus/fixtures`), `tests/golden/identity/corpus/*.json`, `tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml` (+ its `UPSTREAM_BLOB_SHA`), `src/wardline/core/vocabulary.yaml`. The `to_level` census (2026-08-09) proves no corpus/golden fixture carries a malformed marker call, so the behaviour changes in Tasks 4–6 fire on no frozen fixture. If a scan-golden test goes red, the change is wrong — stop and fix the change, never the golden.
- **Exactly two sanctioned golden re-freezes**, both of `tests/conformance/mcp_output_schemas.golden.json` (an API-surface golden, not a scan golden): Task 7 (decorator_coverage summary key) and Task 18 (verify_attestation `schema_recognized`). Each follows the module's RE-FREEZE PROCEDURE and bumps `VENDORED_BLOB_SHA` in the same commit.
- **`REGISTRY_VERSION` stays `"wardline-generic-2"`** (`src/wardline/core/registry.py:22`) and **`ATTEST_SCHEMA` stays `"wardline-attest-2"`** (`src/wardline/core/attest.py:63`) throughout S0. The `generic-3`/`attest-3` bumps are S1, gated by the Rollout Fence section.
- **`src/wardline/core/descriptor.py` output is untouched** — new `RegistryEntry` fields are NOT serialised into the vocabulary descriptor in S0.
- **The three shipped markers' runtime signatures are frozen** — no edits to `src/wardline/decorators/` or `packages/weft-markers/`. (`@trusted` accepts only `level=`; `to_level=` on it is a runtime `TypeError` — which is WHY the analyzer-only tolerance dies in Task 4.)
- New rule id is exactly **`PY-WL-130`**; new FACT id is exactly **`WLN-ENGINE-UNKNOWN-MARKER`** (ids reserved by the spec; next free id after this plan is 131).
- Conventions: FACTs are `Severity.NONE` + `Kind.FACT`; PY-WL-130 is `Severity.ERROR` + `Kind.DEFECT`, `maturity=Maturity.STABLE` (default), `multi_emit=True`.
- Test commands run from `/home/john/wardline` unless a task names another repo. Full suite = `uv run pytest -q`.
- Commit messages follow `feat(scope):` / `fix(scope):` / `test(scope):` / `docs(scope):`, on branch `release/1.5.0` (wardline). Other repos: current checked-out branch, orchestrator verifies cleanliness first.
- **No consumer version bumps in S0.** Loomweave's plugin version is CI-lockstepped to the Rust workspace version (`scripts/check-workspace-version-lockstep.py`); the rollout floor is recorded as commits, not version strings (see Rollout Fence).

## Task dependency order

T1 → T2 → {T3, T4} → T5 → T6 → T7; T8–T16 depend only on earlier wardline tasks where stated (T12 needs T5+T6). Cross-repo: **T17 independent; T18 BEFORE T19 (T19 vendors T18's vector); T20 independent.** Recommended execution order is numeric.

## Filigree discipline

- Before T1: `work_start` on `wardline-4928b75782` (atomic claim). The S0 ticket `wardline-5a795253f1` is dependency-blocked by the bug — do NOT claim it yet.
- After T6's final green (the bug's fix is Tasks 2–6): close `wardline-4928b75782` with commit refs and the before/after repro from Final Verification, THEN `work_start` on `wardline-5a795253f1` for the remainder.
- During T13: file the two pre-found engine defects listed there (they are discoveries of this planning pass, not S0 scope).

---

### Task 1: `ArgKind` + `RegistryEntry.kwargs` / `arg_kinds` (P14, registry half)

**Files:**
- Modify: `src/wardline/core/registry.py`
- Modify: `src/wardline/scanner/boundary_types.py:133-141` (tripwire extension)
- Test: `tests/unit/core/test_registry.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `wardline.core.registry.ArgKind` (StrEnum: `LEVEL`, `TOKEN_SET`, `REF`); `RegistryEntry.kwargs: frozenset[str]`; `RegistryEntry.arg_kinds: Mapping[str, ArgKind]`. There is **NO `ignored_kwargs`** — spec §4.2 (:93) declares exactly `kwargs` + `arg_kinds`, and the runtime accepts nothing beyond them. The load-time tripwire now guarantees `REGISTRY[name].kwargs == {la.arg_name for la in bt.level_args}` so the registry (declaration contract) and the boundary types (seed semantics) cannot drift.

- [ ] **Step 1: Write the failing tests** — append to `tests/unit/core/test_registry.py`:

```python
from wardline.core.registry import REGISTRY, ArgKind


def test_registry_declares_marker_kwargs() -> None:
    # The declared keyword set per marker — spec §4.2. These mirror the runtime
    # signatures exactly (src/wardline/decorators/trust.py): external_boundary
    # takes no kwargs, trust_boundary takes only to_level, trusted only level.
    assert REGISTRY["external_boundary"].kwargs == frozenset()
    assert REGISTRY["trust_boundary"].kwargs == frozenset({"to_level"})
    assert REGISTRY["trusted"].kwargs == frozenset({"level"})


def test_registry_arg_kinds_cover_the_level_args() -> None:
    assert dict(REGISTRY["trusted"].arg_kinds) == {"level": ArgKind.LEVEL}
    assert dict(REGISTRY["trust_boundary"].arg_kinds) == {"to_level": ArgKind.LEVEL}
    assert dict(REGISTRY["external_boundary"].arg_kinds) == {}


def test_registry_kwarg_invariants() -> None:
    for entry in REGISTRY.values():
        assert set(entry.arg_kinds) <= entry.kwargs, entry.canonical_name


def test_registry_arg_kinds_are_immutable() -> None:
    import pytest

    with pytest.raises(TypeError):
        REGISTRY["trusted"].arg_kinds["level"] = ArgKind.REF  # type: ignore[index]


def test_registry_kwargs_match_boundary_type_level_args() -> None:
    # One source of truth: the tripwire in boundary_types enforces this at import,
    # this test makes the fusion a named contract.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES

    for bt in BUILTIN_BOUNDARY_TYPES:
        assert REGISTRY[bt.canonical_name].kwargs == frozenset(
            la.arg_name for la in bt.level_args
        ), bt.canonical_name
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/core/test_registry.py -v`
Expected: FAIL — `ImportError: cannot import name 'ArgKind'`.

- [ ] **Step 3: Implement in `src/wardline/core/registry.py`.** Add `from enum import StrEnum` and extend the dataclass import with `field`. Insert after `REGISTRY_VERSION`:

```python
class ArgKind(StrEnum):
    """The marker-argument grammar (declaration-surface-v2 §4.2, P14).

    Declares how the engine READS each keyword argument of a registered marker.
    S0 ships only ``LEVEL`` consumers; ``TOKEN_SET`` (tuples of value tokens,
    e.g. ``evidence=``/``marks=``) and ``REF`` (module-level declaration
    references, e.g. ``contract=``) get their readers in S2/S3. Every kind is
    fail-closed on any deviation from its form. There is no ignored/compat
    keyword concept: a keyword outside ``kwargs`` is PY-WL-130's DEFECT and the
    seed drops (the runtime signatures reject it too).
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
    ``kwargs`` is the declared keyword set the marker's call form accepts —
    exactly the runtime signature's keyword parameters, fused to the boundary
    types' ``level_args`` by the load-time tripwire in ``boundary_types``.
    ``arg_kinds`` maps declared keywords to their :class:`ArgKind` reading
    discipline. Mappings are wrapped in ``MappingProxyType`` at construction.
    """

    canonical_name: str
    group: int
    attrs: Mapping[str, type]
    kwargs: frozenset[str] = frozenset()
    arg_kinds: Mapping[str, ArgKind] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))
        object.__setattr__(self, "arg_kinds", MappingProxyType(dict(self.arg_kinds)))
        if not set(self.arg_kinds) <= self.kwargs:
            raise ValueError(f"{self.canonical_name}: arg_kinds keys must be declared in kwargs")
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
        arg_kinds={"level": ArgKind.LEVEL},
    ),
}
```

- [ ] **Step 4: Extend the load-time tripwire.** In `src/wardline/scanner/boundary_types.py`, the tripwire loop at `:133-141` currently checks name + group. Replace its body check with:

```python
for _bt in BUILTIN_BOUNDARY_TYPES:
    if _bt.module_prefix == _WEFT_MARKERS_PREFIX:
        continue
    _entry = REGISTRY.get(_bt.canonical_name)
    if _entry is None or _entry.group != _bt.group:  # pragma: no cover
        raise ValueError(f"builtin BoundaryType {_bt.canonical_name!r} drifted from REGISTRY")
    if _entry.kwargs != frozenset(_la.arg_name for _la in _bt.level_args):  # pragma: no cover
        # The registry's declared keyword set IS the level-arg schema; PY-WL-130
        # and seeding both derive tolerance from one place. Fail CLOSED-LOUD.
        raise ValueError(f"builtin BoundaryType {_bt.canonical_name!r} kwargs drifted from REGISTRY")
del _bt, _entry
```

(Adjust the trailing `del` to also drop `_la` if your linter flags it: `del _bt, _entry` is what exists today; the comprehension variable does not leak.)

- [ ] **Step 5: Run tests to verify they pass, and prove zero drift**

Run: `uv run pytest tests/unit/core/test_registry.py tests/unit/core/test_descriptor.py tests/grammar tests/conformance/test_vocabulary_descriptor_wire_golden.py -q`
Expected: all PASS. `test_committed_vocabulary_yaml_matches_registry` proves the descriptor bytes did not move.

- [ ] **Step 6: Commit** — `feat(registry): ArgKind grammar + declared kwarg sets on RegistryEntry, fused to level_args by tripwire (S0, P14)`

---

### Task 2: Shared marker-reader engine-floor module + call-shape validator (P9)

**Files:**
- Create: `src/wardline/scanner/marker_reader.py`
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (delete moved functions, import instead)
- Modify: `src/wardline/scanner/rules/invalid_decorator_level.py` (drop the loose local readers; import shared)
- Modify: `src/wardline/scanner/rules/contradictory_trust.py` (drop the local resolver + provider-private import; import shared)
- Test: `tests/unit/scanner/test_marker_reader_agreement.py` (new)

**Interfaces:**
- Consumes: `TaintState` from `wardline.core.taints`.
- Produces (all public, exact signatures — Tasks 4–6 import these):
  - `dotted_name(node: ast.expr) -> str | None`
  - `resolve_dotted_fqn(node: ast.expr, alias_map: Mapping[str, str]) -> str | None`
  - `resolve_decorator_fqn(deco: ast.expr, alias_map: Mapping[str, str]) -> str | None`
  - `level_token(value: ast.expr, alias_map: Mapping[str, str]) -> str | None` (STRICT: alias-resolved `wardline.core.taints.TaintState` receiver or str literal)
  - `read_level(deco: ast.expr, arg: str, *, allowed: frozenset[TaintState], default: TaintState | None, alias_map: Mapping[str, str]) -> TaintState | None` (NO `ignored_args` parameter — the tolerance concept is gone)
  - `call_shape_offences(deco: ast.expr, *, declared: frozenset[str], required: frozenset[str]) -> tuple[tuple[str, str], ...]` — the ONE call-shape verdict
  - `is_builtin_decorator_fqn(fqn: str, canonical_name: str, module_prefix: str) -> bool`
  - `shadowed_builtin_roots(project_modules: frozenset[str]) -> frozenset[str]`
  - Constants `VOCAB_PREFIX = "wardline.decorators"`, `WEFT_MARKERS_PREFIX = "weft_markers"`, `BUILTIN_MARKER_ROOTS`

- [ ] **Step 1: Create `src/wardline/scanner/marker_reader.py`.** Move (bodies verbatim, names made public, docstrings intact) from `decorator_provider.py`: `_dotted_name`, `_resolve_dotted_fqn`, `_resolve_decorator_fqn`, `_level_token` (:128-143), `_read_level` (:146-198, MINUS the `ignored_args` parameter and its two `in ignored_args` branches — delete them; nothing supplies ignored args any more), `_is_builtin_decorator_fqn`, `_shadowed_builtin_roots`, and the constants `_VOCAB_PREFIX`/`_WEFT_MARKERS_PREFIX`/`_TAINTSTATE_FQN`/`_BUILTIN_MARKER_ROOTS` (public: `VOCAB_PREFIX`, `WEFT_MARKERS_PREFIX`, `BUILTIN_MARKER_ROOTS`; `_TAINTSTATE_FQN` may stay private). Module docstring:

```python
# src/wardline/scanner/marker_reader.py
"""The ONE marker-reading grammar (engine floor, declaration-surface-v2 P9).

Every consumer of a trust-marker AST — the L1 seeding provider AND every
validation rule (PY-WL-110, PY-WL-114, PY-WL-130, the S2+ declaration
validators) — reads through these primitives, so a rule can never recognise or
read a marker differently than seeding does (the recogniser-agreement property,
wardline-09c09f14df). Fail-closed everywhere: an unreadable value is ``None``,
never a guess.

``call_shape_offences`` is the single authority on "this marker call's SHAPE is
malformed": the provider drops the seed exactly when it returns offences, and
PY-WL-130 emits exactly one DEFECT per offence — agreement by construction.

Imports only ``core`` (acyclic floor): the provider and the rules both import
THIS; neither reaches into the other.
"""
```

Then add the validator:

```python
def call_shape_offences(
    deco: ast.expr,
    *,
    declared: frozenset[str],
    required: frozenset[str],
) -> tuple[tuple[str, str], ...]:
    """Every statically-provable malformation of one marker call's SHAPE.

    Returns ``(offender, reason)`` pairs in source order; reasons are
    ``positional_args`` | ``undeclared_kwarg`` | ``unreadable_splat`` |
    ``duplicate_kwarg`` | ``missing_level``. Value problems are NOT shape
    problems: a declared keyword carrying an unreadable value (``level=CFG``)
    or a readable-but-invalid token (``level='ASURED'``) returns no offence
    here — those are the reader's fail-closed ``None`` (no opinion) and
    PY-WL-114's DEFECT respectively. The drop-coverage matrix
    (tests/grammar/test_drop_coverage_matrix.py) pins the full partition.
    """
    if not isinstance(deco, ast.Call):
        # Bare form: fine unless the marker REQUIRES a level (default=None).
        return tuple((arg, "missing_level") for arg in sorted(required))
    out: list[tuple[str, str]] = []
    if deco.args:
        out.append(("<positional>", "positional_args"))
    supplied: dict[str, int] = {}
    unreadable_splat = False
    for kw in deco.keywords:
        if kw.arg is None:
            if not isinstance(kw.value, ast.Dict):
                unreadable_splat = True
                out.append(("<**splat>", "unreadable_splat"))
                continue
            for key in kw.value.keys:
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    unreadable_splat = True
                    out.append(("<**splat>", "unreadable_splat"))
                elif key.value not in declared:
                    out.append((key.value, "undeclared_kwarg"))
                else:
                    supplied[key.value] = supplied.get(key.value, 0) + 1
            continue
        if kw.arg not in declared:
            out.append((kw.arg, "undeclared_kwarg"))
        else:
            supplied[kw.arg] = supplied.get(kw.arg, 0) + 1
    for arg, n in supplied.items():
        if n > 1:
            out.append((arg, "duplicate_kwarg"))
    if not unreadable_splat:
        for arg in sorted(required - set(supplied)):
            out.append((arg, "missing_level"))
    return tuple(out)
```

- [ ] **Step 2: Rewire `decorator_provider.py`.** Delete the moved definitions; add:

```python
from wardline.scanner.marker_reader import (
    BUILTIN_MARKER_ROOTS as _BUILTIN_MARKER_ROOTS,
    VOCAB_PREFIX as _VOCAB_PREFIX,
    WEFT_MARKERS_PREFIX as _WEFT_MARKERS_PREFIX,
    is_builtin_decorator_fqn as _is_builtin_decorator_fqn,
    level_token as _level_token,
    read_level as _read_level,
    resolve_decorator_fqn as _resolve_decorator_fqn,
    resolve_dotted_fqn as _resolve_dotted_fqn,
    shadowed_builtin_roots as _shadowed_builtin_roots,
)
```

Keep `vocabulary_star_exports`, the fingerprint/identity helpers, and the provider class in place (only the reading primitives move). Do NOT change `_match`'s behaviour in this task (the tolerance removal is Task 4) — the `ignored = frozenset({"to_level"}) ...` line at `:404` temporarily passes its set into a local shim: since the shared `read_level` no longer takes `ignored_args`, keep a private `_read_level_with_ignored` copy of the OLD `_read_level` body (with the ignored branches) inside `decorator_provider.py` for this one task, used only by `_match`. Task 4 deletes it. (This keeps the PROVIDER side behaviour-identical in this task — the only behaviour deltas in Task 2 are PY-WL-114's two documented alias-direction fixes, pinned in Step 5.)

- [ ] **Step 3: Unify PY-WL-114 onto the shared reader.** In `src/wardline/scanner/rules/invalid_decorator_level.py`: delete the local `_dotted_name` (:63-70), `_level_token` (:73-81), `_resolve_decorator_fqn` (:84-94). Replace the provider-private import at `:20` with:

```python
from wardline.scanner.marker_reader import (
    is_builtin_decorator_fqn as _is_builtin_decorator_fqn,
    level_token as _level_token,
    resolve_decorator_fqn as _resolve_decorator_fqn,
    shadowed_builtin_roots as _shadowed_builtin_roots,
)
```

At the call site (`:162`) pass the alias map: `token = _level_token(kw.value, alias_map)`. **Behaviour delta (deliberate, two directions, both pinned in Step 5):** the old local reader was alias-BLIND (textual `"TaintState"` suffix match). The shared strict reader alias-resolves. So: (a) `from wardline.core.taints import TaintState as T` + `@t := trusted(level=T.ASURED)` — the provider always read this and dropped the seed; the rule was blind → PY-WL-114 now FIRES there (an FN closed); (b) `@trusted(level=myconfig.TaintState.ASURED)` — the provider never read this (foreign receiver); the old rule fired anyway → PY-WL-114 now goes SILENT there (an FP closed). Update `METADATA.examples_violation` — append:

```python
        # An aliased genuine TaintState with a typo: the provider reads it (alias-
        # resolved) and drops the seed, so the rule must fire (shared reader, P9).
        "from wardline.core.taints import TaintState as T\n@trusted(level=T.ASURED)\ndef f(p):\n    return p",
```

and `METADATA.examples_clean` — append:

```python
        # A foreign *.TaintState receiver is not the exact known export: seeding
        # never read it, so the rule takes no opinion either (shared reader, P9).
        "import myconfig\n@trusted(level=myconfig.TaintState.ASURED)\ndef h2(p):\n    return p",
```

Check `tests/unit/scanner/rules/test_invalid_decorator_level.py` and `tests/unit/scanner/rules/test_invalid_decorator_level_recognizer.py` for pins of the OLD textual behaviour (`grep -n "TaintState" tests/unit/scanner/rules/test_invalid_decorator_level*.py`); update any case asserting a fire on a foreign `*.TaintState` receiver to assert silence, and any case asserting silence on an aliased genuine `TaintState` typo to assert a fire.

- [ ] **Step 4: Unify PY-WL-110 onto the shared module.** In `src/wardline/scanner/rules/contradictory_trust.py`: delete the local `_dotted_name` (:63-70) and `_resolve_decorator_fqn` (:71-77); replace the provider-private import at `:30` with:

```python
from wardline.scanner.marker_reader import (
    is_builtin_decorator_fqn as _is_builtin_decorator_fqn,
    resolve_decorator_fqn as _resolve_decorator_fqn,
)
```

`_marker_canonical_name` keeps its exact logic (now calling the shared helpers). PY-WL-110 deliberately consults NO shadow set — its anchored-provenance gate at `:99-101` is the cover (under a shadowed root nothing seeds, so nothing is anchored and the rule never runs); add one sentence to the module docstring stating that, citing PY-WL-114's `:97-109` contrast. **No behaviour change intended for this rule** — the resolvers are body-identical to the shared ones. (Its counting of markers off the AST irrespective of level-readability is a pre-existing nuance — filed in Task 13, NOT changed here.)

- [ ] **Step 5: Write the agreement tests** — `tests/unit/scanner/test_marker_reader_agreement.py`:

```python
"""P9 — one marker-reading grammar: the rule-side reader IS the provider-side reader."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from wardline.core.run import run_scan
from wardline.scanner.marker_reader import call_shape_offences, level_token

CASES = [
    ("'ASSURED'", {}, "ASSURED"),
    ("TaintState.ASSURED", {"TaintState": "wardline.core.taints.TaintState"}, "ASSURED"),
    ("taints.TaintState.ASSURED", {"taints": "wardline.core.taints"}, "ASSURED"),
    ("T.ASSURED", {"T": "wardline.core.taints.TaintState"}, "ASSURED"),  # aliased import
    # Foreign/re-exported TaintState: NOT the exact known export — unreadable.
    ("shim.TaintState.ASSURED", {"shim": "myapp.shim"}, None),
    ("myconfig.TaintState.ASURED", {"myconfig": "myconfig"}, None),
    ("LEVEL", {}, None),
    ("get_level()", {}, None),
    ("f'{x}'", {}, None),
    ("cfg.ASSURED", {"cfg": "myapp.cfg"}, None),
]


@pytest.mark.parametrize(("expr", "alias_map", "expected"), CASES)
def test_level_token_is_the_single_reader(expr: str, alias_map: dict, expected: str | None) -> None:
    value = ast.parse(expr, mode="eval").body
    assert level_token(value, alias_map) == expected


_DECLARED = frozenset({"level"})
_REQUIRED_NONE: frozenset[str] = frozenset()
_TB_DECLARED = frozenset({"to_level"})
_TB_REQUIRED = frozenset({"to_level"})

SHAPE_CASES = [
    ("trusted(level='ASSURED')", _DECLARED, _REQUIRED_NONE, ()),
    ("trusted", _DECLARED, _REQUIRED_NONE, ()),  # bare, level defaults
    ("trusted('ASSURED')", _DECLARED, _REQUIRED_NONE, (("<positional>", "positional_args"),)),
    ("trusted(level='ASSURED', audit=True)", _DECLARED, _REQUIRED_NONE, (("audit", "undeclared_kwarg"),)),
    ("trusted(**KW)", _DECLARED, _REQUIRED_NONE, (("<**splat>", "unreadable_splat"),)),
    (
        "trusted(level='A', **{'level': 'B'})",
        _DECLARED,
        _REQUIRED_NONE,
        (("level", "duplicate_kwarg"),),
    ),
    ("trust_boundary", _TB_DECLARED, _TB_REQUIRED, (("to_level", "missing_level"),)),
    ("trust_boundary()", _TB_DECLARED, _TB_REQUIRED, (("to_level", "missing_level"),)),
    ("trust_boundary(to_level='ASSURED')", _TB_DECLARED, _TB_REQUIRED, ()),
    # Unreadable value is NOT a shape offence — the reader's None handles it.
    ("trusted(level=CFG)", _DECLARED, _REQUIRED_NONE, ()),
]


@pytest.mark.parametrize(("src", "declared", "required", "expected"), SHAPE_CASES)
def test_call_shape_offences_table(src: str, declared, required, expected) -> None:
    deco = ast.parse(f"@{src}\ndef f(): ...").body[0].decorator_list[0]
    assert call_shape_offences(deco, declared=declared, required=required) == expected


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
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames  # provider dropped the seed too


def test_rule_and_provider_agree_on_aliased_taintstate_typo(tmp_path: Path) -> None:
    # The FN direction closed: an aliased GENUINE TaintState with a typo is read
    # by the provider (seed drops) — the rule now reads it identically and fires.
    src = (
        "from wardline.core.taints import TaintState as T\n"
        "from wardline.decorators import trusted\n"
        "@trusted(level=T.ASURED)\n"
        "def f(p):\n"
        "    return p\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    result = run_scan(proj)
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_no_rule_imports_provider_privates() -> None:
    # P9's structural half: rules read markers ONLY through marker_reader.
    import pathlib

    rules_dir = pathlib.Path("src/wardline/scanner/rules")
    offenders = [
        p.name
        for p in rules_dir.glob("*.py")
        if "taint.decorator_provider import" in p.read_text(encoding="utf-8")
    ]
    assert offenders == []
```

- [ ] **Step 6: Run the affected suites**

Run: `uv run pytest tests/unit/scanner/test_marker_reader_agreement.py tests/unit/scanner/rules/test_invalid_decorator_level.py tests/unit/scanner/rules/test_invalid_decorator_level_recognizer.py tests/unit/scanner/rules/test_contradictory_trust.py tests/unit/scanner/taint/test_decorator_provider.py tests/grammar -q && uv run lint-imports`
Expected: PASS (fix any test that imported the moved privates from `decorator_provider` by pointing it at `marker_reader` — `grep -rn "from wardline.scanner.taint.decorator_provider import" tests/ src/` and update each hit). `lint-imports` proves the layering contracts still hold.

- [ ] **Step 7: Run the full suite** — `uv run pytest -q`. Expected: PASS, zero scan-golden drift.

- [ ] **Step 8: Commit** — `refactor(scanner): shared marker_reader module + call_shape_offences; PY-WL-110/114 unified onto it (S0, P9)`

---

### Task 3: Migrate the 9 incidental legacy `to_level` fixture sites (behaviour-neutral)

**Files (all test-fixture edits, no assertions change):**
- Modify: `tests/unit/scanner/rules/test_untrusted_reaches_trusted.py:71`
- Modify: `tests/unit/scanner/taint/test_review_fixups_engine.py:177,193,209,225,283,333,351,385`

The 2026-08-09 census found EXACTLY 10 occurrences of the invalid legacy shape `@trusted(level=..., to_level=...)`. Nine are incidental fixture noise (the `to_level=` asserts nothing); the tenth is the deliberate tolerance pin `test_trusted_level_tolerates_legacy_to_level_keyword` (`tests/unit/scanner/taint/test_decorator_provider.py:164-171`), which Task 4 REWRITES — do not touch it here.

- [ ] **Step 1: Edit the nine sites.** In each listed line, change `@trusted(level='ASSURED', to_level='ASSURED')` → `@trusted(level='ASSURED')` (match the exact quoting each site uses). These are decorator strings inside test source fixtures; the enclosing tests assert rebinding/precision behaviour, not the decorator shape.

- [ ] **Step 2: Verify the census is exhausted.** Run: `grep -rn "to_level" tests/ --include='*.py' | grep "trusted(level"`. Expected: exactly ONE hit remaining — `test_decorator_provider.py:167` (the tolerance test, rewritten next task).

- [ ] **Step 3: Run the two touched suites** — `uv run pytest tests/unit/scanner/rules/test_untrusted_reaches_trusted.py tests/unit/scanner/taint/test_review_fixups_engine.py -q`. Expected: PASS (behaviour-neutral — the tolerance still exists this commit, and `level=` alone seeds identically).

- [ ] **Step 4: Commit** — `test(scanner): migrate 9 incidental legacy to_level fixture sites to the lawful @trusted(level=...) form (S0)`

---

### Task 4: Provider — call-shape validator wired into `_match`; the `to_level` tolerance dies

**Files:**
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (`_match` :363-420; delete `_read_level_with_ignored`)
- Modify: `tests/unit/scanner/taint/test_decorator_provider.py:164-171` (rewrite the tolerance test)

**Interfaces:**
- Consumes: Task 2's `call_shape_offences`, `read_level`.
- Produces: the provider's new drop discipline — a builtin OR custom marker call with any shape offence NEVER seeds. Builtins stay silent in the provider (PY-WL-130 is the loud channel, Task 5); customs keep their existing `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT channel (identical outcome shape to today's unreadable path). `@external_boundary(anything)` now DROPS instead of seeding (it was never runtime-valid).

- [ ] **Step 1: Write the failing tests.** REWRITE `test_trusted_level_tolerates_legacy_to_level_keyword` (`tests/unit/scanner/taint/test_decorator_provider.py:164-171`) into its opposite, and add the external_boundary pin next to it:

```python
def test_legacy_to_level_on_trusted_now_drops_the_seed() -> None:
    # REVERSAL (S0, spec §4.2): the analyzer-only tolerance for the runtime-
    # invalid `@trusted(level=..., to_level=...)` shape is gone. The runtime
    # raises TypeError on this call; the analyzer now agrees — undeclared
    # keyword => shape offence => no seed (and PY-WL-130 fires, rule suite).
    out = _seed(
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', to_level='ASSURED')\n"
        "def f():\n"
        "    return 1\n"
    )
    assert "m.f" not in out


def test_external_boundary_with_any_arguments_drops_the_seed() -> None:
    # external_boundary's runtime signature takes NO call arguments; the provider
    # previously never inspected them (level_args=()) and seeded anyway. The
    # shape validator closes that: a runtime-TypeError declaration never seeds.
    for call in ("external_boundary(source='http')", "external_boundary('http')", "external_boundary(**KW)"):
        out = _seed(
            "from wardline.decorators import external_boundary\n"
            f"@{call}\n"
            "def f():\n"
            "    return 1\n"
        )
        assert "m.f" not in out, call


def test_bare_external_boundary_still_seeds() -> None:
    out = _seed(
        "from wardline.decorators import external_boundary\n"
        "@external_boundary\n"
        "def f():\n"
        "    return 1\n"
    )
    assert out["m.f"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)
```

(`_seed`, `FunctionTaint`, `T` are this file's existing helpers/imports — match the surrounding tests' exact usage.)

- [ ] **Step 2: Run to verify the rewritten test fails** — `uv run pytest tests/unit/scanner/taint/test_decorator_provider.py -v`. Expected: the two new drop tests FAIL (tolerance still seeds; external_boundary still seeds); everything else PASS.

- [ ] **Step 3: Implement.** In `_match` (:363-420): delete the `ignored = frozenset({"to_level"}) ...` comment+line block (:399-404) and insert the validator gate right after a boundary type matches (before the `levels` loop):

```python
            declared = frozenset(la.arg_name for la in bt.level_args)
            required = frozenset(la.arg_name for la in bt.level_args if la.default is None)
            if call_shape_offences(deco, declared=declared, required=required):
                # Malformed call SHAPE: never seed. Builtins stay silent HERE —
                # PY-WL-130 is the loud channel; a custom marker keeps its
                # WLN-ENGINE-UNPROVABLE-BOUNDARY FACT (P10 asymmetry).
                return None, (None if bt.builtin else bt.canonical_name)
            levels: dict[str, TaintState] = {}
            unreadable = False
            for la in bt.level_args:
                lvl = _read_level(
                    deco,
                    la.arg_name,
                    allowed=la.allowed,
                    default=la.default,
                    alias_map=alias_map,
                )
                if lvl is None:
                    unreadable = True
                    break
                levels[la.arg_name] = lvl
```

Import `call_shape_offences` from `marker_reader`; delete the temporary `_read_level_with_ignored` from Task 2 Step 2 (the shared `read_level` is now the only reader). Note the docstring of `_match` gains one line: "Shape offences (call_shape_offences) drop the seed before any level is read."

- [ ] **Step 4: Run to verify pass + hunt stragglers**

Run: `uv run pytest tests/unit/scanner/taint/test_decorator_provider.py tests/grammar tests/corpus tests/golden -q`
Expected: PASS. The grammar/corpus/golden suites prove zero drift (the census: no frozen fixture carries a malformed shape). Then `grep -rn "external_boundary(" tests/ src/ --include='*.py' | grep -v "def external_boundary" | grep -E "external_boundary\([^)]"` — any hit that expects a SEED from a called-with-args external_boundary is a straggler; fix the fixture to the bare form.

- [ ] **Step 5: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 6: Commit** — `fix(provider)!: call-shape validator gates seeding; remove the runtime-invalid to_level-on-@trusted tolerance (S0, wardline-4928b75782 seed half)`

---

### Task 5: PY-WL-130 — malformed builtin-marker call (the false-green fix, rule half) + the four inventory pins

**Files:**
- Create: `src/wardline/scanner/rules/malformed_marker_call.py`
- Modify: `src/wardline/scanner/rules/__init__.py` (import; append to `_ALL_RULE_CLASSES` LAST)
- Modify: `tests/grammar/test_grammar_model.py:38-65` (ordered id list)
- Modify: `tests/grammar/test_analyzer_wiring.py:15-42` (`_BUILTIN_IDS`)
- Modify: `tests/unit/scanner/rules/test_default_registry.py:41-68` (id set)
- Modify: `tests/unit/scanner/rules/test_vocabulary_shape_pin.py:54-81` (metadata table)
- Test: `tests/unit/scanner/rules/test_malformed_marker_call.py` (new)

**Interfaces:**
- Consumes: `call_shape_offences`, `resolve_decorator_fqn`, `is_builtin_decorator_fqn`, `shadowed_builtin_roots` (Task 2); `BUILTIN_BOUNDARY_TYPES`; `RuleMetadata`; `compute_finding_fingerprint`.
- Produces: rule class `MalformedMarkerCall`, `rule_id="PY-WL-130"`, `Severity.ERROR`, `Kind.DEFECT`, `Maturity.STABLE`, `multi_emit=True`. Findings carry `properties={"decorator", "offender", "reason"}` with `reason ∈ {positional_args, undeclared_kwarg, unreadable_splat, duplicate_kwarg, missing_level}` and fingerprint discriminator `taint_path=f"{name}:{offender}#{deco_ordinal}.{offence_ordinal}"` (PY-WL-114's move-stable ordinal discipline).

- [ ] **Step 1: Write the failing tests** — `tests/unit/scanner/rules/test_malformed_marker_call.py`:

```python
"""PY-WL-130 — a malformed builtin-marker call must be a loud ERROR DEFECT.

The engine drops the seed for these shapes (wardline-4928b75782): the function
falls out of declared_qualnames and every tier-modulated rule goes quiet — the
scan gets GREENER on a typo. This suite pins the rule that makes the shape red,
its agreement with seeding (fires exactly where call_shape_offences drops the
seed), and where it stays silent (well-formed calls, unreadable VALUES,
foreign/custom/shadowed markers)."""

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
    assert hit.properties == {"decorator": "trusted", "offender": "audit", "reason": "undeclared_kwarg"}
    # Agreement: the seed dropped (rule observes, never repairs).
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_legacy_to_level_on_trusted_fires(tmp_path: Path) -> None:
    # The runtime rejects this call; the tolerance is gone (Task 4) — loud DEFECT.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', to_level='ASSURED')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trusted", "offender": "to_level", "reason": "undeclared_kwarg"}
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_positional_arg_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted('INTEGRAL')\ndef f(p):\n    return p\n",
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
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames  # Task 4: no more seeding through it


def test_bare_trust_boundary_fires_missing_level(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trust_boundary\n@trust_boundary\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trust_boundary", "offender": "to_level", "reason": "missing_level"}


def test_zero_arg_trust_boundary_fires_missing_level(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trust_boundary\n@trust_boundary()\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties["reason"] == "missing_level"


def test_duplicate_level_via_splat_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', **{'level': 'ASSURED'})\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trusted", "offender": "level", "reason": "duplicate_kwarg"}


def test_unreadable_value_is_not_a_shape_offence(tmp_path: Path) -> None:
    # level=CFG is a runtime-VALID call whose value is statically unreadable —
    # the reader's documented no-opinion, NOT this rule's DEFECT (matrix, T12).
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted(level=CFG)\ndef f(p):\n    return p\n",
    )
    assert not _hits(result)


def test_aliased_builtin_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted as t\n@t(level='INTEGRAL', audit=True)\ndef f(p):\n    return p\n",
    )
    assert len(_hits(result)) == 1


def test_foreign_and_custom_markers_are_not_this_rules_concern(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import other_pkg\n@other_pkg.trusted(level='X', extra=1)\ndef f(p):\n    return p\n",
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

- [ ] **Step 2: Run tests to verify they fail** — `uv run pytest tests/unit/scanner/rules/test_malformed_marker_call.py -v`. Expected: FAIL — no `PY-WL-130` findings.

- [ ] **Step 3: Implement `src/wardline/scanner/rules/malformed_marker_call.py`:**

```python
# src/wardline/scanner/rules/malformed_marker_call.py
"""PY-WL-130 — builtin trust marker called with a malformed argument shape.

A builtin marker call carrying a positional argument, an undeclared or
duplicated keyword, an unreadable ** splat, or missing its required level is
silently UN-DECLARED by the engine: ``call_shape_offences`` drops the seed, the
function falls out of ``declared_qualnames``, and every tier-modulated rule
goes quiet (wardline-4928b75782). Every such shape is also a runtime
``TypeError`` on the shipped marker signatures. This rule makes the shape a
loud ERROR DEFECT, using the SAME validator seeding uses — it fires exactly
where the seed drops, by construction.

Deliberately NOT silenced by the builtin-stays-quiet convention: that
convention preserves the byte-identity oracle, and a NEW rule id appears in no
frozen golden. Value problems are out of scope: readable-but-invalid levels are
PY-WL-114; statically-unreadable values are the reader's documented no-opinion
(the drop-coverage matrix pins the partition).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType
from wardline.scanner.marker_reader import (
    call_shape_offences,
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
        "called with a positional argument, an undeclared or duplicated keyword, "
        "an unreadable ** splat, or without its required level; the engine "
        "silently drops the declaration, disabling every tier-modulated rule on "
        "the function."
    ),
    examples_violation=(
        "@trusted(level='INTEGRAL', audit=True)\ndef f(p):\n    return p",
        "@trusted('INTEGRAL')\ndef g(p):\n    return p",
        "@trusted(level='ASSURED', to_level='ASSURED')\ndef legacy(p):\n    return p",
        "@external_boundary(source='http')\ndef r(p):\n    return p",
        "@trust_boundary\ndef b(p):\n    if not p: raise ValueError\n    return p",
    ),
    examples_clean=(
        "@trusted(level='INTEGRAL')\ndef f(p):\n    return p",
        "@trusted\ndef g(p):\n    return p",
        "@trust_boundary(to_level='ASSURED')\ndef b(p):\n    if not p: raise ValueError\n    return p",
        # A statically-unreadable VALUE on a declared keyword is runtime-valid;
        # it is the reader's no-opinion, never this rule's shape DEFECT.
        "@trusted(level=cfg.LEVEL)\ndef h(p):\n    return p",
        # A foreign decorator merely spelled like a marker is not the builtin.
        "import other_pkg\n@other_pkg.trusted(level='X', extra=1)\ndef f2(p):\n    return p",
    ),
)


def _builtin_marker(
    deco: ast.expr, alias_map: Mapping[str, str], shadowed_roots: frozenset[str]
) -> BoundaryType | None:
    """The matched builtin BoundaryType iff *deco* resolves to a builtin marker
    seeding would honour (exact known export, root not shadowed)."""
    fqn = resolve_decorator_fqn(deco, alias_map)
    if fqn is None:
        return None
    for bt in BUILTIN_BOUNDARY_TYPES:
        if not bt.builtin:
            continue
        if bt.module_prefix.split(".")[0] in shadowed_roots:
            continue
        if is_builtin_decorator_fqn(fqn, bt.canonical_name, bt.module_prefix):
            return bt
    return None


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
                bt = _builtin_marker(deco, alias_map, shadowed)
                if bt is None:
                    continue
                declared = frozenset(la.arg_name for la in bt.level_args)
                required = frozenset(la.arg_name for la in bt.level_args if la.default is None)
                offences = call_shape_offences(deco, declared=declared, required=required)
                for offence_ordinal, (offender, reason) in enumerate(offences):
                    detail = {
                        "positional_args": "a positional argument",
                        "undeclared_kwarg": f"undeclared keyword {offender!r}",
                        "unreadable_splat": "an unreadable ** splat",
                        "duplicate_kwarg": f"keyword {offender!r} supplied more than once",
                        "missing_level": f"no statically-readable required {offender!r} argument",
                    }[reason]
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            message=(
                                f"{qualname}: builtin marker @{bt.canonical_name} called with {detail} — "
                                f"the engine drops this declaration (no seed; every tier-modulated "
                                f"rule is disabled on this function), and the call raises TypeError "
                                f"at runtime"
                            ),
                            severity=self.base_severity,
                            kind=Kind.DEFECT,
                            location=entity.location,
                            fingerprint=_fp(
                                rule_id=self.rule_id,
                                path=entity.location.path,
                                qualname=qualname,
                                # PY-WL-114's move-stable ordinal discipline (wardline-377b896a87):
                                # within-def ordinals only; offence_ordinal splits co-located offences.
                                taint_path=f"{bt.canonical_name}:{offender}#{deco_ordinal}.{offence_ordinal}",
                            ),
                            taint_path_v0=f"{bt.canonical_name}:{offender}#{deco_ordinal}.{offence_ordinal}",
                            qualname=qualname,
                            properties={"decorator": bt.canonical_name, "offender": offender, "reason": reason},
                        )
                    )
        return findings
```

- [ ] **Step 4: Register the rule.** In `src/wardline/scanner/rules/__init__.py`: add `from wardline.scanner.rules.malformed_marker_call import MalformedMarkerCall` alongside the sibling imports, and append `MalformedMarkerCall,` as the LAST entry of `_ALL_RULE_CLASSES` (:52-80) — registration order = emission order; appending preserves every frozen ordering.

- [ ] **Step 5: Edit the four inventory pins** (each reds until edited — run `uv run pytest tests/grammar/test_grammar_model.py tests/grammar/test_analyzer_wiring.py tests/unit/scanner/rules/test_default_registry.py tests/unit/scanner/rules/test_vocabulary_shape_pin.py -q` first to see all four fail):
  1. `tests/grammar/test_grammar_model.py:38-65` — append `"PY-WL-130",` after `"PY-WL-126",` in the ordered list.
  2. `tests/grammar/test_analyzer_wiring.py:15-42` — append `"PY-WL-130",` to `_BUILTIN_IDS` (one edit, two assertions go green).
  3. `tests/unit/scanner/rules/test_default_registry.py:41-68` — add `"PY-WL-130",` to the id set.
  4. `tests/unit/scanner/rules/test_vocabulary_shape_pin.py:54-81` — add `"PY-WL-130": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),` to `_EXPECTED_RULE_SHAPE`.

- [ ] **Step 6: Run the whole gate battery for a new rule**

Run: `uv run pytest tests/unit/scanner/rules/test_malformed_marker_call.py tests/grammar tests/unit/scanner/rules/test_rule_examples_meta.py tests/unit/scanner/rules/test_discriminator_shape.py tests/unit/mcp/test_server_resources.py tests/corpus tests/golden tests/test_self_hosting.py -q`
Expected: PASS. Named criteria: every `examples_violation` fires PY-WL-130 and every `examples_clean` fires ZERO defects of ANY rule (test_rule_examples_meta); the ordinal `taint_path` satisfies the multi_emit discriminator lint; the MCP rules resource sees a non-empty description; no corpus/golden/self-host fixture fires it (census-verified).

- [ ] **Step 7: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 8: Commit** — `feat(rules): PY-WL-130 malformed builtin-marker call is a loud ERROR, sharing seeding's shape validator (wardline-4928b75782 rule half)`

---

### Task 6: `WLN-ENGINE-UNKNOWN-MARKER` FACT + pipeline override preservation (observability half; P11 both directions)

**Files:**
- Modify: `src/wardline/scanner/marker_reader.py` (add `unknown_vocabulary_marker`)
- Modify: `src/wardline/scanner/taint/provider.py` (`SeedResult.unknown_markers`)
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (`taint_for` :306-335 collects unknowns)
- Modify: `src/wardline/scanner/taint/function_level.py` (`FunctionSeed.unknown_markers` + threading)
- Modify: `src/wardline/scanner/pipeline.py` (FACT emission after :280; override fix at :165-181)
- Test: `tests/grammar/test_unknown_marker.py` (new); `tests/unit/scanner/test_pipeline.py` (append the two override-preservation tests)

**Interfaces:**
- Consumes: Task 2's `resolve_decorator_fqn`/`is_builtin_decorator_fqn`; `REGISTRY`.
- Produces: `marker_reader.unknown_vocabulary_marker(deco, alias_map, shadowed_roots) -> str | None`; `SeedResult.unknown_markers: tuple[str, ...] = ()`; `FunctionSeed.unknown_markers: tuple[str, ...] = ()`; findings `rule_id="WLN-ENGINE-UNKNOWN-MARKER"`, `Severity.NONE`, `Kind.FACT`, `properties={"marker": <fqn>, "reason": "unrecognised_vocabulary"}`. Task 7 counts these by rule_id. The pipeline's configured-source override now PRESERVES both `unprovable_boundaries` and `unknown_markers` (it silently voided the FACT for config-declared sources).

- [ ] **Step 1: Write the failing tests** — `tests/grammar/test_unknown_marker.py`:

```python
"""WLN-ENGINE-UNKNOWN-MARKER — cross-version conformance, BOTH directions (P11).

Direction 1 (new markers, old wardline): a decorator rooted in the vocabulary
(``wardline.decorators`` / ``weft_markers``) that THIS engine does not recognise
takes no opinion (fail-closed), never crashes, and leaves a FACT.

Direction 2 (unknown category in a declared slot): an unknown token in a KNOWN
marker's declared argument makes the WHOLE declaration unreadable — the seed
drops, nothing is partially honoured. S0's only arg kind is LEVEL; TOKEN_SET
(evidence=) inherits this exact contract in S2/S3 (spec P11 "unknown evidence
category → whole declaration unreadable").
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
        "import weft_markers\n@weft_markers.audit_record\ndef write_event(e):\n    return e\n",
    )
    (fact,) = _facts(result)
    assert fact.severity is Severity.NONE
    assert fact.kind is Kind.FACT
    assert fact.properties == {"marker": "weft_markers.audit_record", "reason": "unrecognised_vocabulary"}
    assert result.context is not None
    assert "svc.write_event" not in result.context.declared_qualnames
    assert not [f for f in result.findings if f.kind is Kind.DEFECT]


def test_from_import_form_is_detected(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from weft_markers import audit_record\n@audit_record\ndef write_event(e):\n    return e\n",
    )
    (fact,) = _facts(result)
    assert fact.properties["marker"] == "weft_markers.audit_record"


def test_nested_vocabulary_path_is_observable(tmp_path: Path) -> None:
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
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert not _facts(result)
    assert [f for f in result.findings if f.rule_id == "PY-WL-130"]


def test_unknown_level_category_makes_the_whole_declaration_unreadable(tmp_path: Path) -> None:
    # P11 direction 2, S0 rendition: an unknown token in the one declared arg
    # kind that exists (LEVEL). Nothing partial survives: no seed, and the
    # readable-but-invalid channel (PY-WL-114) is the loud diagnostic.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='CONFIDENTIAL')\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert not _facts(result)  # a KNOWN marker is never "unknown vocabulary"


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

Additionally, append the override-preservation tests to `tests/unit/scanner/test_pipeline.py` (it already imports `run_parse_project_stage`, `ParseProjectInput`, `WardlineConfig`, `DecoratorTaintSourceProvider`, `vocabulary_star_exports`, `T` — the `:143-161` config-source test is the idiom being extended):

```python
def test_config_source_override_preserves_unknown_markers(tmp_path) -> None:
    # The configured-source override (the FunctionSeed reconstruction below the
    # seeding call) must PRESERVE the observability channels, not void them.
    path = tmp_path / "m.py"
    path.write_text(
        "import weft_markers\n@weft_markers.audit_record\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(untrusted_sources=("m.feed",)),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.body_taint == T.EXTERNAL_RAW  # the directive took effect...
    assert seed.unknown_markers == ("weft_markers.audit_record",)  # ...channel intact


def test_config_source_override_preserves_unprovable_boundaries(tmp_path) -> None:
    # Pre-existing bug closed by the same edit: the reconstruction hardcoded
    # unprovable_boundaries=() — a config-declared source that ALSO carried an
    # unprovable CUSTOM boundary lost its WLN-ENGINE-UNPROVABLE-BOUNDARY FACT.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType, LevelArg
    from wardline.scanner.taint.provider import FunctionTaint

    custom = BoundaryType(
        "sanitized",
        "myproj.trust",
        1,
        (LevelArg("to_level", frozenset({T.GUARDED, T.ASSURED}), None),),
        lambda lv: FunctionTaint(T.EXTERNAL_RAW, lv["to_level"]),
    )
    path = tmp_path / "m.py"
    path.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=CFG)\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(boundary_types=BUILTIN_BOUNDARY_TYPES + (custom,)),
            config=WardlineConfig(untrusted_sources=("m.feed",)),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.body_taint == T.EXTERNAL_RAW
    assert seed.unprovable_boundaries == ("sanitized",)

- [ ] **Step 2: Run tests to verify they fail** — `uv run pytest tests/grammar/test_unknown_marker.py -v`. Expected: FAIL — no FACT emitted.

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
    a shadow). This is the new-markers-old-wardline observability hook:
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
  1. `provider.py` — add to `SeedResult` after `unprovable_boundaries` (and extend its docstring: "``unknown_markers`` carries the resolved FQNs of vocabulary-rooted decorators this engine does not recognise — surfaced as ``WLN-ENGINE-UNKNOWN-MARKER`` FACTs. Builtin malformed-CALL loudness lives in PY-WL-130 (a rule), so builtins still never appear in ``unprovable_boundaries``."):

```python
    unknown_markers: tuple[str, ...] = ()
```

  2. `decorator_provider.py` `taint_for` (:306-335) — collect unknowns in the decorator loop and carry them out on BOTH return paths:

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

     …and add `unknown_markers=tuple(unknown)` to both `SeedResult(...)` constructions (:320 and :335). Import `unknown_vocabulary_marker` from `marker_reader`.
  3. `function_level.py` — add `unknown_markers: tuple[str, ...] = ()` to `FunctionSeed` (docstring: same sentence as SeedResult) and `unknown_markers=res.unknown_markers,` to both `FunctionSeed(...)` constructions in `seed_function_taints` (:61, :69).
  4. `pipeline.py` — FIX the configured-source override (:165-181): the wholesale reconstruction dropped `unprovable_boundaries` (voiding the UNPROVABLE FACT for config-declared sources) and would drop `unknown_markers`. Replace the `seeds[ent.qualname] = FunctionSeed(...)` block with:

```python
                    original = seeds[ent.qualname]
                    seeds[ent.qualname] = FunctionSeed(
                        qualname=ent.qualname,
                        body_taint=TaintState.EXTERNAL_RAW,
                        return_taint=TaintState.EXTERNAL_RAW,
                        source="provider",
                        # The directive overrides the TAINT, never the observability
                        # channels: an unprovable custom boundary / unknown marker on a
                        # config-declared source still surfaces its FACT.
                        unprovable_boundaries=original.unprovable_boundaries,
                        unknown_markers=original.unknown_markers,
                    )
```

  5. `pipeline.py` — directly after the `unprovable_boundaries` FACT loop (after :280), same indent:

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

(`_fp` here is pipeline.py's own positional NUL-join sha256 helper at `:32` — NOT `compute_finding_fingerprint`; this matches the sibling FACT's style exactly.)

- [ ] **Step 5: Run tests to verify they pass** — `uv run pytest tests/grammar/test_unknown_marker.py tests/unit/scanner/test_pipeline.py tests/grammar tests/unit/scanner/taint -q`. Expected: PASS (no fixture carries an unknown marker; FACTs are maturity-STABLE but the identity corpus excludes FACTs by construction — the byte oracle is a stream over corpus fixtures which contain none of these shapes).

- [ ] **Step 6: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 7: Commit** — `feat(engine): WLN-ENGINE-UNKNOWN-MARKER FACT + pipeline override preserves observability channels (wardline-4928b75782 observability half, P11 both directions)`

---

### Task 7: `decorator_coverage` surfaces the unknown-marker count (+ MCP golden re-freeze #1)

**Files:**
- Modify: `src/wardline/core/decorator_coverage.py:110-244`
- Modify: `src/wardline/mcp/server.py` (`_DECORATOR_COVERAGE_OUTPUT_SCHEMA` summary block, ~:3185-3193)
- Modify: `src/wardline/cli/decorator_coverage.py:72-81` (`_render_human`)
- Modify: `tests/conformance/mcp_output_schemas.golden.json` + `tests/conformance/test_mcp_output_schema_golden.py:69` (`VENDORED_BLOB_SHA`)
- Test: `tests/unit/core/test_decorator_coverage.py` (extend), plus the MCP/CLI coverage tests (`grep -rln "decorator_coverage" tests/unit/`)

**Interfaces:**
- Consumes: Task 6's FACT id (matched by `rule_id == "WLN-ENGINE-UNKNOWN-MARKER"` over `result.findings`).
- Produces: `DecoratorCoverageReport.unknown_marker_count: int = 0`; summary dict gains key `"unknown_markers"` (six keys: `total, clean, defect, unknown, suppressed, unknown_markers`).

- [ ] **Step 1: Write the failing test** (in the existing core decorator-coverage test module, using its established build helper):

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

(Import: `from wardline.core.decorator_coverage import build_decorator_coverage` — the real entry point, `build_decorator_coverage(root: Path, *, config_path=None, ...) -> DecoratorCoverageReport` at `decorator_coverage.py:244`; the bare-`root` call above matches its signature.)

- [ ] **Step 2: Run to verify it fails** — `uv run pytest tests/unit/core/test_decorator_coverage.py -v`. Expected: FAIL (`KeyError: 'unknown_markers'`).

- [ ] **Step 3: Implement.**
  1. `core/decorator_coverage.py` — `DecoratorCoverageReport` gains a field and the summary a key:

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

  3. `mcp/server.py` `_DECORATOR_COVERAGE_OUTPUT_SCHEMA` summary block: add `"unknown_markers": {"type": "integer", "description": "Count of vocabulary-rooted decorators this engine does not recognise (WLN-ENGINE-UNKNOWN-MARKER FACTs) — newer weft-markers than wardline."}` to `properties` and `"unknown_markers"` to `required` (the block is `additionalProperties: False`).
  4. `cli/decorator_coverage.py` `_render_human`: print `unknown_markers=<n>` after `suppressed`, reading `summary["unknown_markers"]`.

- [ ] **Step 4: Re-freeze the MCP output-schema golden** (RE-FREEZE PROCEDURE from `tests/conformance/test_mcp_output_schema_golden.py:26-31`). Scratch script:

```python
# uv run python <scratchpad>/refreeze_mcp_golden.py
import hashlib, json, sys
sys.path.insert(0, "tests/conformance")
from test_mcp_output_schema_golden import _GOLDEN_PATH, _live_output_schemas

live = _live_output_schemas()
data = (json.dumps(live, indent=2, sort_keys=True) + "\n").encode("utf-8")
_GOLDEN_PATH.write_bytes(data)
print("new VENDORED_BLOB_SHA =", hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest())
```

Update `VENDORED_BLOB_SHA` at `test_mcp_output_schema_golden.py:69` to the printed value — SAME commit as the schema edit.

- [ ] **Step 5: Run** — `uv run pytest tests/unit/core/test_decorator_coverage.py tests/conformance/test_mcp_output_schema_golden.py tests/conformance/test_mcp_structured_output.py -q`, then fix any exact-summary-dict assertions found via `grep -rln "decorator_coverage" tests/unit/` (update them to include `unknown_markers`). Then full suite `uv run pytest -q`. Expected: PASS.

- [ ] **Step 6: Commit** — `feat(coverage): decorator_coverage surfaces the unrecognised-vocabulary count; MCP schema golden re-frozen (S0)`

---

### Task 8: Corpus harness — strict manifest, preview reconciliation, per-kind FP gate (P1, P2, P3)

**Files:**
- Modify: `tests/corpus/harness.py`
- Modify: `tests/corpus/MANIFEST.yaml` (new rows + header ONLY — see the warning below)
- Modify: `tests/corpus/test_fp_rate.py`

⚠️ `test_fired_sentinel_counts_against_budget` (`test_fp_rate.py:57-58`) string-matches the EXACT text `qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE` in MANIFEST.yaml. Do not reformat existing rows; add new fields on NEW rows only.

**Interfaces:**
- Consumes: `BUILTIN_RULE_CLASSES` metadata (rule_id → maturity).
- Produces: `Expectation` gains `maturity: str = "stable"`, `kind: str = "core"`, `interaction: str = ""` (defaults — the only constructor is `load_manifest` itself); `Reconciliation` gains `active_by_kind: dict[str, int] = field(default_factory=dict)`, `fp_by_kind: dict[str, int] = field(default_factory=dict)` (defaults — the four keyword call sites in `test_fp_rate.py:75-84` stay valid); `load_manifest` rejects unknown keys, unknown rule ids, bad maturity/kind/interaction values, maturity drift against the live rule set, and rows whose fixture file does not exist. The PREVIEW skip at `harness.py:96-97` is DELETED.

- [ ] **Step 1: Write the failing tests** — append to `tests/corpus/test_fp_rate.py`:

```python
import corpus.harness as harness  # type: ignore[import-not-found]
import pytest
from wardline.core.finding import Kind
from wardline.core.run import run_scan


def _scratch_manifest(tmp_path, text):
    scratch = tmp_path / "MANIFEST.yaml"
    scratch.write_text(text, encoding="utf-8")
    return scratch


def test_manifest_rejects_unknown_keys(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE, maturty: stable}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="unknown key"):
        harness.load_manifest()


def test_manifest_rejects_unknown_rule_ids(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-999, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="unknown rule_id"):
        harness.load_manifest()


def test_manifest_maturity_must_match_the_rule(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-118, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE, maturity: stable}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="maturity"):
        harness.load_manifest()


def test_manifest_rejects_missing_fixture_files(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  no_such_file.py:\n"
        '    - {rule_id: PY-WL-106, qualname: "x.f", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="no such fixture"):
        harness.load_manifest()


def test_manifest_rejects_unknown_kind_and_interaction(tmp_path, monkeypatch):
    for field_yaml, match in (("kind: sorcery", "kind"), ("interaction: frenemies", "interaction")):
        bad = _scratch_manifest(
            tmp_path,
            "fixtures:\n  deser_sink.py:\n"
            f'    - {{rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE, {field_yaml}}}\n',
        )
        monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
        with pytest.raises(ValueError, match=match):
            harness.load_manifest()


def test_preview_finding_moves_numerator_and_denominator(monkeypatch, tmp_path):
    # THE discriminating case for P1: a corpus whose only findings come from
    # snippets built on a PREVIEW rule's own examples_violation (guaranteed to
    # fire by the examples contract). Under the old maturity skip reconcile()
    # counted nothing here (active_defects == 0); with the skip gone the preview
    # findings land in the denominator AND, labeled FALSE_POSITIVE, the
    # numerator.
    from wardline.scanner.rules.sql_injection import METADATA as SQLI

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    sentinels = tmp_path / "sentinels"
    sentinels.mkdir()
    (sentinels / "clean_placeholder.py").write_text("X = 1\n", encoding="utf-8")
    src = (
        "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
        + SQLI.examples_violation[0]
        + "\n"
    )
    (fixtures / "preview_fp.py").write_text(src, encoding="utf-8")

    # Discover every DEFECT the engine fires here, then manifest ALL of them so
    # the reconciliation is closed: PY-WL-118 rows as FALSE_POSITIVE (the point),
    # any co-firing stable rule as TRUE_POSITIVE.
    maturities = harness._rule_maturities()
    fired = [f for f in run_scan(fixtures).findings if f.kind is Kind.DEFECT]
    assert any(f.rule_id == "PY-WL-118" for f in fired), "PY-WL-118's violation example must fire it"
    rows = "".join(
        f'    - {{rule_id: {f.rule_id}, qualname: "{f.qualname}", '
        f"label: {'FALSE_POSITIVE' if f.rule_id == 'PY-WL-118' else 'TRUE_POSITIVE'}, "
        f"maturity: {maturities[f.rule_id]}, "
        f'note: "synthetic P1 gate row"}}\n'
        for f in fired
    )
    manifest = _scratch_manifest(tmp_path, "fixtures:\n  preview_fp.py:\n" + rows)
    monkeypatch.setattr(harness, "CORPUS_ROOT", fixtures)
    monkeypatch.setattr(harness, "SENTINEL_ROOT", sentinels)
    monkeypatch.setattr(harness, "MANIFEST_PATH", manifest)

    rec = harness.reconcile()
    n_preview = sum(1 for f in fired if f.rule_id == "PY-WL-118")
    assert rec.active_defects == len(fired)  # denominator includes preview (was: excluded)
    assert rec.false_positives == n_preview  # numerator includes the preview FP rows
    assert not rec.unaccounted


def test_per_kind_fp_rate_within_budget():
    # P3: each kind with >=10 defects meets the 5% budget; a smaller kind must
    # carry >=3 FALSE_POSITIVE sentinels of that kind (spec §12 per-kind gates).
    rec = harness.reconcile()
    from collections import Counter

    sentinel_counts = Counter(e.kind for e in harness.load_manifest() if e.label == harness.FALSE_POSITIVE)
    assert rec.active_by_kind, "per-kind tallies missing"
    for kind, defects in rec.active_by_kind.items():
        fps = rec.fp_by_kind.get(kind, 0)
        if defects >= 10:
            assert fps / defects <= 0.05, f"kind {kind}: FP rate {fps}/{defects} exceeds 5%"
        else:
            assert sentinel_counts.get(kind, 0) >= 3, f"kind {kind}: <10 defects and <3 FP sentinels"
```

- [ ] **Step 2: Run to verify failures** — `cd tests && uv run pytest corpus/test_fp_rate.py -v`. Expected: the new tests FAIL (no strict keys, preview skip still present, no per-kind fields).

- [ ] **Step 3: Implement `harness.py`.**
  1. `Expectation` gains `maturity: str = "stable"`, `kind: str = "core"`, `interaction: str = ""`.
  2. `Reconciliation` gains (with `from dataclasses import dataclass, field`):

```python
    active_by_kind: dict[str, int] = field(default_factory=dict)
    fp_by_kind: dict[str, int] = field(default_factory=dict)
```

  3. Strict loading — module-level:

```python
_ALLOWED_KEYS = frozenset({"rule_id", "qualname", "label", "note", "maturity", "kind", "interaction"})
_MATURITIES = frozenset({"stable", "preview"})
_ALLOWED_KINDS = frozenset({"core", "contracts", "facets", "restoration", "sensitivity", "dependency_taint"})
_ALLOWED_INTERACTIONS = frozenset({"", "contradiction", "match"})
_SECTION_ROOTS = {"fixtures": CORPUS_ROOT, "sentinels": SENTINEL_ROOT}


def _rule_maturities() -> dict[str, str]:
    from wardline.scanner.rules import BUILTIN_RULE_CLASSES

    return {cls.metadata.rule_id: cls.metadata.maturity.value for cls in BUILTIN_RULE_CLASSES}
```

     Inside the entry loop of `load_manifest`, before constructing `Expectation`:

```python
                unknown = set(entry) - _ALLOWED_KEYS
                if unknown:
                    raise ValueError(f"{path}: unknown key(s) {sorted(unknown)} in manifest entry")
                if not (_SECTION_ROOTS[section] / path).is_file():
                    raise ValueError(f"{path}: no such fixture under {section}/")
                maturities = _rule_maturities()
                if entry["rule_id"] not in maturities:
                    raise ValueError(f"{path}: unknown rule_id {entry['rule_id']!r}")
                maturity = entry.get("maturity", "stable")
                if maturity not in _MATURITIES:
                    raise ValueError(f"{path}: bad maturity {maturity!r} (want one of {sorted(_MATURITIES)})")
                if maturities[entry["rule_id"]] != maturity:
                    raise ValueError(
                        f"{path}: {entry['rule_id']} maturity is {maturities[entry['rule_id']]!r} but the "
                        f"manifest says {maturity!r} — a graduated rule must update its entries"
                    )
                kind = entry.get("kind", "core")
                if kind not in _ALLOWED_KINDS:
                    raise ValueError(f"{path}: bad kind {kind!r} (want one of {sorted(_ALLOWED_KINDS)})")
                interaction = entry.get("interaction", "")
                if interaction not in _ALLOWED_INTERACTIONS:
                    raise ValueError(f"{path}: bad interaction {interaction!r}")
```

     …then pass `maturity=maturity, kind=kind, interaction=interaction` to `Expectation`. NOTE: `_SECTION_ROOTS` reads the module-level `CORPUS_ROOT`/`SENTINEL_ROOT` — build it INSIDE `load_manifest` (`{"fixtures": CORPUS_ROOT, "sentinels": SENTINEL_ROOT}` as a local) so the monkeypatched roots in the tests take effect.
  4. `reconcile()`: DELETE the preview skip (:96-97, `if finding.maturity is Maturity.PREVIEW: continue`) and drop `Maturity` from the import at `:25`. Add per-kind tallies inside the loop:

```python
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

     (initialise `active_by_kind: dict[str, int] = {}` / `fp_by_kind: dict[str, int] = {}` before the loop; add both to the `Reconciliation(...)` return). Update the module docstring: the FP population now includes preview DEFECTs (P1) — no maturity blind spot.

- [ ] **Step 4: Reconcile the real corpus.**

Run: `cd tests && uv run python -c "from corpus.harness import reconcile; r = reconcile(); [print(k) for k in r.unaccounted]"`
For EACH `(path, rule_id, qualname)` printed (these are the previously-skipped PREVIEW findings over fixtures/sentinels), add a manifest row under its file with `maturity: preview` and an honest label: `TRUE_POSITIVE` if the fixture genuinely exhibits that preview rule's defect shape at that site, `FALSE_POSITIVE` if the rule wrongly fires. Add a `note:` per row. Update the MANIFEST.yaml header comment to document the three new fields and their defaults. The dead PY-WL-118 sentinel row (`clean_sql_parameterized.py:60`) gains `maturity: preview` and is now LIVE.
**Decision gate:** if the resulting global or per-kind FP rate exceeds 5%, STOP — do not relabel findings to pass. Report the failing rate and the offending rule ids to John (spec P1 budgets this red deliberately; preview-rule triage is a separate decision).

- [ ] **Step 5: Run the corpus suite** — `cd tests && uv run pytest corpus -v`. Expected: PASS (or the documented STOP).

- [ ] **Step 6: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 7: Commit** — `test(corpus): strict manifest (keys/rules/maturity/kind/files), preview findings reconciled, per-kind FP gate (S0 P1-P3)`

---

### Task 9: Determinism guard covers `sentinels/` (P4)

**Files:**
- Modify: `tests/grammar/test_output_determinism.py:27,30-39`

- [ ] **Step 1: Extend the corpus glob.** Replace the single-root constant (:27) and collection (:37):

```python
_CORPUS_ROOTS = (
    REPO_ROOT / "tests" / "corpus" / "fixtures",
    REPO_ROOT / "tests" / "corpus" / "sentinels",
)
```

and in `_corpus_findings`: `files = sorted(p for root in _CORPUS_ROOTS for p in root.rglob("*.py"))`. Update the docstring: "…over the fixed corpus (fixtures/ AND sentinels/ — P4: sentinel-shape churn gets the same two-run byte guard)". `test_builtin_source_defects_have_source_lines` (:53-59) inherits the wider glob unchanged.

- [ ] **Step 2: Run it twice to prove stability** — `uv run pytest tests/grammar/test_output_determinism.py -v && uv run pytest tests/grammar/test_output_determinism.py -v`. Expected: PASS both times.

- [ ] **Step 3: Commit** — `test(determinism): two-run byte guard covers corpus sentinels (S0 P4)`

---

### Task 10: Canonical-orderings pin (P7)

**Files:**
- Create: `tests/conformance/test_canonical_orderings.py`

All expectations below were VERIFIED against the live APIs on 2026-08-09 (baseline top-level keys `fingerprint_scheme/version/entries`; entry keys `fingerprint/rule_id/path/message`; dedup via `unique.setdefault(f.fingerprint, ...)`; sort key `(_SEVERITY_SORT, rule_id, path, fingerprint)`; `to_jsonl` keys sorted; `_canonical_bytes` compact key-sorted).

- [ ] **Step 1: Write the pins** (these pass immediately — they FREEZE current behaviour so the S1+ serialisation work cannot un-sort anything silently):

```python
"""P7 — canonical orderings pinned at every serialisation seam.

The declaration ledger (S1+) inherits these seams; each is pinned here so an
ordering regression is a named failure, not a byte-drift mystery."""

from __future__ import annotations

import json

from wardline.core.attest import _canonical_bytes
from wardline.core.baseline import build_baseline_document
from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint


def _finding(rule_id: str, path: str, severity: Severity, qualname: str | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="m",
        severity=severity,
        kind=Kind.DEFECT,
        location=Location(path=path, line_start=1),
        fingerprint=compute_finding_fingerprint(rule_id=rule_id, path=path, qualname=qualname),
        qualname=qualname,
    )


def test_finding_jsonl_keys_are_sorted() -> None:
    payload = json.loads(_finding("PY-WL-101", "a.py", Severity.ERROR).to_jsonl())
    assert list(payload) == sorted(payload)


def test_attest_canonical_bytes_are_key_sorted_and_compact() -> None:
    assert _canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}}) == b'{"a":{"c":3,"d":2},"b":1}'


def test_baseline_document_shape_is_pinned() -> None:
    doc = build_baseline_document([_finding("PY-WL-101", "a.py", Severity.ERROR)])
    assert list(doc) == ["fingerprint_scheme", "version", "entries"]
    assert list(doc["entries"][0]) == ["fingerprint", "rule_id", "path", "message"]


def test_baseline_orders_by_severity_then_rule_then_path_then_fingerprint() -> None:
    tie_a = _finding("PY-WL-101", "b.py", Severity.ERROR)               # no qualname
    tie_b = _finding("PY-WL-101", "b.py", Severity.ERROR, qualname="m.g")  # same (sev,rule,path), distinct fp
    findings = [
        _finding("PY-WL-108", "b.py", Severity.ERROR),
        _finding("PY-WL-101", "a.py", Severity.CRITICAL),
        tie_a,
        tie_b,
        _finding("PY-WL-101", "a.py", Severity.CRITICAL),  # duplicate fingerprint -> dedup, first wins
    ]
    doc = build_baseline_document(findings)
    assert len(doc["entries"]) == 4  # dedup collapsed the repeat
    assert [(e["rule_id"], e["path"]) for e in doc["entries"]] == [
        ("PY-WL-101", "a.py"),  # CRITICAL sorts first
        ("PY-WL-101", "b.py"),
        ("PY-WL-101", "b.py"),
        ("PY-WL-108", "b.py"),
    ]
    # The (severity, rule, path) tie breaks on the fingerprint hex, ascending.
    assert [e["fingerprint"] for e in doc["entries"][1:3]] == sorted([tie_a.fingerprint, tie_b.fingerprint])
```

- [ ] **Step 2: Run** — `uv run pytest tests/conformance/test_canonical_orderings.py -v`. Expected: PASS immediately (if any pin genuinely fails, that is a live serialisation bug — stop and report).

- [ ] **Step 3: Commit** — `test(conformance): pin canonical orderings at the serialisation seams (S0 P7)`

---

### Task 11: Provider-fingerprint mutation table + `builtin` joins the digest (P8)

**Files:**
- Modify: `src/wardline/scanner/taint/decorator_provider.py:274-289` (`_grammar_digest`)
- Create: `tests/unit/scanner/taint/test_provider_fingerprint_mutations.py`

**Interfaces:** `_grammar_digest`'s parts gain `str(bt.builtin)` — the flag is behaviour-changing (shadow rejection, FACT emission) but was absent from the digest, so two grammars differing only in it shared cached summaries. This changes cache keys for CUSTOM grammars only; the builtin-only provider fingerprint short-circuits to the literal `"decorator-vocab:wardline-generic-2"` and is untouched (verify: `grep -rn "_grammar_digest" tests/ src/` — no test pins a custom digest literal).

- [ ] **Step 1: Fix the digest.** In `_grammar_digest` (:283):

```python
        parts = [bt.canonical_name, bt.module_prefix, str(bt.group), str(bt.builtin), _seed_identity(bt.seed)]
```

(One-line change; the docstring's "(name, prefix, group, seed identity, level-arg schema)" becomes "(name, prefix, group, builtin flag, seed identity, level-arg schema)".)

- [ ] **Step 2: Write the mutation table** — `tests/unit/scanner/taint/test_provider_fingerprint_mutations.py`:

```python
"""P8 — the provider fingerprint moves iff the declaration surface moves.

Mutation table: every component of a grammar's identity (name, prefix, group,
builtin flag, level-arg schema, seed body, order) must change the fingerprint.
Reformat stability: cosmetic re-authoring of an identical seed must NOT change
it. The builtin literal is pinned so a REGISTRY_VERSION drift in S0 is loud."""

from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import FunctionTaint

_ALLOWED = frozenset({TaintState.GUARDED, TaintState.ASSURED})


def _seed(levels):
    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])


def _bt(
    name="sanitized",
    prefix="myproj.trust",
    group=1,
    arg="to_level",
    allowed=_ALLOWED,
    default=None,
    seed=_seed,
    builtin=False,
):
    return BoundaryType(
        canonical_name=name,
        module_prefix=prefix,
        group=group,
        level_args=(LevelArg(arg, allowed, default),),
        seed=seed,
        builtin=builtin,
    )


def _fp(*bts) -> str:
    return DecoratorTaintSourceProvider(boundary_types=tuple(bts)).fingerprint()


BASE = _bt()

MUTATIONS = {
    "canonical_name": _bt(name="cleansed"),
    "module_prefix": _bt(prefix="otherproj.trust"),
    "group": _bt(group=2),
    "builtin_flag": _bt(builtin=True),
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


def test_collision_pairs_distinct_grammars_never_collide() -> None:
    fps = {_fp(BASE)} | {_fp(m) for m in MUTATIONS.values()} | {_fp(_bt(name="alpha"), _bt(name="beta"))}
    assert len(fps) == len(MUTATIONS) + 2


def _make_seed():
    def seed(levels):
        return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])

    return seed


def test_reformat_stability_of_an_identical_seed() -> None:
    # Same factory called twice: identical qualname, code object, consts —
    # a cosmetic re-authoring (comments/whitespace) of the SAME logic must not
    # move the digest. (Two distinct def statements would differ in qualname,
    # which _seed_identity deliberately folds in — hence the shared factory.)
    assert _fp(_bt(seed=_make_seed())) == _fp(_bt(seed=_make_seed()))


def test_builtin_fingerprint_literal_is_pinned_for_s0() -> None:
    # S0 must not move the vocabulary version; the S1 generic-3 bump updates this pin.
    assert DecoratorTaintSourceProvider().fingerprint() == "decorator-vocab:wardline-generic-2"
```

- [ ] **Step 3: Run** — `uv run pytest tests/unit/scanner/taint/test_provider_fingerprint_mutations.py tests/unit/scanner/taint -q` then full suite. Expected: PASS (the digest change invalidates no builtin cache and no test pins a custom digest).

- [ ] **Step 4: Commit** — `test(provider): fingerprint mutation table incl. builtin flag; collision pairs; reformat stability (S0 P8)`

---

### Task 12: Drop-coverage matrix + the malformity asymmetry, named pins (P10)

**Files:**
- Create: `tests/grammar/test_drop_coverage_matrix.py`
- Create: `tests/grammar/test_malformity_asymmetry.py`

**Interfaces:** Consumes Tasks 4–6. The matrix is the "specified and tested" answer to "fires exactly where the seed drops": every builtin seed-drop shape maps to EXACTLY ONE channel — PY-WL-130 (shape), PY-WL-114 (readable-but-invalid value), or pinned deliberate silence (statically-unreadable value; shadowed root).

- [ ] **Step 1: Write the matrix** — `tests/grammar/test_drop_coverage_matrix.py`:

```python
"""The builtin seed-drop coverage matrix (P10 / wardline-4928b75782).

Every shape that makes a builtin marker's seed drop is enumerated with the ONE
diagnostic channel that owns it. 'silent' rows are the two DELIBERATE gaps:
a statically-unreadable VALUE on a declared keyword (runtime-valid code — the
reader's documented no-opinion), and a shadowed builtin root (anti-spoof
rejection with its own rationale). Anything else going silent is a regression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.finding import Kind
from wardline.core.run import run_scan

_IMPORTS = "from wardline.decorators import external_boundary, trust_boundary, trusted\n"

# (case id, decorator line, expected channel, seed must drop)
MATRIX = [
    ("positional", "@trusted('ASSURED')", "PY-WL-130", True),
    ("undeclared_kwarg", "@trusted(level='ASSURED', audit=True)", "PY-WL-130", True),
    ("legacy_to_level", "@trusted(level='ASSURED', to_level='ASSURED')", "PY-WL-130", True),
    ("external_boundary_kwarg", "@external_boundary(source='http')", "PY-WL-130", True),
    ("dynamic_splat", "@trusted(**KW)", "PY-WL-130", True),
    ("duplicate_via_splat", "@trusted(level='ASSURED', **{'level': 'ASSURED'})", "PY-WL-130", True),
    ("bare_required", "@trust_boundary", "PY-WL-130", True),
    ("zero_arg_required", "@trust_boundary()", "PY-WL-130", True),
    ("typo_level", "@trusted(level='ASURED')", "PY-WL-114", True),
    ("out_of_range_level", "@trust_boundary(to_level='INTEGRAL')", "PY-WL-114", True),
    ("unreadable_value", "@trusted(level=CFG)", "silent", True),
    ("well_formed", "@trusted(level='ASSURED')", "none", False),
    ("bare_defaulted", "@trusted", "none", False),
]


@pytest.mark.parametrize(("case", "deco", "channel", "drops"), MATRIX, ids=[m[0] for m in MATRIX])
def test_drop_coverage(tmp_path: Path, case: str, deco: str, channel: str, drops: bool) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(f"{_IMPORTS}{deco}\ndef f(p):\n    return p\n", encoding="utf-8")
    result = run_scan(proj)
    assert result.context is not None
    assert ("svc.f" not in result.context.declared_qualnames) is drops, case
    fired = {f.rule_id for f in result.findings if f.kind is Kind.DEFECT}
    if channel in ("PY-WL-130", "PY-WL-114"):
        assert channel in fired, f"{case}: expected {channel}, fired {sorted(fired)}"
        assert ("PY-WL-130" in fired) != ("PY-WL-114" in fired), f"{case}: channels must not overlap"
    else:
        assert not fired & {"PY-WL-130", "PY-WL-114"}, f"{case}: expected no marker diagnostic, fired {sorted(fired)}"


def test_shadowed_root_is_the_other_deliberate_silence(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "wardline" / "decorators").mkdir(parents=True)
    (proj / "wardline" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "wardline" / "decorators" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        f"{_IMPORTS}@trusted(level='ASSURED', audit=True)\ndef f(p):\n    return p\n", encoding="utf-8"
    )
    result = run_scan(proj)
    assert not [f for f in result.findings if f.rule_id in ("PY-WL-130", "PY-WL-114")]
```

- [ ] **Step 2: Write the asymmetry pin** — `tests/grammar/test_malformity_asymmetry.py`:

```python
"""P10 — the malformity asymmetry, pinned by name.

Malformed BUILTIN declarations are ERROR DEFECTs (PY-WL-130 for call shape,
PY-WL-114 for readable-but-invalid levels): the builtin vocabulary is provable,
so malformity gates. Malformed CUSTOM/pack declarations are FACTs
(WLN-ENGINE-UNPROVABLE-BOUNDARY): the custom path is the unprovable one, so it
observes without gating. Neither channel may leak into the other."""

from __future__ import annotations

from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import build_analyzer
from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
from wardline.scanner.taint.provider import FunctionTaint

_CUSTOM = BoundaryType(
    canonical_name="sanitized",
    module_prefix="myproj.trust",
    group=1,
    level_args=(LevelArg("to_level", frozenset({TaintState.GUARDED, TaintState.ASSURED}), None),),
    seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
    builtin=False,
)


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
    # The exact construction test_unprovable_boundary.py:31-46 uses.
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=CFG, extra=1)\ndef g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(_CUSTOM,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    facts = [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert len(facts) == 1 and facts[0].severity is Severity.NONE and facts[0].kind is Kind.FACT
    assert not [x for x in findings if x.rule_id == "PY-WL-130"]
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW
```

- [ ] **Step 3: Run** — `uv run pytest tests/grammar/test_drop_coverage_matrix.py tests/grammar/test_malformity_asymmetry.py -v`. Expected: PASS.

- [ ] **Step 4: Commit** — `test(grammar): builtin seed-drop coverage matrix + builtin-DEFECT vs custom-FACT asymmetry pins (S0 P10)`

---

### Task 13: Invariant split + RAW_ZONE matrix + inertness-denominator pins (P5, P6, P12) + file two discovered defects

**Files:**
- Modify: `tests/unit/core/test_taint_invariants.py:29-41`
- Create: `tests/unit/core/test_raw_zone_matrix.py`
- Create: `tests/unit/core/test_resolution_posture_pins.py`

- [ ] **Step 1: Split the never-produced invariant (P5).** In `tests/unit/core/test_taint_invariants.py`, replace the `UNREACHABLE` definition (:29-30) and the trio test (:33-41) with:

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

Everything else in the file — `REACHABLE`, both closure tests, `_CORPUS`, `test_no_unreachable_state_in_scan_output` — stays byte-identical (the pipeline test still asserts `state not in UNREACHABLE`; S3 will narrow it to `NEVER_PRODUCED` + witness checks, not S0).

- [ ] **Step 2: RAW_ZONE × reserved-states matrix (P6)** — `tests/unit/core/test_raw_zone_matrix.py`. The `_DOWNGRADE` map below is copied verbatim from `src/wardline/scanner/rules/severity_model.py:38-44`; `_TRUSTED`/`_PARTIAL` from `:17-20`:

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
    Severity.INFO: Severity.INFO,  # floor — never below INFO via downgrade
    Severity.NONE: Severity.NONE,
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

- [ ] **Step 3: Inertness-denominator pins (P12)** — `tests/unit/core/test_resolution_posture_pins.py`. (Names verified: `_MIN_FUNCTIONS` :48, `_RECOGNIZED_BOUNDARY_BUCKETS` :44 — Z spelling; `compute_resolution_posture(findings)` :78 reads `WLN-ENGINE-METRICS` properties.)

```python
"""P12 — the inertness denominators, decided and pinned (declaration-surface-v2 §11.4).

Decision of record for S0: recognition buckets are ("anchored", "config"); the
non-trivial-scan floor is 5 analyzed functions; the trip is recognized==0 over
a scan at/above the floor. S1's per-group arming EXTENDS this base (one counter
per declaration group; uplift-only groups never de-inert) — it must not move it.

KNOWN LIMITATION (filed, not fixed here): project_resolver.py:285-289 emits only
{anchored, module_default, fallback} into taint_source_counts — the "config" and
"callgraph" provenances never reach the histogram, so a config-sources-only
project computes INERT and functions_analyzed undercounts. These pins freeze the
POSTURE COMPUTATION's contract; the emission gap is the filed engine bug."""

from __future__ import annotations

from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint
from wardline.core.resolution_posture import (
    _MIN_FUNCTIONS,
    _RECOGNIZED_BOUNDARY_BUCKETS,
    compute_resolution_posture,
)


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

- [ ] **Step 5: File the two discovered engine defects** (orchestrator, filigree — discoveries of this planning pass, OUT of S0 scope because fixing them drifts the METRIC bytes in the golden / changes PY-WL-110 semantics):
  1. Bug: "`taint_source_counts` never emits the `config`/`callgraph` buckets (`project_resolver.py:285-289`) — a config-sources-only project reads INERT and `functions_analyzed` undercounts (`resolution_posture.py:92-94`)."
  2. Bug (minor): "PY-WL-110 counts markers off the AST irrespective of whether each seeded (`contradictory_trust.py`) — with one seeding and one shape-dropped marker its message claims a clash resolution that never occurred."

- [ ] **Step 6: Commit** — `test(core): invariant split (NEVER_PRODUCED vs RESTORATION_ONLY), RAW_ZONE matrix, inertness denominator pins (S0 P5/P6/P12)`

---

### Task 14: Waiver ceiling decoupled from rule count (P13)

**Files:**
- Modify: `tests/corpus/test_waiver_discipline.py` (docstring :1-4; delete import :14; replace test :41-47)

- [ ] **Step 1: Replace the rule-count coupling.** Delete `from wardline.scanner.rules import _ALL_RULE_CLASSES` (:14). Rewrite the module docstring's second sentence to "…and the waiver count stays within a fixed, reviewed budget" (the old "does not outgrow rule count" text — and its stale "(4 today)" comment, the rule set is 27 — described the coupling this task removes). Replace `test_waiver_count_not_outgrowing_rule_count` with:

```python
# P13: decoupled from rule count. The old `<= len(_ALL_RULE_CLASSES)` ceiling
# silently grew from 4 to 26 as rules shipped — a suppression budget must not
# scale with the detection surface it suppresses. The repo carries ZERO waivers
# today. 5 is an explicit RISK BUDGET (a reviewed constant, not a derived
# number): headroom for genuinely triaged FPs, small enough that suppression
# growth is a named event. Raising it is a reviewed decision with a stated
# reason, never a side effect of adding rules — and the per-kind self-hosting
# gate requires ZERO committed suppressions for every new declaration kind
# (spec §12), so new-kind work never consumes this budget.
_WAIVER_CEILING = 5


def test_waiver_count_within_fixed_ceiling():
    waiver_count = len(_repo_waivers())
    assert waiver_count <= _WAIVER_CEILING, (
        f"waiver count {waiver_count} exceeds the fixed ceiling {_WAIVER_CEILING} — "
        "suppression is outgrowing its reviewed budget (FP-economics breach)"
    )
```

- [ ] **Step 2: Run** — `uv run pytest tests/corpus/test_waiver_discipline.py -v`. Expected: PASS (repo has zero waivers).

- [ ] **Step 3: Commit** — `test(corpus): waiver ceiling is a fixed reviewed risk budget, decoupled from rule count (S0 P13)`

---

### Task 15: CODEOWNERS for the identity corpus + doc truth-up

**Files:**
- Create: `.github/CODEOWNERS`
- Modify: `tests/golden/identity/regen.py:6-8` (docstring), `tests/golden/identity/README.md:55-58`

- [ ] **Step 1: Create `.github/CODEOWNERS`:**

```
# Identity-corpus rekeys get routed to the maintainer for review. CODEOWNERS
# ROUTES review requests; it does not by itself enforce approval — enforcement
# is the branch-protection "require review from Code Owners" setting if/when
# enabled. The parity test remains the hard gate on the bytes themselves
# (tests/golden/identity/README.md).
/tests/golden/identity/corpus/ @tachyon-beep
```

- [ ] **Step 2: Truth-up the docs.** `regen.py` docstring: reword the enforcement claim to "the hard enforcement is the parity test; `.github/CODEOWNERS` routes `tests/golden/identity/corpus/` changes to the maintainer for review (approval enforcement requires the branch-protection Code Owners setting)". `README.md:55-58`: change "*Recommended complement* (not yet wired):" to "Wired: `.github/CODEOWNERS` routes `tests/golden/identity/corpus/` to the maintainer (routing, not approval enforcement)."

- [ ] **Step 3: Commit** — `docs(golden): CODEOWNERS routing for the identity corpus; truth-up regen/README claims (S0)`

---

### Task 16: Changelog — S0 entries + version-bump discipline with precise terms

**Files:**
- Modify: `CHANGELOG.md` (under `## [Unreleased]`)

- [ ] **Step 1: Add under `### Added`:**

```markdown
- **PY-WL-130 — malformed builtin-marker calls are loud.** A builtin trust
  marker called with a positional argument, an undeclared/duplicated keyword,
  an unreadable `**` splat, or without its required level previously
  UN-DECLARED the function silently (the seed dropped and every tier-modulated
  rule went quiet — the scan got greener on a typo). It is now an ERROR DEFECT
  sharing the exact call-shape validator seeding uses. Companion FACT
  `WLN-ENGINE-UNKNOWN-MARKER` surfaces vocabulary-rooted decorators this engine
  does not recognise (new-weft-markers-on-old-wardline skew), counted in
  `decorator_coverage`'s new `unknown_markers` summary key.
- **Marker-argument grammar (ArgKind) on the registry.** `RegistryEntry` now
  declares each marker's keyword set and per-keyword `ArgKind` (`level` today;
  `token_set`/`ref` readers arrive with the declaration-surface stages), fused
  to the boundary types' level-arg schema by a load-time tripwire. The
  vocabulary descriptor and `REGISTRY_VERSION` are unchanged.
```

- [ ] **Step 2: Add under `### Changed` (BREAKING for analyzer tolerance, not for any runtime API):**

```markdown
- **BREAKING (analyzer-only): the legacy `to_level=` tolerance on `@trusted` is
  removed.** The shape was always a runtime `TypeError`; the analyzer no longer
  seeds it, and PY-WL-130 flags it. `@external_boundary(...)` called with any
  arguments (equally runtime-invalid) no longer seeds either. Migrate to
  `@trusted(level=...)` / bare `@external_boundary`.
```

- [ ] **Step 3: Add a `### Development` discipline note with the terms DEFINED:**

```markdown
- **Vocabulary version-bump discipline (recorded).** Terms: the *serialized
  declaration surface* = the bytes consumers parse — `vocabulary.yaml` /
  descriptor wire content, the attest payload schema, the baseline document
  schema, the legis artifact shape. The *internal registry structure* = Python
  dataclass fields on `RegistryEntry`/`BoundaryType` that are NOT serialized
  (this release's `kwargs`/`arg_kinds` are internal — hence no bump). Any
  change to the serialized declaration surface bumps `REGISTRY_VERSION`
  (`src/wardline/core/registry.py`) AND `_RESOLVER_VERSION`
  (`src/wardline/scanner/taint/project_resolver.py`) in the same commit — the
  builtin-only provider fingerprint otherwise serves warm pre-upgrade caches
  against new seeding. A serialized `REGISTRY` content change additionally
  re-vendors, in one commit: `src/wardline/core/vocabulary.yaml`, the
  descriptor golden + `UPSTREAM_BLOB_SHA` in
  `tests/conformance/test_vocabulary_descriptor_wire_golden.py`, and (consumer
  side) loomweave's vendored golden + pins. Consumers ship dual-accept BEFORE
  wardline emits a new version (declaration-surface-v2 §13.1; see the Rollout
  Fence in the S0 plan).
```

- [ ] **Step 4: Commit** — `docs(changelog): S0 hardening entries, tolerance-removal notice, bump discipline with defined terms (ticket 5a795253f1 item e)`

---

### Task 17: Loomweave dual-accept via (schema, version) pairs (§13.1.1) — repo `/home/john/loomweave`

**Files (all under `/home/john/loomweave`; NEVER touch `.worktrees/`):**
- Modify: `plugins/python/src/loomweave_plugin_python/wardline_descriptor.py` (:30 constants; `_state_from_text` :146; `_parse_descriptor` :166-188)
- Modify: `plugins/python/plugin.toml:77-78` (`[integrations.wardline]`)
- Modify: `scripts/check-wardline-version-bounds.py`
- Modify: `plugins/python/tests/test_wardline_vocabulary_descriptor_conformance.py` (docstring of :250 test; new acceptance test)
- Modify: `plugins/python/tests/test_package.py:47-49` (manifest pin extension)
- Create: `plugins/python/tests/fixtures/wardline-vocabulary-descriptor.generic-3.preview.yaml`
- Test: `plugins/python/tests/test_wardline_descriptor.py` (extend)

**Interfaces:**
- Produces: `ACCEPTED_DESCRIPTORS: frozenset[tuple[str, str]]` = {(v1, generic-2), (v2, generic-3)}; the parser now READS the `schema` key (previously ignored; absent → `"wardline.vocabulary/v1"`, the pre-schema era). `WardlineVocabulary` gains `schema: str`. Wardline S1 depends on this landing FIRST (Rollout Fence).
- **Key constraints (verified 2026-08-09):** `manifest.rs:137` deserialises `[integrations.wardline]` as `BTreeMap<String, String>` — a TOML **array** value is a HARD manifest-parse failure (`LMWV-INFRA-MANIFEST-MALFORMED`; the plugin refuses to load). The accepted-set key below is therefore a space-separated STRING. `EXPECTED_DESCRIPTOR_VERSION` stays `"wardline-generic-2"` everywhere in S0 (the check script + `test_package.py:47` + CI `verify.yml:82-85` pin it). The generic-3 fixture is a SEMANTIC fixture — parsed and field-asserted, NOT byte-pinned; wardline's S1 producer output gets byte-frozen (and blob-pinned on both sides) when it exists.

- [ ] **Step 1: Write the failing tests** — append to `plugins/python/tests/test_wardline_descriptor.py` (its idiom: inline `mkdir` + `write_text` at `:214-221`; module fixture `_DESCRIPTOR` at `:15-29` carries NO schema line):

```python
GENERIC_3_FIXTURE = (
    Path(__file__).parent / "fixtures" / "wardline-vocabulary-descriptor.generic-3.preview.yaml"
)


def _plant(tmp_path: Path, text: str) -> None:
    descriptor = tmp_path / ".weft" / "wardline" / "vocabulary.yaml"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(text, encoding="utf-8")


def test_generic_3_descriptor_is_accepted_not_skew(tmp_path: Path) -> None:
    # Consumer-first dual-accept (wardline declaration-surface-v2 §13.1.1):
    # the (wardline.vocabulary/v2, wardline-generic-3) PAIR is accepted BEFORE
    # wardline can emit it. The v2 schema's new `facets:` section is an unknown
    # top-level key to this parser — tolerated by construction.
    _plant(tmp_path, GENERIC_3_FIXTURE.read_text(encoding="utf-8"))
    state = load_wardline_descriptor(tmp_path)
    assert state.status == "enabled"
    assert state.descriptor_version == "wardline-generic-3"
    assert state.vocabulary is not None
    assert state.vocabulary.confidence_basis == "descriptor"
    assert set(state.vocabulary.entries_by_name) >= {"external_boundary", "trust_boundary", "trusted"}


def test_generic_3_with_v1_schema_is_pair_mismatch_skew(tmp_path: Path) -> None:
    # Version alone is NOT enough: generic-3 under the v1 schema is not an
    # accepted PAIR — degrade to skew exactly like an unknown version.
    _plant(tmp_path, _DESCRIPTOR.replace("wardline-generic-2", "wardline-generic-3"))
    state = load_wardline_descriptor(tmp_path)
    assert state.status == "version_skew"
    assert state.descriptor_version == "wardline-generic-3"


def test_generic_9_is_still_version_skew(tmp_path: Path) -> None:
    _plant(tmp_path, _DESCRIPTOR.replace("wardline-generic-2", "wardline-generic-9"))
    state = load_wardline_descriptor(tmp_path)
    assert state.status == "version_skew"
    assert state.descriptor_version == "wardline-generic-9"
```

(`_DESCRIPTOR` has no `schema:` line — absent schema defaults to v1, so `test_generic_3_with_v1_schema_is_pair_mismatch_skew` exercises the pair rule through BOTH the absent-schema default and the version bump. The existing skew tests at `:52`, `:116`, `:213-227` keep passing unchanged for the same reason.)

- [ ] **Step 2: Author the semantic preview fixture** — `plugins/python/tests/fixtures/wardline-vocabulary-descriptor.generic-3.preview.yaml` (NO comments inside — content only; comments would survive into byte comparisons later):

```yaml
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

- [ ] **Step 3: Run to verify failure** — from `/home/john/loomweave`: `uv run pytest plugins/python/tests/test_wardline_descriptor.py -v`. Expected: `test_generic_3_descriptor_is_accepted_not_skew` FAILS with `status == "version_skew"`; the pair-mismatch and generic-9 tests already pass (both are skew today).

- [ ] **Step 4: Implement (schema, version) pair acceptance** in `wardline_descriptor.py`:
  1. Replace `:30` with:

```python
EXPECTED_DESCRIPTOR_VERSION = "wardline-generic-2"
# Pre-schema descriptors (no `schema:` key) are the v1 era by definition.
_DEFAULT_SCHEMA = "wardline.vocabulary/v1"
# Consumer-first dual-accept (wardline declaration-surface-v2 §13.1.1): the
# (schema, version) PAIR gates acceptance — generic-3 is accepted only under
# the v2 schema, BEFORE wardline emits it. EXPECTED_DESCRIPTOR_VERSION remains
# the canonical current version for messages/tooling and the manifest pin.
ACCEPTED_DESCRIPTORS: frozenset[tuple[str, str]] = frozenset(
    {
        ("wardline.vocabulary/v1", "wardline-generic-2"),
        ("wardline.vocabulary/v2", "wardline-generic-3"),
    }
)
```

  2. `WardlineVocabulary` gains a field `schema: str` (after `version`); `_parse_descriptor` reads it:

```python
    schema = descriptor.get("schema")
    if schema is None:
        schema = _DEFAULT_SCHEMA
    if not isinstance(schema, str):
        msg = "descriptor schema must be a string when present"
        raise _DescriptorError(msg)
```

     …and passes `schema=schema` to both `WardlineVocabulary(...)` constructions (`_parse_descriptor`'s at :183-188 and the skew-branch copy in `_state_from_text` :151-156).
  3. The gate at `:146` becomes:

```python
    if (vocabulary.schema, vocabulary.version) not in ACCEPTED_DESCRIPTORS:
```

     (the degrade-to-`version_skew` body is unchanged).

- [ ] **Step 5: plugin.toml + check script.** In `plugin.toml` `[integrations.wardline]` (:77-78) — STRING value, never an array (manifest.rs:137):

```toml
[integrations.wardline]
expected_descriptor_version = "wardline-generic-2"
accepted_descriptor_versions = "wardline-generic-2 wardline-generic-3"
```

In `scripts/check-wardline-version-bounds.py`: add module constant `ACCEPTED_DESCRIPTOR_VERSIONS = ("wardline-generic-2", "wardline-generic-3")`; in `wardline_descriptor_version()` after the existing pin check (:94-98), add:

```python
    accepted_raw = section.get("accepted_descriptor_versions")
    if not isinstance(accepted_raw, str) or tuple(accepted_raw.split()) != ACCEPTED_DESCRIPTOR_VERSIONS:
        raise CheckError(
            f"{manifest_path} [integrations.wardline].accepted_descriptor_versions must be the "
            f"space-separated string {' '.join(ACCEPTED_DESCRIPTOR_VERSIONS)!r}, got {accepted_raw!r}"
        )
    if value not in accepted_raw.split():
        raise CheckError(
            f"{manifest_path} expected_descriptor_version {value!r} is not in accepted_descriptor_versions"
        )
```

Extend `run_self_test()`: the `aligned` manifest text gains the `accepted_descriptor_versions` line; add one `_expect(manifest, "accepted_descriptor_versions")` case with the key missing, and one with a wrong value. Extend `plugins/python/tests/test_package.py:47-49`:

```python
    assert manifest["integrations"]["wardline"]["accepted_descriptor_versions"].split() == sorted(
        ["wardline-generic-2", "wardline-generic-3"]
    )
```

- [ ] **Step 6: Update the conformance test's meaning.** In `test_wardline_vocabulary_descriptor_conformance.py`, the `:250` test (`test_consumer_version_gate_rejects_skew_copy`) still passes — the golden carries `schema: wardline.vocabulary/v1` (line 1), so the generic-3 substitution produces the UNACCEPTED pair (v1, generic-3). Update its docstring: "…the gate keys on the (schema, version) PAIR: the same golden bytes with only the version bumped are a pair mismatch — the proof that version alone cannot unlock v2 parsing." Add the acceptance twin right below it:

```python
def test_consumer_accepts_the_v2_pair(tmp_path: Path) -> None:
    # The dual-accept half: the (wardline.vocabulary/v2, wardline-generic-3)
    # pair from the SEMANTIC preview fixture is enabled, not skew. This fixture
    # is field-asserted, never byte-pinned — the byte-freeze happens in S1 when
    # wardline's producer emits real generic-3 bytes (Rollout Fence).
    preview = Path(__file__).parent / "fixtures" / "wardline-vocabulary-descriptor.generic-3.preview.yaml"
    _write_project_descriptor(tmp_path, preview.read_text(encoding="utf-8"))
    state = load_wardline_descriptor(tmp_path)
    assert state.status == "enabled"
    assert state.descriptor_version == "wardline-generic-3"
```

- [ ] **Step 7: Run the loomweave gates** — from `/home/john/loomweave`:
  1. `uv run pytest plugins/python/tests/test_wardline_descriptor.py plugins/python/tests/test_wardline_vocabulary_descriptor_conformance.py plugins/python/tests/test_package.py -q` — PASS; the generic-2 golden byte-pin (`UPSTREAM_BLOB_SHA`) is untouched.
  2. `python scripts/check-wardline-version-bounds.py --self-test && python scripts/check-wardline-version-bounds.py` — both green.
  3. `cargo test -p loomweave-core manifest && cargo test -p loomweave-storage --test writer_actor python_plugin_edge_kinds_are_accepted_by_writer_contract` — proves the string key parses (manifest.rs:137) and the production manifest still loads.

- [ ] **Step 8: Commit (orchestrator, in /home/john/loomweave, current branch, explicit paths only)** — `feat(wardline-descriptor): dual-accept via (schema, version) pairs — generic-2/v1 + generic-3/v2 — with semantic preview fixture (consumer-first)`

---

### Task 18: `wardline-attest-3` staged — contract doc, shared vector, verifier dual-read, MCP surface (§13.1.2, wardline side)

**Files:**
- Modify: `src/wardline/core/attest.py` (after :63; verify conjunct :368-374; the three return sites :379-384/:399-404/:408-413; docstring)
- Modify: `src/wardline/mcp/server.py` (`_VERIFY_ATTESTATION_OUTPUT_SCHEMA` :3509-3539; tool `description` :3546-3547)
- Modify: `tests/conformance/mcp_output_schemas.golden.json` + `tests/conformance/test_mcp_output_schema_golden.py:69` (`VENDORED_BLOB_SHA`) — golden re-freeze #2
- Modify: `tests/conformance/test_mcp_structured_output.py:303-316` (assert the new key)
- Modify: `tests/conformance/test_attest_contract_freeze.py`
- Modify: `tests/conformance/seam_registry.json:490-507`
- Create: `docs/contracts/wardline-attest-3.md`
- Create: `tests/conformance/fixtures/wardline-attest-3.vector.json`
- Create: `tests/conformance/test_attest_dual_read.py`

**Interfaces:**
- Produces: `ACCEPTED_ATTEST_SCHEMAS: tuple[str, ...] = ("wardline-attest-2", "wardline-attest-3")` (LITERALS — never `(ATTEST_SCHEMA, ...)`, which would silently lose v2 when the constant bumps in S1); `verify_attestation` reports gain `"schema_recognized": bool` at ALL THREE return sites. Warpline (Task 19) vendors the vector byte-for-byte and re-derives its HMAC as the cross-impl pin.
- Verified mechanics this task rides: `_sign(payload, key, *, schema=ATTEST_SCHEMA)` already binds the BUNDLE'S OWN recorded schema at verify (`:366` passes `schema=schema`), which is exactly why the "correctly re-signed unknown schema" case is distinguishable only via the split; the MCP handler returns `verify_attestation`'s dict verbatim into an `additionalProperties: False` schema, so the schema + description + golden must move in this same commit.

- [ ] **Step 1: Write the failing tests** — `tests/conformance/test_attest_dual_read.py`:

```python
"""Consumer-first dual-read for wardline-attest-3 (declaration-surface-v2 §13.1.2).

Wardline still EMITS attest-2 (the freeze test pins that). This suite proves the
verifier RECOGNISES attest-3 — schema recognition is split out of
signature_valid so an attest-3 bundle is distinguishable from a bad key or a
tampered payload — and freezes the shared attest-3 vector warpline vendors."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wardline.core.attest import ACCEPTED_ATTEST_SCHEMAS, ATTEST_SCHEMA, _sign, verify_attestation

VECTOR = Path(__file__).parent / "fixtures" / "wardline-attest-3.vector.json"
# Public, test-only key — the vector is a conformance artefact, not a secret.
VECTOR_KEY = "wardline-attest-3-conformance-vector-key"


def _bundle() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_accepted_schemas_are_pinned() -> None:
    assert ATTEST_SCHEMA == "wardline-attest-2"  # S0 emits v2, unchanged
    assert ACCEPTED_ATTEST_SCHEMAS == ("wardline-attest-2", "wardline-attest-3")


def test_attest_3_vector_signature_is_internally_consistent() -> None:
    bundle = _bundle()
    assert bundle["schema"] == "wardline-attest-3"
    expected = _sign(bundle["payload"], VECTOR_KEY, schema="wardline-attest-3")
    assert bundle["signature"]["value"] == expected["value"]


# ---- the five-case recognition/validity matrix ----


def test_valid_v3_is_recognised_and_valid() -> None:
    report = verify_attestation(_bundle(), VECTOR_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is True


def test_wrong_key_is_recognised_but_invalid() -> None:
    report = verify_attestation(_bundle(), "not-the-vector-key")
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is False


def test_tampered_v3_is_recognised_but_invalid() -> None:
    bundle = _bundle()
    bundle["payload"]["commit"] = "0" * 40
    report = verify_attestation(bundle, VECTOR_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is False


def test_correctly_resigned_unknown_schema_is_unrecognised() -> None:
    # THE case the split exists for: _sign binds the bundle's own recorded
    # schema tag, so a wardline-attest-9 bundle re-signed with the RIGHT key
    # over its own tag has a matching HMAC — recognition is the only thing
    # separating it from a real bundle. Both flags must be False.
    bundle = _bundle()
    bundle["schema"] = "wardline-attest-9"
    bundle["signature"] = _sign(bundle["payload"], VECTOR_KEY, schema="wardline-attest-9")
    report = verify_attestation(bundle, VECTOR_KEY)
    assert report["schema_recognized"] is False
    assert report["signature_valid"] is False


def test_missing_schema_is_unrecognised() -> None:
    bundle = _bundle()
    del bundle["schema"]
    report = verify_attestation(bundle, VECTOR_KEY)
    assert report["schema_recognized"] is False
    assert report["signature_valid"] is False


def test_attest_2_bundles_still_verify_with_the_new_key_present() -> None:
    payload = {"wardline_version": "1.5.0", "attested_at": "2026-08-09", "commit": None, "dirty": False}
    bundle = {"schema": ATTEST_SCHEMA, "payload": payload, "signature": _sign(payload, VECTOR_KEY)}
    report = verify_attestation(bundle, VECTOR_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is True
    assert set(report) == {"schema_recognized", "signature_valid", "reproduced", "mismatches", "note"}


def test_vendored_warpline_copy_is_byte_identical_when_present() -> None:
    # Layer-2 cross-repo drift check (the loomweave descriptor-golden pattern):
    # warpline vendors this vector byte-for-byte; a one-sided edit reds here.
    repo = os.environ.get("WARPLINE_REPO", "/home/john/warpline")
    vendored = Path(repo) / "tests" / "fixtures" / "wardline-attest-3.vector.json"
    if not vendored.exists():
        pytest.skip(f"warpline vendored vector not found at {vendored} — set WARPLINE_REPO to enable")
    assert vendored.read_bytes() == VECTOR.read_bytes()
```

- [ ] **Step 2: Generate the vector once** (scratch script; the tests then freeze it — the HMAC pin makes any later edit loud):

```python
# uv run python <scratchpad>/gen_attest3_vector.py
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
        {
            "qualname": "svc.fetch_order",
            "sei": "loomweave:eid:9adc480cd5aa4d71503c19fd8b29907e",
            "content_hash": "blake3:" + "cd" * 16,
            "verdict": "clean",
            "tier": "ASSURED",
        }
    ],
    "sei_source": "loomweave",
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

- [ ] **Step 3: Run to verify the dual-read failures** — `uv run pytest tests/conformance/test_attest_dual_read.py -v`. Expected: FAIL on the `ACCEPTED_ATTEST_SCHEMAS` import, then on `schema_recognized`.

- [ ] **Step 4: Implement the verifier split** in `src/wardline/core/attest.py`. After `:63` add:

```python
# Consumer-first dual-read (declaration-surface-v2 §13.1.2): the verifier
# RECOGNISES attest-3 before the builder EMITS it (S1). LITERALS on purpose —
# deriving the first element from ATTEST_SCHEMA would silently drop v2 from the
# accepted set the moment S1 bumps the constant. Order = oldest first.
ACCEPTED_ATTEST_SCHEMAS: tuple[str, ...] = ("wardline-attest-2", "wardline-attest-3")
```

Replace the conjunct block at `:368-374` with:

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

Add `"schema_recognized": schema_recognized,` as the FIRST key of ALL THREE return dicts (:379-384, :399-404, :408-413). Extend the docstring's signature paragraph: "An unrecognised schema reports `schema_recognized=False` — distinguishable from a wrong key or tamper even when the bundle was re-signed over its own unknown tag (the signer binds the recorded schema). A recognised non-current schema (`wardline-attest-3`) signature-verifies against its own recorded tag; `--reproduce` re-derives the CURRENT builder's payload, so a v3 bundle verified before S1 honestly reports the v3-only keys as mismatches (the `sei_diagnostics` precedent)."

- [ ] **Step 5: Update the MCP surface (same commit).**
  1. `_VERIFY_ATTESTATION_OUTPUT_SCHEMA` (:3509-3539): add to `properties` (first entry) `"schema_recognized": {"type": "boolean", "description": "True iff the bundle's schema tag is one this verifier accepts (wardline-attest-2 | wardline-attest-3). False means signature_valid is necessarily false too — an unrecognised schema is not a validity verdict."}` and prepend `"schema_recognized"` to `required`.
  2. Tool `description` (:3546-3547): the prose embeds the key set — change to `"Returns {schema_recognized, signature_valid, reproduced, mismatches, note}."`.
  3. Re-freeze `tests/conformance/mcp_output_schemas.golden.json` with the SAME scratch script as Task 7 Step 4 and update `VENDORED_BLOB_SHA` (:69).
  4. `tests/conformance/test_mcp_structured_output.py:303-316`: after `assert verified["signature_valid"] is True` add `assert verified["schema_recognized"] is True` (the `_validated` helper already jsonschema-validates the new key against the amended schema).

- [ ] **Step 6: Author `docs/contracts/wardline-attest-3.md`** with these sections (content from spec §11.2; follow `wardline-attest-2.md`'s structure): **Status** — staged in S0: consumers dual-read; wardline emits v3 from S1 behind the Rollout Fence; **Envelope** — `{schema: "wardline-attest-3", payload, signature}`, HMAC-SHA256 over compact key-sorted JSON of `{"schema", "payload"}`, `key_id` = first 8 hex of sha256(key); **Payload** — everything in attest-2 PLUS `declarations[]` (sorted by `declaration_id`; entries `{declaration_id, kind, content_digest, verification_class, subject, sei?}`, `verification_class ∈ {machine_verified, structurally_verified, recorded_unverified}`), `declaration_counts` (per-kind, zero-filled), `declaration_debt` (`lapsed_expiries`, `stale_dependency_pins`, `record_only_claims`), `grants` (`trusted_packs`, `trust_dependency_taint`, `strict_defaults`), `dependency_taint_digest` (nullable), `authorship_note` (payload-resident HMAC disclaimer, D3); **Shared vector** — `tests/conformance/fixtures/wardline-attest-3.vector.json`, key `wardline-attest-3-conformance-vector-key`, vendored byte-for-byte by warpline (Layer-2 byte-compare on the wardline side; HMAC re-derivation as warpline's cross-impl pin); **Verification** — `verify_attestation` reports `schema_recognized` separately from `signature_valid`; the boundary key-set/verdict vocabulary is unchanged from v2; **Migration** — attest-2 bundles verify unchanged; attest-1 remains rejected everywhere.

- [ ] **Step 7: Update the freeze + registry.** `test_attest_contract_freeze.py`: keep `test_attest_schema_tag_frozen` exactly as is (emission is still v2); add `test_accepted_schemas_include_staged_v3` asserting the tuple literal, and `test_v3_contract_doc_exists` asserting `docs/contracts/wardline-attest-3.md` exists. `seam_registry.json` attest row (:490-507): append to the `wire` text "; attest-3 STAGED consumer-first (verifier + warpline dual-read, shared vector tests/conformance/fixtures/wardline-attest-3.vector.json); producer emits v3 from S1", add the new doc/vector/test paths to the evidence list, and correct stale refs while there (`attest.py:62`→`:63`).

- [ ] **Step 8: Run** — `uv run pytest tests/conformance/test_attest_dual_read.py tests/conformance/test_attest_contract_freeze.py tests/conformance/test_mcp_output_schema_golden.py tests/conformance/test_mcp_structured_output.py tests/conformance/test_seam_registry.py tests/unit/core/test_attest.py tests/unit/mcp/test_server_attest.py -q` then full suite `uv run pytest -q`. Expected: PASS. (The Layer-2 warpline test SKIPS until Task 19 lands the vendored copy — re-run it after Task 19.)

- [ ] **Step 9: Commit** — `feat(attest): stage wardline-attest-3 — contract doc, shared vector, verifier schema_recognized split, MCP schema+golden re-freeze (S0 §13.1.2)`

---

### Task 19: Warpline dual-accept `attest-2 | attest-3` (§13.1.2, consumer side) — repo `/home/john/warpline`

**Files (all under `/home/john/warpline`):**
- Modify: `src/warpline/_attest.py` (:44 constants; :182-187 gate; :260 `source`)
- Create: `tests/fixtures/wardline-attest-3.vector.json` (byte-for-byte copy of wardline's `tests/conformance/fixtures/wardline-attest-3.vector.json`)
- Test: `tests/test_attest.py` (extend)

**Depends on Task 18 (vendors its vector).** Verified mechanics: the schema gate is `parsed["schema"] != ATTEST_SCHEMA` (:182); `source` is the CONSTANT, not a pass-through (:260) — it must become `parsed["schema"]` so the verdict names what it consumed; the bundle factory default is `schema: str = ATTEST_SCHEMA` (`tests/test_attest.py:47`); the attest-1 rejection is `:133-141` (and `:269-277` is a DIFFERENT guard — structurally-unusable — leave it alone).

- [ ] **Step 1: Write the failing tests** — append to `tests/test_attest.py` (reuse `_bundle`/`_boundary`/`_hashes`/`_risk`, `SEI_A`/`HASH_A`/`COMMIT`, `_COMPLETE` — all module helpers at :20-70):

```python
def test_attest_3_schema_is_accepted_and_named_as_source() -> None:
    verdict = _risk(
        impact_completeness=_COMPLETE,
        affected_seis=[SEI_A],
        bundle=_bundle(boundaries=[_boundary(SEI_A, HASH_A)], schema="wardline-attest-3"),
        current_commit=COMMIT,
        content_hash_for_sei=_hashes({SEI_A: HASH_A}),
    )
    assert verdict["risk"] == "proven"
    assert verdict["reason_code"] == "attested_clean"
    # The verdict names what it actually consumed — no constant echo.
    assert verdict["source"] == "wardline-attest-3"


# NOTE: test_unknown_schema_is_rejected (:133-141, attest-1) and
# test_structurally_unusable_bundle_is_schema_unknown (:269-277) stay untouched
# and must remain green — attest-1 and garbage stay rejected under dual-accept.


def test_vendored_attest_3_vector_parses_and_pins_the_hmac() -> None:
    import hashlib
    import hmac as hmac_mod
    import json
    from pathlib import Path

    from warpline._attest import parse_attest_bundle

    vector = json.loads(
        (Path(__file__).parent / "fixtures" / "wardline-attest-3.vector.json").read_text(encoding="utf-8")
    )
    parsed = parse_attest_bundle(vector)
    assert parsed["schema"] == "wardline-attest-3"
    assert "loomweave:eid:9adc480cd5aa4d71503c19fd8b29907e" in parsed["by_sei"]

    # Cross-impl canonicalization pin (the legis expected_signature pattern):
    # re-derive wardline's HMAC from first principles — compact, key-sorted,
    # UTF-8 JSON over {"schema", "payload"} with the public conformance key.
    # If either side's canonical-JSON formula drifts, this stops reproducing.
    material = json.dumps(
        {"schema": vector["schema"], "payload": vector["payload"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected = hmac_mod.new(b"wardline-attest-3-conformance-vector-key", material, hashlib.sha256).hexdigest()
    assert vector["signature"]["value"] == expected
```

- [ ] **Step 2: Copy the vector** — byte-identical: `cp /home/john/wardline/tests/conformance/fixtures/wardline-attest-3.vector.json /home/john/warpline/tests/fixtures/wardline-attest-3.vector.json` (create `tests/fixtures/` if absent), then `cmp` both files to confirm. (Wardline's `test_vendored_warpline_copy_is_byte_identical_when_present` now un-skips and enforces this forever.)

- [ ] **Step 3: Run to verify failure** — from `/home/john/warpline`: `uv run pytest tests/test_attest.py -v`. Expected: the acceptance test FAILS with `reason_code == "attestation_schema_unknown"`; the vector test passes already (parse + HMAC need no code change).

- [ ] **Step 4: Implement.** In `src/warpline/_attest.py`:
  1. `:44` becomes:

```python
ATTEST_SCHEMA = "wardline-attest-2"
# Dual-accept (wardline declaration-surface-v2 §13.1.2): attest-3 is honored
# BEFORE wardline emits it. LITERALS on purpose (deriving from ATTEST_SCHEMA
# would lose v2 when the constant bumps). attest-1 and anything else stay
# rejected.
ACCEPTED_ATTEST_SCHEMAS: frozenset[str] = frozenset({"wardline-attest-2", "wardline-attest-3"})
```

  2. The gate at `:182-187` becomes:

```python
    if parsed["schema"] not in ACCEPTED_ATTEST_SCHEMAS:
        return _unavailable(
            "attestation_schema_unknown",
            cause=f"attestation schema is {parsed['schema']!r}, not one of {sorted(ACCEPTED_ATTEST_SCHEMAS)}",
            fix="supply a wardline-attest-2 or wardline-attest-3 bundle (other attest schemas are not honored)",
        )
```

  3. The proven-verdict `source` at `:260` becomes `"source": parsed["schema"],` (the existing `:85` assertion `verdict["source"] == ATTEST_SCHEMA` still passes — an attest-2 bundle's parsed schema IS the constant).
  4. `parse_attest_bundle` needs no change (five-field projection; attest-3's additive payload keys pass through).

- [ ] **Step 5: Run warpline's attest tests** — `uv run pytest tests/test_attest.py -v`. Expected: PASS, including the untouched `:133-141` attest-1 rejection, `:269-277` structural rejection, and the closed-vocab test (`:280-295` — no new reason codes were minted). Then from `/home/john/wardline`: `uv run pytest tests/conformance/test_attest_dual_read.py -q` — the Layer-2 byte-compare now runs and passes.

- [ ] **Step 6: Commit (orchestrator, /home/john/warpline, current branch, explicit paths)** — `feat(attest): dual-accept wardline-attest-2|3, verdict source names the consumed schema, vendored shared vector (consumer-first)`

---

### Task 20: Legis unknown-key tolerance pin + declarations preview vector (§13.1.3) — repos `/home/john/wardline` + `/home/john/legis`

**Files:**
- Create (wardline, the authority copy): `tests/conformance/fixtures/wardline-legis-declarations-preview.v1.json`
- Create (wardline): `tests/conformance/test_legis_declarations_preview_vector.py`
- Create (legis, byte-identical vendored copy): `tests/contract/weft/vectors/wardline_declarations_preview.v1.json`
- Create (legis): `tests/contract/weft/test_unknown_artifact_key_tolerance.py`

**Verified mechanics this task pins:** `wardline_artifact_fields` (`ingest.py:255-263`) copies every non-signature key — NO allowlist — so an additive `declarations` key is signature-covered automatically; `verify_wardline_artifact` (`:266-367`) requires only the four `ARTIFACT_PROVENANCE_FIELDS` + `artifact_signature` in keyed posture; `active_defects` (`:482-499`) requires `findings` present; `scan_digest` (`service/wardline.py:221`) = `sha256(canonical_json(artifact minus signature))`, so the added key SHIFTS it (additive but audit-visible, by design). The legis contract tests are vector-driven with the plain UTF-8 key `test-shared-secret-key` — no fixtures, no helpers. Spec §13.1.3: legis "receives the wire vectors for lockstep adoption" — wardline authors the preview vector; legis vendors it.

- [ ] **Step 1: Author the preview vector** (wardline authority copy) — `tests/conformance/fixtures/wardline-legis-declarations-preview.v1.json`. Modeled on the legis golden's shape (`wardline_scan_artifact.v1.json` `valid[0]`), widened with the S1-preview `declarations` key; NO `expected_signature` (the `clean_scan_empty_findings` precedent — the consumer test computes and verifies live, so no cross-side hex pin exists to re-freeze in S1):

```json
{
  "contract": "weft/wardline-scan-artifact-declarations-preview",
  "description": "S0 preview vector for wardline's S1 additive `declarations` member (declaration-surface-v2 §13.1.3). Pins legis's stated posture TODAY: unknown top-level keys are accepted, swept into the signed payload, and shift scan_digest (audit-visible, by design). Authored in wardline, vendored byte-identical in legis.",
  "signing": {
    "key_utf8": "test-shared-secret-key",
    "scheme": "hmac-sha256:v2",
    "policy": "no expected_signature hex: the consumer test signs and verifies live, so the S1 producer can extend `declarations` without a two-sided hex re-pin of THIS vector (the main scan-artifact vector keeps that role)."
  },
  "valid": [
    {
      "name": "declarations_preview_signed",
      "description": "The golden single-defect artifact widened with an empty declarations ledger: signature must cover it, verification must accept it, scan_digest must shift.",
      "artifact": {
        "scanner_identity": "wardline@1.5.0",
        "rule_set_version": "sha256:deadbeef",
        "commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
        "tree_sha": "tttttttttttttttttttttttttttttttttttttttt",
        "findings": [
          {
            "rule_id": "PY-WL-101",
            "message": "leak",
            "severity": "ERROR",
            "kind": "defect",
            "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "qualname": "svc.leaky",
            "properties": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW"},
            "suppression_state": "active"
          }
        ],
        "declarations": []
      }
    }
  ]
}
```

- [ ] **Step 2: Write the legis pin** — `tests/contract/weft/test_unknown_artifact_key_tolerance.py`:

```python
"""Wardline declaration-surface-v2 §13.1.3 — legis's stated posture, pinned.

Legis accepts unknown top-level keys in the wardline scan artifact today:
``wardline_artifact_fields`` copies every non-signature key (no allowlist,
ingest.py:255-263) and ``verify_wardline_artifact`` requires only the four
provenance fields + the signature. Wardline's S1 additive ``declarations``
member depends on this tolerance, so it is pinned here — with its one
observable side effect: ``scan_digest`` covers the whole artifact, so the added
key SHIFTS the digest (additive, but visible in the audit record, by design).
Vector: vendored byte-identical from wardline (the authority copy)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from legis.canonical import content_hash
from legis.crypto.signing import sign
from legis.wardline.ingest import (
    active_defects,
    verify_wardline_artifact,
    wardline_artifact_fields,
)

VECTOR_PATH = Path(__file__).parent / "vectors" / "wardline_declarations_preview.v1.json"
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
_KEY = VECTOR["signing"]["key_utf8"].encode("utf-8")


def _ids(cases: list[dict]) -> list[str]:
    return [c["name"] for c in cases]


def test_vector_self_describes() -> None:
    assert VECTOR["contract"] == "weft/wardline-scan-artifact-declarations-preview"


@pytest.mark.parametrize("case", VECTOR["valid"], ids=_ids(VECTOR["valid"]))
def test_unknown_declarations_key_is_signature_covered_and_verifies(case: dict) -> None:
    artifact = dict(case["artifact"])
    fields = wardline_artifact_fields(artifact)
    assert "declarations" in fields  # swept into the signed payload — no allowlist
    signed = {**artifact, "artifact_signature": sign(fields, _KEY)}
    provenance = verify_wardline_artifact(signed, artifact_key=_KEY)
    assert provenance["artifact_status"] == "verified"
    # The gate population is untouched by the unknown key.
    assert [f.fingerprint for f in active_defects(signed)] == [
        f["fingerprint"] for f in artifact["findings"]
    ]


@pytest.mark.parametrize("case", VECTOR["valid"], ids=_ids(VECTOR["valid"]))
def test_added_key_shifts_the_scan_digest(case: dict) -> None:
    artifact = dict(case["artifact"])
    without = {k: v for k, v in artifact.items() if k != "declarations"}
    assert content_hash(wardline_artifact_fields(without)) != content_hash(
        wardline_artifact_fields(artifact)
    )
```

- [ ] **Step 3: Vendor + wardline-side receipt.** Copy the vector byte-identically: `cp /home/john/wardline/tests/conformance/fixtures/wardline-legis-declarations-preview.v1.json /home/john/legis/tests/contract/weft/vectors/wardline_declarations_preview.v1.json`, confirm with `cmp`. Then create the wardline-side Layer-2 receipt — `tests/conformance/test_legis_declarations_preview_vector.py`:

```python
"""The wardline↔legis declarations preview vector (spec §13.1.3): wardline
authors it, legis vendors it byte-identically. This receipt reds on one-sided
drift, exactly like the descriptor-golden and attest-vector Layer-2 checks."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

AUTHORITY = Path(__file__).parent / "fixtures" / "wardline-legis-declarations-preview.v1.json"


def test_vector_parses_and_carries_the_preview_key() -> None:
    vector = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    assert vector["contract"] == "weft/wardline-scan-artifact-declarations-preview"
    assert all("declarations" in case["artifact"] for case in vector["valid"])


def test_legis_vendored_copy_is_byte_identical_when_present() -> None:
    repo = os.environ.get("LEGIS_REPO", "/home/john/legis")
    vendored = Path(repo) / "tests" / "contract" / "weft" / "vectors" / "wardline_declarations_preview.v1.json"
    if not vendored.exists():
        pytest.skip(f"legis vendored vector not found at {vendored} — set LEGIS_REPO to enable")
    assert vendored.read_bytes() == AUTHORITY.read_bytes()
```

- [ ] **Step 4: Run** — from `/home/john/legis`: `uv run pytest tests/contract/weft/test_unknown_artifact_key_tolerance.py -v`. Expected: PASS — this pins EXISTING behaviour; if it fails, legis is NOT tolerant, spec §13.1.3's premise is wrong: STOP and report to John before any S1 work. From `/home/john/wardline`: `uv run pytest tests/conformance/test_legis_declarations_preview_vector.py -v`. Expected: PASS.

- [ ] **Step 5: Commits (orchestrator).** Wardline: `test(conformance): author the wardline↔legis declarations preview vector + Layer-2 receipt (S0 §13.1.3)` (files: the fixture + receipt test). Legis (current branch, explicit paths): `test(weft): pin unknown-artifact-key tolerance + vendor wardline's declarations preview vector`.

---

## Rollout Fence — what S1 may and may not assume (record of decision)

S0 stages consumers; S1 flips producers. The fence below is copied into S1's plan as preconditions — S1 must not start its version bumps until every line holds.

**1. Consumer readiness floors (commits, not version strings).** Loomweave's plugin version is CI-lockstepped to the Rust workspace (`scripts/check-workspace-version-lockstep.py` — six files move together), and warpline/legis version bumps are release decisions, so the enforceable floor is: *the Task 17 commit merged in loomweave, the Task 19 commit merged in warpline, the Task 20 commit merged in legis*, each on its repo's working branch. Record the three commit hashes in the S0 close comment on `wardline-5a795253f1`.

**2. Cold-install fence.** The operative tool stack installs from LOCAL checkouts (`uv tool install wardline[loomweave,rust]`, non-editable — same-version reinstalls need `--reinstall --no-cache`). Before S1 flips emission: reinstall the stack and verify the INSTALLED consumers, not the checkouts:
- `python -c "from loomweave_plugin_python.wardline_descriptor import ACCEPTED_DESCRIPTORS; assert ('wardline.vocabulary/v2','wardline-generic-3') in ACCEPTED_DESCRIPTORS"`
- `python -c "from warpline._attest import ACCEPTED_ATTEST_SCHEMAS; assert 'wardline-attest-3' in ACCEPTED_ATTEST_SCHEMAS"`
- restart any long-running `wardline mcp` / federation processes (stale-server precedent, PR #30).

**3. S1 emission preflight (wardline side).** In the same S1 commit that bumps `REGISTRY_VERSION`/`ATTEST_SCHEMA`: bump `_RESOLVER_VERSION`; re-vendor `vocabulary.yaml` + descriptor golden + `UPSTREAM_BLOB_SHA` (both repos); byte-freeze the real generic-3 producer output against Task 17's SEMANTIC fixture (promote it to a byte-pinned golden with a blob SHA on both sides only THEN); update Task 11's pinned fingerprint literal `decorator-vocab:wardline-generic-2` and Task 18's `test_attest_schema_tag_frozen`.

**4. The generic-3 inversion trap (S1 must re-tokenize four tests).** Four loomweave tests derive their skew case by literally replacing `"wardline-generic-2"` → `"wardline-generic-3"` (`test_wardline_descriptor.py:52,116,217`; `test_wardline_vocabulary_descriptor_conformance.py:261`). Once generic-3 is accepted-and-expected, those derivations invert (the conformance one even self-asserts `skewed != golden` and reds). S1 switches their skew token to `"wardline-generic-9"`. Task 17 deliberately does NOT touch them — they still pass in S0 because (v1-or-absent schema, generic-3) remains an unaccepted pair.

**5. Legis two-sided re-pin (S1).** When S1 adds real `declarations` content to the MAIN scan-artifact vector (`wardline_scan_artifact.v1.json`), its `expected_signature` hex is pinned on BOTH sides (the legis vector note says the hex is identical to wardline's golden in `tests/unit/core/test_legis_artifact.py`) — a two-sided re-pin in one coordinated pair of commits, plus the documented `scan_digest` shift in every routed scan. The Task 20 preview vector deliberately carries no hex so it needs no re-pin.

**6. Rollback ordering.** If S1's flip misbehaves: revert the WARDLINE producer commit first (emission returns to generic-2/attest-2 — consumers' dual-accept keeps working); consumer dual-accept commits stay in place (harmless surplus acceptance). Never revert consumers while a producer emits the new formats.

**7. Shared-artifact discipline table.**

| Artifact | Authority | Vendored copy | Pin mechanism |
|---|---|---|---|
| vocabulary descriptor golden (generic-2) | wardline `tests/conformance/fixtures/` | loomweave `plugins/python/tests/fixtures/` | git-blob SHA both sides (`UPSTREAM_BLOB_SHA`) + Layer-2 byte-compare (existing) |
| generic-3 preview fixture | loomweave (SEMANTIC, Task 17) | — | field assertions only; byte-freeze deferred to S1 §3 |
| attest-3 vector | wardline `tests/conformance/fixtures/` (Task 18) | warpline `tests/fixtures/` (Task 19) | HMAC self-consistency (wardline) + cross-impl HMAC re-derivation (warpline) + Layer-2 byte-compare (wardline) |
| declarations preview vector | wardline `tests/conformance/fixtures/` (Task 20) | legis `tests/contract/weft/vectors/` | live sign/verify (legis) + Layer-2 byte-compare (wardline); no hex by design |
| MCP output-schema golden | wardline only | — | `VENDORED_BLOB_SHA` (re-frozen Tasks 7 + 18) |

---

## Final verification (after all tasks)

- [ ] Wardline: `uv run pytest -q` (full), `uv run lint-imports`, `uv run mypy src`, `uv run ruff check src tests` — all green.
- [ ] Self-scan gate (CLAUDE.md command, whole repo): `uv run wardline scan . --fail-on ERROR` — exit 0. If PY-WL-130 fires anywhere in the repo, the marker use it found is a REAL defect — fix the source, never suppress (the self-hosting gate demands zero committed suppressions).
- [ ] End-to-end bug reproduction (the ticket's scenario): a scratch project with `@trusted(level="INTEGRAL", audit=True)` + a taint sink now exits 1 at `--fail-on ERROR` (was: exit 0, the false green). Record the before/after in the `wardline-4928b75782` close comment.
- [ ] Loomweave: descriptor + conformance + package pytest, both check scripts, the two cargo tests (Task 17 Step 7). Warpline: `uv run pytest tests/test_attest.py`. Legis: `uv run pytest tests/contract/weft -q`.
- [ ] Cross-repo Layer-2 receipts from the wardline side: `uv run pytest tests/conformance/test_attest_dual_read.py tests/conformance/test_legis_declarations_preview_vector.py -q` — no skips (both vendored copies present).
- [ ] Filigree (orchestrator): close `wardline-4928b75782` (fixed by Tasks 2–6, commit refs + repro) — if not already closed at the Task 6 boundary per the Filigree discipline section; close `wardline-5a795253f1` with the full commit list + the three consumer commit hashes (Rollout Fence §1); note in epic `wardline-aee6ae068b` that S0 is done and S1 (`wardline-7342234667`) is unblocked pending P0 re-review.

## Self-review notes (spec + review coverage)

- Ticket item (a) → Tasks 1–5; (b) → Tasks 6–7; (c) P1/P2/P3 → Task 8, P4 → Task 9, P7 → Task 10, P8 → Task 11, P9 → Task 2, P10 → Task 12, P13 → Task 14; (d) → Task 15; (e) → Task 16. Spec §12 P5/P6/P12 → Task 13; P11 both directions → Task 6. P14 → Tasks 1–5. §13.1.1 → Task 17; §13.1.2 → Tasks 18–19; §13.1.3 → Task 20; §13.1 sequencing → Rollout Fence.
- NO-GO findings disposition: (1) `to_level` exception removed → Tasks 3–5 + changelog; (2) inventory pins + P9 completeness + pipeline override + validator → Tasks 5, 2, 6, 2/4; (3) QE tests rebuilt on verified APIs → Tasks 8, 10, 11, 12, 13; (4) MCP surface + literal accepted-schemas + 5-case matrix → Task 18; (5) (schema,version) pairs + conformance test + string-encoded manifest key → Task 17; (6) consumer DAG/fence/vectors/semantic-vs-byte → Task-order note + Rollout Fence + Task 20; (7) placeholders/ellipses/artifact_key/CODEOWNERS wording/bump-terms/scan-scope/filigree ordering → all task bodies, Task 15, Task 16, Final Verification, Filigree discipline.
- Deliberately NOT in S0: any weft-markers export, `REGISTRY_VERSION`/`vocabulary.yaml`/`ATTEST_SCHEMA` changes, attest-3 EMISSION, the declarations inventory factory, per-group inertness arming, fixes to the two Task 13-filed engine bugs (golden-drifting / semantics-changing — S1+ with their own tickets).





