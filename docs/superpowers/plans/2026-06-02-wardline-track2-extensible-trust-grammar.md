# Track 2 — Extensible Trust Grammar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Wardline's three hardcoded trust decorators and four hardcoded rules into one open, agent-extensible *trust grammar* — without changing any builtin finding (byte-identical oracle) and without adding a dependency.

**Architecture:** A new `src/wardline/scanner/grammar.py` defines the meta-model (`LevelArg`, `BoundaryType`, `TrustGrammar`, `default_grammar()`). `DecoratorTaintSourceProvider._match` is rewritten as a generic loop over `grammar.boundary_types`; `build_default_registry` takes the rule set from `grammar.rules`. Builtins are preloaded defaults derived from the released `REGISTRY` (which stays frozen). An agent extends via `default_grammar().extend(...)` and constructs the analyzer with it — zero engine edits. Unprovable *custom* boundaries emit a `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT (builtins never do, preserving the oracle).

**Tech Stack:** Python 3.12+, stdlib only (zero-dep base); `uv run pytest` / `ruff` / `mypy`; the existing JSONL emitter for the golden.

**Design spec:** `docs/superpowers/specs/2026-06-02-wardline-track2-extensible-trust-grammar-design.md` — read §1 (acceptance fixture + litmus), §3 (REGISTRY blocker), §4 (T2.4 scoping), §5 (oracle), §6 (fingerprint).

**The litmus (every task is subordinate to it):** landing the Task 6 acceptance fixture must require **zero edits** to `decorator_provider._match`, `rules/__init__._ALL_RULE_CLASSES`, and `core/registry._ENTRIES`.

---

## File Structure

- **Create** `src/wardline/scanner/grammar.py` — `LevelArg`, `BoundaryType`, `TrustGrammar`, `default_grammar()`, `BUILTIN_BOUNDARY_TYPES`. The meta-model. Imports: stdlib + `core.taints` + `scanner.taint.provider` (for `FunctionTaint`) only.
- **Modify** `src/wardline/scanner/taint/provider.py` — add `SeedResult`; widen `TaintSourceProvider.taint_for` return to `SeedResult`; update `DefaultTaintSourceProvider`.
- **Modify** `src/wardline/scanner/taint/decorator_provider.py` — `_match` if-ladder → generic boundary-type loop; constructor takes `boundary_types`; `fingerprint()` incorporates grammar identity (legacy string for builtins); return `SeedResult`.
- **Modify** `src/wardline/scanner/taint/function_level.py` — `FunctionSeed` gains `unprovable_boundary`; `seed_function_taints` consumes `SeedResult` and returns boundary diagnostics.
- **Modify** `src/wardline/scanner/rules/__init__.py` — `build_default_registry(config, *, rules=None)`; default from `default_grammar().rules`.
- **Modify** `src/wardline/scanner/analyzer.py` — hoist a `grammar`; wire provider + registry from it; add a `build_analyzer(grammar=...)` helper; emit the `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACTs.
- **Create** `tests/grammar/` — `test_golden_oracle.py` (Task 0), `test_grammar_model.py`, `test_provider_loop.py`, `test_unprovable_boundary.py`, `test_acceptance_custom_grammar.py`, `fixtures/`.
- **Create** `tests/grammar/golden/builtin_findings.jsonl` — the committed byte-identity golden (Task 0).
- **Modify** `docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md` — Track 2 status (Task 7).

---

## Task 0: Mechanize the byte-identity oracle (RED-first for the refactor)

**Files:**
- Create: `tests/grammar/__init__.py` (empty)
- Create: `tests/grammar/golden_harness.py`
- Create: `tests/grammar/test_golden_oracle.py`
- Create: `tests/grammar/golden/builtin_findings.jsonl` (generated, then committed)

The oracle must be captured **before** any grammar code so the refactor diffs against a frozen golden (design spec §5). **It covers the T1.4 corpus** (fixed input where all 4 builtin rules fire), including FACTs/METRICs and emission order, serialized via `Finding.to_jsonl()`. **Not the dogfood tree** — the refactor adds source files (`scanner/grammar.py`), which legitimately moves the dogfood scan's METRIC counts; dogfood-clean is guarded by `tests/test_self_hosting.py` (zero DEFECT, tolerates growth). *(This corpus-only scoping was confirmed empirically while building Task 0 — the corpus portion stayed byte-identical when a new src file was added; only dogfood metrics drifted. The harness in the repo reflects this; the two-root sketch below is superseded.)*

- [ ] **Step 1: Write the harness that produces the canonical stream**

`tests/grammar/golden_harness.py`:

```python
"""Byte-identity oracle harness (Track 2, Task 0).

Produces the canonical findings stream for the builtin grammar over the dogfood
tree + the T1.4 corpus, serialized exactly as `wardline scan` would (the shared
emitter, fingerprints included). Used to freeze a golden before the grammar
refactor and to assert byte-for-byte reproduction after it.
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import WardlineAnalyzer

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).resolve().parent / "golden" / "builtin_findings.jsonl"

# Two roots, analyzed independently and concatenated in a fixed order so the
# golden is deterministic regardless of cwd. Each root scanned with its own
# repo-relative paths (findings carry root-relative paths).
_TARGETS = (
    ("src/wardline", REPO_ROOT),
    ("tests/corpus/fixtures", REPO_ROOT),
)


def produce_stream() -> str:
    # Serialize via the SHIPPED per-finding serializer Finding.to_jsonl() — the
    # exact line format core.emit.JsonlEmitter writes; verified: emit.py has no
    # module-level serializer, JsonlEmitter just writes `finding.to_jsonl()` lines.
    chunks: list[str] = []
    for rel, root in _TARGETS:
        target = root / rel
        files = sorted(target.rglob("*.py"))
        analyzer = WardlineAnalyzer()  # builtin grammar / default provider + registry
        findings = analyzer.analyze(files, WardlineConfig(), root=root)
        chunks.append("\n".join(f.to_jsonl() for f in findings))
    return "\n=== ROOT BOUNDARY ===\n".join(chunks)
```

> CONFIRMED (no longer open): `core/emit.py` exposes only `JsonlEmitter` (writes `finding.to_jsonl()` per line) — there is no module-level `findings_to_jsonl`. The harness above uses `Finding.to_jsonl()` directly, which is the real shipped line format. This is real `wardline scan` output, not an invented serializer.

- [ ] **Step 2: Generate and commit the golden**

Run a one-off (in the test or a throwaway snippet) to write `produce_stream()` to `tests/grammar/golden/builtin_findings.jsonl`. Inspect it: it must contain DEFECT findings for the corpus (21 TRUE_POSITIVE per Track 1) and FACTs/metrics; the dogfood section must be DEFECT-free. Commit it.

- [ ] **Step 3: Write the oracle test (passes against TODAY's engine)**

`tests/grammar/test_golden_oracle.py`:

```python
from __future__ import annotations

from grammar.golden_harness import GOLDEN, produce_stream
# (import form CONFIRMED: tests/ is not a package; pytest puts tests/ on sys.path,
#  so the module is `grammar.golden_harness` — mirroring `from corpus.harness import
#  reconcile` already used in tests/corpus/test_fp_rate.py.)


def test_builtin_findings_match_golden() -> None:
    expected = GOLDEN.read_text(encoding="utf-8")
    actual = produce_stream()
    assert actual == expected, "builtin findings stream drifted from the frozen golden"
```

- [ ] **Step 4: Run it — must PASS now**

Run: `uv run pytest tests/grammar/test_golden_oracle.py -v`
Expected: PASS (the golden was just generated from the same engine). This is the tripwire every later task must keep green.

- [ ] **Step 5: Commit**

```bash
git add tests/grammar/
git commit -m "test(track2): freeze byte-identity golden for builtin grammar (T0)"
```

---

## Task 1: The grammar meta-model (`grammar.py`) — T2.1

**Files:**
- Create: `src/wardline/scanner/grammar.py`
- Create: `tests/grammar/test_grammar_model.py`

- [ ] **Step 1: Write failing tests for the model + builtin/REGISTRY consistency**

`tests/grammar/test_grammar_model.py`:

```python
from __future__ import annotations

from wardline.core.registry import REGISTRY
from wardline.core.taints import TaintState
from wardline.scanner.grammar import (
    BUILTIN_BOUNDARY_TYPES,
    BoundaryType,
    LevelArg,
    TrustGrammar,
    default_grammar,
)
from wardline.scanner.taint.provider import FunctionTaint


def test_default_grammar_has_three_builtins_and_four_rules() -> None:
    g = default_grammar()
    assert tuple(bt.canonical_name for bt in g.boundary_types) == (
        "external_boundary", "trust_boundary", "trusted",
    )
    assert len(g.rules) == 4
    assert [r.rule_id for r in g.rules] == ["PY-WL-101", "PY-WL-102", "PY-WL-103", "PY-WL-104"]


def test_builtin_boundary_types_align_with_registry() -> None:
    # One source of truth: builtin names/group/attr-names must mirror REGISTRY (spec §3).
    by_name = {bt.canonical_name: bt for bt in BUILTIN_BOUNDARY_TYPES}
    assert set(by_name) == set(REGISTRY)
    for name, entry in REGISTRY.items():
        bt = by_name[name]
        assert bt.group == entry.group
        assert {la.arg_name for la in bt.level_args} == {
            k.removeprefix("_wardline_").replace("to_level", "to_level") for k in entry.attrs
        } or {la.arg_name for la in bt.level_args} == _expected_args(name)


def _expected_args(name: str) -> set[str]:
    return {"external_boundary": set(), "trust_boundary": {"to_level"}, "trusted": {"level"}}[name]


def test_seed_semantics_round_trip() -> None:
    by_name = {bt.canonical_name: bt for bt in BUILTIN_BOUNDARY_TYPES}
    assert by_name["external_boundary"].seed({}) == FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW)
    assert by_name["trust_boundary"].seed({"to_level": TaintState.ASSURED}) == FunctionTaint(
        TaintState.EXTERNAL_RAW, TaintState.ASSURED
    )
    assert by_name["trusted"].seed({"level": TaintState.INTEGRAL}) == FunctionTaint(
        TaintState.INTEGRAL, TaintState.INTEGRAL
    )


def test_extend_appends_never_replaces() -> None:
    custom = BoundaryType(
        canonical_name="sanitized", module_prefix="myproj.trust", group=1,
        level_args=(LevelArg("to_level", frozenset({TaintState.GUARDED}), None),),
        seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]), builtin=False,
    )
    g = default_grammar().extend(boundary_types=(custom,))
    assert g.boundary_types[:3] == default_grammar().boundary_types  # builtins still first, unchanged
    assert g.boundary_types[-1] is custom
    assert g.rules == default_grammar().rules
```

> The implementer should simplify `test_builtin_boundary_types_align_with_registry` to whatever cleanly expresses "builtin arg names match the known per-decorator set"; the `_expected_args` fallback shows the intended mapping. Keep the *intent*: builtins can't drift from REGISTRY silently.

- [ ] **Step 2: Run — must FAIL (module missing)**

Run: `uv run pytest tests/grammar/test_grammar_model.py -v`
Expected: FAIL — `ModuleNotFoundError: wardline.scanner.grammar`.

- [ ] **Step 3: Implement `grammar.py`**

`src/wardline/scanner/grammar.py`:

```python
# src/wardline/scanner/grammar.py
"""The extensible trust grammar (Track 2).

Generalizes Wardline's three hardcoded trust decorators and four hardcoded rules
into one open meta-model an agent can extend WITHOUT editing engine source, while
the builtin vocabulary keeps producing byte-identical findings.

Layering (preserved, load-bearing): a `BoundaryType` feeds L1 seeding (declaration
-> taint); rules read the RESOLVED taint state, not the decorator. The grammar
registers both; it does not couple them per-instance.

Zero-dep: stdlib + core.taints + the provider's FunctionTaint only.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from wardline.core.registry import REGISTRY
from wardline.core.taints import TaintState
from wardline.scanner.context import _Rule  # the rule Protocol (rule_id + check)
from wardline.scanner.taint.provider import FunctionTaint

_VOCAB_PREFIX = "wardline.decorators"
_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})


@dataclass(frozen=True, slots=True)
class LevelArg:
    """A statically-read keyword argument of a boundary marker (e.g. ``to_level``).

    ``default=None`` means REQUIRED: a missing/unreadable/out-of-range value is a
    fail-closed seed (the engine returns the unprovable signal — see the provider).
    """

    arg_name: str
    allowed: frozenset[TaintState]
    default: TaintState | None


@dataclass(frozen=True, slots=True)
class BoundaryType:
    """A declared trust transition: a recognizable decorator marker + its L1 seed.

    ``module_prefix`` + ``canonical_name`` are how the engine RECOGNIZES the marker
    on a target's AST (alias-resolved). ``level_args`` is what it reads from the call
    site (generic machinery in the provider). ``seed`` maps the read levels to the
    function's seed taint. ``builtin`` gates the T2.4 unprovable FACT (builtins never
    emit it, preserving the byte-identity oracle).
    """

    canonical_name: str
    module_prefix: str
    group: int
    level_args: tuple[LevelArg, ...]
    seed: Callable[[Mapping[str, TaintState]], FunctionTaint]
    builtin: bool = False


# --- Builtin boundary types: one source of truth, aligned with REGISTRY (spec §3) ---

def _seed_external(levels: Mapping[str, TaintState]) -> FunctionTaint:
    return FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW)


def _seed_boundary(levels: Mapping[str, TaintState]) -> FunctionTaint:
    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])


def _seed_trusted(levels: Mapping[str, TaintState]) -> FunctionTaint:
    return FunctionTaint(levels["level"], levels["level"])


BUILTIN_BOUNDARY_TYPES: tuple[BoundaryType, ...] = (
    BoundaryType("external_boundary", _VOCAB_PREFIX, 1, (), _seed_external, builtin=True),
    BoundaryType(
        "trust_boundary", _VOCAB_PREFIX, 1,
        (LevelArg("to_level", _BOUNDARY_LEVELS, default=None),),
        _seed_boundary, builtin=True,
    ),
    BoundaryType(
        "trusted", _VOCAB_PREFIX, 1,
        (LevelArg("level", _TRUSTED_LEVELS, default=TaintState.INTEGRAL),),
        _seed_trusted, builtin=True,
    ),
)

# Consistency tripwire: builtin names/group must mirror the released REGISTRY.
for _bt in BUILTIN_BOUNDARY_TYPES:
    _entry = REGISTRY.get(_bt.canonical_name)
    if _entry is None or _entry.group != _bt.group:
        raise ValueError(f"builtin BoundaryType {_bt.canonical_name!r} drifted from REGISTRY")
del _bt, _entry


@dataclass(frozen=True, slots=True)
class TrustGrammar:
    """The wiring object: the boundary types (L1 seeding) + rule classes (enforcement)."""

    boundary_types: tuple[BoundaryType, ...]
    rules: tuple[type[_Rule], ...]

    def extend(
        self,
        *,
        boundary_types: tuple[BoundaryType, ...] = (),
        rules: tuple[type[_Rule], ...] = (),
    ) -> TrustGrammar:
        """Append agent-defined types/rules to the defaults (append, never replace)."""
        return TrustGrammar(self.boundary_types + tuple(boundary_types), self.rules + tuple(rules))


def default_grammar() -> TrustGrammar:
    """The builtin grammar: 3 boundary types + 4 rule classes, in today's exact order."""
    from wardline.scanner.rules import BUILTIN_RULE_CLASSES  # local import: avoid cycle

    return TrustGrammar(BUILTIN_BOUNDARY_TYPES, BUILTIN_RULE_CLASSES)
```

> Note: `BUILTIN_RULE_CLASSES` is introduced in Task 4 (a rename/exposure of `_ALL_RULE_CLASSES`). Until Task 4 lands, `default_grammar()` will raise on import of that name — Task 1's tests that call `default_grammar()` depend on Task 4. **Sequencing fix:** do Step 3 of Task 4 (expose `BUILTIN_RULE_CLASSES`) as part of Task 1, OR run Task 1's `default_grammar()`-dependent assertions after Task 4. Simplest: land the one-line `BUILTIN_RULE_CLASSES = _ALL_RULE_CLASSES` export (Task 4 Step 3) here in Task 1 first. The implementer should make that tiny export now so Task 1 is self-contained.

- [ ] **Step 4: Add the `BUILTIN_RULE_CLASSES` export** (pulled forward from Task 4)

In `src/wardline/scanner/rules/__init__.py`, after `_ALL_RULE_CLASSES`:

```python
# Public alias: the builtin rule set the default grammar preloads (Track 2).
BUILTIN_RULE_CLASSES = _ALL_RULE_CLASSES
```

- [ ] **Step 5: Run — must PASS**

Run: `uv run pytest tests/grammar/test_grammar_model.py -v`
Expected: PASS.

- [ ] **Step 6: Oracle still green + lint/type**

Run: `uv run pytest tests/grammar/test_golden_oracle.py && uv run ruff check src/wardline/scanner/grammar.py && uv run mypy`
Expected: all PASS (no engine wiring changed yet).

- [ ] **Step 7: Commit**

```bash
git add src/wardline/scanner/grammar.py tests/grammar/test_grammar_model.py src/wardline/scanner/rules/__init__.py
git commit -m "feat(track2): trust-grammar meta-model — BoundaryType/TrustGrammar/default_grammar (T2.1)"
```

---

## Task 2: `SeedResult` seam + provider returns it — T2.4 plumbing (no behavior change yet)

**Files:**
- Modify: `src/wardline/scanner/taint/provider.py`
- Modify: `src/wardline/scanner/taint/function_level.py`
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (return-shape only; loop comes in Task 3)
- Test: `tests/unit/scanner/taint/test_provider.py`, `tests/unit/scanner/taint/test_function_level.py`

This widens the seam contract `taint_for -> FunctionTaint | None` to `taint_for -> SeedResult`. It is purely structural here (the carried `unprovable_boundary` stays `None` for all current providers); the FACT emission is Task 5. Doing the seam change in isolation keeps the oracle green and the diff reviewable.

- [ ] **Step 1: Write failing tests for the new seam shape**

Add to `tests/unit/scanner/taint/test_provider.py`:

```python
from wardline.scanner.taint.provider import SeedResult, FunctionTaint, DefaultTaintSourceProvider
from wardline.core.taints import TaintState


def test_default_provider_returns_empty_seedresult() -> None:
    # The trivial provider: no opinion -> SeedResult(taint=None, unprovable_boundary=None)
    res = DefaultTaintSourceProvider().taint_for(_dummy_entity(), _dummy_ctx())
    assert isinstance(res, SeedResult)
    assert res.taint is None
    assert res.unprovable_boundary is None
```

(Reuse the file's existing `_dummy_entity`/`_dummy_ctx` helpers; if absent, build a minimal `Entity` + `SeedContext` as the file's other tests do.)

- [ ] **Step 2: Run — FAIL** (`SeedResult` undefined; default provider returns `None`).

Run: `uv run pytest tests/unit/scanner/taint/test_provider.py -v`

- [ ] **Step 3: Add `SeedResult` and rewire the seam**

In `src/wardline/scanner/taint/provider.py`, add after `FunctionTaint`:

```python
@dataclass(frozen=True, slots=True)
class SeedResult:
    """A provider's per-entity result: the declared seed taint (or None for 'no
    opinion', preserving the UNKNOWN_RAW fail-closed fallback), plus the
    canonical_name of a matched-but-UNPROVABLE *custom* boundary type, if any
    (the analyzer turns that into a WLN-ENGINE-UNPROVABLE-BOUNDARY FACT — T2.4).
    Builtins never set ``unprovable_boundary`` (byte-identity oracle, spec §4)."""

    taint: FunctionTaint | None
    unprovable_boundary: str | None = None
```

Change the Protocol:

```python
    def taint_for(self, entity: Entity, ctx: SeedContext) -> SeedResult: ...
```

Change `DefaultTaintSourceProvider.taint_for` to `return SeedResult(taint=None)`.

- [ ] **Step 4: Thread through `function_level.py`**

In `FunctionSeed`, add field `unprovable_boundary: str | None = None`. In `seed_function_taints`, consume `SeedResult`:

```python
    for entity in entities:
        res = provider.taint_for(entity, ctx)
        declared = res.taint
        if declared is None:
            seeds[entity.qualname] = FunctionSeed(
                qualname=entity.qualname, body_taint=_FALLBACK, return_taint=_FALLBACK,
                source="default", unprovable_boundary=res.unprovable_boundary,
            )
        else:
            seeds[entity.qualname] = FunctionSeed(
                qualname=entity.qualname, body_taint=declared.body_taint,
                return_taint=declared.return_taint, source="provider",
                unprovable_boundary=res.unprovable_boundary,
            )
```

- [ ] **Step 5: Make `DecoratorTaintSourceProvider.taint_for` return `SeedResult`**

Currently it returns `FunctionTaint | None`. Wrap its existing result: where it returns `None`, return `SeedResult(taint=None)`; where it returns a `FunctionTaint ft`, return `SeedResult(taint=ft)`. (The `_match` *internals* are untouched here — only `taint_for`'s wrapper. The generic loop is Task 3.)

- [ ] **Step 6: Update any other `taint_for` callers/fakes**

Run: `grep -rn "taint_for\|FunctionTaint(" tests/ src/` — update test doubles and assertions that expected the old `FunctionTaint | None` return to the `SeedResult` shape.

- [ ] **Step 7: Run targeted + oracle + suite**

Run: `uv run pytest tests/unit/scanner/taint tests/grammar/test_golden_oracle.py -v`
Expected: PASS — `unprovable_boundary` is `None` everywhere, so no behavior changed.

- [ ] **Step 8: Commit**

```bash
git add src/wardline/scanner/taint tests/unit/scanner/taint
git commit -m "refactor(track2): widen taint seam to SeedResult (T2.4 plumbing, no behavior change)"
```

---

## Task 3: Generic boundary-type loop in the provider — T2.2 (delete the if-ladder)

**Files:**
- Modify: `src/wardline/scanner/taint/decorator_provider.py`
- Test: `tests/grammar/test_provider_loop.py`, existing `tests/unit/scanner/taint/test_decorator_provider.py`

The litmus task: replace the `if canonical == "external_boundary" / ...` dispatch with a loop over `self._boundary_types`. The builtin behavior is reproduced exactly (oracle); a custom type now rides the same path.

- [ ] **Step 1: Write failing tests for loop-driven matching of a CUSTOM type**

`tests/grammar/test_provider_loop.py`:

```python
from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import FunctionTaint, SeedContext
# build an Entity from a snippet the way the existing decorator_provider tests do


def _entity(src: str):
    tree = ast.parse(src)
    fn = tree.body[0]
    # match how tests/unit/scanner/taint/test_decorator_provider.py builds Entity
    ...


def test_custom_boundary_type_seeds_via_loop() -> None:
    custom = BoundaryType(
        "sanitized", "myproj.trust", 1,
        (LevelArg("to_level", frozenset({TaintState.GUARDED, TaintState.ASSURED}), None),),
        lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]), builtin=False,
    )
    provider = DecoratorTaintSourceProvider(boundary_types=default_grammar().boundary_types + (custom,))
    ent = _entity("import myproj.trust\n@myproj.trust.sanitized(to_level='GUARDED')\ndef f(p):\n    return p\n")
    res = provider.taint_for(ent, SeedContext(module="m", alias_map={"myproj": "myproj"}))
    assert res.taint == FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.GUARDED)


def test_unprovable_custom_boundary_signals() -> None:
    custom = BoundaryType(
        "sanitized", "myproj.trust", 1,
        (LevelArg("to_level", frozenset({TaintState.GUARDED}), None),),  # required
        lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]), builtin=False,
    )
    provider = DecoratorTaintSourceProvider(boundary_types=default_grammar().boundary_types + (custom,))
    # to_level is a bare Name (unreadable) -> fail-closed
    ent = _entity("import myproj.trust\n@myproj.trust.sanitized(to_level=CFG)\ndef f(p):\n    return p\n")
    res = provider.taint_for(ent, SeedContext(module="m", alias_map={"myproj": "myproj"}))
    assert res.taint is None
    assert res.unprovable_boundary == "sanitized"


def test_unprovable_BUILTIN_does_not_signal() -> None:
    # Oracle-preserving twin: an unreadable builtin level stays silent (no FACT).
    provider = DecoratorTaintSourceProvider()  # builtins only
    ent = _entity("from wardline.decorators import trust_boundary\n@trust_boundary(to_level=CFG)\ndef f(p):\n    return p\n")
    res = provider.taint_for(ent, SeedContext(module="m", alias_map={}))
    assert res.taint is None
    assert res.unprovable_boundary is None
```

- [ ] **Step 2: Run — FAIL** (`DecoratorTaintSourceProvider` has no `boundary_types` kwarg; no loop).

- [ ] **Step 3: Rewrite the provider to loop over boundary types**

In `decorator_provider.py`:
- Add `__init__(self, *, boundary_types: tuple[BoundaryType, ...] | None = None)` defaulting to `BUILTIN_BOUNDARY_TYPES` (import from `wardline.scanner.grammar`). Store `self._boundary_types`.
- Replace `_match`'s if-ladder with a generic match against `self._boundary_types`:

```python
    def _match(self, deco: ast.expr, alias_map: Mapping[str, str]) -> tuple[FunctionTaint | None, str | None]:
        """Return (seed_taint, unprovable_custom_name). Generic over boundary types.

        (seed, None)            -> a type matched and proved
        (None, name)            -> a CUSTOM type matched but a required arg was unreadable
        (None, None)            -> no type matched (not vocabulary) — 'no opinion'
        """
        fqn = _resolve_decorator_fqn(deco, alias_map)
        if fqn is None:
            return None, None
        for bt in self._boundary_types:
            full = bt.module_prefix + "." + bt.canonical_name
            if fqn != full:
                continue
            levels: dict[str, TaintState] = {}
            unreadable = False
            for la in bt.level_args:
                lvl = _read_level(deco, la.arg_name, allowed=la.allowed, default=la.default, alias_map=alias_map)
                if lvl is None:
                    unreadable = True
                    break
                levels[la.arg_name] = lvl
            if unreadable:
                # Fail-closed. Custom types surface the under-seed as a FACT (T2.4);
                # builtins stay silent to hold the byte-identity oracle (spec §4).
                return None, (None if bt.builtin else bt.canonical_name)
            return bt.seed(levels), None
        return None, None
```

- Rewrite `taint_for` to aggregate across decorators using the existing per-field least-trusted conflict rule, and surface an `unprovable_boundary` if any matched-custom-unprovable was seen and no proven taint won:

```python
    def taint_for(self, entity: Entity, ctx: SeedContext) -> SeedResult:
        candidates: list[FunctionTaint] = []
        unprovable: str | None = None
        for deco in entity.node.decorator_list:
            ft, unprov = self._match(deco, ctx.alias_map)
            if ft is not None:
                candidates.append(ft)
            elif unprov is not None and unprovable is None:
                unprovable = unprov
        if not candidates:
            return SeedResult(taint=None, unprovable_boundary=unprovable)
        body = max((ft.body_taint for ft in candidates), key=lambda t: TRUST_RANK[t])
        ret = max((ft.return_taint for ft in candidates), key=lambda t: TRUST_RANK[t])
        return SeedResult(taint=FunctionTaint(body, ret), unprovable_boundary=None)
```

> Note: when a function carries BOTH a provable and an unprovable-custom decorator, the provable seed wins and no FACT fires (the function IS anchored). That is correct: the unprovable annotation didn't change the resolved seed, so there is no under-seed to report. Document this in the method.

- The old `AssertionError`-on-REGISTRY-drift branch and the `canonical not in REGISTRY` check are **deleted** — recognition is now "matches a registered boundary type's `module_prefix.canonical_name`", not "in REGISTRY". (REGISTRY stays the released contract per spec §3; the consistency test in Task 1 prevents builtin drift.)

- [ ] **Step 4: Update `decorator_provider.fingerprint()` (grammar identity — spec §6)**

```python
    def fingerprint(self) -> str:
        # Builtin-only grammar keeps today's EXACT string (cache/baseline stability).
        if self._boundary_types == BUILTIN_BOUNDARY_TYPES:
            return f"decorator-vocab:{REGISTRY_VERSION}"
        # A custom grammar gets a distinct, stable digest so cached summaries from a
        # different loaded grammar cannot cross-contaminate (false-green guard).
        digest = _grammar_digest(self._boundary_types)
        return f"decorator-vocab:{REGISTRY_VERSION}+grammar:{digest}"
```

`_grammar_digest` = a stable sha256 over each boundary type's `(canonical_name, module_prefix, group, level_arg schema, seed-identity)`. Seed identity: use `seed.__qualname__` (callables aren't hashable-by-value); document that two grammars differing only in seed-function *body* but sharing a qualname is an accepted, vanishingly-rare collision (same caveat style as descriptor.py's `__name__` note). Order-sensitive over the tuple.

- [ ] **Step 5: Run targeted + the existing provider tests + oracle**

Run: `uv run pytest tests/grammar/test_provider_loop.py tests/unit/scanner/taint/test_decorator_provider.py tests/grammar/test_golden_oracle.py -v`
Expected: PASS. **The golden test is the proof the if-ladder→loop refactor is byte-identical.** If it fails, the loop diverged from the old dispatch — fix before proceeding.

- [ ] **Step 6: Full suite + lint + mypy**

Run: `uv run pytest && uv run ruff check src tests && uv run mypy`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/wardline/scanner/taint/decorator_provider.py tests/grammar/test_provider_loop.py tests/unit/scanner/taint/test_decorator_provider.py
git commit -m "feat(track2): generic boundary-type loop replaces _match if-ladder; grammar-aware fingerprint (T2.2)"
```

---

## Task 4: Rule set from the grammar + `build_analyzer` helper — T2.2

**Files:**
- Modify: `src/wardline/scanner/rules/__init__.py`
- Modify: `src/wardline/scanner/analyzer.py`
- Test: `tests/grammar/test_provider_loop.py` (extend) or new `tests/grammar/test_analyzer_wiring.py`

- [ ] **Step 1: Write failing test for `build_default_registry(rules=...)` and `build_analyzer(grammar=...)`**

`tests/grammar/test_analyzer_wiring.py`:

```python
from __future__ import annotations

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import build_analyzer
from wardline.scanner.grammar import default_grammar
from wardline.scanner.rules import build_default_registry


def test_build_default_registry_uses_grammar_rules() -> None:
    g = default_grammar()
    reg = build_default_registry(WardlineConfig(), rules=g.rules)
    assert [r.rule_id for r in reg.rules] == ["PY-WL-101", "PY-WL-102", "PY-WL-103", "PY-WL-104"]


def test_build_default_registry_default_is_builtin_rules() -> None:
    reg = build_default_registry(WardlineConfig())  # no rules= -> builtins
    assert [r.rule_id for r in reg.rules] == ["PY-WL-101", "PY-WL-102", "PY-WL-103", "PY-WL-104"]


def test_build_analyzer_threads_grammar_into_provider_and_registry() -> None:
    analyzer = build_analyzer(grammar=default_grammar())
    assert analyzer._provider.fingerprint() == build_analyzer()._provider.fingerprint()  # builtin == default
```

- [ ] **Step 2: Run — FAIL** (`build_analyzer` undefined; `rules=` kwarg missing).

- [ ] **Step 3: `build_default_registry(config, *, rules=None)`**

```python
def build_default_registry(config: WardlineConfig, *, rules: tuple[type, ...] | None = None) -> RuleRegistry:
    rule_classes = rules if rules is not None else BUILTIN_RULE_CLASSES
    registry = RuleRegistry()
    for cls in rule_classes:
        rule_id = cls.rule_id
        if not _enabled(rule_id, config.rules_enable):
            continue
        override = config.rules_severity.get(rule_id)
        base = Severity(override) if override is not None else None
        registry.register(cls(base_severity=base))
    return registry
```

(`BUILTIN_RULE_CLASSES` was exposed in Task 1 Step 4.)

- [ ] **Step 4: Add `build_analyzer` to `analyzer.py` and thread the grammar**

Add a module-level helper:

```python
def build_analyzer(
    *, grammar: TrustGrammar | None = None, summary_cache: SummaryCache | None = None
) -> WardlineAnalyzer:
    """Construct an analyzer from a TrustGrammar (default = builtins). The grammar's
    boundary types feed the provider; its rules feed the per-config registry."""
    g = grammar if grammar is not None else default_grammar()
    provider = DecoratorTaintSourceProvider(boundary_types=g.boundary_types)
    analyzer = WardlineAnalyzer(provider=provider, summary_cache=summary_cache)
    analyzer._grammar_rules = g.rules  # consumed in analyze() when building the default registry
    return analyzer
```

In `WardlineAnalyzer.__init__`, add `self._grammar_rules: tuple[type, ...] | None = None`. In `analyze()`, change the registry line:

```python
        registry = self._registry if self._registry is not None else build_default_registry(
            config, rules=self._grammar_rules
        )
```

> Cleaner alternative the implementer may prefer: give `WardlineAnalyzer.__init__` a `grammar: TrustGrammar | None` parameter directly (provider + rules derived inside), and make `build_analyzer` a thin wrapper or drop it. Either is fine **provided** existing `WardlineAnalyzer()` (no-arg) construction stays behavior-identical and the golden holds. Pick one, keep the no-arg path = builtins.

- [ ] **Step 5: Run targeted + oracle + full suite + lint + mypy**

Run: `uv run pytest tests/grammar tests/test_self_hosting.py tests/corpus && uv run pytest && uv run ruff check src tests && uv run mypy`
Expected: PASS. Golden still byte-identical (rule order/identity unchanged for builtins).

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/rules/__init__.py src/wardline/scanner/analyzer.py tests/grammar/test_analyzer_wiring.py
git commit -m "feat(track2): rule set + analyzer wiring from TrustGrammar; build_analyzer helper (T2.2)"
```

---

## Task 5: Emit `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT for unprovable customs — T2.4

**Files:**
- Modify: `src/wardline/scanner/taint/function_level.py` (return boundary diagnostics) or `analyzer.py` (collect from seeds)
- Modify: `src/wardline/scanner/analyzer.py` (emit the FACT)
- Test: `tests/grammar/test_unprovable_boundary.py`

- [ ] **Step 1: Write failing test for the FACT (custom fires; builtin twin does not)**

`tests/grammar/test_unprovable_boundary.py`:

```python
from __future__ import annotations

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import build_analyzer
from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
from wardline.scanner.taint.provider import FunctionTaint

_CUSTOM = BoundaryType(
    "sanitized", "myproj.trust", 1,
    (LevelArg("to_level", frozenset({TaintState.GUARDED}), None),),
    lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]), builtin=False,
)


def test_unprovable_custom_emits_fact_and_unknown_seed(tmp_path) -> None:
    f = tmp_path / "m.py"
    f.write_text("import myproj.trust\n@myproj.trust.sanitized(to_level=CFG)\ndef g(p):\n    return p\n")
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(_CUSTOM,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    facts = [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert len(facts) == 1
    assert facts[0].kind == Kind.FACT and facts[0].severity == Severity.NONE
    # and the function resolved to the UNKNOWN_RAW fail-closed seed
    assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW


def test_unprovable_BUILTIN_emits_no_fact(tmp_path) -> None:
    f = tmp_path / "m.py"
    f.write_text("from wardline.decorators import trust_boundary\n@trust_boundary(to_level=CFG)\ndef g(p):\n    return p\n")
    analyzer = build_analyzer()  # builtins only
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert not [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
```

- [ ] **Step 2: Run — FAIL** (no such FACT emitted).

- [ ] **Step 3: Collect boundary diagnostics and emit FACTs**

Make `seed_function_taints` also return the unprovable diagnostics with locations. Change its return to a small dataclass or a tuple `(seeds, boundary_diags)` where each diag is `(qualname, boundary_name, Location)`. (It iterates `entities`, so it has `entity.location`.) Update the single caller in `analyzer.py` (line ~125).

In `analyzer.py`, after the per-file seeding, append FACTs (mirroring `func_skip_findings`):

```python
                for qn, bname, loc in boundary_diags:
                    parse_findings.append(
                        Finding(
                            rule_id="WLN-ENGINE-UNPROVABLE-BOUNDARY",
                            message=f"{qn}: custom boundary @{bname} could not be proven "
                                    f"(argument unreadable) — seeded UNKNOWN_RAW",
                            severity=Severity.NONE,
                            kind=Kind.FACT,
                            location=loc,
                            fingerprint=_fp("WLN-ENGINE-UNPROVABLE-BOUNDARY", qn),
                            qualname=qn,
                            properties={"boundary": bname, "reason": "arg_unreadable"},
                        )
                    )
```

> Decision to record in the plan/PR: whether `WLN-ENGINE-UNPROVABLE-BOUNDARY` belongs in `UNANALYZED_RULE_IDS`. It is a *declared-but-unreadable annotation* (an honest under-seed at a point the developer DID annotate), not a file/function under-scan. Recommendation: **NOT** in `UNANALYZED_RULE_IDS` (it doesn't mean "we failed to scan this unit" — we scanned it; the annotation was unreadable). Confirm against how `UNANALYZED_RULE_IDS` is consumed (the unanalyzed-count metric) and document the choice.

- [ ] **Step 4: Run targeted + oracle + full suite**

Run: `uv run pytest tests/grammar tests/grammar/test_golden_oracle.py && uv run pytest`
Expected: PASS. Oracle holds (no builtin emits the new FACT; the corpus/dogfood have no custom boundaries).

- [ ] **Step 5: Lint + mypy + commit**

```bash
uv run ruff check src tests && uv run mypy
git add src/wardline/scanner/taint/function_level.py src/wardline/scanner/analyzer.py tests/grammar/test_unprovable_boundary.py
git commit -m "feat(track2): unprovable custom boundary -> WLN-ENGINE-UNPROVABLE-BOUNDARY FACT (T2.4)"
```

---

## Task 6: The end-to-end acceptance fixture — the DoD gate

**Files:**
- Create: `tests/grammar/fixtures/custom_grammar.py`
- Create: `tests/grammar/fixtures/target_uses_sanitized.py`
- Create: `tests/grammar/test_acceptance_custom_grammar.py`

This is the program-spec DoD's first gate. It must fire with the **litmus held** — verified by inspection: the fixture touches none of `_match`, `_ALL_RULE_CLASSES`, `_ENTRIES`.

- [ ] **Step 1: Author the custom grammar (agent-side, outside src/wardline)**

`tests/grammar/fixtures/custom_grammar.py` — a new boundary type `@myproj.trust.sanitized(to_level=...)` **and** a new rule. Choose a rule whose firing is unambiguous on the resolved state. Suggested rule `MYPROJ-001` "a `@sanitized` boundary that does not actually raise trust" — but to avoid re-deriving 102's logic, make it a clearly-novel check, e.g. **"a function whose resolved body taint is `EXTERNAL_RAW` but is reachable as a `@sanitized` boundary return"** — or simplest and unambiguous: a rule that fires on any anchored function returning less-trusted-than-declared *and* whose qualname matches a project convention. Keep it small; its job is to prove the seam, not to be a good rule.

```python
import ast
from collections.abc import Mapping

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg, FunctionTaint, default_grammar
from wardline.scanner.rules.metadata import RuleMetadata

SANITIZED = BoundaryType(
    canonical_name="sanitized",
    module_prefix="myproj.trust",
    group=1,
    level_args=(LevelArg("to_level", frozenset({TaintState.GUARDED, TaintState.ASSURED}), None),),
    seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
    builtin=False,
)


class SanitizerLeaksRaw:
    """MYPROJ-001 — a @sanitized boundary whose actual return is less trusted than declared."""
    rule_id = "MYPROJ-001"
    metadata = RuleMetadata(
        rule_id="MYPROJ-001", base_severity=Severity.ERROR, kind=Kind.DEFECT,
        description="A @sanitized boundary returns data less trusted than its declared to_level.",
    )

    def __init__(self, base_severity=None):
        self.base_severity = base_severity or self.metadata.base_severity

    def check(self, context):
        out = []
        for qn, entity in context.entities.items():
            prov = context.taint_provenance.get(qn)
            if prov is None or prov.source != "anchored":
                continue
            declared = context.project_return_taints.get(qn)
            actual = context.function_return_taints.get(qn)
            if declared is None or actual is None:
                continue
            if TRUST_RANK[actual] <= TRUST_RANK[declared]:
                continue
            out.append(Finding(
                rule_id=self.rule_id, message=f"{qn}: sanitizer leaks {actual.value} (declared {declared.value})",
                severity=self.base_severity, kind=Kind.DEFECT, location=entity.location,
                fingerprint=_fp(rule_id=self.rule_id, path=entity.location.path,
                                line_start=entity.location.line_start, qualname=qn,
                                taint_path=f"{actual.value}->{declared.value}"),
                qualname=qn, properties={"declared_return": declared.value, "actual_return": actual.value},
            ))
        return out


GRAMMAR = default_grammar().extend(boundary_types=(SANITIZED,), rules=(SanitizerLeaksRaw,))
```

`tests/grammar/fixtures/target_uses_sanitized.py` (the scanned target — static, never executed):

```python
import myproj.trust  # a marker module that need not exist at scan time (static read only)


@myproj.trust.sanitized(to_level="ASSURED")
def clean(p):
    return validate(p)        # returns declared trust -> no MYPROJ-001


@myproj.trust.sanitized(to_level="ASSURED")
def leaks(p):
    return read_raw(p)        # returns raw -> MYPROJ-001 fires


def read_raw(p): return p
def validate(p):
    if not p: raise ValueError
    return p
```

> The implementer must ensure `validate`/`read_raw` resolve so `clean` is genuinely clean and `leaks` genuinely leaks under the engine's L2/L3 — mirror the corpus fixtures' proven shapes. Adjust until the assertions below hold.

- [ ] **Step 2: Write the acceptance test**

`tests/grammar/test_acceptance_custom_grammar.py`:

```python
from __future__ import annotations

from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import build_analyzer
from grammar.fixtures.custom_grammar import GRAMMAR  # adjust import to resolved package form

FIX = Path(__file__).resolve().parent / "fixtures"


def test_agent_defined_boundary_and_rule_fire_end_to_end() -> None:
    analyzer = build_analyzer(grammar=GRAMMAR)
    findings = analyzer.analyze([FIX / "target_uses_sanitized.py"], WardlineConfig(), root=FIX)
    fired = [f for f in findings if f.rule_id == "MYPROJ-001"]
    assert len(fired) == 1
    assert fired[0].qualname.endswith(".leaks")
    # The @sanitized boundary seeded the taint the rule keyed on:
    assert analyzer.last_context.taint_provenance[fired[0].qualname].source == "anchored"
```

- [ ] **Step 3: Run — iterate until PASS**

Run: `uv run pytest tests/grammar/test_acceptance_custom_grammar.py -v`
Expected: PASS (the custom boundary + custom rule fire end-to-end).

- [ ] **Step 4: Verify the litmus by inspection (record in the commit message)**

Confirm with `git diff --stat` over the whole track that landing this fixture changed **zero** lines in `decorator_provider._match`, `rules/__init__._ALL_RULE_CLASSES`, and `core/registry._ENTRIES` *for the fixture itself* (those were generalized in Tasks 1–4; the fixture adds only new files). State this explicitly in the commit body.

- [ ] **Step 5: Full suite + lint + mypy + oracle + dogfood + corpus**

Run: `uv run pytest && uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy && make test-cov`
Expected: all PASS; coverage ≥90% global and ≥95% on `scanner/taint/` and `scanner/grammar.py`.

- [ ] **Step 6: Commit**

```bash
git add tests/grammar/fixtures tests/grammar/test_acceptance_custom_grammar.py
git commit -m "test(track2): end-to-end acceptance — agent-defined boundary type + rule fire (DoD gate; litmus held)"
```

---

## Task 7: Close-out — tracker, CHANGELOG, descriptor tripwire, panel review

**Files:**
- Modify: `docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Confirm the non-regression tripwires are green**

Run: `uv run pytest -k "descriptor or vocabulary"` (vocabulary.yaml ≡ descriptor.py drift), the warm/cold byte-identical test, and `tests/grammar/test_golden_oracle.py`. All must pass. Verify Clarion's probe still works: `uv run python -c "import wardline.core.registry as r; assert r.REGISTRY and r.REGISTRY_VERSION and r.RegistryEntry"`.

- [ ] **Step 2: Update the progress tracker**

In the Track 2 table set every unit ☑; update the "Current position" line to "Track 2 (extensible trust grammar) COMPLETE … next: T1.5 (rule breadth, on the grammar) / parallel T3.1–T3.3, T4.1–T4.2." Mark the grammar seam available for Track 5.

- [ ] **Step 3: CHANGELOG [Unreleased]**

Add Added: "Extensible trust grammar — agents can declare custom boundary types + rules via `wardline.scanner.grammar` (`default_grammar().extend(...)`); builtins unchanged." Added: "`WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT for unprovable custom boundaries." Note byte-identical builtins.

- [ ] **Step 4: Default code-review panel**

Dispatch the default code-review panel (SA, ST, PE, QE, SAE, SecArch) over the whole-track diff. Focus prompts: (a) litmus actually held (no builtin-only assumptions left in the loop); (b) oracle integrity (no path emits a new builtin FACT); (c) fingerprint/cache cross-contamination closed; (d) REGISTRY contract intact; (e) fail-closed inherited by the extension plane. Apply convergent must-fixes; file genuine tech debt.

- [ ] **Step 5: Commit the close-out**

```bash
git add docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md CHANGELOG.md
git commit -m "docs(track2): mark Track 2 complete; CHANGELOG; close-out"
```

---

## Self-review notes (spec coverage)

- T2.1 → Task 1. T2.2 → Tasks 3–4. T2.3 (byte-identical re-expression) → Task 0 golden + held green through Tasks 3–6. T2.4 → Tasks 2 (plumbing) + 5 (FACT). Acceptance fixture → Task 6. The three blockers: REGISTRY contract (Task 1 consistency test + Task 3 deletes REGISTRY-coupled recognition while leaving REGISTRY frozen + Task 7 probe check); oracle (Task 0); descriptor/vocabulary (unchanged because REGISTRY unchanged — Task 7 tripwire); fingerprint (Task 3 Step 4). Layering preserved (rules read resolved state) — Task 6's rule and all builtins.
- Type consistency: `SeedResult` introduced Task 2, consumed everywhere after; `BUILTIN_RULE_CLASSES` exposed Task 1 Step 4, consumed by `default_grammar()` and `build_default_registry`; `build_analyzer(grammar=)` introduced Task 4, used by Tasks 5–6.
- Open implementer confirmations (flagged inline, not placeholders): exact emitter symbol in `core/emit.py` (Task 0); `tests/` import-package form (`grammar.*` vs `tests.grammar.*`); `UNANALYZED_RULE_IDS` membership of the new FACT (Task 5).
