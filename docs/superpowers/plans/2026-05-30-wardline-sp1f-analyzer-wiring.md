# SP1f — Analyzer Wiring + Diagnostics + CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `NoOpAnalyzer` with `WardlineAnalyzer` — the end-to-end engine that parses a project, seeds L1, runs L3 transitive taint, computes per-file L2, exposes the result for SP2, and emits engine-diagnostic `Finding`s; add disk persistence to the summary cache and a `--cache-dir` CLI flag. After SP1f, `wardline scan <project>` computes real transitive taints end-to-end.

**Architecture:** A new `analyzer.py` orchestrates the SP1a–e pieces behind SP0's `Analyzer` protocol. Per file: read (LF-normalised) → `ast.parse` → index → L1 seed (pluggable provider) → `ModuleInput`. Then one `resolve_project_taints` call (full L3; `minimum_scope` is deliberately NOT on the pipeline — L3 subsumes its one-hop refinement, user-confirmed 2026-05-30). Then per-file L2 with a properly-built call-taint-map and a per-function `RecursionError` boundary. Engine diagnostics (metrics + facts) become `Finding`s; the taint map + L2 ride on an `AnalysisContext` for SP2. No policy rules ship (empty `RuleRegistry` seam). No SARIF/Filigree (SP4). No baseline (SP3).

**Tech Stack:** Python 3.12, stdlib `ast`/`hashlib`/`json`, `click` (CLI). Gate: `.venv/bin/python -m pytest -q` (the `test_self_hosting.py` xfail STAYS xfail — it is an SP2 gate, not SP1f), `.venv/bin/ruff check src tests`, `.venv/bin/mypy src`.

---

## Context for the implementer

SP1a–e are merged and green (418 passed, 1 xfailed). The contracts you wire:

- **SP0 `Analyzer` protocol** (`core/protocols.py`): `analyze(self, files: Sequence[Path], config: WardlineConfig, *, root: Path) -> Sequence[Finding]`. The analyzer receives file PATHS and must parse them itself.
- **`Finding`** (`core/finding.py`): `Finding(rule_id, message, severity: Severity, kind: Kind, location: Location, fingerprint, suggestion=None, qualname=None, confidence=None, related_entities=(), properties={})`. `Severity` = CRITICAL/ERROR/WARN/INFO/NONE; `Kind` = DEFECT/FACT/CLASSIFICATION/METRIC/SUGGESTION. `Location(path, line_start, line_end, col_start, col_end)`. `compute_placeholder_fingerprint(rule_id, path, line_start, message)` exists.
- **SP1a**: `core/qualname.module_dotted_name(rel_path) -> str | None` (None ⇒ emit nothing); `scanner/index.discover_file_entities(tree, *, module, path) -> list[Entity]`, `discover_class_qualnames(tree, *, module) -> set[str]`; `Entity(qualname, kind, node, location)`.
- **SP1a/c**: `scanner/ast_primitives.build_import_alias_map(tree, module_path=...) -> dict[str,str]`.
- **SP1b**: `scanner/taint/provider.{TaintSourceProvider, DefaultTaintSourceProvider, SeedContext, FunctionTaint}` — provider has `taint_for(entity, ctx)` and `fingerprint() -> str`. `scanner/taint/function_level.seed_function_taints(entities, *, ctx, provider) -> dict[str, FunctionSeed]`.
- **SP1c**: `scanner/taint/variable_level.compute_variable_taints(func_node, function_taint, taint_map) -> dict[str, TaintState]`. The `taint_map` is keyed by the **call-site name AS WRITTEN** (bare `"foo"` for `foo()`, dotted `"mod.fn"` for `mod.fn()`). `_resolve_call` checks `_SERIALISATION_SINKS` against the **literal** dotted name FIRST, then `taint_map.get(dotted)`, then bare `taint_map[name]`.
- **SP1b**: `scanner/taint/stdlib_taint.{load_stdlib_taint() -> Mapping[(pkg,fn), StdlibTaintEntry], stdlib_taint_keys()}`. `StdlibTaintEntry(taint, rationale)`. The yaml has 10 entries; sinks among them are `(json, loads)` and `(json, load)`. Non-sink examples: `(subprocess, check_output) -> EXTERNAL_RAW`, `(ast, literal_eval) -> GUARDED`.
- **SP1d**: `scanner/taint/project_resolver.{ModuleInput, resolve_project_taints}`; `ResolverResult(taint_map, project_edges, taint_provenance, diagnostics, metadata)`; `ResolverRunMetadata(scc_size_distribution, convergence_iterations_max, convergence_iterations_histogram, taint_source_counts)`; `propagation.TaintProvenance`. `ModuleInput(module_path, entities, class_qualnames, alias_map, seeds, source_bytes)`. Kernel diagnostics are `(code: str, message: str)` tuples — codes `"L3_CONVERGENCE_BOUND"`, `"L3_MONOTONICITY_VIOLATION"`, `"L3_LOW_RESOLUTION"`.
- **SP1e**: `scanner/taint/summary_cache.SummaryCache` (in-memory: get/put/invalidate/clear/hit_rate/hits/misses/__len__; 64-hex key validation). `resolve_project_taints(..., summary_cache=None, dirty_modules=None)` (both-or-neither).
- **SP0 wiring**: `core/discovery.discover(root, cfg) -> list[Path]`; `core/emit.JsonlSink(output).write(findings)`; `cli/scan.py` currently builds `NoOpAnalyzer`.

### Settled design decisions (apply; do not re-litigate)

1. **`minimum_scope` is NOT wired** (user-confirmed). Full L3 only. Leave the module + its tests as-is; document it as subsumed-by-L3.
2. **Serialization-sink vs stdlib precedence — the collision fix (CRITICAL).** When the L2 call-taint-map is built from `stdlib_taint`, any stdlib entry whose `(pkg, fn)` joins to a string in `_SERIALISATION_SINKS` MUST be inserted as `UNKNOWN_RAW`, not its stdlib taint. Reason: `_resolve_call`'s sink check matches the *literal* written name, so an aliased `import json as j; j.loads(p)` would skip the sink check and hit `taint_map["j.loads"]` — if that held the stdlib `GUARDED`, the result would be `GUARDED` (under-taint, false-negative). Inserting `UNKNOWN_RAW` for sink keys at construction makes literal and aliased calls agree. **Gate:** the discriminating test is `import json as j; x = j.loads(p)` ⇒ `UNKNOWN_RAW` (NOT the literal `json.loads`, which passes even with the bug).
3. **External-dotted-taint channel.** The L2 call-taint-map carries `stdlib_taint` (and project-function returns) keyed by **alias-resolved** call-site name. Positive test uses a **non-sink stdlib** entry: `import subprocess as sp; x = sp.check_output(c)` ⇒ `EXTERNAL_RAW`. (`pd.read_csv` is NOT stdlib — config-declared external taint rides the same mechanism when SP2 adds the vocabulary; do not build a config channel here.)
4. **`RecursionError` boundary.** Each function's `compute_variable_taints` runs inside `try/except RecursionError`; on error its var-taints collapse to empty (callers treat absent vars as the function taint / `UNKNOWN_RAW`). One pathological body must not abort the scan.
5. **CLI cache = `dirty_modules=frozenset()`.** A full scan declares nothing dirty; `cache_key` mismatches drive freshness automatically (changed file → new key → miss → recompute). No mtime/git dirty tracking. Disk: load before, save after.
6. **Fingerprints for engine diagnostics.** No taint path exists yet (taint-path identity lands with SP2 *defect* findings — nothing to fold in until rules exist; this is not deferral-of-doable-work). Make engine-diagnostic fingerprints stable from **identifying fields**: facts from `(module, package)`; the aggregate metrics finding from a fixed metric identity (NOT the metric values, which drift); L3 `(code,message)` diagnostics from `(code, message)` (the only identifier the kernel tuple carries — acceptable for informational engine diagnostics).
7. **Body-vs-return taint.** L2 call resolution uses `ResolverResult.taint_map` (refined *body* taint). It equals return taint for all non-anchored functions — SP1's entire universe under the default provider — so it is correct now. Mark with a `# SP2` comment that anchored callees with distinct return tiers will need the return map exposed.
8. **Engine rule_id namespace:** `WLN-ENGINE-*` / `WLN-L3-*` (distinct from SP2's `PY-WL-*` policy rules).

**Gate commands (repo root; `.venv/bin/python`):**
```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests
.venv/bin/mypy src
```

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `src/wardline/scanner/context.py` (create) | `AnalysisContext` + `RuleRegistry` seam | 1 |
| `src/wardline/scanner/taint/summary_cache.py` (modify) | disk `save()`/`load()` + `cache_dir` | 2 |
| `src/wardline/scanner/taint/call_taint_map.py` (create) | per-file L2 call-taint-map builder (collision fix + external-dotted) | 3 |
| `src/wardline/scanner/diagnostics.py` (create) | engine-diagnostic `Finding` builders (metrics + L3 diags + unknown-import facts) | 4 |
| `src/wardline/scanner/analyzer.py` (create) | `WardlineAnalyzer` orchestration | 5 |
| `src/wardline/cli/scan.py` (modify) + `src/wardline/scanner/__init__.py` (modify) | wire `WardlineAnalyzer`, add `--cache-dir` | 6 |

---

## Task 1: `context.py` — `AnalysisContext` + `RuleRegistry` seam

**Files:**
- Create: `src/wardline/scanner/context.py`
- Test: `tests/unit/scanner/test_context.py`

**Why:** The hand-off object SP2 rules consume (project taint map, per-function L2 var-taints, entities, provenance) + the empty rule-dispatch seam. Keep it to exactly what SP2 needs — no speculative fields.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import ast

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.taints import TaintState as T
from wardline.scanner.context import AnalysisContext, RuleRegistry
from wardline.scanner.index import Entity


def _entity(q: str) -> Entity:
    node = ast.parse("def f(): pass").body[0]
    assert isinstance(node, ast.FunctionDef)
    return Entity(qualname=q, kind="function", node=node, location=Location(path="m.py"))


def test_context_holds_engine_outputs() -> None:
    ctx = AnalysisContext(
        project_taints={"m.f": T.UNKNOWN_RAW},
        function_var_taints={"m.f": {"x": T.INTEGRAL}},
        entities={"m.f": _entity("m.f")},
        taint_provenance={},
    )
    assert ctx.project_taints["m.f"] == T.UNKNOWN_RAW
    assert ctx.function_var_taints["m.f"]["x"] == T.INTEGRAL
    assert ctx.entities["m.f"].qualname == "m.f"


def test_empty_registry_runs_no_rules() -> None:
    reg = RuleRegistry()
    assert reg.rules == ()
    ctx = AnalysisContext(
        project_taints={}, function_var_taints={}, entities={}, taint_provenance={}
    )
    assert reg.run(ctx) == []


def test_registry_runs_registered_rule() -> None:
    finding = Finding(
        rule_id="X", message="m", severity=Severity.INFO, kind=Kind.FACT,
        location=Location(path="m.py"), fingerprint="fp",
    )

    class _Rule:
        rule_id = "X"

        def check(self, context: AnalysisContext):  # noqa: ANN201, ARG002
            return [finding]

    reg = RuleRegistry()
    reg.register(_Rule())
    ctx = AnalysisContext(
        project_taints={}, function_var_taints={}, entities={}, taint_provenance={}
    )
    assert reg.run(ctx) == [finding]
    assert len(reg.rules) == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_context.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `context.py`**

```python
# src/wardline/scanner/context.py
"""The analyzer's structured output + the (empty in SP1) rule-dispatch seam.

``AnalysisContext`` carries exactly what SP2 policy rules consume: the
project-scope taint map, per-function L2 variable taints, the entity index, and
the L3 provenance. ``RuleRegistry`` is the dispatch seam — SP1 registers no
rules, so ``run`` returns nothing; SP2 supplies the rule set.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.core.finding import Finding
    from wardline.core.taints import TaintState
    from wardline.scanner.index import Entity
    from wardline.scanner.taint.propagation import TaintProvenance


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    """Engine output handed to SP2 rules (and to SP1f's own diagnostics)."""

    project_taints: Mapping[str, TaintState]
    function_var_taints: Mapping[str, Mapping[str, TaintState]]
    entities: Mapping[str, Entity]
    taint_provenance: Mapping[str, TaintProvenance]


class _Rule(Protocol):
    rule_id: str

    def check(self, context: AnalysisContext) -> list[Finding]: ...


class RuleRegistry:
    """Ordered rule set. Empty in SP1 — SP2 registers the policy vocabulary."""

    def __init__(self) -> None:
        self._rules: list[_Rule] = []

    def register(self, rule: _Rule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> tuple[_Rule, ...]:
        return tuple(self._rules)

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(rule.check(context))
        return findings
```

- [ ] **Step 4: Run + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_context.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit** (NO git for subagents — controller commits. Skip this step.)

---

## Task 2: `summary_cache.py` — disk persistence

**Files:**
- Modify: `src/wardline/scanner/taint/summary_cache.py`
- Test: `tests/unit/scanner/taint/test_summary_cache.py` (append)

**Why:** A summary cache only pays off across runs, which needs disk. Add `cache_dir` + atomic `save()`/`load()` of the slim `FunctionSummary`. **NO governance** (no CI attestation, no `Finding`/`Severity` imports). Malformed/stale entries are dropped on load (cold-cache fallback).

- [ ] **Step 1: Write the failing tests** (append)

```python
def test_save_and_load_roundtrip(tmp_path) -> None:
    c = SummaryCache(cache_dir=tmp_path)
    summaries = (_summary("m.a"), _summary("m.b"))
    c.put(_KEY, summaries)
    c.save()
    c2 = SummaryCache(cache_dir=tmp_path)
    c2.load()
    assert c2.get(_KEY) == summaries


def test_load_drops_malformed_json(tmp_path) -> None:
    (tmp_path / f"{_KEY}.json").write_text("{not json", encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path)
    c.load()  # must not raise
    assert len(c) == 0


def test_load_ignores_non_hex_stem_files(tmp_path) -> None:
    (tmp_path / "notes.json").write_text("[]", encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path)
    c.load()
    assert len(c) == 0


def test_save_requires_cache_dir() -> None:
    with pytest.raises(ValueError, match="cache_dir"):
        SummaryCache().save()


def test_load_requires_cache_dir() -> None:
    with pytest.raises(ValueError, match="cache_dir"):
        SummaryCache().load()


def test_in_memory_cache_has_no_cache_dir() -> None:
    assert SummaryCache().cache_dir is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_summary_cache.py -q`
Expected: FAIL (`TypeError` for `cache_dir` kwarg / `AttributeError`).

- [ ] **Step 3: Modify `summary_cache.py`**

Add `cache_dir` to `__init__`, a `cache_dir` property, `save()`, `load()`, and the two serialise helpers. Update imports (`contextlib`, `json`, `logging`, `os`, `tempfile`, `Path`, plus `TaintState` and `FunctionSummary` at runtime for (de)serialisation).

```python
def __init__(self, *, cache_dir: Path | None = None) -> None:
    self._entries: dict[str, tuple[FunctionSummary, ...]] = {}
    self._hits: int = 0
    self._misses: int = 0
    self._cache_dir: Path | None = cache_dir

@property
def cache_dir(self) -> Path | None:
    return self._cache_dir
```

```python
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
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self._cache_dir, delete=False, suffix=".tmp",
        ) as tf:
            json.dump(payload, tf)
            temp_path = Path(tf.name)
        try:
            os.replace(temp_path, target)
        except OSError:
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
        if any(s.schema_version != SUMMARY_SCHEMA_VERSION for s in summaries):
            continue
        self._entries[cache_key] = summaries
```

Module-level helpers (slim `FunctionSummary` — no propagators):

```python
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
        body_taint=TaintState(cast("str", d["body_taint"])),
        return_taint=TaintState(cast("str", d["return_taint"])),
        taint_source=taint_source,  # type: ignore[arg-type]  # validated above
        unresolved_calls=int(cast("int", d["unresolved_calls"])),
        schema_version=int(cast("int", d["schema_version"])),
        cache_key=str(d["cache_key"]),
    )
```

Add a module logger `_logger = logging.getLogger(__name__)` and import `FunctionSummary`/`TaintState` at runtime (move `FunctionSummary` out of TYPE_CHECKING since `_deserialise_summary` constructs it; import `TaintState`, `cast`).

- [ ] **Step 4: Run + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_summary_cache.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit** (controller — skip in subagent).

---

## Task 3: `call_taint_map.py` — per-file L2 call-taint-map builder

**Files:**
- Create: `src/wardline/scanner/taint/call_taint_map.py`
- Test: `tests/unit/scanner/taint/test_call_taint_map.py`

**Why:** Build the `taint_map` that `compute_variable_taints` consumes for one file — keyed by call-site name AS WRITTEN. It folds in (a) project function return taints (alias-resolved) and (b) `stdlib_taint`, with the **serialization-sink override** (decision #2) and the **alias-resolved external-dotted channel** (decision #3).

- [ ] **Step 1: Write the failing tests** (the discriminating aliased-sink test is the gate)

```python
from __future__ import annotations

import ast

from wardline.core.taints import TaintState as T
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.taint.call_taint_map import build_call_taint_map


def _aliases(src: str, module: str) -> dict[str, str]:
    return build_import_alias_map(ast.parse(src), module_path=module)


def test_local_function_keyed_bare() -> None:
    aliases = _aliases("def a(): pass\ndef b(): pass\n", "m")
    tm = build_call_taint_map(
        module_path="m", alias_map=aliases,
        project_taints={"m.a": T.MIXED_RAW, "m.b": T.UNKNOWN_RAW},
    )
    assert tm["a"] == T.MIXED_RAW
    assert tm["b"] == T.UNKNOWN_RAW


def test_from_import_project_function_keyed_bare() -> None:
    aliases = _aliases("from other import helper\n", "m")
    tm = build_call_taint_map(
        module_path="m", alias_map=aliases,
        project_taints={"other.helper": T.EXTERNAL_RAW},
    )
    assert tm["helper"] == T.EXTERNAL_RAW


def test_dotted_module_project_call_keyed_dotted() -> None:
    aliases = _aliases("import other\n", "m")
    tm = build_call_taint_map(
        module_path="m", alias_map=aliases,
        project_taints={"other.fn": T.MIXED_RAW},
    )
    assert tm["other.fn"] == T.MIXED_RAW


def test_stdlib_external_dotted_taint_carries() -> None:
    # Positive external-dotted channel: a non-sink stdlib entry, aliased.
    aliases = _aliases("import subprocess as sp\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases, project_taints={})
    assert tm["sp.check_output"] == T.EXTERNAL_RAW


def test_aliased_serialisation_sink_overrides_to_unknown_raw() -> None:
    # THE collision-fix gate: json.loads is stdlib GUARDED, but it is a
    # serialisation sink; under aliasing the literal sink check is bypassed, so
    # the taint_map entry MUST be UNKNOWN_RAW (conservative wins).
    aliases = _aliases("import json as j\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases, project_taints={})
    assert tm["j.loads"] == T.UNKNOWN_RAW


def test_unaliased_serialisation_sink_also_unknown_raw() -> None:
    aliases = _aliases("import json\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases, project_taints={})
    assert tm["json.loads"] == T.UNKNOWN_RAW


def test_from_import_sink_keyed_bare_unknown_raw() -> None:
    aliases = _aliases("from json import loads\n", "m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases, project_taints={})
    assert tm["loads"] == T.UNKNOWN_RAW


def test_project_function_takes_precedence_over_stdlib() -> None:
    # A project function shadowing a stdlib name keeps its refined taint.
    aliases = _aliases("import subprocess as sp\n", "m")
    tm = build_call_taint_map(
        module_path="m", alias_map=aliases,
        project_taints={"m.sp": T.INTEGRAL},  # local 'sp' bare function
    )
    assert tm["sp"] == T.INTEGRAL  # local bare entry untouched by stdlib dotted
```

Then the **integration** test through L2 proving the collision is closed end-to-end:

```python
from wardline.scanner.taint.variable_level import compute_variable_taints


def test_l2_aliased_sink_yields_unknown_raw_end_to_end() -> None:
    src = "import json as j\ndef f(p):\n    x = j.loads(p)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases, project_taints={})
    out = compute_variable_taints(func, T.ASSURED, dict(tm))
    assert out["x"] == T.UNKNOWN_RAW  # NOT GUARDED, NOT ASSURED


def test_l2_aliased_nonsink_stdlib_carries_external_raw() -> None:
    src = "import subprocess as sp\ndef f(c):\n    x = sp.check_output(c)\n"
    func = ast.parse(src).body[1]
    assert isinstance(func, ast.FunctionDef)
    aliases = build_import_alias_map(ast.parse(src), module_path="m")
    tm = build_call_taint_map(module_path="m", alias_map=aliases, project_taints={})
    out = compute_variable_taints(func, T.INTEGRAL, dict(tm))
    assert out["x"] == T.EXTERNAL_RAW
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_call_taint_map.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `call_taint_map.py`**

```python
# src/wardline/scanner/taint/call_taint_map.py
"""Build the per-file L2 call-taint-map consumed by ``compute_variable_taints``.

Keyed by call-site name AS WRITTEN (bare ``foo`` / dotted ``mod.fn``), mapping to
the call's return taint. Folds in two sources, alias-resolved against the file's
import map:

  * Project function returns — from the L3 ``ResolverResult.taint_map`` (refined
    body taint; equals return taint for all non-anchored functions, SP1's whole
    universe — see ``# SP2`` note in the analyzer).
  * ``stdlib_taint`` — with the SERIALISATION-SINK OVERRIDE: any stdlib entry
    whose ``(pkg, fn)`` is also a serialisation sink is inserted as
    ``UNKNOWN_RAW``, never its stdlib taint. ``_resolve_call``'s sink check only
    matches the *literal* written name, so without this override an aliased
    ``import json as j; j.loads(p)`` would skip the sink check and read the
    stdlib ``GUARDED`` — an under-taint. Inserting ``UNKNOWN_RAW`` makes literal
    and aliased calls agree (conservative wins).

Project entries take precedence over stdlib (``setdefault`` for stdlib).
Residual known gap: an aliased serialisation sink NOT in the stdlib table (e.g.
``import pickle as p`` when pickle is uncurated) has no taint_map entry and the
literal sink check misses the alias, so it falls back to the function taint —
pre-existing, not worsened here.
"""

from __future__ import annotations

from wardline.core.taints import TaintState
from wardline.scanner.taint.stdlib_taint import load_stdlib_taint
from wardline.scanner.taint.variable_level import _SERIALISATION_SINKS


def build_call_taint_map(
    *,
    module_path: str,
    alias_map: dict[str, str],
    project_taints: dict[str, TaintState] | None = None,
) -> dict[str, TaintState]:
    """Return ``{call-site-name: return-taint}`` for one file."""
    project_taints = project_taints or {}
    tm: dict[str, TaintState] = {}

    # (a) Local top-level functions — bare-callable in this module.
    local_prefix = module_path + "."
    for fqn, taint in project_taints.items():
        if fqn.startswith(local_prefix):
            rest = fqn[len(local_prefix):]
            if "." not in rest:  # top-level function (methods aren't bare-callable)
                tm[rest] = taint

    # (b)+(c) Imported project symbols, via the file's alias map.
    for local, target in alias_map.items():
        if target in project_taints:
            tm[local] = project_taints[target]  # from-import of a project function
            continue
        target_prefix = target + "."  # module import: dotted local.x calls
        for fqn, taint in project_taints.items():
            if fqn.startswith(target_prefix):
                rest = fqn[len(target_prefix):]
                if "." not in rest:
                    tm[f"{local}.{rest}"] = taint

    # (d) stdlib_taint with the serialisation-sink override.
    stdlib = load_stdlib_taint()
    for (pkg, fn), entry in stdlib.items():
        value = (
            TaintState.UNKNOWN_RAW
            if f"{pkg}.{fn}" in _SERIALISATION_SINKS
            else entry.taint
        )
        for local, target in alias_map.items():
            if target == pkg:
                tm.setdefault(f"{local}.{fn}", value)         # import pkg [as local]
            elif target == f"{pkg}.{fn}":
                tm.setdefault(local, value)                   # from pkg import fn [as local]

    return tm
```

> **Implementer note:** importing the private `_SERIALISATION_SINKS` from `variable_level` is intentional — it is the single source of truth for the sink set, and re-declaring it would risk drift. If ruff flags the private import, that is acceptable here; do not duplicate the set.

- [ ] **Step 4: Run + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_call_taint_map.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit** (controller — skip in subagent).

---

## Task 4: `diagnostics.py` — engine-diagnostic Finding builders

**Files:**
- Create: `src/wardline/scanner/diagnostics.py`
- Test: `tests/unit/scanner/test_diagnostics.py`

**Why:** Turn the resolver's metadata, kernel `(code,message)` diagnostics, and unresolved imports into SP0 `Finding`s. Includes a lightweight `diagnose_unknown_imports` (ported from `.old`, returning plain tuples — no `Finding`/`RuleId` coupling).

- [ ] **Step 1: Write the failing tests**

```python
from __future__ import annotations

import ast

from wardline.core.finding import Kind, Severity
from wardline.scanner.diagnostics import (
    build_diagnostic_findings,
    build_metric_finding,
    build_unknown_import_findings,
    diagnose_unknown_imports,
)
from wardline.scanner.taint.resolver_metadata import ResolverRunMetadata


def _meta() -> ResolverRunMetadata:
    return ResolverRunMetadata(
        scc_size_distribution=((1, 3),),
        convergence_iterations_max=1,
        convergence_iterations_histogram=((1, 3),),
        taint_source_counts={"anchored": 1, "module_default": 0, "fallback": 2},
    )


def test_metric_finding_is_metric_kind_none_severity() -> None:
    f = build_metric_finding(_meta(), cache_hit_rate=0.5)
    assert f.kind == Kind.METRIC
    assert f.severity == Severity.NONE
    assert f.properties["convergence_iterations_max"] == 1
    assert f.properties["cache_hit_rate"] == 0.5
    assert f.properties["taint_source_counts"]["anchored"] == 1


def test_metric_finding_fingerprint_stable_across_values() -> None:
    # Fingerprint is keyed on metric IDENTITY, not the (drifting) values.
    a = build_metric_finding(_meta(), cache_hit_rate=0.0)
    b = build_metric_finding(_meta(), cache_hit_rate=1.0)
    assert a.fingerprint == b.fingerprint


def test_l3_diagnostic_findings_map_code_to_severity() -> None:
    diags = [
        ("L3_MONOTONICITY_VIOLATION", "func x moved up"),
        ("L3_CONVERGENCE_BOUND", "SCC of size 3 hit bound"),
        ("L3_LOW_RESOLUTION", "Function m.f has 80% unresolved (4/5)"),
    ]
    out = {f.rule_id: f for f in build_diagnostic_findings(diags)}
    assert out["WLN-L3-MONOTONICITY-VIOLATION"].severity == Severity.ERROR
    assert out["WLN-L3-MONOTONICITY-VIOLATION"].kind == Kind.DEFECT
    assert out["WLN-L3-CONVERGENCE-BOUND"].severity == Severity.WARN
    assert out["WLN-L3-LOW-RESOLUTION"].severity == Severity.INFO
    assert out["WLN-L3-LOW-RESOLUTION"].kind == Kind.METRIC


def test_unknown_diagnostic_code_is_error_not_silent() -> None:
    out = build_diagnostic_findings([("MYSTERY_CODE", "???")])
    assert out[0].severity == Severity.ERROR
    assert "MYSTERY_CODE" in out[0].message


def test_diagnose_unknown_imports_flags_external_named_import() -> None:
    tree = ast.parse("from external_pkg import thing\n")
    out = diagnose_unknown_imports(
        tree=tree, module_path="m",
        project_modules=frozenset({"m"}), stdlib_keys=frozenset(),
    )
    assert len(out) == 1
    assert out[0][0] == "m"
    assert "external_pkg" in out[0][2]


def test_diagnose_unknown_imports_skips_stdlib_and_project_and_relative() -> None:
    tree = ast.parse(
        "import os\n"
        "from typing import TYPE_CHECKING\n"
        "from m import sibling\n"   # project module
        "from . import rel\n"        # relative
    )
    out = diagnose_unknown_imports(
        tree=tree, module_path="m.sub",
        project_modules=frozenset({"m", "m.sub"}), stdlib_keys=frozenset(),
    )
    assert out == []


def test_unknown_import_findings_are_facts() -> None:
    tree = ast.parse("from external_pkg import thing\n")
    findings = build_unknown_import_findings(
        [("pkg/mod.py", "pkg.mod", tree)],
        project_modules=frozenset({"pkg.mod"}),
    )
    assert len(findings) == 1
    assert findings[0].kind == Kind.FACT
    assert findings[0].rule_id == "WLN-ENGINE-UNKNOWN-IMPORT"
    # Fingerprint stable from (module, package) — not message text.
    again = build_unknown_import_findings(
        [("pkg/mod.py", "pkg.mod", tree)], project_modules=frozenset({"pkg.mod"})
    )
    assert findings[0].fingerprint == again[0].fingerprint
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_diagnostics.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `diagnostics.py`**

Port `diagnose_unknown_imports` from `/home/john/wardline.old/src/wardline/scanner/taint/project_resolver.py` (lines ~342–484: the `_is_type_checking_guarded`, `_top_level_module`, `_is_stdlib_module`, `diagnose_unknown_imports` block) VERBATIM in logic, but as standalone functions returning `(module_path, detail, reason)` tuples — no `Finding`/`RuleId`. Then add the Finding builders:

```python
# src/wardline/scanner/diagnostics.py
"""Engine-diagnostic Finding builders (SP1f).

Turns the L3 resolver's run metadata, kernel (code, message) diagnostics, and
unresolved-import facts into SP0 Findings. These are ENGINE diagnostics
(WLN-ENGINE-* / WLN-L3-*), distinct from SP2's policy rules (PY-WL-*). No taint
path is involved, so fingerprints are stable from identifying fields (not the
drifting metric values / percentages).
"""

from __future__ import annotations

import ast
import hashlib
import sys
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity

if TYPE_CHECKING:
    from wardline.scanner.taint.resolver_metadata import ResolverRunMetadata

_ENGINE_PATH = "<engine>"

# code -> (rule_id, severity, kind)
_DIAG_MAP: dict[str, tuple[str, Severity, Kind]] = {
    "L3_CONVERGENCE_BOUND": ("WLN-L3-CONVERGENCE-BOUND", Severity.WARN, Kind.METRIC),
    "L3_MONOTONICITY_VIOLATION": ("WLN-L3-MONOTONICITY-VIOLATION", Severity.ERROR, Kind.DEFECT),
    "L3_LOW_RESOLUTION": ("WLN-L3-LOW-RESOLUTION", Severity.INFO, Kind.METRIC),
}


def _fingerprint(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


def build_metric_finding(
    metadata: ResolverRunMetadata, *, cache_hit_rate: float
) -> Finding:
    """One METRIC finding carrying the L3 run metrics. Fingerprint is keyed on
    metric IDENTITY (fixed), since the values drift run to run."""
    return Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="L3 resolver run metrics",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path=_ENGINE_PATH),
        fingerprint=_fingerprint("WLN-ENGINE-METRICS", _ENGINE_PATH),
        properties={
            "scc_size_distribution": [list(p) for p in metadata.scc_size_distribution],
            "convergence_iterations_max": metadata.convergence_iterations_max,
            "convergence_iterations_histogram": [
                list(p) for p in metadata.convergence_iterations_histogram
            ],
            "taint_source_counts": dict(metadata.taint_source_counts),
            "cache_hit_rate": cache_hit_rate,
        },
    )


def build_diagnostic_findings(diagnostics: list[tuple[str, str]]) -> list[Finding]:
    """Map kernel (code, message) diagnostics to Findings. Unknown codes become
    WLN-ENGINE-DIAGNOSTIC at ERROR so a new kernel code can never go silent."""
    findings: list[Finding] = []
    for code, message in diagnostics:
        mapped = _DIAG_MAP.get(code)
        if mapped is not None:
            rule_id, severity, kind = mapped
        else:
            rule_id, severity, kind = ("WLN-ENGINE-DIAGNOSTIC", Severity.ERROR, Kind.DEFECT)
            message = f"unknown L3 diagnostic {code!r}: {message}"
        findings.append(
            Finding(
                rule_id=rule_id,
                message=message,
                severity=severity,
                kind=kind,
                location=Location(path=_ENGINE_PATH),
                fingerprint=_fingerprint(rule_id, message),
            )
        )
    return findings


def build_unknown_import_findings(
    file_trees: list[tuple[str, str, ast.Module]],
    *,
    project_modules: frozenset[str],
) -> list[Finding]:
    """FACT findings for unresolved external imports across all files.

    ``file_trees`` is ``[(relpath, module_path, tree), ...]``. Fingerprint is
    stable from ``(module_path, package)``.
    """
    findings: list[Finding] = []
    for relpath, module_path, tree in file_trees:
        for _mp, detail, reason in diagnose_unknown_imports(
            tree=tree, module_path=module_path,
            project_modules=project_modules, stdlib_keys=frozenset(),
        ):
            package = detail.split()[1] if detail.startswith("from ") else detail
            findings.append(
                Finding(
                    rule_id="WLN-ENGINE-UNKNOWN-IMPORT",
                    message=f"{module_path}: {reason}",
                    severity=Severity.NONE,
                    kind=Kind.FACT,
                    location=Location(path=relpath),
                    fingerprint=_fingerprint("WLN-ENGINE-UNKNOWN-IMPORT", module_path, package),
                    properties={"module": module_path, "package": package, "detail": detail},
                )
            )
    return findings


# --- diagnose_unknown_imports (ported from .old, Finding-free) ----------------
# [Implementer: reproduce .old's _is_type_checking_guarded, _top_level_module,
#  _is_stdlib_module, and diagnose_unknown_imports here, returning
#  list[tuple[str, str, str]] = (module_path, detail, reason). Drop the
#  stdlib_keys parameter's coupling to a real table for SP1f — callers pass
#  frozenset() because the named-import branch's stdlib check is handled by
#  _is_stdlib_module (sys.stdlib_module_names) already. Keep: relative-import
#  skip, TYPE_CHECKING-guard skip, stdlib-module skip, (module_path, mod) dedup.]
```

The implementer reproduces the four `.old` functions below that comment. Keep the `stdlib_keys` parameter on `diagnose_unknown_imports` (tests pass `frozenset()`); the `_is_stdlib_module` check via `sys.stdlib_module_names` is what suppresses stdlib noise.

- [ ] **Step 4: Run + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_diagnostics.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit** (controller — skip in subagent).

---

## Task 5: `analyzer.py` — `WardlineAnalyzer` orchestration

**Files:**
- Create: `src/wardline/scanner/analyzer.py`
- Test: `tests/unit/scanner/test_analyzer.py`

**Why:** The end-to-end engine implementing SP0's `Analyzer` protocol. Parses files → indexes → seeds → L3 resolves → per-file L2 (with the `RecursionError` boundary) → builds an `AnalysisContext` (stashed on the instance for SP2/tests) → emits engine-diagnostic findings.

- [ ] **Step 1: Write the failing test** (acceptance: real metric + fact findings on a multi-module fixture)

```python
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.core.taints import TaintState as T
from wardline.scanner.analyzer import WardlineAnalyzer


def _write(root: Path, rel: str, src: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


def test_analyzer_emits_metrics_and_computes_transitive_taint(tmp_path) -> None:
    # io_layer.read_raw is anchored MIXED_RAW via a provider; flows up.
    _write(tmp_path, "pkg/io_layer.py", "def read_raw(p):\n    return p\n")
    _write(tmp_path, "pkg/service.py",
           "from pkg.io_layer import read_raw\ndef fetch(p):\n    return read_raw(p)\n")
    files = [tmp_path / "pkg/io_layer.py", tmp_path / "pkg/service.py"]

    class _Provider:
        def taint_for(self, entity, ctx):  # noqa: ANN001, ANN201
            from wardline.scanner.taint.provider import FunctionTaint
            if entity.qualname.endswith(".read_raw"):
                return FunctionTaint(body_taint=T.MIXED_RAW, return_taint=T.MIXED_RAW)
            return None

        def fingerprint(self) -> str:
            return "test-v1"

    analyzer = WardlineAnalyzer(provider=_Provider())
    findings = analyzer.analyze(files, WardlineConfig(), root=tmp_path)

    # A metrics finding is always emitted.
    assert any(f.rule_id == "WLN-ENGINE-METRICS" and f.kind == Kind.METRIC for f in findings)
    # Transitive taint is exposed for SP2.
    ctx = analyzer.last_context
    assert ctx is not None
    assert ctx.project_taints["pkg.io_layer.read_raw"] == T.MIXED_RAW
    assert ctx.project_taints["pkg.service.fetch"] == T.MIXED_RAW


def test_analyzer_emits_unknown_import_fact(tmp_path) -> None:
    _write(tmp_path, "app.py", "from some_external_lib import thing\ndef f(): return thing()\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "app.py"], WardlineConfig(), root=tmp_path)
    assert any(
        f.rule_id == "WLN-ENGINE-UNKNOWN-IMPORT" and f.kind == Kind.FACT for f in findings
    )


def test_analyzer_default_provider_all_unknown_raw(tmp_path) -> None:
    _write(tmp_path, "m.py", "def f(p):\n    return p\n")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([tmp_path / "m.py"], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    assert set(analyzer.last_context.project_taints.values()) == {T.UNKNOWN_RAW}


def test_analyzer_recursion_error_is_contained(tmp_path) -> None:
    # A pathological deep-nested expression must not abort the scan.
    deep = "x = " + "(" * 600 + "p" + ")" * 600 + "\n"
    _write(tmp_path, "m.py", f"def f(p):\n    {deep}    return x\n")
    analyzer = WardlineAnalyzer()
    # Must not raise; the function is contained and the scan completes.
    findings = analyzer.analyze([tmp_path / "m.py"], WardlineConfig(), root=tmp_path)
    assert any(f.rule_id == "WLN-ENGINE-METRICS" for f in findings)


def test_analyzer_skips_unparseable_file_with_fact(tmp_path) -> None:
    _write(tmp_path, "bad.py", "def f(:\n")  # syntax error
    _write(tmp_path, "good.py", "def g(): return 1\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(
        [tmp_path / "bad.py", tmp_path / "good.py"], WardlineConfig(), root=tmp_path
    )
    assert any(f.rule_id == "WLN-ENGINE-PARSE-ERROR" and f.kind == Kind.FACT for f in findings)
    assert analyzer.last_context is not None
    assert "good.g" in analyzer.last_context.project_taints
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_analyzer.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `analyzer.py`**

```python
# src/wardline/scanner/analyzer.py
"""WardlineAnalyzer — the end-to-end SP1 engine (replaces NoOpAnalyzer).

Parses each file, indexes entities, seeds L1 via the pluggable provider, runs the
L3 transitive fixed point ONCE over the whole project (minimum_scope is NOT on
the pipeline — full L3 subsumes its one-hop refinement), computes per-file L2
variable taints inside a per-function RecursionError boundary, exposes the result
as an AnalysisContext for SP2, and emits engine-diagnostic Findings. No policy
rules ship (empty RuleRegistry seam).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.qualname import module_dotted_name
from wardline.core.taints import TaintState
from wardline.scanner.context import AnalysisContext, RuleRegistry
from wardline.scanner.diagnostics import (
    build_diagnostic_findings,
    build_metric_finding,
    build_unknown_import_findings,
)
from wardline.scanner.index import discover_class_qualnames, discover_file_entities
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.taint.call_taint_map import build_call_taint_map
from wardline.scanner.taint.function_level import seed_function_taints
from wardline.scanner.taint.project_resolver import ModuleInput, resolve_project_taints
from wardline.scanner.taint.provider import (
    DefaultTaintSourceProvider,
    SeedContext,
    TaintSourceProvider,
)
from wardline.scanner.taint.variable_level import compute_variable_taints

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from wardline.core.config import WardlineConfig
    from wardline.scanner.index import Entity
    from wardline.scanner.taint.summary_cache import SummaryCache

import hashlib


def _fp(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


class WardlineAnalyzer:
    """SP1 analyzer implementing core.protocols.Analyzer."""

    def __init__(
        self,
        *,
        provider: TaintSourceProvider | None = None,
        registry: RuleRegistry | None = None,
        summary_cache: SummaryCache | None = None,
    ) -> None:
        self._provider: TaintSourceProvider = provider or DefaultTaintSourceProvider()
        self._registry = registry or RuleRegistry()
        self._cache = summary_cache
        self.last_context: AnalysisContext | None = None

    def analyze(
        self, files: Sequence[Path], config: WardlineConfig, *, root: Path
    ) -> Sequence[Finding]:
        modules: list[ModuleInput] = []
        # (relpath, module_path, tree, entities, alias_map)
        file_meta: list[tuple[str, str, ast.Module, tuple[Entity, ...], dict[str, str]]] = []
        parse_findings: list[Finding] = []

        for path in files:
            relpath = (
                path.relative_to(root).as_posix()
                if path.is_relative_to(root)
                else path.as_posix()
            )
            module = module_dotted_name(relpath)
            if module is None:
                continue
            source = path.read_text(encoding="utf-8")  # universal-newline -> LF
            try:
                tree = ast.parse(source)
            except SyntaxError as exc:
                parse_findings.append(
                    Finding(
                        rule_id="WLN-ENGINE-PARSE-ERROR",
                        message=f"{relpath}: could not parse ({exc.msg})",
                        severity=Severity.NONE,
                        kind=Kind.FACT,
                        location=Location(path=relpath, line_start=exc.lineno),
                        fingerprint=_fp("WLN-ENGINE-PARSE-ERROR", relpath),
                        properties={"module": module},
                    )
                )
                continue
            entities = tuple(discover_file_entities(tree, module=module, path=relpath))
            classes = discover_class_qualnames(tree, module=module)
            alias_map = build_import_alias_map(tree, module_path=module)
            seeds = seed_function_taints(
                entities, ctx=SeedContext(module=module), provider=self._provider
            )
            modules.append(
                ModuleInput(
                    module_path=module,
                    entities=entities,
                    class_qualnames=classes,
                    alias_map=alias_map,
                    seeds=seeds,
                    source_bytes=source.encode("utf-8"),
                )
            )
            file_meta.append((relpath, module, tree, entities, alias_map))

        if self._cache is not None:
            result = resolve_project_taints(
                modules=modules,
                provider_fingerprint=self._provider.fingerprint(),
                summary_cache=self._cache,
                dirty_modules=frozenset(),
            )
        else:
            result = resolve_project_taints(
                modules=modules, provider_fingerprint=self._provider.fingerprint()
            )

        project_taints = dict(result.taint_map)

        # Per-file L2 with a per-function RecursionError boundary.
        # NOTE: project_taints is the refined *body* taint; equals return taint
        # for all non-anchored functions (SP1 universe). # SP2: expose the
        # return map for anchored callees with distinct return tiers.
        function_var_taints: dict[str, dict[str, TaintState]] = {}
        entity_index: dict[str, Entity] = {}
        for relpath, module, _tree, entities, alias_map in file_meta:
            call_tm = build_call_taint_map(
                module_path=module, alias_map=alias_map, project_taints=project_taints
            )
            for ent in entities:
                entity_index[ent.qualname] = ent
                seed = project_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)
                try:
                    var_taints = compute_variable_taints(ent.node, seed, dict(call_tm))
                except RecursionError:
                    var_taints = {}  # fail-closed; absent vars read as the function taint
                function_var_taints[ent.qualname] = var_taints

        context = AnalysisContext(
            project_taints=project_taints,
            function_var_taints=function_var_taints,
            entities=entity_index,
            taint_provenance=dict(result.taint_provenance),
        )
        self.last_context = context

        findings: list[Finding] = list(parse_findings)
        cache_hit_rate = self._cache.hit_rate() if self._cache is not None else 0.0
        findings.append(build_metric_finding(result.metadata, cache_hit_rate=cache_hit_rate))
        findings.extend(build_diagnostic_findings(list(result.diagnostics)))
        findings.extend(
            build_unknown_import_findings(
                [(rp, mp, tr) for rp, mp, tr, _e, _a in file_meta],
                project_modules=frozenset(mp for _rp, mp, _tr, _e, _a in file_meta),
            )
        )
        findings.extend(self._registry.run(context))  # empty in SP1
        return findings
```

> **Implementer notes:** (1) move the `import hashlib` to the top of the imports block (it's shown low here only for readability — ruff will require top placement). (2) `is_relative_to` exists on `Path` (3.9+). (3) Do NOT add `minimum_scope`. (4) Keep the `# SP2` body-vs-return comment.

- [ ] **Step 4: Run + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_analyzer.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit** (controller — skip in subagent).

---

## Task 6: CLI wiring — `--cache-dir` + replace `NoOpAnalyzer`

**Files:**
- Modify: `src/wardline/cli/scan.py`
- Modify: `src/wardline/scanner/__init__.py` (export `WardlineAnalyzer`; keep `NoOpAnalyzer` exported too)
- Test: `tests/unit/cli/test_cli.py` (append), `tests/test_self_hosting.py` (UNCHANGED — stays xfail)

**Why:** Make `wardline scan` use the real analyzer; add `--cache-dir` for cross-run persistence (load before, save after). The self-hosting xfail stays xfail (no rules yet — SP2).

- [ ] **Step 1: Write the failing tests** (append to `tests/unit/cli/test_cli.py`)

```python
import json as _json

from click.testing import CliRunner

from wardline.cli.scan import scan


def test_scan_emits_engine_metrics(tmp_path) -> None:
    (tmp_path / "m.py").write_text("def f(p):\n    return p\n", encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    res = CliRunner().invoke(scan, [str(tmp_path), "--output", str(out)])
    assert res.exit_code == 0, res.output
    lines = [_json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert any(f["rule_id"] == "WLN-ENGINE-METRICS" for f in lines)


def test_scan_cache_dir_persists_and_warm_equals_cold(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(p):\n    return p\n", encoding="utf-8")
    cache = tmp_path / "cache"
    out1 = tmp_path / "f1.jsonl"
    out2 = tmp_path / "f2.jsonl"
    runner = CliRunner()
    r1 = runner.invoke(scan, [str(proj), "--cache-dir", str(cache), "--output", str(out1)])
    assert r1.exit_code == 0, r1.output
    assert cache.exists() and any(cache.iterdir())  # cache written
    r2 = runner.invoke(scan, [str(proj), "--cache-dir", str(cache), "--output", str(out2)])
    assert r2.exit_code == 0, r2.output
    # Warm run's findings equal the cold run's (metric values are run-identical
    # here since the project is unchanged).
    assert out1.read_text() == out2.read_text()
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q`
Expected: FAIL (no `--cache-dir`; `NoOpAnalyzer` emits nothing).

- [ ] **Step 3: Modify `cli/scan.py`**

Replace the `NoOpAnalyzer` wiring. Add a `--cache-dir` option; when set, construct a `SummaryCache(cache_dir=...)`, `load()` it before analysis and `save()` after.

```python
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.taint.summary_cache import SummaryCache
```

Add the option:
```python
@click.option("--cache-dir", type=click.Path(path_type=Path), default=None,
              help="Persist L3 summary cache here for faster incremental scans.")
```

In the body (inside the existing `try`):
```python
    cache = None
    if cache_dir is not None:
        cache = SummaryCache(cache_dir=cache_dir)
        cache.load()
    files = discover(path, cfg)
    findings = WardlineAnalyzer(summary_cache=cache).analyze(files, cfg, root=path)
    if cache is not None:
        cache.save()
    JsonlSink(output).write(findings)
```

(Add `cache_dir: Path | None` to the `scan` signature.) Leave `--fail-on` inert (SP3) and the SARIF guard as-is.

- [ ] **Step 4: Modify `scanner/__init__.py`** — export `WardlineAnalyzer` alongside `NoOpAnalyzer`:

```python
from wardline.scanner.analyzer import WardlineAnalyzer

__all__ = ["NoOpAnalyzer", "WardlineAnalyzer"]
```

(Keep the `NoOpAnalyzer` class definition; it's still a valid trivial analyzer.)

- [ ] **Step 5: Run the FULL gate**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS (the `test_self_hosting.py` xfail STAYS xfail); ruff + mypy clean.

- [ ] **Step 6: Commit** (controller — skip in subagent).

---

## Final review

After all 6 tasks: dispatch a final code-reviewer over the SP1f diff (focus: the L2 collision fix + the aliased-sink discriminating test; the analyzer's RecursionError containment; that no SARIF/baseline/rules crept in; CLI cache load/save ordering). Then use `superpowers:finishing-a-development-branch` to merge `sp1f-analyzer-wiring` → `main` (`--no-ff`), verify green on the merge, delete the branch, and update `memory/project_generic_rebuild.md`: SP1 COMPLETE (a–f); record that `minimum_scope` is intentionally unwired (subsumed by L3), the serialization-sink collision fix, the body-vs-return `# SP2` note, and that taint-path fingerprint identity lands with SP2 defects.

## Self-review notes (author)

- **Spec coverage:** SP1f row of §6 — `WardlineAnalyzer` (Task 5) + `AnalysisContext` (Task 1) + `diagnostics` (Task 4) + `RuleRegistry` hook (Task 1); CLI wired replacing `NoOpAnalyzer` (Task 6); `wardline scan <fixture>` emits engine-diagnostic findings + exposes the taint map (Tasks 5–6); self-hosting xfail stays xfail (Task 6). SP1e disk persistence (Task 2). All four carried debts settled: serialization precedence + external-dotted (Task 3, with the discriminating aliased-sink gate), RecursionError boundary (Task 5), minimum_scope (dropped, user-confirmed). ✓
- **The collision fix is gated by the discriminating test** `import json as j; j.loads(p)` ⇒ `UNKNOWN_RAW` (Task 3, unit + end-to-end), not the literal form that passes even with the bug. ✓
- **Acceptance is real findings,** not just the xfail: Task 5 asserts actual METRIC + FACT findings + transitive taint on a multi-module fixture; Task 6 asserts CLI metrics output + warm==cold. ✓
- **Fingerprints stable from fields** (facts: module+package; metrics: fixed identity) — Task 4. ✓
- **Type consistency:** `AnalysisContext(project_taints, function_var_taints, entities, taint_provenance)`; `build_call_taint_map(*, module_path, alias_map, project_taints)`; `WardlineAnalyzer(provider, registry, summary_cache)` with `.last_context`. ✓
