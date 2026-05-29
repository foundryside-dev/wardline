# SP1 — Wardline Analyzer Core (Design)

**Date:** 2026-05-29
**Status:** design — awaiting user review before per-stage implementation planning
**Sub-project:** SP1 of the generic-Wardline rebuild (see [SP0 spec](2026-05-29-wardline-sp0-skeleton-design.md) §1 for the decomposition)
**Source engine:** `/home/john/wardline.old/src/wardline/scanner/` + `scanner/taint/` (architecture mapped 2026-05-29)
**Contract:** [Loom integration brief](../../integration/2026-05-29-wardline-loom-integration-brief.md) §Round 2 (the qualname producer contract SP1 must match byte-for-byte)

---

## 1. Goal

Replace `NoOpAnalyzer` with a real **semantic-tainting analyzer**: given a Python project, build the entity/import graph, seed per-function trust taints, propagate them transitively across the whole project to a fixed point, and emit `Finding`s. This is the technical heart of Wardline, ported and **generalized** from `wardline.old`'s engine — stripped of governance, decoupled from any specific rule set or decorator vocabulary.

**Scope (user decision 2026-05-29): the FULL engine** — L1 (function-level), L2 (intra-function variable-level), bounded minimum-scope propagation, L3 (whole-project transitive SCC fixed-point), and the incremental summary cache.

SP1 produces the **engine and its own structural/diagnostic findings**; *policy rules* that turn taints into violations are **SP2**, and SARIF/Filigree/Clarion emission is **SP4**.

---

## 2. The taint model (ported verbatim — it is already generic)

**Lattice** (`core/taints.py`, ~99 LOC, zero deps — port as-is): `TaintState(StrEnum)` with 8 tokens ordered by trust:
```
INTEGRAL < ASSURED < GUARDED < UNKNOWN_ASSURED < UNKNOWN_GUARDED < EXTERNAL_RAW < UNKNOWN_RAW < MIXED_RAW
```
`MIXED_RAW` is the absorbing top; `taint_join` is the lattice join (a small explicit table; all other distinct pairs → `MIXED_RAW`). `TRUST_RANK` (int 0–7) gives the ordering. This domain is fully generic and carries over unchanged.

**Analysis levels:**
- **L1** — each function gets a single body/return taint from its *taint source* (see §4 pluggability), else `UNKNOWN_RAW`.
- **L2** — `compute_variable_taints` walks a function body, propagating taint through assignments / control-flow joins / call sites.
- **minimum-scope** — bounded one-hop cross-file propagation (direct callee + one intermediary), a cheap pre-L3 refinement.
- **L3** — `propagate_callgraph_taints`: Tarjan SCC decomposition + synchronous fixed-point over the inter-module call graph, callees-first, monotone (non-anchored functions only move toward less-trusted). This is the transitive whole-project capability.

---

## 3. Pipeline & target package layout

End-to-end flow (entry point: `WardlineAnalyzer.analyze(files, config, *, root)` implementing SP0's `Analyzer` protocol):

```
discover .py (SP0 discovery)
  → build per-file index: entities(qualname,node,loc) + import-alias map + L1 seeds
  → minimum-scope edges + bounded refinement
  → module summaries (FunctionSummary)  ──[summary cache]
  → L3: build project graph → SCC fixed-point → project taint_map
  → per-file: L2 variable taints, slice L3 taints, build analysis context
  → emit Findings (engine diagnostics now; rule dispatch hook for SP2)
```

Target layout under `src/wardline/`:
```
core/taints.py            # TaintState + taint_join + TRUST_RANK         (SP1b)
core/qualname.py          # module_dotted_name + reconstruct_qualname    (SP1a)
scanner/
  analyzer.py             # WardlineAnalyzer (implements core.protocols.Analyzer)  (SP1f)
  index.py                # per-file/project indexing (entities, aliases) (SP1a/f)
  ast_primitives.py       # import-alias resolver, scope walkers          (SP1a)
  import_graph.py         # project module graph, walk_function_defs      (SP1a)
  context.py              # AnalysisContext (slim; no governance fields)   (SP1f)
  diagnostics.py          # engine-level Finding builders (facts/metrics)  (SP1f)
  taint/
    function_level.py     # L1 seeding (pluggable taint source)           (SP1b)
    stdlib_taint.py + stdlib_taint.yaml                                   (SP1b)
    variable_level.py     # L2                                            (SP1c)
    minimum_scope.py      # bounded propagation                           (SP1c)
    callgraph.py          # call-edge extraction + TRUST_RANK             (SP1d)
    propagation.py        # SCC + fixed-point kernel (was callgraph_propagation) (SP1d)
    summary.py            # FunctionSummary + cache_key                   (SP1d)
    module_summariser.py  # per-module summaries                          (SP1d)
    project_resolver.py   # build graph → kernel → ResolverResult         (SP1d)
    summary_cache.py      # incremental cache                            (SP1e)
    resolver_metadata.py  # ResolverResult / provenance containers        (SP1d)
    reverse_edge_index.py # dirty-set transitive closure                  (SP1e)
```
Each module keeps one responsibility; `core/taints.py` and `core/qualname.py` stay stdlib-only.

---

## 4. Generalization decisions (what changes vs. `.old`)

The `.old` engine is reusable but coupled to wardline-specifics. SP1 removes that coupling:

1. **Qualnames realigned to Clarion (NON-NEGOTIABLE).** `.old`'s `_qualnames.py` emits `outer.inner` for closures and its L3 path skips nested functions — both **diverge** from Clarion. SP1 implements `core/qualname.py` to match Clarion's contract byte-for-byte (brief §Round 2):
   - `module_dotted_name(rel_path)`: one-level `src/` strip → drop `.py` → collapse `__init__` → join `.`; top-level `__init__.py` emits no entity.
   - `reconstruct_qualname`: reverse-walk ancestors; `FunctionDef`/`AsyncFunctionDef` → `{name}.<locals>.`; `ClassDef` → `{name}.`; final `f"{module}.{qualname}"`.
   - Honor the divergence gotchas (`<locals>` from function parents only; `@overload` stubs dropped; first-wins on duplicate qualnames; `async def`≡`def`). The engine's call graph must use this **single** qualname scheme everywhere (no separate L1/L3 schemes as `.old` had).
   - **Deliverable:** a shared **qualname conformance corpus** (`tests/conformance/qualnames.json`: `{layout, file, symbol} → expected`) seeded from the brief's examples + edge cases; both Wardline and Clarion test against it.

2. **Taint source is pluggable.** `.old` hard-codes wardline decorator names in `BODY_EVAL_TAINT`/`RETURN_TAINT` and `_WARDLINE_PREFIXES`. SP1 defines a `TaintSourceProvider` seam: L1 seeding asks the provider for a function's declared taint (from decorators/annotations/config). SP1 ships a **trivial default provider** (everything `UNKNOWN_RAW` except `stdlib_taint.yaml` entries); **SP2** supplies the real decorator-vocabulary provider via the registry. This keeps SP1 independent of SP2.

3. **`Finding` is SP0's `Finding`.** `.old`'s `context.Finding` carries governance fields (exception_*, summary_provenance, anchor_source, annotation_groups). SP1 emits SP0's `wardline.core.finding.Finding`. Engine diagnostics map to `kind=fact`/`metric` (e.g. unresolved-import facts, L3 low-resolution metrics); taint *provenance* rides `properties`. No governance fields.

4. **Rule dispatch is a hook, not a rule set.** SP1 ports the `RuleBase`/`PostResolverRule` **protocol** (the seam) and a `RuleRegistry`, but ships **no rules** — `scanner/rules/` stays the empty SP2 package. The analyzer runs whatever rules are registered (none in SP1) plus its own engine diagnostics.

5. **Discarded outright:** `manifest/`, `bar/`, `fingerprint.py` (signing), `exceptions.py` (ledger), `manifest_audit.py`, `anchor_integrity.py`, `sarif.py`/`sarif_schema.py` (→ SP4), `report/`, `deep_immutability.py`, `result_slice.py`, `core/evidence.py`, `core/tiers.py`. Anchor *resolution* precedence (`anchor_resolver.py`) is kept but simplified to (taint-source-provider > stdlib > UNKNOWN_RAW) — no `dependency_taint` manifest tier.

---

## 5. What SP1 emits (without rules)

Running `wardline scan` after SP1 produces a `findings.jsonl` containing **engine diagnostics only** (rules come in SP2):
- `kind=fact`: unresolved-import / unknown-symbol facts from `diagnose_unknown_imports`.
- `kind=metric`: L3 resolution metrics (SCC count/size distribution, convergence iterations, low-resolution ratio, cache hit-rate) — useful signal, and the data SP4 later promotes to SARIF run-level properties.
- The computed project **taint map** is exposed on the analyzer result (in-memory) for SP2's rules and SP1's own diagnostics; it is not itself a finding.

This gives a runnable, honest SP1: the engine demonstrably computes transitive taints (verifiable on fixtures and via the metrics), even before any policy rule exists.

---

## 6. Sub-decomposition (each stage ends green & testable)

| Stage | Deliverable | Key acceptance |
|---|---|---|
| **SP1a** | `core/qualname.py` (Clarion-aligned) + AST primitives (import-alias resolver, scope walkers) + entity discovery + **conformance corpus** | corpus passes; entities for a fixture match expected qualnames incl. nested-class/closure/`__init__` cases |
| **SP1b** | `core/taints.py` (lattice+join) + L1 `function_level` seeding via `TaintSourceProvider` (default provider) + `stdlib_taint` | join-table tests; L1 seeds correct for fixtures; provider seam documented |
| **SP1c** | L2 `variable_level` + `minimum_scope` bounded propagation | variable-taint join tests; one-hop refinement test |
| **SP1d** | `callgraph` + SCC `propagation` kernel + `module_summariser` + `project_resolver` + `resolver_metadata` | SCC/fixed-point tests (incl. cyclic SCC, monotonicity, convergence bound); transitive taint correct on a multi-module fixture |
| **SP1e** | `summary_cache` + `reverse_edge_index` (incremental dirty-set) | cache hit/miss + dirty-set invalidation tests; cached run ≡ cold run |
| **SP1f** | `WardlineAnalyzer` + `AnalysisContext` + `diagnostics` + `RuleRegistry` hook; wire into CLI replacing `NoOpAnalyzer` | `wardline scan <fixture>` emits engine-diagnostic findings + exposes taint map; self-hosting xfail still xfails (no rules yet) |

Build order SP1a → SP1b → SP1c → SP1d → SP1e → SP1f. Each gets its own plan + subagent-driven execution.

---

## 7. Non-goals (deferred / never)

- **No policy rules** (`PY-WL-*` etc.) — SP2. **No decorator vocabulary** — SP2 (SP1 ships only the pluggable seam + trivial default provider).
- **No SARIF / Filigree / Clarion emission** — SP4. SP1 writes `findings.jsonl` only (SP0's `JsonlSink`).
- **No baseline / waivers** — SP3.
- **Never:** manifest governance, BAR, fingerprint signing, exception ledger, conformance evidence.

---

## 8. Risks & mitigations

- **Port fidelity of the SCC kernel.** `propagation.py` is a subtle fixed-point algorithm. Mitigation: port with its convergence-bound + monotonicity tests intact; add a cyclic-SCC fixture; verify cached≡cold in SP1e.
- **Qualname drift from Clarion.** Mitigation: the shared conformance corpus is a hard gate in SP1a and runs in CI on both sides.
- **Engine size / context.** Mitigation: the six-stage split keeps each plan to ~600–900 LOC; subagent-driven execution with two-stage review per task.
- **`Finding` impedance.** `.old`'s rich `Finding` → SP0's slimmer one. Mitigation: taint provenance → `properties`; engine diagnostics → `kind=fact/metric`; no governance fields.
