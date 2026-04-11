# L3 Call-Graph Taint Propagation Design — WP 2.1

**Date:** 2026-03-24
**Status:** Draft
**Scope:** Intra-module call-graph taint inference with fixed-point propagation
**Target release:** v0.3.0
**Dependencies:** None (L1 and L2 taint infrastructure exist)
**Spike:** `docs/superpowers/specs/2026-03-23-callgraph-approach-spike.md`
**Spec references:** Wardline Framework Specification v0.2.0 — §5 (taint model), §10 property 6 (taint flow verification)

## Context

L1 taint assigns a `TaintState` per function from decorators or module defaults. L2 tracks per-variable taint within function bodies. Neither considers what a function *calls* — a function with no decorator that only calls `@external_boundary` functions is currently `UNKNOWN_RAW`, even though its actual data context is external.

L3 refines function-level taints by propagating taint along intra-module call edges. The spike decided: stdlib `ast` only (no `astroid`), intra-module scope only, direct calls + `self.method()` resolution.

This design was informed by a 7-reviewer panel. The panel identified three critical flaws in the spike's original propagation formula that this spec corrects:

- **Static Analysis C-1:** The `taint_join` lattice collapses cross-family pairs to `MIXED_RAW`, which would saturate the call graph. L3 needs a total trust order.
- **Static Analysis C-2:** Decorated functions must be anchored (read-only seeds), not participants in the join.
- **Static Analysis I-2 / Systems Thinker C2:** Unresolved calls must be transparent (no contribution), not `UNKNOWN_RAW` sources.

Additional panel findings incorporated: Solution Architect C1 (L3 consumes and returns same type as L1), Quality F3 (property-based convergence testing), Python I3 (super() out of scope), Solution Architect I1 (separate extractor and propagator modules).

**Second-pass panel review (7 reviewers on written spec) — critical findings resolved:**
- **All 7 reviewers:** Module_tiers functions misclassified as anchored. Fixed: three-way provenance classification.
- **Security C-2 + Static Analysis I-2:** Trust-upgrade invariant contradicts design goal. Fixed: floating functions CAN be refined in either direction; security property is anchored immutability only.
- **IRAP C-1:** Taint-drift finding lacked governance attributes. Fixed: UNCONDITIONAL exceptionability, ERROR severity, registered RuleId.
- **IRAP C-3 + Security I-1:** Unresolved-call evidence gap. Fixed: resolved/unresolved counts in provenance, informational finding at high unresolved ratio.
- **IRAP S-1:** Provenance must be mandatory, not optional. Fixed: mandatory deliverable.
- **Systems C-2:** Exception migration workflow needed. Fixed: preview-drift and migrate commands.

## 1. Trust Order for L3 Propagation

### Problem

The existing `taint_join()` in `core/taints.py` is designed for L2 variable-level merges within a function body. It uses a partial order where cross-family joins (e.g., `ASSURED + EXTERNAL_RAW`) collapse to `MIXED_RAW`. This is correct for data-flow merges — if a variable holds data from both a pipeline and an external source, it genuinely has mixed provenance.

For call-graph propagation, the question is different: "what is the least-trusted data this function transitively touches?" A `ASSURED` function that calls an `EXTERNAL_RAW` function doesn't have mixed data — it has a dependency on untrusted data. The effective trust should be `EXTERNAL_RAW`, not `MIXED_RAW`.

### Solution: Total Trust Order

Define a total ordering over `TaintState` for L3 purposes (most trusted → least trusted):

```
INTEGRAL > ASSURED > GUARDED > UNKNOWN_ASSURED >
UNKNOWN_GUARDED > EXTERNAL_RAW > UNKNOWN_RAW > MIXED_RAW
```

Represented as an integer rank (lower = more trusted):

| TaintState | Rank |
|---|---|
| `INTEGRAL` | 0 |
| `ASSURED` | 1 |
| `GUARDED` | 2 |
| `UNKNOWN_ASSURED` | 3 |
| `UNKNOWN_GUARDED` | 4 |
| `EXTERNAL_RAW` | 5 |
| `UNKNOWN_RAW` | 6 |
| `MIXED_RAW` | 7 |

L3 propagation uses `max(rank)` — the effective taint is the least-trusted state in the transitive call closure. This replaces `taint_join` for L3 purposes only. L2 variable-level taint continues to use `taint_join` unchanged.

**Location:** New function `least_trusted(a, b) -> TaintState` in `scanner/taint/callgraph.py`. Returns the taint with the higher rank (less trusted). Not added to `core/taints.py` — this is an L3-specific operation, not a lattice primitive.

**Safety:** Add a module-level assertion `assert len(TRUST_RANK) == len(TaintState)` to catch enum/rank-table drift when new taint states are added.

## 2. Anchored vs. Floating Functions

### Problem

The spike's formula `function_taint = join(own_taint, join(callee_taints))` allows decorated functions to have their taint altered by call-graph propagation. This violates the L1 security invariant (function_level.py line 13-14): "a function explicitly decorated `@external_boundary` must still get `EXTERNAL_RAW`."

Worse: if propagation is bidirectional (callee taint flows to caller AND caller context influences callee), a decorated function could be *upgraded* — a trust boundary violation.

### Solution: Three-Way Provenance Classification

The classification is based on **how the taint was assigned** (provenance), not the taint value itself. This requires L1 to emit provenance metadata alongside the taint map.

**L1 provenance output:** `assign_function_taints` returns an additional `dict[str, TaintSource]` where `TaintSource` is `Literal["decorator", "module_default", "fallback"]`. The engine passes this to L3.

**Classification:**

- **Anchored (decorator):** Functions whose taint was assigned by a decorator (`TaintSource == "decorator"`). Their taint is an explicit developer assertion. Immutable — they are read-only seeds in the call graph. Their own taint never changes.
- **Floating (module_default):** Functions whose taint came from a `module_tiers` path match (`TaintSource == "module_default"`). Their taint is a blanket organizational classification, not a per-function assertion. L3 can refine them — downward only (toward less trust). A `ASSURED` function in a module_tiers module that calls `@external_boundary` functions should be refined to `EXTERNAL_RAW`.
- **Floating (fallback):** Functions that defaulted to `UNKNOWN_RAW` (`TaintSource == "fallback"`). L3 can refine them in either direction — if they only call trusted functions, they can be refined upward toward `INTEGRAL`; if they call untrusted functions, they stay at or move below `UNKNOWN_RAW`.

**Rationale for allowing upward refinement of fallback functions:** A function with no decorator and no module_tiers match has `UNKNOWN_RAW` purely because the tool has no information. If L3 discovers it only calls `@integral_read` functions, the actual trust context is `INTEGRAL`. Preventing this refinement would make L3 useless for its primary purpose — inferring trust for unannotated code. The security boundary is anchored immutability: decorated functions (explicit developer assertions) can never be overridden by inference.

**Propagation formula for floating functions:**

```
L3_taint(F) = max_rank(callee_taints)
            where callee_taints = {L3_taint(G) for G in resolved_callees(F)}
```

If a floating function has no resolved callees, its taint remains at its L1 value (module_default or `UNKNOWN_RAW`).

Guard against empty callee set: use `max(ranks, default=current_L1_rank)` to avoid `ValueError` on empty input.

**Invariants (enforced post-fixed-point):**

```
For all functions F:
    L3_taint(F) == L1_taint(F)                             if F is anchored (decorator)
    trust_rank(L3_taint(F)) >= trust_rank(L1_taint(F))     if F is floating (module_default)
    (no rank constraint)                                     if F is floating (fallback)
```

- **Anchored immutability:** Decorated functions' taints never change. This is the core security property. Violation is a scanner bug.
- **Module_default downward-only:** Module_tiers functions can be refined to *less* trusted (higher rank) but not *more* trusted than their module default. This respects the manifest author's intent while allowing L3 to discover trust-boundary violations within the module.
- **Fallback unconstrained:** Fallback functions can move in either direction based on their callees. This is where L3 provides its primary value.

Violation of the first two invariants → log error, emit `TOOL-ERROR` finding (UNCONDITIONAL exceptionability, ERROR severity), return original `taint_map` unchanged. The `TOOL-ERROR` finding fails CI — a broken invariant invalidates all L3 assignments in the file.

## 3. Unresolved Call Policy

### Problem

The spike says unresolved calls map to `UNKNOWN_RAW`. Combined with the trust-order propagation, any function that calls an imported function (which is nearly every function) would be pulled to `UNKNOWN_RAW` or worse, destroying L3's value.

### Solution: Transparent Unresolved Calls

Unresolved calls contribute nothing to the callee taint set. Only resolved intra-module edges participate in propagation.

**Rationale:** L3 explicitly scopes to intra-module analysis. Injecting `UNKNOWN_RAW` for cross-module calls would make L3 strictly worse than L1 for any function that imports anything. The pragmatic approach: L3 refines taint based on edges it *can* resolve. Edges it cannot resolve are treated as if they don't exist.

**Semantic:** "L3 computes the taint contribution of intra-module call relationships. Cross-module effects are not modeled and assumed neutral."

**Evidence gap mitigation (IRAP C-3):** Record the resolved and unresolved call counts per function in the provenance record (Section 7). When `unresolved / (resolved + unresolved) > 0.7` (configurable), emit an informational `L3-LOW-RESOLUTION` finding so downstream consumers know the refinement is based on a minority of the actual call surface. This is not a scan finding — it is a governance-level diagnostic for assessors evaluating L3 confidence.

**What is unresolved:**
- `import foo; foo.bar()` — cross-module call
- `func_ref()` where `func_ref` is a parameter — higher-order call
- `getattr(obj, name)()` — dynamic dispatch
- `super().method()` — requires MRO resolution (explicitly out of scope for v0.3.0)
- `renamed()` where `renamed = original` — alias tracking (deferred)

**What is resolved:**
- `foo()` where `foo` is a module-level `def foo` — direct call
- `self.method()` where `method` is defined in the enclosing class — method call
- `ClassName()` — constructor call to a class defined in the same module

## 4. Call Graph Extraction

### Module: `scanner/taint/callgraph.py`

**Function:** `extract_call_edges(tree: ast.Module, qualname_map: dict[int, str]) -> dict[str, set[str]]`

**Algorithm:**

1. **Collect definitions:** Reuse `ScanEngine._build_qualname_map()` (extract to shared utility `scanner/_qualnames.py` if not already shared). Produces `{id(node): qualname}` for all functions.

2. **Build reverse map:** `{name: qualname}` for module-level functions, `{class_name: {method_name: qualname}}` for class methods.

3. **Extract edges per function:** Walk each function body:
   - `ast.Call(func=ast.Name(id=X))` where X is in module-level defs → edge to X's qualname
   - `ast.Call(func=ast.Attribute(value=ast.Name(id='self'), attr=M))` where M is in enclosing class → edge to `EnclosingClass.M`'s qualname
   - `ast.Call(func=ast.Name(id=ClassName))` where ClassName is a module-level class → edge to `ClassName.__init__` if it exists
   - Everything else → no edge (transparent)

4. **Return adjacency list:** `{caller_qualname: {callee_qualname, ...}}`

**Enclosing class resolution:** The qualname already encodes the class (`ClassName.method`). To resolve `self.method()`, extract the class prefix from the caller's qualname (`qualname.rsplit(".", 1)[0]`) and look up the method in the class's method set.

### Module: `scanner/taint/callgraph_propagation.py`

Separate from extraction (panel finding Solution Architect I1 — two distinct failure modes deserve independent test surfaces).

## 5. Fixed-Point Propagation

### Module: `scanner/taint/callgraph_propagation.py`

**Function:** `propagate_callgraph_taints(edges: dict[str, set[str]], taint_map: dict[str, TaintState]) -> dict[str, TaintState]`

**Input:**
- `edges`: adjacency list from `extract_call_edges`
- `taint_map`: L1 function-level taint map from `assign_function_taints`

**Output:** Refined `dict[str, TaintState]` — same type as input, drop-in replacement for L1 map.

**Algorithm:**

1. **Classify functions:** Using L1 provenance metadata (see Section 2), partition into: anchored (decorator), floating-module_default, floating-fallback.

2. **Initialize:** Copy `taint_map`. Floating functions start at `UNKNOWN_RAW`.

3. **SCC decomposition:** Compute strongly connected components via Tarjan's algorithm (O(V+E)). Process SCCs in reverse topological order — DAG portions converge in a single pass, iteration only within SCCs.

4. **Worklist iteration per SCC:**
   For each SCC (in reverse-topo order):
   - If the SCC contains only anchored functions, skip (their taints are fixed).
   - Initialize worklist with all floating functions in the SCC.
   - While worklist is non-empty:
     - Pop function F from worklist.
     - Compute `new_taint = max_rank({current_taint(G) for G in resolved_callees(F)}, default=L1_taint(F))`. The `default` handles the empty-callee-set case (no resolved callees → stays at L1 taint).
     - If `new_taint` differs from F's current taint: update F's taint, add all floating callers of F (within this SCC) to the worklist.
   - Safety bound: if iterations exceed `LATTICE_HEIGHT * SCC_SIZE` (= `8 * len(scc)`), emit a structured `L3-CONVERGENCE-BOUND` finding (WARNING severity) in SARIF output, break, use current state. This should never trigger if the implementation is monotonic — triggering indicates a propagation bug.

5. **Post-fixed-point assertion:** For every function F:
   - If anchored (decorator): assert `result[F] == taint_map[F]`
   - If floating (module_default): assert `trust_rank(result[F]) >= trust_rank(taint_map[F])` (downward-only)
   - If floating (fallback): no rank constraint (upward refinement allowed)
   - Violation of anchored or module_default invariants → log error, emit `TOOL-ERROR` finding (UNCONDITIONAL exceptionability, ERROR severity — fails CI), return original `taint_map` unchanged.

**Convergence guarantee:** The trust-rank lattice has height 8. The transfer function (`max_rank` over callees) is monotone — taint can only stay the same or decrease in trust. With SCC-based ordering, DAG portions converge in one pass. Within SCCs, worst-case iterations = `LATTICE_HEIGHT * SCC_SIZE`. Total worst-case: `O(V + E + 8 * max_SCC_size * SCC_count)`, which is effectively `O(V + E)` for practical call graphs.

## 6. Engine Integration

### Pass Ordering

Current: L1 → L2 → rules
New:     L1 → L3 → L2 → rules

L3 runs *before* L2 because L2's `_resolve_call()` in `variable_level.py` looks up callee taint in `taint_map`. If L3 has refined a callee's taint, L2 should see the refined value.

### Engine Changes (`scanner/engine.py`)

In `_scan_file()`, between the existing L1 assignment and L2 variable taint:

```python
# Pass 1.5: Level 3 call-graph taint (when analysis_level >= 3)
if self._analysis_level >= 3 and taint_map:
    taint_map = self._run_callgraph_taint(tree, taint_map, file_path, result)

# Pass 1.75: Level 2 variable-level taint (existing, renumbered from "Pass 1.5")
```

The existing L2 pass comment changes from "Pass 1.5" to "Pass 1.75" to accommodate L3's insertion.

This replaces the local `taint_map` variable before `ScanContext` construction (engine.py:179). L3 returns a plain `dict`, and `ScanContext.__post_init__` handles the `dict → MappingProxyType` conversion. No `ScanContext` field changes needed for the core taint map — rules already read `function_level_taint_map`, which now contains L3-refined taints.

**ScanContext addition:** Add `analysis_level: int = 1` field to `ScanContext`. This allows rules and the exception matching pipeline to know the active analysis depth without engine-level coupling. Wire from `ScanEngine._analysis_level` during context construction.

**L2 integration note:** L2's `_resolve_call()` in `variable_level.py` uses bare `ast.Name.id` for callee lookup, while `taint_map` is keyed by qualname. This is a pre-existing gap: `self.method()` calls are not resolved by L2 regardless of L3. L3 refinements for class methods will appear in the taint_map but L2 cannot consume them. This is documented as a known limitation and filed as a separate follow-up work item.

### New Engine Method

```python
def _run_callgraph_taint(
    self,
    tree: ast.Module,
    taint_map: dict[str, TaintState],
    file_path: Path,
    result: ScanResult,
) -> dict[str, TaintState]:
    """Run L3 call-graph taint propagation. Returns refined taint_map."""
    from wardline.scanner.taint.callgraph import extract_call_edges
    from wardline.scanner.taint.callgraph_propagation import propagate_callgraph_taints

    qualname_map = self._build_qualname_map(tree)
    try:
        edges = extract_call_edges(tree, qualname_map)
        return propagate_callgraph_taints(edges, taint_map)
    except Exception as exc:
        logger.warning("L3 call-graph taint failed for %s: %s", file_path, exc)
        result.errors.append(f"L3 taint failed for {file_path}: {exc}")
        return taint_map  # Fall back to L1 map
```

### Qualname Map Extraction

`ScanEngine._build_qualname_map()` (engine.py:228-248) should be extracted to `scanner/_qualnames.py` as a shared utility, since L3's `extract_call_edges` needs the same mapping. This avoids a third implementation of scope tracking.

## 7. Taint Provenance Tracking (Mandatory)

Provenance is assessment evidence, not a convenience feature. An assessor reviewing a function refined to `INTEGRAL` by L3 needs to know which callee dominated the assignment and how many call edges were excluded. Provenance ships with L3 core, not deferred.

```python
@dataclass(frozen=True)
class TaintProvenance:
    source: Literal["decorator", "module_default", "callgraph", "fallback"]
    via_callee: str | None = None  # qualname of the dominating callee (L3 only)
    resolved_call_count: int = 0   # number of resolved intra-module call edges
    unresolved_call_count: int = 0 # number of unresolved call edges (transparent)
```

The propagation function returns `tuple[dict[str, TaintState], dict[str, TaintProvenance]]` from day one. The engine stores provenance in `ScanContext` as a field for `explain` and governance diagnostics to consume.

L1 also emits provenance: `assign_function_taints` returns `tuple[dict[str, TaintState], dict[str, TaintSource]]` where `TaintSource` is `Literal["decorator", "module_default", "fallback"]`. L3 converts these to `TaintProvenance` records and upgrades the `source` to `"callgraph"` for refined functions.

## 8. Exception Register Impact

### Problem (Systems Thinker C1, Security F4)

Exception matching uses `(rule, taint_state, location)` as key. When L3 changes a function's effective taint, existing exceptions silently stop matching.

### Solution

This is an exception register design change, not an L3 algorithm change. Three interventions:

**1. `GOVERNANCE-EXCEPTION-TAINT-DRIFT` finding:**

During `apply_exceptions`, when an exception's `taint_state` doesn't match the function's current effective taint at the active analysis level, emit a governance finding. Register `RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT` in `core/severity.py`. Attributes:
- **Exceptionability:** UNCONDITIONAL — taint drift is a policy-layer change that must not be suppressed by another exception
- **Severity:** ERROR — forces re-review
- **SARIF ruleId:** `GOVERNANCE-EXCEPTION-TAINT-DRIFT`

Implementation: extend `scanner/exceptions.py`.

**2. `analysis_level` field on exception entries:**

Add `analysis_level: int = 1` to `ExceptionEntry` model. Store the analysis level active when the exception was granted. Behavior:
- When an exception's `analysis_level` is lower than the active scan level, emit `GOVERNANCE-EXCEPTION-LEVEL-STALE` (ERROR, UNCONDITIONAL) regardless of whether taint happens to match. This ensures the L1→L3 transition produces an audit signal for every affected exception.
- Level-stale exceptions are **inactive** (non-suppressing) until re-granted at the current level. Re-granting is a standard governance event subject to temporal separation at Assurance level.

Implementation: extend `ExceptionEntry` model and `exception_cmds.py`.

**3. Exception migration workflow:**

- `wardline exception preview-drift --analysis-level=3` — dry-run: reports which exceptions would break at L3 without changing anything. Shows old taint, new taint, and the callee that caused the drift.
- `wardline exception migrate --analysis-level=3` — updates exception `taint_state` fields to match L3 taints while preserving audit trail (adds a `migrated_from` note to each modified exception).

These commands provide a controlled transition path for teams upgrading from L1/L2 to L3, preventing the "first L3 scan breaks CI" problem.

All three are scoped as requirements within WP 2.1, not separate work packages.

## 9. Corpus Upgrades

### Prerequisites (ship in v0.2.1)

- **Corpus verifier taint wiring:** `corpus_cmds.py` must wire `ScanContext` from specimen YAML metadata so taint-dependent rules execute correctly. Without this, L3 specimens are meaningless.
- **`analysis_level_required` field:** Add to `corpus-specimen.schema.json`. Verifier skips specimens above configured level. Default 1 for all existing specimens.
- **Rules 006-009 in verifier:** `_make_rules()` in `corpus_cmds.py` currently only instantiates rules 001-005. Add all 9.

### L3 Specimens (ship with WP 2.1)

Minimum specimen set for L3 validation:

| Specimen | Pattern | Expected L3 Behavior |
|---|---|---|
| Multi-hop call chain | A→B→C where C is `@external_boundary` | A and B refined to `EXTERNAL_RAW` |
| Direct recursion | A calls A (self-recursive) | Taint stable (no infinite loop) |
| Mutual recursion | A↔B cycle | Both converge to least-trusted callee taint |
| Mixed resolved/unresolved | A calls B (resolved) and `json.loads` (unresolved) | A refined by B only; `json.loads` transparent |
| Anchored not demoted | `@external_boundary` A calls `@integral_read` B | A stays `EXTERNAL_RAW` (anchored) |
| Floating refinement | Undecorated A calls only `@integral_read` functions | A refined from `UNKNOWN_RAW` to `INTEGRAL` |
| Diamond pattern | A calls B and C; B and C both call D | A gets `max_rank(B_taint, C_taint)` |
| No resolved callees | A calls only imported functions | A stays `UNKNOWN_RAW` |
| Module_default not upgraded | `module_tiers: ASSURED` function calls only `@integral_read` | Stays `ASSURED` (module_default is downward-only) |
| Module_default demoted | `module_tiers: ASSURED` function calls `@external_boundary` | Refined to `EXTERNAL_RAW` (downward allowed) |
| Anchored immutable | Adversarial: decorator-anchored function in crafted call chain | Taint unchanged; assertion verifies |

Set `analysis_level_required: 3` on all L3 specimens. Existing KFN specimens (PY-WL-001-KFN-01, PY-WL-004-KFN-01) should flip to TP at L3 — update their metadata.

## 10. Self-Hosting Baseline

L3 will change finding counts for taint-gated rules (especially PY-WL-003, which fires only at `EXTERNAL_RAW`/`UNKNOWN_RAW`/`MIXED_RAW`). The self-hosting test (`test_scan_finding_count_stable`) needs per-analysis-level baselines.

**Approach:** Parameterize the self-hosting test by analysis level. Maintain separate expected ranges for L1 (existing), L2 (existing), and L3 (measured after L3 stabilizes). CI runs at the configured analysis level.

## 11. Performance

Per the static analysis specialist (S-1): call-graph construction is O(V+E), fixed-point iteration is O(V * LATTICE_HEIGHT) = O(8V). The ast.parse() call dominates. No performance concern for intra-module analysis.

**Validation:** Add a `pytest-benchmark` test that runs the self-hosting scan at L3 and records wall time. Set a 30-second budget (same as the existing performance requirement from panel I10).

## 12. Known Limitations

| Limitation | Rationale |
|---|---|
| Intra-module only | Cross-module requires import resolution — deferred to L4+ |
| No alias tracking | `renamed = original; renamed()` unresolvable without data flow |
| No `super()` resolution | Requires MRO computation, which requires class hierarchy — effectively cross-module |
| No dynamic dispatch | `getattr()`, `dispatch_table[key]()` — runtime information unavailable |
| No higher-order calls | `func_ref()` where `func_ref` is a parameter — requires inter-procedural analysis |
| Unresolved calls are transparent | Conservative choice would be UNKNOWN_RAW, but this causes cascade; transparency trades false negatives for noise reduction. Resolved/unresolved counts recorded in provenance; `L3-LOW-RESOLUTION` finding at >70% unresolved. |
| L2 cannot consume L3-refined method taints | L2's `_resolve_call()` uses bare `ast.Name.id`, not qualnames. `self.method()` lookups fail. Pre-existing gap — file as separate WP. |
| `__init__.py` re-exports are intra-file | `from .submodule import helper` followed by `helper()` is syntactically intra-module but semantically cross-module. Resolved as intra-module (same file). |
| Nested function closure scope | Nested functions can call module-level functions by bare name. Resolved via module-level def reverse map. |
| Iterative Tarjan's required | Classic recursive Tarjan's may hit Python recursion limit on large modules (1000+ functions). Use iterative implementation. |

## 13. Testing Strategy

### Unit Tests

- **Call graph extraction:** Test each resolution pattern (direct call, self.method, ClassName(), unresolved) independently.
- **Propagation:** Test anchored/floating classification, single-step propagation, multi-hop chains, diamond patterns.
- **SCC handling:** Direct recursion, mutual recursion, large SCC.

### Property-Based Tests (Hypothesis)

- **Convergence:** Random call graphs (DAGs and cyclic) with random initial taints → propagation terminates within bound.
- **Monotonicity:** Between consecutive iterations, no function's trust rank decreases (becomes more trusted).
- **Idempotence:** Running propagation twice on the same input produces identical output.
- **Anchored immutability:** Anchored functions' taints never change regardless of call graph structure.

### Integration Tests

- Self-hosting scan at L3 completes without errors.
- L3 corpus specimens produce expected results.
- KFN specimens flip to TP at L3.

## 14. Implementation Summary

| Component | File | Lines (est.) | Effort |
|---|---|---|---|
| Trust order + `least_trusted` | `scanner/taint/callgraph.py` | ~30 | XS |
| L1 provenance output | `scanner/taint/function_level.py` | ~30 | XS |
| Call graph extraction | `scanner/taint/callgraph.py` | ~80 | S |
| SCC decomposition (Tarjan's) | `scanner/taint/callgraph_propagation.py` | ~60 | S |
| Fixed-point propagation | `scanner/taint/callgraph_propagation.py` | ~80 | S |
| Engine integration | `scanner/engine.py` | ~20 | XS |
| Qualname extraction to shared utility | `scanner/_qualnames.py` | ~30 | XS |
| Taint provenance (mandatory) | `scanner/taint/callgraph_propagation.py` | ~50 | S |
| Exception taint-drift + level-stale findings | `scanner/exceptions.py` + `core/severity.py` | ~60 | S |
| Exception migration CLI (preview-drift, migrate) | `cli/exception_cmds.py` | ~80 | S |
| `analysis_level` on ScanContext + ExceptionEntry | `scanner/context.py` + `manifest/models.py` | ~20 | XS |
| L3 corpus specimens (9+) | `corpus/specimens/` | ~200 | S |
| Property-based tests | `tests/unit/scanner/` | ~100 | S |
| Unit + integration tests | `tests/` | ~150 | S |
| Self-hosting baseline (L3) | `tests/integration/` | ~30 | XS |
| **Total** | | ~1070 | **L** |
