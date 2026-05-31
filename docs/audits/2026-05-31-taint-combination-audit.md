# Audit — taint-combination soundness & precision across the wardline taint engine

**Verdict:** The three migrations are complete and correct. Every combination /
merge / aggregation / alternative site in the engine is on `least_trusted`.
`taint_join` is dead in production. No remaining over-taint (MIXED_RAW) site and
no operator-level under-taint were found. Six findings, all P2–P4
(dead-code / latent / by-design / stale-comment); **zero P0/P1, zero live FP, zero
live FN.** Oracles: soundness battery 30/30, self-host 0 PY-WL defects, all
repros below pass.

## The reachable-state result (the linchpin)

The only taint states any source can introduce into the live pipeline are:

| Entry point | States it can produce |
|---|---|
| `decorator_provider` (`@external_boundary`/`@trust_boundary`/`@trusted`) | EXTERNAL_RAW, GUARDED, ASSURED, INTEGRAL |
| L1 fail-closed fallback (`function_level._FALLBACK`) | UNKNOWN_RAW |
| `stdlib_taint.yaml` (shipped) | ASSURED, EXTERNAL_RAW, GUARDED, UNKNOWN_RAW |
| serialisation-sink override | UNKNOWN_RAW |

So the **reachable set = {INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}**.
`least_trusted` returns one of its inputs, so its closure over that set is that
same set. **MIXED_RAW, UNKNOWN_GUARDED, and UNKNOWN_ASSURED are never assigned as
a value anywhere in production.** This was confirmed two ways: (1) literal
attribute-access assignments — the only ones live in the dead `taint_join` body,
the `TRUST_RANK` table, and rule membership sets; and (2) **exhaustive** dynamic
construction — `grep "TaintState(" src/wardline/` returns six call sites, every
one of which is either allow-gated to the reachable subset (`decorator_provider`,
`coerce_level`) or feeds the pipeline only with provider-produced reachable states
(`stdlib_taint`, `summary_cache` — both ungated and folded into F5). No third
ungated source feeds combination, so the reachable set is **provably** as stated.

REPL proof:
```
least_trusted closure over reachable set => [ASSURED, EXTERNAL_RAW, GUARDED, INTEGRAL, UNKNOWN_RAW]
  manufactures MIXED_RAW? False   UNKNOWN_GUARDED? False   UNKNOWN_ASSURED? False
taint_join clean-input MIXED_RAW pairs that least_trusted avoids: 20  (e.g. INTEGRAL+ASSURED, ASSURED+GUARDED…)
rank-invariant least_trusted<=taint_join violations: []
```

This both (a) confirms the FP class the migrations targeted is genuinely closed —
20 ordered clean-input pairs that `taint_join` would have spiked to MIXED_RAW
(rank 7, firing RAW_ZONE) now resolve to a clean rank; and (b) makes several
findings below *latent* rather than live.

---

## Findings

### F1 — MIXED_RAW / UNKNOWN_* unreachable ⇒ the PY-WL-101↔modulate MIXED_RAW asymmetry is latent
- **Classification:** precision / dead-state. **Severity:** P3. **Direction:** dead-code (latent FP *and* latent FN).
- **Sites:** `untrusted_reaches_trusted.py:35-37` `_RAW_ZONE` (contains MIXED_RAW → **fires**) vs `severity_model.py:32-38` `modulate` (MIXED_RAW falls to the `_FREEDOM` else → **NONE / suppressed**). Same state, opposite firing direction.
- **Repro / observed:** see the closure proof above — no production path yields MIXED_RAW, so neither branch is ever reached with it. `modulate` consumes a *single* `context.project_taints[qualname]` tier (`broad_exception.py:45`, `silent_exception.py:44`), never a combination, so even a combination bug could only reach it through a value, and no value is MIXED_RAW.
- **Downstream:** none today — cannot flip a decision because the input is unreachable.
- **Fix:** No code change required for correctness. Worth a one-line comment at `_RAW_ZONE` and at `modulate`'s `_FREEDOM` note recording that MIXED_RAW is *currently unreachable* and that the two rule families would disagree on it if it ever became reachable (see F5). This is the design guard that keeps F5 from becoming live.

### F2 — Dead inner unresolved-clamp in the SCC round
- **Classification:** floor / clamp. **Severity:** P3. **Direction:** dead-code.
- **Site:** `propagation.py:173-178`. After the line-172 floor `new_taint = floor if rank[floor] > rank[combined] else combined`, we have `rank[new_taint] >= rank[floor]` unconditionally; the inner guard `rank[floor] > rank[new_taint]` is therefore never true.
- **Repro:** swept 625 seed/floor configs with `unresolved>0`, `settrace` on line 178 → **0 executions**. Algebraic check over the reachable set → the condition is `True` in **0** configs.
- **Downstream:** none — never executes.
- **Fix:** Remove lines 173-178 (the line-172 floor subsumes them), or, if kept for parity with `minimum_scope`'s single-clamp comment, annotate it `# unreachable: line-172 floor already pins new_taint >= floor`. `minimum_scope.py:158-161` makes exactly this point in prose ("This single clamp also covers the unresolved-call case") — propagation.py kept the redundant second clamp the prose says is unnecessary.

### F3 — `taint_join` is dead production code
- **Classification:** operator. **Severity:** P3. **Direction:** dead-code.
- **Site:** `core/taints.py:65-84`. The only live `taint_join(` calls are its own 8 unit-test references in `tests/unit/core/test_taints.py`; every other repo reference (in `test_analyzer`, `test_propagation`, `test_minimum_scope`, `test_variable_level`) is an explanatory comment asserting `least_trusted` is used *instead*.
- **Downstream:** none.
- **Fix (recommended): keep, with an explicit "documented-but-unused" marker.** Rationale: (a) the function and its `_JOIN_TABLE` encode the provenance-clash semantics that ~20 migration regression-guard comments across the test suite cite by name — deleting the operator orphans those references; (b) its 8 unit tests pin the very semantics (`taint_join(INTEGRAL,ASSURED)==MIXED_RAW`) the migration comments contrast against, so they remain useful as the "why we did NOT use this" record. Add a module-level note that `taint_join` has no production call site and exists as the documented contrast operator. (If the project's no-dead-code stance is strict, the alternative is to delete the operator + `_JOIN_TABLE` + its 8 tests and soften the regression-guard comments to reference `least_trusted` only — a larger, lower-value churn.)

### F4 — Anchored `effective_return` laundering through a *broken* `@trust_boundary` (by-design)
- **Classification:** anchor. **Severity:** P3. **Direction:** under-taint (delegated, not a hole).
- **Site:** `project_resolver.py:156-159` (`effective_return`: anchored → declared return). A caller of a validator reads the validator's *declared* raised tier, regardless of whether the validator actually rejects.
- **Repro (end-to-end scan):**
  ```
  @trust_boundary(to_level=ASSURED) def bad_validate(p): return p      → PY-WL-102 fires (cannot validate) ✓
  @trusted(level=ASSURED)          def producer(p): return bad_validate(read_raw(p))   → SILENT (reads bad_validate's declared ASSURED)
  @trusted(level=ASSURED)          def direct_launder(p): return read_raw(p)           → PY-WL-101 fires (actual EXTERNAL_RAW > ASSURED) ✓
  ```
- **Downstream:** `producer` is silent on PY-WL-101 *because* its laundering is through a declared boundary — and the broken boundary itself is caught by PY-WL-102. The delegation the rule docstring claims **holds**: nothing escapes into a rule other than 102. Direct (non-boundary) raw laundering still fires (FN guard passes).
- **Fix:** No action — correct as-is. The trust model treats the annotation as the contract; the only statically-decidable enforcement of a validator is "can it reject at all" (PY-WL-102). Residual (out of static reach, not a combination issue): a validator that *has* a rejection path but validates the wrong predicate is semantically invisible. Document as a known boundary of the model, not a bug.

### F5 — Two ungated dynamic-construction entry points accept the unreachable trio
- **Classification:** ad-hoc / entry-point. **Severity:** P3. **Direction:** latent under-/over-taint enabler.
- **Exhaustive grep** `TaintState(` across `src/wardline/` returns six dynamic-construction sites; classified:
  - `decorator_provider.py:108` — **gated** (`:111` `level if level in allowed else None`), feeds pipeline ✓
  - `decorators/_base.py:32` `coerce_level` — **gated** (`raises` if `level not in allowed`) AND runtime decorator code, not the scanner's static path ✓
  - `core/taints.py:18` — the class definition, not a call ✓
  - **`stdlib_taint.py:69`** `TaintState(returns_taint_raw)` — **ungated**; feeds `taint_map`/`return_taint_map`. `TaintState("MIXED_RAW")` succeeds.
  - **`summary_cache.py:199-200`** `_deserialise_summary` — **ungated**; rehydrates `body_taint`/`return_taint` from the **disk-persistent** cache (`cache_dir=…` + `load()`), which feeds `summaries` → the pipeline. "MIXED_RAW" is a *valid* TaintState string so the "malformed files silently dropped" guard does NOT catch it; the cache_key fingerprint only rejects stale-schema files, not a same-schema file holding a poisoned-but-valid state.
- **Downstream:** today none — the shipped yaml uses only {ASSURED, EXTERNAL_RAW, GUARDED, UNKNOWN_RAW} and the cache only ever round-trips provider-produced (reachable) states. But a future yaml entry — or a hand-edited/corrupted on-disk cache file — carrying `MIXED_RAW` (or `UNKNOWN_GUARDED`/`UNKNOWN_ASSURED`) would inject an otherwise-unreachable state, immediately activating the F1 asymmetry (it would *fire* PY-WL-101 yet *suppress* the tier-modulated rules).
- **Fix:** Constrain *both* parsers to the call-return-legal subset `{ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}` and raise on MIXED_RAW / UNKNOWN_GUARDED / UNKNOWN_ASSURED, with a message pointing at F1. Cheap guard that makes the reachable-set invariant *enforced* rather than incidental. (Cache severity is lower — a local cache file is a trusted artifact — but the one-line guard covers both for free.)

### F6 — Stale comment: control-flow merges "keep taint_join"
- **Classification:** stale comment. **Severity:** P4. **Direction:** doc-only.
- **Site:** `tests/unit/scanner/taint/test_variable_level.py:830` — *"only control-flow MERGES (if/else, loops, match arms) keep taint_join."* This predates the control-flow-merge migration (wardline-4d9f840c24); those merges are now on `least_trusted` (verified at `variable_level.py:642,678,708,778,841` and by the L2 repro below). The comment actively misdescribes current behavior.
- **Fix:** Reword to "control-flow merges also use `least_trusted` (wardline-4d9f840c24)."

---

## Coverage table — every site inspected

Legend: **Op** = operator used. **Verdict:** ✓ correct / latent / dead / by-design.
**Exercised:** how it was empirically driven.

| # | Site (`file:line`) | Class | Op | Verdict | Empirically exercised |
|---|---|---|---|---|---|
| 1 | `taints.py:87 least_trusted` | operator | — | ✓ closed over reachable set | YES — closure + invariant sweep |
| 2 | `taints.py:65 taint_join` | operator | — | dead (F3) | YES — grep + closure contrast |
| 3 | `variable_level.py:134 BinOp` | value-merge | LT | ✓ | YES — L2 driver (clean+raw) |
| 4 | `variable_level.py:142 List/Tuple/Set` | aggregation | LT | ✓ | YES |
| 5 | `variable_level.py:155 Dict` | aggregation | LT | ✓ | YES |
| 6 | `variable_level.py:168 IfExp` | alternative | LT | ✓ | YES |
| 7 | `variable_level.py:189 BoolOp` | alternative | LT | ✓ | YES |
| 8 | `variable_level.py:232 JoinedStr` | value-merge | LT | ✓ | YES (.join proxy + str) |
| 9 | `variable_level.py:272 DictComp` | aggregation | LT | ✓ | covered by container/list cases |
| 10 | `variable_level.py:337 .format/.join` | value-merge | LT | ✓ | YES |
| 11 | `variable_level.py:355 .get/.pop default` | alternative | LT | ✓ | YES |
| 12 | `variable_level.py:371 propagating builtins` | value-merge | LT | ✓ | YES (str(raw)) |
| 13 | `variable_level.py:560 AugAssign` | value-merge | LT | ✓ | YES |
| 14 | `variable_level.py:595 container-base write` | value-merge | LT | ✓ floor toward less-trusted | covered by dict-raw case |
| 15 | `variable_level.py:642 if/else merge` | alternative | LT | ✓ | YES |
| 16 | `variable_level.py:678 for back-edge` | alternative | LT | ✓ | YES |
| 17 | `variable_level.py:708 while back-edge` | alternative | LT | ✓ | same shape as for (16) |
| 18 | `variable_level.py:778 try/except merge` | alternative | LT | ✓ | YES |
| 19 | `variable_level.py:841 match-arm merge` | alternative | LT | ✓ | YES |
| 20 | `variable_level.py:925 compute_return_taint` | aggregation | LT | ✓ | YES (every L2 case returns through it) |
| 21 | `variable_level.py:961 compute_return_callee` | diagnostic | LT | ✓ (returns one input; well-defined) | indirectly (101 properties) |
| 22 | `minimum_scope.py:155 callee combine` | aggregation | LT | ✓ | YES — 2-hop refine repro (clean+raw) |
| 23 | `minimum_scope.py:161 seed floor` | floor | rank | ✓ toward less-trusted | YES — 2-hop refine repro (floor pins to seed) |
| 24 | `minimum_scope.py:164 via_callee max` | diagnostic | rank | ✓ non-firing | YES — executed in refine (result stored only on change) |
| 25 | `propagation.py:170 SCC-round combine` | aggregation | LT | ✓ | YES — SCC cycle repro |
| 26 | `propagation.py:172 SCC-round floor` | floor | rank | ✓ toward less-trusted | YES — SCC cycle repro |
| 27 | `propagation.py:173-178 unresolved clamp` | floor | rank | **dead (F2)** | YES — 625-config sweep, 0 hits |
| 28 | `propagation.py:314 ext-influence combine` | aggregation | LT | ✓ | YES — DAG repro |
| 29 | `propagation.py:318-328 ext floors (L1/unresolved)` | floor | rank | ✓ toward less-trusted | YES — DAG repro |
| 30 | `propagation.py:404 Phase-1b seed-join` | aggregation | LT | ✓ order-independent | YES — SCC cycle repro |
| 31 | `propagation.py:414 phase2_floor freeze` | floor | rank | ✓ no wash-out | YES — SCC cycle repro (traced) |
| 32 | `propagation.py:457 monotonicity check` | assertion | rank | ✓ pins to safer value | not triggered (no violation) |
| 33 | `propagation.py:502 post-assertion` | assertion | rank | ✓ | not triggered |
| 34 | `decorator_provider.py:131-132 per-field max` | aggregation | rank | ✓ = per-field least-trusted (conservative on decorator conflict) | algebraic (max-by-rank == least_trusted) |
| 35 | `project_resolver.py:156 effective_return` | anchor | — | by-design (F4) | YES — end-to-end scan |
| 36 | `call_taint_map.py:55-114` | assignment | — | ✓ no combination; sink override conservative | read-confirmed |
| 37 | `callgraph.py` (edges) | — | — | ✓ no taint combination | read-confirmed |
| 38 | `analyzer.py:204-276 fn_return_taints assembly` | aggregation | LT | ✓ (via compute_return_taint) | YES (end-to-end + L2 driver) |
| 39 | `untrusted_reaches_trusted.py:71,76` | ordering | rank | ✓ consumes actual vs declared | YES — end-to-end (101 fires/silent) |
| 40 | `boundary_without_rejection.py:59` | ordering | rank | ✓ consumes body vs declared | YES — end-to-end (102 fires) |
| 41 | `severity_model.py:32 modulate` | tier-map | set | ✓ single tier; MIXED_RAW branch latent (F1) | read + reachability proof |
| 42 | `stdlib_taint.py:69 parser` | entry-point | — | latent (F5) | YES — `TaintState("MIXED_RAW")` accepted |
| 43 | `summary_cache.py:199 deserialise` | entry-point | — | latent (F5 sibling) | YES — ungated, disk-persistent, valid-string passes drop-guard |
| 44 | `decorators/_base.py:32 coerce_level` | entry-point | — | ✓ gated + runtime-only (not scanner path) | YES — grep + read (`in allowed` raise) |

LT = `least_trusted`. "rank" = `TRUST_RANK` ordering comparison (not a combination).

## Answers to the five specific questions
1. **`taint_join` reachable?** No — dead apart from its 8 own unit tests. Disposition: keep with an unused-marker comment (F3).
2. **Sites still on `taint_join` / missed by the migrations?** None on `taint_join`. The only non-`least_trusted` combiner is `decorator_provider`'s per-field `max`-by-rank (#34), which *is* least-trusted by another name and is correct (conservative on annotation conflict).
3. **`least_trusted`/floor/anchor sites that under-taint?** No operator under-taint (`least_trusted` cannot, by construction; every floor clamps *toward* less-trusted = the L1 seed, never promotes). The only trust-raising read is the anchored `effective_return` (#35/F4) — by design, delegated to and caught by PY-WL-102; verified.
4. **L1/L2/L3 layering consistent / no double-count or wash-out?** Yes. Floors clamp to the L1 seed; `phase2_floor` freezes the post-seed lower bound so a later round can't wash out a seed-join (verified in the SCC repro); Phase-1b avoids self-loop re-injection; `least_trusted` is commutative/associative/idempotent so the result is visitation-order-independent.
5. **`project_taints` vs `function_return_taints` consumed inconsistently?** No. PY-WL-101 reads `function_return_taints` (actual return) vs `project_return_taints` (declared); PY-WL-102 reads `project_taints` (body) vs `project_return_taints`; the tier-modulated rules read `project_taints` (body). Each consumes a single resolved tier matched to its intent — no combination crosses between them.

## Could-not-drive
- `propagation.py:457` monotonicity violation and `:502` post-assertion are defensive branches that fire only on a transfer-function bug; with the migration correct, no crafted reachable input triggers them. Verified they did NOT fire (diagnostics empty) across all repros — i.e. the engine stayed monotone — but the *violation* arm itself is, correctly, not reachable by sound inputs.
