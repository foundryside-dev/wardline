# Adaptive Pydantic Discovery Budget Design

**Date:** 2026-07-12

**Status:** User-approved design

## Objective

Allow legitimate large projects to complete cross-module Pydantic model discovery without
making scan cost repository-configurable or unbounded. Preserve Wardline's fail-closed
fallback when discovery genuinely exceeds a deterministic resource ceiling.

Elspeth is the motivating case. Its current scan contains 593 Python files, 11,493
top-level statements, and a model fixed point that progresses through 206, 259, and 263
known models before stabilising at 263 on round four. The current budget is
`11,493 * 32 = 367,776` work units. Discovery needs 480,048 units to finish the fourth
round, so Wardline stops during a healthy convergence and emits
`WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT`.

This is aggregate project-graph work, not pathological complexity in the file being
visited when the counter crosses the threshold.

## Approaches Considered

### A. Increase the existing multiplier

Raising `32` to `48` or `64` would make Elspeth pass. It would retain the current
mid-round failure mode, continue to ignore file-count overhead, and merely postpone the
same false limit for a larger or more model-dense project.

### B. Add a `weft.toml` budget setting

An operator override would be flexible but would place a resource-amplification control in
repository-authored input. Wardline scans untrusted checkouts, so a repository must not be
able to request arbitrarily expensive analysis. A CLI override would avoid that trust
problem but would make local and CI results diverge and turn routine scans into tuning
exercises.

### C. Wardline-owned adaptive budget with a hard ceiling — selected

Budget from structural input size, charge the exact cost of each full discovery round, and
retain a fixed Wardline-owned absolute ceiling. This accommodates ordinary project growth,
keeps resource use deterministic, and preserves the fail-closed outcome for pathological
inputs.

## Budget Contract

Wardline computes these values once from the parsed project:

- `file_count`: number of parsed Python modules entering the analyzer;
- `statement_count`: sum of top-level AST statement counts across those modules;
- `structural_units = file_count + statement_count`.

The available work budget is:

```text
scaled_budget = structural_units * 64
work_budget = min(5_000_000, max(4_096, scaled_budget))
```

The constants are Wardline policy, not configuration:

- `64` provides measured headroom over Elspeth's approximately 40 work units per
  structural unit while remaining proportional to project size;
- `4_096` preserves useful capacity for tiny projects;
- `5_000_000` is the absolute denial-of-service ceiling for this discovery phase.

For a round beginning with `known_model_count` models, its exact cost is:

```text
round_cost = statement_count + file_count * (known_model_count + 1)
```

This equals the work currently charged incrementally across every file. Before starting a
round, Wardline checks whether `completed_work + round_cost <= work_budget`.

- If it fits, Wardline runs the complete round and increments `completed_work` by
  `round_cost`.
- If it does not fit, Wardline runs none of that round and takes the existing conservative
  fallback.
- The existing structural round limit (`top_level_class_count + 1`) remains an independent
  cycle/termination guard.

Elspeth receives a budget of 773,504 units. Its four complete rounds cost 12,086,
134,244, 165,673, and 168,045 units, totalling 480,048, so the stable fourth round is
admitted without approaching the hard ceiling.

## Analyzer Flow

1. Parse the project and calculate the three structural counts.
2. Calculate the adaptive budget once.
3. At the start of every model-discovery round, calculate the full round cost from the
   current known-model set.
4. Admit or reject the whole round before calling `discover_pydantic_models()` for any
   file.
5. After an admitted round, compare the complete next model set with the prior state:
   - identical: discovery is complete;
   - previously seen: retain the existing repeated-state fallback;
   - new: begin another preflighted round.
6. On a budget or round-limit failure, retain the existing fail-closed behaviour of
   treating all discovered classes as possible Pydantic models.

No partial round contributes a partially updated model set, and no source file is implied
to be the cause merely because it happened to be visited near the threshold.

## Diagnostic Contract

`WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT` remains an `ERROR` `DEFECT` at `<engine>`. Existing
`reason`, `round`, `work`, and `budget` properties remain available for compatibility.
For a budget rejection:

- `work` means work completed by whole rounds;
- `round` is the rejected round number;
- `budget` is the adaptive budget after the absolute cap;
- `next_round_cost` is the exact cost of the rejected round;
- `required_total` is `work + next_round_cost`;
- `file_count`, `statement_count`, and `known_model_count` explain the calculation;
- `absolute_cap_applied` states whether the five-million-unit ceiling constrained the
  scaled budget.

The human message reports completed work, required total, and the budget. It must not name
the file at which the old incremental counter would have crossed.

Repeated-state and round-limit diagnostics retain their current reasons and gain the same
structural-count context where applicable.

## Security and Trust Boundary

- No repository configuration, pack, environment variable, or model annotation can raise
  the five-million-unit ceiling.
- Work accounting depends only on parsed structure and the deterministic known-model set.
- File order cannot change the budget, round admission, model result, or diagnostic.
- Failure remains conservative: Wardline over-approximates body models and emits a gating
  engine defect rather than silently under-scanning.
- Existing source-root confinement and safe source reads are unchanged.

## Testing

### Budget arithmetic

- Pin the Elspeth structural counts and the 773,504-unit budget.
- Pin all four Elspeth round costs and their 480,048-unit total.
- Cover the 4,096-unit minimum and five-million-unit maximum.

### Convergence

- Add an in-memory Elspeth-shaped model graph whose population progresses
  `206 -> 259 -> 263 -> 263` and completes without a discovery-limit finding.
- Preserve direct, transitive, aliased, and shadowed Pydantic model behaviour.
- Prove reversing file order yields identical models, work totals, and diagnostics.

### Fail-closed limits

- Construct a next round whose exact cost exceeds the remaining adaptive budget and prove
  no file discovery call occurs for that round.
- Assert the conservative all-class fallback and active `ERROR` defect.
- Pin every diagnostic field, including `required_total` and `absolute_cap_applied`.
- Preserve repeated-state and structural round-limit coverage.

### Repository verification

- Run the focused FastAPI/Pydantic analyzer suites.
- Run the full test suite, Ruff, formatting, mypy, and `git diff --check`.
- Run `wardline scan . --fail-on ERROR --local-only` for Wardline.
- Re-run the Elspeth local-only scan and confirm the Pydantic discovery-limit defect is
  absent. Any other Elspeth findings remain separate work.

## Non-Goals

- No `weft.toml`, CLI, environment, or pack override for discovery work.
- No weakening or suppression of engine-limit defects.
- No change to what qualifies as a Pydantic model.
- No broad rewrite of model discovery into a graph/worklist engine in this change.
- No attempt to bind Elspeth's custom trust decorators to Wardline.

## Acceptance Criteria

1. Elspeth's four-round model discovery reaches the stable 263-model state.
2. The analyzer admits or rejects complete rounds only; it never stops within a round.
3. The budget is deterministic, structurally adaptive, capped at five million units, and
   not user-configurable.
4. Genuine exhaustion still produces an active fail-closed engine defect with actionable
   arithmetic.
5. Existing Pydantic precision and full repository gates remain green.
