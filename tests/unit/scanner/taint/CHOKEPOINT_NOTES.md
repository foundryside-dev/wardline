# Chokepoint contextvar coupling notes (`scanner/taint/variable_level.py`)

Companion to `test_property_chokepoint.py` (wardline-369f54b83b). The L2 walk
threads SEVEN pieces of ambient state through `contextvars.ContextVar` slots
instead of parameters. This invisible coupling is where new handlers go wrong:
a handler that forgets to branch-copy / merge / reset one of these maps either
leaks state across mutually-exclusive branch arms (FP/FN) or across functions
(stale-state launder). This file documents, per contextvar, who SETS the slot
(rebinds it, with token/reset discipline), who READS it, and who MUTATES the
dict it points to (a mutation is visible to every reader of the same slot
binding — strictly stronger coupling than a read).

Line numbers reference the file as of 2026-06-11 (2,178 lines); they drift,
the handler names do not.

## The seven contextvars

| ContextVar | Type | Purpose |
|---|---|---|
| `_CURRENT_ALIAS_MAP` | `dict[str, str] \| None` | import alias -> FQN for call/annotation resolution |
| `_CURRENT_CALL_SITE_ARG_TAINTS` | `dict[int, dict[int\|str\|None, TaintState]] \| None` | out-channel: resolved arg taints keyed by `id(call_node)` (sink-rule input) |
| `_CURRENT_VAR_TYPES` | `dict[str, list[str]] \| None` | local name -> CANDIDATE SET of class FQNs it may hold (typed-receiver dispatch) |
| `_CURRENT_ATTR_WRITES` | `dict[str, dict[str, TaintState]] \| None` | out-channel: attribute writes recorded during the walk (class-attribute taint) |
| `_CURRENT_LAMBDA_BINDINGS` | `dict[str, list[ast.Lambda]] \| None` | local name -> CANDIDATE SET of lambda bodies it may hold |
| `_CURRENT_MODULE_PREFIX` | `str \| None` | module dotted prefix for FQN minting |
| `_PROVENANCE_CLASH` | `bool` (lives in `core/taints.py`) | switches `combine()` between `least_trusted` (default) and `taint_join` |

## Who sets each slot (token + `finally: reset` discipline)

| Setter | ALIAS_MAP | ARG_TAINTS | VAR_TYPES | ATTR_WRITES | LAMBDA_BINDINGS | MODULE_PREFIX | PROVENANCE_CLASH |
|---|---|---|---|---|---|---|---|
| `analyze_function_variables` (:326) | set | set | — | — | — | set | — |
| `compute_variable_taints` (:547) | set (if arg given) | set (if arg given) | set fresh `{}` | — | set fresh `{}` | — | set (if arg given) |
| `attribute_write_recording` CM (:264) | — | — | — | set | — | — | — |
| `_walk_branch_body` (:1559) | — | — | set arm copy | — | set arm copy | — | — |
| `_handle_match` per-case (:1969) | — | — | set arm copy | — | set arm copy | — | — |

Key consequences:

- **`compute_variable_taints` is the lifecycle owner** of `VAR_TYPES` and
  `LAMBDA_BINDINGS`: both are ALWAYS fresh per function and ALWAYS reset in its
  `finally`. Any code that runs AFTER it returns sees `None` for both.
- **`compute_return_taint` / `compute_return_callee` run with `VAR_TYPES` and
  `LAMBDA_BINDINGS` unset** (they are called by `analyze_function_variables`
  *after* `compute_variable_taints` has reset them). Re-resolving a `return
  h.method()` therefore takes the GENERIC raw-receiver path (`_resolve_call`
  :1102 receiver-taint check), never the typed-receiver dispatch — the
  declared-raw guard is only exercisable through an in-body assignment. The
  property tests bind `x = h.method()` in the body for exactly this reason.
- `ATTR_WRITES` is opt-in: it defaults to `None` and is only live inside the
  analyzer's `attribute_write_recording` block. Every recorder is a no-op
  when it is `None`.
- Branch arms get arm-local COPIES of `VAR_TYPES` / `LAMBDA_BINDINGS` (deep
  enough: the candidate lists are copied too), then the arms are UNION-merged
  back into the parent dict in place (`_merge_branch_types` /
  `_merge_branch_bindings`). `var_taints` itself is NOT a contextvar — it is a
  positional parameter copied/merged by the same handlers; keep the three in
  lockstep when adding a branching construct.

## Who reads / mutates each slot

### `_CURRENT_ALIAS_MAP`
- `_seed_parameters` (:591) — read; feeds annotation FQN resolution.
- `_resolve_call` (:948) — read; feeds `resolve_call_fqn` (context encoders,
  serialisation sinks, imported-FQN `taint_map` hits).
- `_update_var_type` (:1278) — read; types `x = Type()` constructor results.
- Never mutated by the walk; treated as read-only input.

### `_CURRENT_CALL_SITE_ARG_TAINTS`
- `_resolve_call` (:893) — read slot, **mutates dict**: records/merges
  `resolved_args` under `id(call_node)`. Also written through the lambda-body
  resolution paths (`_resolve_lambda_bodies`, `_resolve_lambda_body_at_call`),
  which re-enter `_resolve_expr` with the same slot live.
- Pure out-channel: nothing in this module reads entries back; sink rules
  consume it after the walk. A call node resolved more than once (loop
  fixpoint iterations, lambda candidates) MERGES via `combine` rather than
  overwriting — re-resolution is monotone, never clean-overwriting.

### `_CURRENT_VAR_TYPES`
- `_seed_parameters` (:590) — read slot, **mutates dict**: annotation types.
- `_resolve_call` (:991) — read-only: typed-receiver method dispatch
  (the declared-raw receiver guard lives here, wardline-03c8805449).
- `_update_var_type` (:1273) — read slot, **mutates dict**: strong update on
  straight-line assignment; INVALIDATES (pops) on untypeable RHS
  (wardline-5ba7ce0f98 stale-type launder fix).
- `_record_attribute_write` (:308) — read-only: receiver class candidates.
- All branching handlers (`_handle_if` :1633, `_handle_for` :1716/:1752,
  `_handle_while` :1777/:1800, `_handle_try` :1840, `_handle_match` :1956) —
  read parent for arm copies; `_merge_branch_types` **mutates the parent dict
  in place** (clear + union of arms).
- Loops snapshot the pre-loop map as a zero-trip arm and union it back after
  the fixpoint (wardline-b369c7d06c / wardline-d6af917bde mirror).
- Invariant: a name is ABSENT or maps to a NON-EMPTY list.

### `_CURRENT_ATTR_WRITES`
- `_record_attribute_write` (:303) — read slot, **mutates dict**: joins the
  RHS taint per (receiver-key, attr) via `combine`. Called from
  `_handle_assign`, the AnnAssign branch of `_process_stmt`, and
  `_handle_augassign` — i.e. recording happens DURING the statement walk at
  the write site, against the current per-statement `var_taints`
  (wardline-b369c7d06c: a later reassignment cannot launder the recording).
- Receiver keys: class-FQN candidates from `VAR_TYPES`, or
  `SELF_ATTRIBUTE_KEY` for `self`/`cls`; projected onto class qualnames later
  by `project_attribute_writes` (pure function, no contextvar).

### `_CURRENT_LAMBDA_BINDINGS`
- `_handle_assign` (:1309) and the AnnAssign branch of `_process_stmt`
  (:1169) — read slot, **mutates dict**: linear rebind stores `[lam]`
  (replace, never append); non-lambda RHS pops the name.
- `_resolve_call` (:902) — read-only: resolves a direct `cb(...)` against
  EVERY candidate body.
- All branching handlers — arm copies + in-place union merge, exactly like
  `VAR_TYPES` (wardline-36016d26f3 arm leak; wardline-383f83fafe single-slot
  FN; wardline-d6af917bde zero-trip union).
- Invariant: ABSENT or NON-EMPTY; candidate lists deduped by node IDENTITY
  (ast nodes are id-hashed — a set would destabilise golden corpora).

### `_CURRENT_MODULE_PREFIX`
- `_resolve_call` (:953) — read; feeds `resolve_call_fqn`.
- `_resolve_expr_fqn` (:1251) — read; prefixes un-aliased bare names.
- Set only by `analyze_function_variables`; read-only everywhere else. NOTE:
  `compute_variable_taints` does NOT set it — a direct call (as the unit tests
  do) runs with whatever the ambient context holds (`None` in tests), so
  annotation FQNs resolve to bare class names there but to
  `pkg.mod.ClassName` under the analyzer. Test `taint_map` keys must match
  the bare spelling; analyzer-built maps use the prefixed one.

### `_PROVENANCE_CLASH` (in `core/taints.py`)
- `combine` — read on EVERY taint combination anywhere in the walk; flips
  between `least_trusted` (default, rank-meet) and `taint_join`
  (provenance-clash semantics).
- Set only via `compute_variable_taints(provenance_clash=...)`; default
  `False` across the live pipeline.

## Hazards for new handlers (the recurring bug shapes)

1. **Forgetting the arm copy**: walking a conditionally-executed body against
   the parent `LAMBDA_BINDINGS`/`VAR_TYPES` leaks bindings into sibling arms
   (wardline-36016d26f3 class of bug). Use `_branch_copy` /
   `_types_branch_copy` + `_walk_branch_body`, then merge.
2. **Forgetting the implicit arm**: no-`else` `if`, zero-trip loops, and
   no-match `match` all keep the PRE-state alive; an arm set that omits the
   pre-state copy drops it (wardline-d6af917bde).
3. **Overwrite instead of merge** on the out-channels: `ARG_TAINTS` entries
   must `combine`-merge on re-resolution (loop fixpoints re-visit call nodes).
4. **Post-reset re-resolution**: anything that re-enters `_resolve_expr` after
   `compute_variable_taints` returned (return-taint/callee computation,
   sink-rule re-resolution) runs WITHOUT `VAR_TYPES`/`LAMBDA_BINDINGS` — do
   not rely on typed dispatch or lambda candidates there.
5. **Empty-list candidates**: storing `[]` in `LAMBDA_BINDINGS`/`VAR_TYPES`
   makes membership checks pass while candidate loops do nothing — a silent
   FN. Writers must store non-empty or pop.

## Future direction (from the ticket)

The reviewers' suggestion stands: a single threaded `_WalkContext` dataclass
(alias_map, module_prefix, var_types, lambda_bindings, arg_taints out-channel,
attr_writes out-channel) passed positionally would make the coupling explicit
and let mypy police it. The property harness in `test_property_chokepoint.py`
is the safety net for that refactor: lattice monotonicity, idempotence, seed
monotonicity, and the receiver guard must all survive it unchanged.
