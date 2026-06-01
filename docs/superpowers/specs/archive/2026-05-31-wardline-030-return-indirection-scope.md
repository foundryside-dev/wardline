# Scope — 0.3.0: resolve return indirection in `compute_return_callee`

**Issue:** wardline-82f49ec3c3 (feature, P3) — the **only open child** of epic
wardline-2b138b3662 ("Taint-combination engine — first-class hardening").
**Branch:** `release/0.3.0`.
**Date:** 2026-05-31.

---

## 0. Headline: the epic is already 90% shipped

The epic has 10 children. **Nine are closed/done** and already in `main`,
shipped as part of `0.2.1` (PR #13, `feat(taint): first-class hardening of the
taint-combination engine`):

| Child | Verdict |
|---|---|
| F5 — gate the two ungated `TaintState(...)` parsers | done |
| F2 — remove dead unresolved-clamp in SCC round | done |
| F6 — fix stale `keep taint_join` comment | done |
| F1+F3 — lattice disposition (decided **RETAIN**, ADR written) | done |
| F1 — document MIXED_RAW-unreachable invariant | done |
| Invariant-enforcement property test (reachable-set closure) | done |
| Fault-injection tests for defensive propagation branches | done |
| F4 — document present-but-wrong-predicate validator blind spot | done |
| Authoritative taint-algebra & combination-semantics design doc | done |

**The one remaining child is wardline-82f49ec3c3.** So "scope the epic for
0.3.0" reduces to scoping this single P3 explain-surface feature. There is no
other open work under the epic.

---

## 1. What the feature is

`compute_return_callee` (`src/wardline/scanner/taint/variable_level.py:929`)
names the callee that contributes a function's *actual* (least-trusted) return
taint — the value surfaced to agents as `immediate_tainted_callee` (MCP
`explain_taint`) and folded into the PY-WL-101 `via_callee` taint-path string.

Today it only names a callee when the least-trusted return path's top-level
expression is a **direct `ast.Call`** (`_return_callee`, line 967). For an
**indirect** return — `return some_var` where `some_var` was tainted by an
earlier call — it returns `None`. The verdict is still correct (the finding
fires); the provenance is just incomplete: "tainted sink, no named source."

This feature closes that gap **single-hop, in-process**.

### Decided framing (not open for re-litigation)

The issue text fixes the direction; do **not** present these as choices:

- **Single-hop only.** N-hop chain walking stays Clarion's job — `explain_chain`
  (`core/explain.py:190`) already walks N hops over the *stored-fact* path via
  `contributing_callee_qualname`. This feature feeds that path a better hop-0.
- **Explain-only.** No fire/no-fire change. `compute_return_taint` VALUES
  (line 899) are untouched — only `compute_return_callee` (the diagnostic
  sibling) gains resolution power.
- **Build it.** The "do we build / defer to SP9" question is settled.

---

## 2. The decision that WAS open — and the answer

To name the callee for `return some_var`, we need to know **which callee set
`some_var` to its taint value**. `var_taints` (`dict[str, TaintState]`,
variable_level.py:83) stores only the *final taint state* per name — provenance
was deliberately dropped in the wardline.old → rebuild port (module docstring,
lines 2–14). So the callee-of-a-variable is not currently recoverable.

**Two strategies were possible; the user chose merge-precise.**

> **DECISION (user, 2026-05-31): merge-precise via a threaded provenance map.**
> Indirect returns whose least-trusted variable was set across a control-flow
> merge (if/else, try/except, loop back-edge, match arm) MUST name the surviving
> branch's callee — not degrade to `None`.

Rejected alternative (localized backward search inside `compute_return_callee`):
lower blast radius, but precise only for straight-line `x = call(); return x`;
degrades to `None` on any control-flow-merged var because it cannot know which
branch's value survived the merge without replaying it.

---

## 3. Design — threaded `var_callee` provenance map

### Internal state object

Introduce a private `_L2State` dataclass that bundles the two maps:

```python
@dataclass
class _L2State:
    taints: dict[str, TaintState]
    callees: dict[str, str | None]
```

All internal walker functions (`_seed_parameters`, `_handle_assign`, …,
`_handle_match`) take `_L2State` instead of two separate dicts. This eliminates
parallel-dict drift: a future write-site addition that forgets `callees` will
produce a type error, not a silent wrong result.

`compute_variable_taints` returns `_L2State`. Its callers in `analyzer.py`
extract `.taints` and `.callees` to pass separately to
`compute_return_callee(var_taints, var_callee, …)`. The public type of
`function_return_callee` (downstream of `compute_return_callee`) is unchanged.

`var_callee` records, per variable name, **the callee name that contributed that
variable's current (least-trusted-so-far) taint**, or `None` when no resolvable
callee is in scope.

### Callee attribution rule for assignments

For any assignment `target = <expr>` (applies at every write site):

| RHS shape | `state.callees[target]` |
|---|---|
| `ast.Call` with resolvable name | callee name via `_return_callee(expr)` |
| `ast.Name` (alias: `y = x`) | `state.callees.get(rhs.id)` — propagate provenance |
| anything else (literal, subscript, attr, …) | `None` |

Name-copy propagation (`y = x`) is the **zero-extra-hop alias** case. `y`'s
taint IS `x`'s taint, so `y`'s provenance is `x`'s provenance. This is not
multi-hop resolution; the "single-hop" boundary refers to `compute_return_callee`
not walking further than one `var_callee` lookup, not to the number of alias
copies tracked.

### The merge rule

`least_trusted` keeps the worst (least-trusted) taint. At a merge the surviving
callee is: **the first source-order worst-rank branch that has a non-`None`
callee; or `None` if every worst-rank branch has a `None` callee.**

This matches `compute_return_callee`'s existing consumer logic exactly (the loop
already skips `None` callees and picks the first non-`None` worst-rank entry).
It is the **opposite** of `minimum_scope.py:164`'s `max(..., key=TRUST_RANK)`
(which selects the most-trusted callee for L3 aggregation) — do not copy that
direction.

When every branch has a non-call RHS (parameter, literal, merged non-call
values), `var_callee[x]` is `None`. Graceful degradation is preserved.

### Resolution in `compute_return_callee`

`_collect_return_paths` already records `(taint, direct_callee_or_None)` per
return. Extend it so that when the chosen least-trusted path is `return <Name>`
and its direct callee is `None`, fall back to `state.callees[<Name>]`. Subscript,
attribute, and other non-`Name` returns are **out of single-hop scope** — they
stay `None`; state this in the docstring. The least-trusted-path-selection logic
is unchanged; only the callee-naming gains the `var_callee` fallback.

---

## 4. Touch points (file:line)

**Allocate and return state:**

- `variable_level.py:63-86` `compute_variable_taints` — allocate `_L2State`,
  call `_seed_parameters` to seed `taints` and `callees` (`None` per param),
  thread `state` through the body walk. Return type changes to `_L2State`;
  `analyzer.py` callers extract `.taints` and `.callees`.

**Write sites — complete list. Every line that sets `state.taints[x]` must also
set `state.callees[x]` using the attribution rule (§3):**

- `:89-100` `_seed_parameters` — `state.callees[name] = None` for every param;
  parameter bindings carry no direct-call provenance.
- `:490` `_handle_assign` — `x = expr`: attribution rule (§3); for `ast.Name`
  RHS propagate `state.callees.get(rhs.id)`.
- `_process_stmt` `AnnAssign` branch — annotated `x: T = expr` uses the same
  attribution rule; bare `x: T` (no value) writes neither map.
- `_assign_target` (called by `for` loop target binding, `match` capture, and
  starred/nested unpack) — callee is context-dependent; see table below.
- `:525` `_handle_unpack` — element-wise when arity matches a tuple/list literal:
  `state.callees[target_i]` from the attribution rule applied to `elements[i]`.
  Whole-RHS rule when arity doesn't match or RHS is not a literal: attribution
  rule on the whole RHS expression for each target. `Starred` targets: `None`.
- `:560` `_handle_augassign` — `x += expr`: new callee is the attribution-rule
  callee of the worse-rank side. On equal rank keep the **existing** callee
  (left-wins). If the winning side has no callee: `None`.
- `:157-161` `_resolve_expr` `NamedExpr` — walrus `x := expr`: attribution rule.
  `_resolve_expr` must receive `state` so the walrus side-effect writes the
  correct scope's `callees`.
- `_walk_exprs_for_walrus` / `_resolve_comprehension` — comprehension walrus
  expressions that leak into the enclosing scope must propagate via the enclosing
  `state.callees`. Confirm all callers of these helpers pass `state`.
- `_handle_with` — `with expr as x:` binding: attribution rule on the context
  manager expression.
- `_taint_container_base` (`:579-596`) — `d[k] = expr` updates the container
  base's taint; update `state.callees[base_name]` with the attribution-rule
  callee of the RHS.
- `except … as e` — exception-handler binding: `state.callees[e] = None`
  (exception object is not the result of a direct call in the catch handler).

**`_assign_target`-mediated callee rules:**

| Binding context | `state.callees` rule |
|---|---|
| `for x in iterable:` | `None` (loop-iteration target; element is not a direct call) |
| `match subject: case x:` | `state.callees.get(subject.id)` if subject is `ast.Name`; `_return_callee(subject)` if `ast.Call`; else `None` |
| Nested / starred unpack via `_assign_target` | inherit from matched element (same element-wise rule as `_handle_unpack`) |

**Merge sites — apply the merge rule (§3) alongside each `least_trusted` combine:**

- `:642` `_handle_if`
- `:678` `_handle_for` — includes back-edge merge at loop exit (pre-loop state
  vs loop-body state); apply merge rule in the back-edge as well.
- `:708` `_handle_while` — same back-edge merge.
- `:778` `_handle_try`
- `:842` `_handle_match`

**Consume the map:**

- `:977-1006` `_collect_return_paths` / `:929` `compute_return_callee` — add
  `var_callee` fallback for `return <Name>` least-trusted paths. Signature:
  `compute_return_callee(var_taints, var_callee, …)`.

**Downstream — verify the ripple; no code change except where noted:**

- `analyzer.py:250` — **walrus isolation (code change required)**: copy
  `state.callees` before passing to `compute_return_callee`, mirroring the
  existing `var_taints` copy (walrus expressions must not mutate the post-walk
  state during return-path resolution).
- `analyzer.py:250` builds `function_return_callee` from `compute_return_callee`
  → flows unchanged through `context.py:48` → `core/explain.py:84`.
- `core/explain.py:88-106` `source_boundary_qualname` — **user-visible API
  change**: every `explain_taint` call on a previously-`None` indirect return
  will now return a `source_boundary_qualname`. Desirable; requires both a
  positive and a negative test (see §5 tests 7 and 8).
- `clarion/facts.py:80` `contributing_callee` now populated for indirect returns
  → `explain_chain` gets a real hop-0. No code change.

---

## 5. Verification plan (the done-signal)

Existing tests assert the **current `None`** behavior and will **invert** — that
inversion is the concrete acceptance signal:

- `tests/unit/scanner/taint/test_variable_level.py:390` —
  `x = read_raw(p); return x` currently asserts `None`; flips to `"read_raw"`.
  (Line :391 `return p` (bare parameter) stays `None` — no contributing call.)
- `tests/unit/core/test_explain.py:68-78`
  `test_explain_non_call_return_has_no_immediate_callee` — currently asserts
  `immediate_tainted_callee is None` for a bare-variable return; flips. (Keep a
  *truly* sourceless case — e.g. `return p` or `return 1` — asserting `None`, so
  graceful degradation stays covered.)

New tests to add:

1. **Merge precision** — `if c: x = read_raw(p); else: x = svc.get(p); return x`
   → names the least-trusted branch's callee. Variants: try/except, match arm.
2. **Loop back-edge merge** — for-loop and while-loop: a call inside the loop
   sets the least-trusted taint; the loop-exit merge must survive:
   ```python
   x = safe_val
   for _ in items:
       x = read_raw(p)
   return x   # expected: "read_raw"
   ```
3. **Equal-rank tie-break** — two branches of equal rank; first source-order
   non-`None` callee wins:
   ```python
   if c:
       x = read_a(p)
   else:
       x = read_b(p)
   return x   # expected: "read_a"
   ```
4. **Mixed direct-return + indirect-return paths** — indirect path must compete
   correctly with direct-return paths:
   ```python
   if c:
       return validate(p)   # direct, worst rank
   x = read_raw(p)
   return x                 # indirect — expected: "read_raw"
   ```
5. **Name-copy (alias) propagation** — provenance follows the value:
   ```python
   x = read_raw(p)
   y = x
   return y   # expected: "read_raw"
   ```
6. **Subscript / attribute out-of-scope** — `return d[k]` and `return obj.attr`
   both stay `None` (graceful degradation boundary).
7. **`source_boundary_qualname` positive** — indirect return whose callee is a
   same-module leaf source now reports the boundary qualname (was `None`).
8. **`source_boundary_qualname` negative** — callee is NOT a same-module leaf
   source; boundary must stay `None`:
   ```python
   x = helper(p)   # helper calls read_raw internally — not a leaf source
   return x        # expected: source_boundary_qualname = None
   ```
9. **`_handle_unpack` element-wise callee**:
   ```python
   a, b = safe_call(), read_raw(p)
   return b   # expected: "read_raw"
   ```
10. **`_handle_augassign` callee update** — RHS wins on worse rank:
    ```python
    x = safe_call()
    x += read_raw(p)
    return x   # expected: "read_raw"
    ```
11. **Walrus callee attribution**:
    ```python
    if (x := read_raw(p)):
        return x   # expected: "read_raw"
    ```
12. **Fire-set invariance** (precise corpus definition): assert
    `compute_return_taint` values and the PY-WL-101 fire set are byte-identical
    before/after on: (a) oracle battery fixture module(s); (b) `src/wardline`
    self-host. Comparison keys: sorted `(rule_id, fingerprint, path, line,
    qualname, declared_return, actual_return)` — byte-identical. Explanation
    fields (`via_callee`, `immediate_tainted_callee`) are expected to change and
    are excluded from this comparison.

**Gates** (project standard, matches how the 9 sibling children shipped): full
`pytest` green, `ruff`/`mypy` clean, `mkdocs build --strict`, oracle battery
30/30, self-host 0 PY-WL defects.

---

## 6. Boundaries (state in PR + docstrings)

- **Single-hop only.** Multi-hop indirection (`x = read_raw(); y = x; return y`)
  resolves at most one hop in-process; full chains are Clarion's `explain_chain`.
- **No fire/no-fire change.** `compute_return_taint` untouched; verified by test 4.
- **Subscript/attribute returns out of single-hop scope** — `return d[k]` /
  `return obj.attr` stay `None`.
- **Update** `compute_return_callee` + `context.py:37` docstrings and CHANGELOG
  `[Unreleased]` (the "indirection deferred to SP9" notes are now partially
  resolved — reword, don't delete the multi-hop caveat).
- **`source_boundary_qualname` is a user-visible contract change**, not an
  internal ripple. Every `explain_taint` call on a previously-`None` indirect
  return will now return a value. Callers that previously pattern-matched on
  `source_boundary_qualname is None` to detect "no boundary" must still work
  correctly (the negative case — non-leaf-source callee — still returns `None`).
  State this explicitly in the PR description and the `source_boundary_qualname`
  docstring.
- **`analyzer.py` walrus isolation** — the existing copy of `var_taints` before
  `compute_return_callee` must be extended to also copy `var_callee`. Both copies
  together prevent walrus side-effects from leaking into return-path resolution.

---

## 7. Effort

Medium. The structural work is larger than the original "small-medium" estimate:
`variable_level.py` requires `_L2State` introduction + a return-type change to
`compute_variable_taints` + ~14 write sites + 5 merge-site callee rules + 2
walrus threading paths. The consume-side fallback in `compute_return_callee` is
small. Downstream is ripple-only except the `analyzer.py` walrus isolation copy.
Tests: 12 new cases (2 inversions + 10 new). The risk is concentrated in the
merge sites inside the fire/no-fire-critical L2 transfer functions — test 12
(fire-set invariance) is the guard. Recommend subagent-execute +
adversarial-review pattern given that proximity.

---

## 8. Pre-implementation blockers (panel review 2026-06-01)

**Status: RESOLVED** — all items below have been incorporated into §§3–6 above.
The section is retained as the audit trail of panel findings. No further spec
changes are required before implementation. Raised by a five-panel review
(Architecture Critic, Systems Thinker, Python Engineer, Static Analysis
Engineer, Quality Engineer) on 2026-06-01; resolved same day.

---

### 8.1 Critical — resolve in this spec before handing off

#### BLOCKER-1: write-site list is incomplete

Section 4 lists ~9 write sites, but `var_taints` is mutated in more places.
Every one of the following also writes `var_taints` and MUST also write
`var_callee` in lockstep, or the two maps will silently drift:

| Site | Location |
|---|---|
| `_seed_parameters` | `:89-100` — parameters must seed `var_callee[name] = None` |
| `AnnAssign` branch | inside `_process_stmt` |
| `_assign_target` | called by `for` target binding, `match` capture binding, and any starred/nested unpack |
| `_walk_exprs_for_walrus` | comprehension walrus leakage back to enclosing scope |
| `_handle_with` target binding | `with expr as x:` |
| `_taint_container_base` | `d[k] = call()` / `obj.x = call()` updates the base var's taint |
| `except … as e` binding | exception handler name binding |
| `match` capture binding | `case x:` — see also BLOCKER-3 |

**Action:** audit every `var_taints[...] =` write in `variable_level.py` to
produce the complete, authoritative list and replace section 4 with it before
implementation begins.

---

#### BLOCKER-2: name-copy propagation is under-specified

The spec says `_handle_assign` sets `callee = _return_callee(expr)`. For a
Name RHS (`y = x`) `_return_callee` returns `None`, so:

```python
x = read_raw(p)   # var_callee[x] = "read_raw"
y = x             # var_callee[y] = None   ← spec as written
return y          # returns None           ← wrong
```

If `var_callee` means "callee that contributed the variable's current taint,"
plain name copies MUST propagate provenance — `y`'s taint IS `read_raw`'s
taint. Calling this "multi-hop" is incorrect; it is a zero-extra-hop alias.

**Action — choose one option and state it explicitly in this spec:**

- **(A) Propagate name copies (recommended):** when the RHS of an assignment is
  `ast.Name`, set `var_callee[target] = var_callee.get(rhs.id)`. Document this
  as the behaviour. Rename the scope label from "single-hop" to
  "variable-provenance resolution" to avoid the ambiguity.
- **(B) Explicitly exclude name copies:** keep `_return_callee(expr)` only.
  Rename the feature from "single-hop" to **"direct-call RHS only"** and
  document that `y = x; return y` stays `None`. The boundary must be stated in
  the PR description and the docstring.

Whichever option is chosen, it must also be reflected in the test plan
(§8.3 TEST-1 below).

---

#### BLOCKER-3: tie-break rule does not match `compute_return_callee`

Section 3 states the merge rule as "min-by-rank, source-order tie-break." That
is not what `compute_return_callee` actually does. The current consumer is:

```python
for taint, callee in returns:
    if taint == worst and callee is not None:   # skips None callees
        return callee
```

It picks the **first source-order worst-rank path that has a non-`None`
callee**. A pure source-order tie-break picks the first worst-rank branch
regardless of whether it has a callee — which can return `None` where the
consumer would return a name. Example:

```python
if c:
    x = p              # EXTERNAL_RAW, callee=None   ← if-branch (first)
else:
    x = read_raw(p)    # EXTERNAL_RAW, callee="read_raw"
return x
```

Under the spec's tie-break: `var_callee[x] = None`.
Under the consumer's logic on equivalent direct returns: `"read_raw"`.

**Action:** Replace the merge tie-break rule in section 3 with:

> At a merge, the surviving callee is: **first source-order worst-rank branch
> with a non-`None` callee; or `None` if all worst-rank branches have `None`
> callees.**

This matches the consumer exactly and eliminates the asymmetry.

---

### 8.2 Important — resolve before merge (may be addressed during implementation)

#### RESOLVE-4: `_handle_augassign` exact callee rule

"Merge old+new; least-trusted rule" (section 4) is ambiguous. The spec must
state:

> For `x += expr`: new taint = `least_trusted(existing, rhs)`.
> New callee = callee of whichever side produced the worse taint.
> On equal rank, keep the **existing** callee (left-wins, consistent with
> `least_trusted`'s tie policy).
> If the winning side has no callee (non-direct-call expression), set
> `var_callee[x] = None`.

#### RESOLVE-5: `_handle_unpack` callee semantics

The spec lists `_handle_unpack` as a write site but does not specify callee
attribution. Required behaviour:

- **Element-wise match** (`a, b = call_a(), call_b()`): `var_callee[a] =
  "call_a"`, `var_callee[b] = "call_b"`.
- **Non-matching RHS** (all targets get RHS taint): `var_callee[tgt] =
  _return_callee(rhs_expr)` for each target.
- **Nested unpack and `Starred`**: follow the same rule recursively (callee
  from the matched element, or whole-RHS callee when element is unavailable).

#### RESOLVE-6: consider a private state object instead of two parallel dicts

Threading two raw dicts through ~14 function signatures is structurally fragile:
a future write-site addition that updates `var_taints` but not `var_callee` will
silently produce wrong provenance. Consider a private internal state object:

```python
@dataclass
class _L2State:
    taints: dict[str, TaintState]
    callees: dict[str, str | None]
```

The public API of `compute_variable_taints` (returns `dict[str, TaintState]`)
and `compute_return_callee` (takes `var_taints`) stays unchanged. The private
walkers all take `_L2State` instead of two separate dicts. This is a "should"
not a "must" — the parallel-dict approach works if BLOCKER-1 is fully resolved —
but it eliminates the drift risk structurally.

#### RESOLVE-7: `source_boundary_qualname` is a user-visible change, not just a ripple

The "auto-extends" framing understates the impact: every MCP `explain_taint`
call on an indirect-return sink that previously returned
`source_boundary_qualname=None` will now return a value. This is desirable, but:

- It must be treated as an **API contract change** for the explain surface and
  Clarion facts.
- It requires both a **positive** test (indirect return → leaf-source boundary
  reported) and a **negative** test (indirect return where the callee is NOT a
  same-module leaf source → boundary stays `None`). The spec currently only
  mentions a positive test.

#### RESOLVE-8: `match` capture pattern callee inheritance

For `case x:` binding from `match some_var:`, the spec says `var_callee` is
written via `_assign_target` (BLOCKER-1 above), but it does not specify what
value to write. The required semantics:

> A `match` capture target `x` inherits `var_callee[some_var]` if the subject
> is an `ast.Name`, or `_return_callee(subject_expr)` if the subject is a
> direct call, or `None` otherwise.

This is consistent with how `var_taints` inherits the subject's taint.

#### RESOLVE-9: walrus threading is deeper than listed

The spec lists `:157-161` `_resolve_expr` NamedExpr as the walrus write site.
But walrus can also leak through `_walk_exprs_for_walrus` and comprehension
bodies (`_resolve_comprehension`). After the change, `_resolve_expr` needs
access to `var_callee` — which propagates into its recursive callers. The full
set of `_resolve_expr` callers that can produce walrus side effects must be
identified and confirmed to carry `var_callee`.

Additionally: `analyzer.py` currently makes a copy of `var_taints` before
passing it to `compute_return_callee` to isolate walrus side effects during
return-walk resolution. The same isolation must apply to `var_callee`.

---

### 8.3 Required additional tests (beyond section 5)

The original verification plan (section 5) is a good backbone but is missing
the following. All items marked **[critical]** must be present before the
feature can be declared done.

#### TEST-1 [critical]: for- and while-loop back-edge merge

```python
# for
x = safe_val
for _ in items:
    x = read_raw(p)
return x   # expected: "read_raw"

# while
x = safe_val
while cond:
    x = read_raw(p)
return x   # expected: "read_raw"
```

Why: loop back-edge merge (`body` vs `pre_loop`) has different semantics from
branch alternatives (`if`/`try`/`match`). Bugs in the loop merge sites can hide
while all branch-merge tests pass.

#### TEST-2 [critical]: equal-rank tie-break pinned

```python
if c:
    x = read_a(p)    # both callees mapped to same taint tier
else:
    x = read_b(p)
return x   # expected: "read_a"  (first source-order with non-None callee)
```

Why: the tie-break rule is a central promise of the design (and was incorrect in
the original spec — BLOCKER-3). Without this test the rule is not pinned.

#### TEST-3 [critical]: mixed direct-return + indirect-return paths

```python
if c:
    return validate(p)        # direct call, less-trusted-than:
x = read_raw(p)
return x                      # indirect — expected: "read_raw"
```

Why: indirect-return provenance must compete correctly with direct-call return
paths. The least-trusted path must win regardless of whether it is direct or
indirect.

#### TEST-4 [critical]: invariance corpus must be defined precisely

The "small corpus" for fire-set invariance (original test 4) must be:
1. The oracle battery fixture module(s).
2. `src/wardline` self-host.
3. The exact comparison keys: sorted
   `(rule_id, fingerprint, path, line, qualname, declared_return, actual_return)`
   must be byte-identical before and after. Explanation fields (`via_callee`,
   `immediate_tainted_callee`) are expected to change and are not in this set.

#### TEST-5 [critical]: negative `source_boundary_qualname`

```python
# helper is NOT a leaf source — it calls read_raw internally
x = helper(p)
return x   # expected: source_boundary_qualname = None
```

Why: positive-only testing can hide over-attribution where any same-module
callee is incorrectly reported as a boundary.

#### TEST-6 [important]: `_handle_unpack` element-wise callee

```python
a, b = safe_call(), read_raw(p)
return b   # expected: "read_raw"
```

#### TEST-7 [important]: `_handle_augassign` callee update

```python
x = safe_call()
x += read_raw(p)   # read_raw produces worse taint
return x           # expected: "read_raw"
```

#### TEST-8 [important]: walrus callee attribution

```python
if (x := read_raw(p)):
    return x   # expected: "read_raw"
```

#### TEST-9 [important]: `return obj.attr` graceful degradation boundary

```python
return obj.attr   # expected: None  (attribute returns out of scope)
```
