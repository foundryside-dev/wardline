# Taint algebra — the combination operators and their invariants

This is the authoritative specification of *how* Wardline combines taint states:
which operator runs at each kind of program point, why, and the invariants that
keep the result sound and precise. It is the engineering complement to the
reader-facing [Taint & trust model](model.md), and it consolidates the
regression-guard rationale that was previously scattered across the test suite as
inline comments.

If you are extending the engine — adding a combination site, a rule, or an entry
point that parses a `TaintState` — read this first.

## The two operators

Wardline's lattice (`src/wardline/core/taints.py`) defines two binary operators
over `TaintState`. They are **not** interchangeable.

### `least_trusted` — the rank-meet (weakest-link). The one the engine uses.

```python
least_trusted(a, b) = a if TRUST_RANK[a] >= TRUST_RANK[b] else b
```

It returns the *less-trusted* (higher `TRUST_RANK`) of its two inputs — always
one of the inputs, never a new state. It is commutative, associative, and
idempotent, so the result of folding a set of states with it is independent of
visitation order. **Every** combination / merge / aggregation / alternative site
in the live engine uses `least_trusted`.

### `taint_join` — the provenance-clash join. Documented, but unused.

```python
taint_join(INTEGRAL, ASSURED) == MIXED_RAW   # different families clash
least_trusted(INTEGRAL, ASSURED) == ASSURED  # weakest link wins
```

`taint_join` models *provenance compatibility*: combining two values of the
**same** family yields that family's weaker member, but combining two values of
**different** families is treated as a provenance clash and collapses to the
absorbing top `MIXED_RAW`. After the three `least_trusted` migrations it has **no
production call site** — it is retained deliberately as the documented contrast
operator. See the ADR:
[Retain the 8-state lattice](../decisions/2026-05-31-wardline-taint-lattice-retain.md).

## The discriminator: why even genuine value-merges use `least_trusted`

There are three shapes of combination point, and **all three resolve to
`least_trusted` at L2**:

| Shape | Example | Why `least_trusted` |
|---|---|---|
| **Alternative** (value is exactly one of N) | `x = a if c else b`; `if/else`, loop back-edges, `try/except`, `match` arms | At the merge a variable holds the value of exactly one branch — weakest-link is the sound, precise bound. |
| **Aggregation** (a summary of a *set*) | a function's callee-set taint; container literals | Aggregating the influence of a set of callees is not building one value by merging provenances — it is a weakest-link summary. |
| **Value-merge** (one value built from several) | `a + b`; `",".join(parts)`; f-strings; `.format` | This is the subtle one — see below. |

The non-obvious case is the genuine **value-merge**. You might expect
`taint_join`'s provenance-clash semantics to be "more correct" for `a + b`. They
are not, and using them here was the false-positive class the migrations fixed:

> Two **clean** operands of **different** families — e.g. an `ASSURED` validated
> value concatenated with an `INTEGRAL` constant separator — would clash to
> `MIXED_RAW` under `taint_join`. `MIXED_RAW` is rank 7, inside the firing raw
> zone, so it fired `PY-WL-101` on validated, clean data. That is the
> `RAW_ZONE` false positive.

`least_trusted` is correct for value-merges too: a value built from an `ASSURED`
part and an `INTEGRAL` part is no more trusted than `ASSURED`, and no *less*
trusted than that either — there is no honest reason to treat a benign literal as
contaminating. A *raw* operand still propagates at its precise rank and still
fires. So the precision win has no soundness cost.

## The reachable-state set and its invariant

The only taint states any source can introduce into the live pipeline are:

```
{INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}
```

These come from exactly four entry points: the decorator provider
(`EXTERNAL_RAW`, `GUARDED`, `ASSURED`, `INTEGRAL`), the L1 fail-closed fallback
(`UNKNOWN_RAW`), the bundled `stdlib_taint.yaml` table (`ASSURED`, `GUARDED`,
`EXTERNAL_RAW`, `UNKNOWN_RAW`), and the serialisation-sink override
(`UNKNOWN_RAW`).

Because `least_trusted` always returns one of its inputs, **its closure over the
reachable set is the reachable set**. The remaining three states —
`{MIXED_RAW, UNKNOWN_GUARDED, UNKNOWN_ASSURED}` — are **never produced anywhere in
production**. This is the linchpin invariant.

### What enforces it

- **`least_trusted` is closed over the set** by construction (it returns an
  input).
- **The F5 parser guards** close the two previously-ungated dynamic entry points
  that could otherwise inject an unreachable state from data:
  - `stdlib_taint.py` accepts only `{ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`
    (a stdlib call cannot produce your own `INTEGRAL` data).
  - `summary_cache.py` `_deserialise_summary` accepts the full reachable set
    `{INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}` — a `@trusted`
    function legitimately caches `INTEGRAL` — and rejects only the trio. A
    rejected (corrupt or tampered) cache file is dropped with a warning, never
    injected.
- **The invariant-enforcement tests** (`tests/unit/core/test_taint_invariants.py`)
  pin both the operator closure and the end-to-end pipeline property (no scan
  output is ever `MIXED_RAW` or an `UNKNOWN_GUARDED`/`UNKNOWN_ASSURED` state).

### Why the trio's unreachability matters

If `MIXED_RAW` ever became reachable, two rule families would **disagree** on it.
`PY-WL-101` would **fire** on it as the *actual* return of a `@trusted` producer
(where `body == declared`, so it passes the rule's trust-raising gate): at rank 7
it is strictly less trusted than any clean declared tier, so the actual-vs-
declared rank comparison trips. `severity_model.modulate`, by contrast, treats it
as the freedom zone and **suppresses** (returns `NONE`). The firing is **not**
unconditional, though: if the *body* is itself `MIXED_RAW` (the realistic route to
a `MIXED_RAW` actual return), `PY-WL-101`'s body-less-trusted-than-declared gate
suppresses first and delegates to `PY-WL-102`, so `101` does not fire there.
(Note `PY-WL-101`'s `RAW_ZONE` set is a suppression gate on the *declared* tier,
not the firing condition — `MIXED_RAW`'s membership in it is inert because you
never *declare* `MIXED_RAW`.) That asymmetry is harmless only because the input is
unreachable. The F5 guards are what keep it latent.

## Floor / clamp / anchor rules

All clamps move **toward less-trusted**, never toward more-trusted:

- A **floor** pins a function's refined taint to be no more trusted than its L1
  seed (its body-evaluation tier). Floors clamp down to the seed; they never
  promote a function to a more-trusted state.
- The L3 fixed point is **monotone**: a non-anchored function only ever moves
  toward less-trusted during propagation. A strict move toward more-trusted
  indicates a transfer-function bug and trips `L3_MONOTONICITY_VIOLATION`, which
  pins the function at its old (safer) value.
- **Anchored** functions are never refined by L3 — their declared tier is
  authoritative, asserted post-fixed-point.

## Per-rule consumption map

Each rule reads exactly one resolved tier, matched to its intent — no combination
crosses between maps:

| Rule | Reads | Against |
|---|---|---|
| `PY-WL-101` (untrusted reaches trusted) | `function_return_taints` (**actual** returned-value taint) | `project_return_taints` (**declared** return tier) |
| `PY-WL-102` (boundary without rejection) | `project_taints` (**body** taint) | `project_return_taints` (**declared** return tier) |
| Tier-modulated rules (e.g. broad/silent exception) | `project_taints` (**body** tier) | — (single tier into `modulate`) |

## Known boundary: a validator that checks the wrong predicate (F4)

When a caller launders raw data through a `@trust_boundary` validator, `PY-WL-101`
reads the validator's **declared** output tier (`effective_return`,
`project_resolver.py:156`) — not the raw input — because the trust model treats
the annotation as the contract.

This is sound for the statically-decidable property. A **broken** validator with
*no rejection path at all* is caught by `PY-WL-102` (it can never raise, so it
cannot validate).

The **residual** — accepted, out of static reach — is a validator that **has** a
rejection path but checks the **wrong predicate** (e.g. it validates length when
it should validate content). Such a validator passes `PY-WL-102` (it *can* reject)
and `PY-WL-101` trusts its declared output. This is semantically invisible to
static analysis: the engine can decide *"can this function reject at all"*, but
not *"does it reject the right thing"*. This is a property limit of the model, not
a bug — it is the boundary between what the annotation-as-contract trust model
promises and what a value-level semantic analysis would require.

## See also

- [Taint & trust model](model.md) — the reader-facing introduction.
- [Rules](rules.md) — the checks built on this algebra.
- [ADR: Retain the 8-state lattice](../decisions/2026-05-31-wardline-taint-lattice-retain.md).
- `docs/audits/2026-05-31-taint-combination-audit.md` — the audit this spec
  consolidates (findings F1–F6).
