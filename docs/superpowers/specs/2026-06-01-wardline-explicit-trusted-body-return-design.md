# Wardline — explicit body/return `@trusted` declarations (design)

**Date:** 2026-06-01  
**Status:** Revised design (incorporates the 2026-06-01 review; ready for implementation planning)  
**Scope:** Extend Wardline's `@trusted(level=...)` declaration with an explicit
`body=/returns=` form that matches the engine's existing
`FunctionTaint(body_taint, return_taint)` model — keeping `level=` as the
symmetric shorthand.

> **This is the foundational spec of a pair.** The sibling
> [config-backed trust declarations](2026-06-01-wardline-config-trust-declarations-design.md)
> reuses the `@trusted` shape and the shared validator defined here. That spec
> **depends on this one** and must land after it (see §11).

---

## 0. Revision note (2026-06-01)

The first draft was reviewed against the engine and three changes were made for
correctness and real-world ergonomics. The guiding principle for the revision:
*a well-crafted surface no one reaches for is not actually used* — so the common
authoring path stays terse, and only genuinely-new power is added.

1. **`level=` is kept, not removed.** The first draft removed `@trusted(level=...)`
   and forced the common symmetric producer to write `@trusted(body=X, returns=X)`.
   That taxes the dominant authoring path (symmetric trust is by far the common
   case) to privilege a rare one. `level=` is retained as the symmetric shorthand;
   `body=/returns=` is *added* for the asymmetric case. (This reopens first-draft
   "fixed decision" #4 with evidence it had not weighed: the common case is
   symmetric.)
2. **A legal-ordering constraint is added.** `@trusted` now requires
   `body` to be **at least as trusted as** `returns`. The first draft's flagship
   example, `@trusted(body="ASSURED", returns="INTEGRAL")`, is a trust-*raising*
   shape and would itself fire `PY-WL-102` (boundary-without-rejection); raising
   trust is the exclusive province of `@trust_boundary`. See §4.3.
3. **The fail-closed read rule is promoted to a tested soundness invariant.** A
   `@trusted(...)` call the analyzer cannot read as a valid level pair must seed
   *no opinion* (`None`) — never the bare `(INTEGRAL, INTEGRAL)` default — or a
   stale/typo'd declaration silently *over-trusts*. See §6.3.

---

## 1. Goal

Make in-source trust declarations more expressive **without** teaching Wardline
a new trust model.

Wardline already reasons about a function in two parts:

- the trust observed **inside the body** (`body_taint`)
- the trust of the function's **return value** (`return_taint`)

And — load-bearing for this design — *different rules already read different
fields*:

- `PY-WL-101` (untrusted-reaches-trusted) reads the **return** tier
  (declared-vs-actual return).
- `PY-WL-103` / `PY-WL-104` (broad / silently-swallowed exception) read the
  **body** tier to modulate severity.

The current `@trusted` collapses both fields to one knob (`level=`), so a single
value must serve two rule families that legitimately want different inputs.
Concretely, a function that operates on pristine `INTEGRAL` data internally but
legitimately returns an `ASSURED`-tier value is forced to choose:

- `level="INTEGRAL"` → `PY-WL-101` false-positives (its actual return is
  `ASSURED`, less trusted than declared); or
- `level="ASSURED"` → `PY-WL-103/104` under-modulate (a bare `except` in
  `INTEGRAL`-grade code is scored as merely `ASSURED`-tier).

`@trusted(body="INTEGRAL", returns="ASSURED")` resolves that tension directly.
That is the concrete payoff; "the surface matches the engine's two-field model"
is the framing, not the motivation.

This design:

- keeps `@external_boundary` and `@trust_boundary(to_level=...)` unchanged;
- keeps `@trusted(level=...)` as the **symmetric shorthand**;
- adds `@trusted(body=..., returns=...)` for the **asymmetric** case.

Because the project currently has **no external users**, breaking changes are
free; this is a surface improvement, not a compatibility exercise.

---

## 2. Current capability review

Wardline already has the right internal shape for this change:

1. `FunctionTaint` is explicitly two-field — `body_taint` and `return_taint`
   (`src/wardline/scanner/taint/provider.py`).
2. `DecoratorTaintSourceProvider` already produces a full `FunctionTaint` per
   decorator and resolves conflicting decorators **per field**, not as one
   scalar (`src/wardline/scanner/taint/decorator_provider.py`).
3. `@external_boundary` and `@trust_boundary(to_level=...)` already model
   asymmetric roles cleanly; the asymmetry gap is concentrated in `@trusted`
   (`src/wardline/decorators/trust.py`).
4. The decorator surface is already published as a versioned registry and
   descriptor, so Wardline has a single place where this public contract is
   defined (`src/wardline/core/registry.py`,
   `tests/unit/core/test_descriptor.py`).

So this is not a taint-engine redesign. It is a declaration-surface correction.

---

## 3. Fixed design decisions

These hold for the rest of the document:

1. **Breaking changes are free.** No compatibility shim is required for any
   change here; optimise for the best surface, not for migration cost.
2. **Keep the named trust vocabulary.** Do not collapse the public surface into
   one generic "declare trust" decorator.
3. **Only `@trusted` changes.** `@external_boundary` and
   `@trust_boundary(to_level=...)` remain unchanged.
4. **`@trusted` has three forms:** bare `@trusted` (default), `@trusted(level=...)`
   (symmetric shorthand), and `@trusted(body=..., returns=...)` (explicit
   asymmetric). `level` and `body`/`returns` are mutually exclusive. Three forms
   are justified because each has a distinct, common purpose; the common
   symmetric path stays terse.
5. **`@trusted` may not raise trust.** `body` must be at least as trusted as
   `returns`. Trust-raising transitions remain the exclusive province of
   `@trust_boundary`. (See §4.3 for why — it is also what keeps `PY-WL-102` from
   firing on a `@trusted`.)
6. **The analyzer stays fail-closed.** A declaration the analyzer cannot read as
   a valid level pair grants *no* trust opinion — never a default tier (§6.3).

Everything below is designed to serve those constraints.

---

## 4. Public decorator surface

### 4.1 `@trusted` forms

`@trusted` has three forms:

```python
from wardline.decorators import trusted


@trusted                                       # bare: the common default
def canonical_record(x):
    ...


@trusted(level="ASSURED")                      # symmetric shorthand
def validated_record(x):
    ...


@trusted(body="INTEGRAL", returns="ASSURED")   # explicit asymmetric contract
def downgrades_on_output(x):
    ...
```

Meaning:

| Form | Meaning | Emitted `FunctionTaint` |
|---|---|---|
| `@trusted` | common default trusted producer | `(INTEGRAL, INTEGRAL)` |
| `@trusted(level=<L>)` | symmetric producer at tier `<L>` | `(<L>, <L>)` |
| `@trusted(body=<L1>, returns=<L2>)` | explicit body/return contract | `(<L1>, <L2>)` |

`level`, `body`, and `returns` each accept either a `TaintState` or the exact
string name of one. `level` is exact sugar for `body == returns`; supplying
`level` *together with* `body` or `returns` is an error, and so is supplying only
one of `body`/`returns`.

### 4.2 Allowed levels

For `@trusted`, `level`, `body`, and `returns` are all restricted to the existing
trusted-producer tiers:

- `INTEGRAL`
- `ASSURED`

This is deliberate. `@trust_boundary(to_level=...)` remains the way to express
raw-to-validated transitions such as `EXTERNAL_RAW -> ASSURED`.

### 4.3 Legal ordering — `@trusted` may not raise trust

`@trusted` requires `body` to be **at least as trusted as** `returns`:

```
TRUST_RANK[body] <= TRUST_RANK[returns]
```

(Recall `TRUST_RANK`: `INTEGRAL=0` is the *most* trusted, `ASSURED=1` less so —
so "at least as trusted" means a numerically lower-or-equal rank.)

With the two declarable tiers, this admits exactly one non-symmetric pair:

| `body` | `returns` | Legal? | Why |
|---|---|---|---|
| `INTEGRAL` | `INTEGRAL` | ✅ | symmetric (== bare `@trusted`) |
| `ASSURED` | `ASSURED` | ✅ | symmetric (== `@trusted(level="ASSURED")`) |
| `INTEGRAL` | `ASSURED` | ✅ | **the asymmetric form** — pristine body, downgraded promise |
| `ASSURED` | `INTEGRAL` | ❌ | raises trust — use `@trust_boundary` |

The forbidden row is the crux of the review that produced this revision. A
`@trusted(body="ASSURED", returns="INTEGRAL")` says "inside I work with `ASSURED`
data, but I return `INTEGRAL`" — i.e. it *manufactures* trust. That is precisely
the shape `@trust_boundary` exists for, and `PY-WL-102` (boundary-without-rejection)
already fires on it: its guard is `if TRUST_RANK[body] <= TRUST_RANK[ret]: continue`,
so a body-less-trusted-than-return function is treated as a validation boundary
and flagged unless it has a rejection path. Allowing that shape on `@trusted`
would let the same structural fact mean two different things depending on which
decorator was typed. The ordering constraint dissolves the collision and keeps
the three-decorator division intact: **`@trust_boundary` raises trust; `@trusted`
never does.**

The single legal asymmetric pair, `(INTEGRAL, ASSURED)`, is exactly the case
from §1: a body the exception rules should police at the strict `INTEGRAL` tier,
with a return the producer only promises at `ASSURED`.

> The `body`/`returns` *syntax* is intentionally general even though today's
> allowed tiers admit only one asymmetric pair: if a later spec widens the
> declarable trusted tiers, the surface already expresses the new combinations
> with no new syntax.

---

## 5. Architecture

Five units, each with one clear responsibility. The first is new and is what
keeps this spec and the config spec from drifting.

### 5.0 `src/wardline/core/taints.py` — shared trusted-level validation

The trust *semantics* (which tiers a `@trusted` may declare, and the body ≤
returns ordering) must be defined **once** and consumed by every declaration
surface — the runtime decorator, the static decorator provider, and the
config-backed provider from the sibling spec. Today the allowed-level set is
duplicated as a private `_TRUSTED_LEVELS` in both `decorators/trust.py` and
`decorator_provider.py`; this consolidates it.

Add to `core/taints.py` (it already owns `TRUST_RANK`, so no new dependency):

```python
TRUSTED_DECLARABLE_LEVELS: frozenset[TaintState] = frozenset(
    {TaintState.INTEGRAL, TaintState.ASSURED}
)


def is_trusted_order(body: TaintState, returns: TaintState) -> bool:
    """True iff a @trusted body/returns pair does not raise trust."""
    return TRUST_RANK[body] <= TRUST_RANK[returns]
```

The constraint is pure taint algebra, so it stays in `core` and is import-safe
for both `decorators/` and `scanner/`. Every surface that builds a trusted
`FunctionTaint` must check `level in TRUSTED_DECLARABLE_LEVELS` (per field) and
`is_trusted_order(body, returns)` — there is no second copy of this rule.

### 5.1 `src/wardline/decorators/trust.py`

Redefine `trusted()` so it supports three forms:

- bare `@trusted` → `(INTEGRAL, INTEGRAL)`
- `@trusted(level=L)` → `(L, L)`
- keyword-only `@trusted(body=..., returns=...)` → `(body, returns)`

Runtime validation (raises `ValueError`, see §6.1) uses the §5.0 helpers:

- `level` together with `body` or `returns` is an error
- exactly one of `body` / `returns` (not both) is an error
- a level outside `TRUSTED_DECLARABLE_LEVELS` is an error
- `not is_trusted_order(body, returns)` is an error

The decorator remains a runtime no-op marker: it stamps Wardline marker attrs on
the function and returns it unchanged. Because `level` is sugar for the symmetric
pair, all three forms stamp the **same two marker attrs**:

- `_wardline_body_level`
- `_wardline_return_level`

The legacy single `_wardline_level` attr is removed.

### 5.2 `src/wardline/core/registry.py`

Update the `trusted` registry entry to the new marker shape, and bump
`REGISTRY_VERSION`:

```python
"trusted": RegistryEntry(
    canonical_name="trusted",
    group=1,
    attrs={
        "_wardline_body_level": TaintState,
        "_wardline_return_level": TaintState,
    },
)
```

The version bump is load-bearing: the provider fingerprint derives from
`REGISTRY_VERSION`, so summary-cache keys must change with this declaration-surface
change (a warm cache that predates the change must not be reused).

### 5.3 `src/wardline/scanner/taint/decorator_provider.py`

Extend the provider's `trusted` read path to accept all three forms statically:

- bare `@trusted` → `(INTEGRAL, INTEGRAL)`
- readable `level=L` → `(L, L)`
- readable `body=` + `returns=` → that pair

Apply the §5.0 validation: a level outside the allowed set, or a pair that fails
`is_trusted_order`, reads as `None` (no opinion). The static read is fail-closed
in every ambiguous case — see §6.3 for the exact "no readable pair → `None`,
never the bare default" invariant.

The existing conflict rule is unchanged: if multiple Wardline trust decorators
appear on one function, the provider resolves the least-trusted value **per
field** (`max` by `TRUST_RANK`). This proposal does not change that safety
invariant.

### 5.4 Descriptor / vocabulary surfaces

The registry is published through `wardline vocab`,
`src/wardline/core/vocabulary.yaml`, the descriptor, and any
read-instead-of-import consumers. The published vocabulary must change in
lockstep with the registry update (the byte-identity snapshot test in
`tests/unit/core/test_descriptor.py` enforces this — regenerate, do not
hand-edit). This is a full-surface change, not an internal implementation detail;
§7 enumerates every consumer that embeds the old `level=`-only shape.

---

## 6. Validation and failure handling

Wardline is strict for authors and conservative for analysis. The asymmetry is
deliberate: the runtime decorator may fail loudly because the author is right
there; the static analyzer must stay safe while reading arbitrary source that
may never be imported.

### 6.1 Runtime authoring behavior

When Python imports and applies the decorator, these raise `ValueError`:

- `level` supplied together with `body` or `returns`
- exactly one of `body` / `returns` supplied (both are required together)
- any level outside `TRUSTED_DECLARABLE_LEVELS` (`INTEGRAL`, `ASSURED`)
- a body/returns pair that fails `is_trusted_order` (i.e. `body` less trusted
  than `returns` — a trust-raising shape; the error message should point the
  author at `@trust_boundary`)

For a valid declaration the function identity is unchanged.

### 6.2 Static-analysis behavior

When Wardline scans source statically, each of these reads as **no opinion**
(`None`), so the engine falls back to the unchanged fail-closed `UNKNOWN_RAW`
precedence:

- a malformed shape (`level` + `body`/`returns`; only one of `body`/`returns`)
- a value that is not a statically-readable string/`TaintState` (dynamic, a
  bare `Name`, an f-string, a non-`TaintState` attribute)
- a level outside the allowed set
- a pair that fails `is_trusted_order`

### 6.3 Soundness invariant — no silent over-trust

This is the load-bearing rule, and it is a **tested invariant**, not a bullet:

> A `@trusted(...)` *call* node for which the analyzer cannot extract a valid
> `(body, returns)` pair seeds **`None`** (no opinion) — it must **never** fall
> through to the bare `@trusted` default `(INTEGRAL, INTEGRAL)`.

The hazard: `INTEGRAL` is the *most* trusted tier. If an unreadable or stale
`@trusted(...)` call silently defaulted to `(INTEGRAL, INTEGRAL)`, a typo'd or
half-migrated declaration would *raise* the function's trust — a fail-open
"false-green" of exactly the kind this project treats as a bug. The runtime
`ValueError` (§6.1) does **not** protect the analyzer, which reads source it
never executes.

The implementation consequence is precise: only a **bare** `@trusted` (a `Name`/
`Attribute` decorator node with no `Call`) maps to the default pair. A `Call`
node (`@trusted(...)`) maps to a pair **only** when its arguments parse to a
valid, correctly-ordered level pair (via `level=` *or* `body=/returns=`);
otherwise `None`.

Because `level=` is **retained** (not removed), every existing
`@trusted(level=...)` site stays valid and readable, so no source rewrite is
forced and there is no window for a half-migrated site to flip trust. That is a
deliberate benefit of keeping the shorthand: the §7 surface work is almost
entirely *additive documentation* (teach the new `body=/returns=` form), not a
risky mechanical rewrite of live annotations.

---

## 7. Full surface

The first draft listed "four units" and a short doc list; the review found that
under-counted. The surface splits into two buckets. Because `level=` is retained,
nothing here is a forced rewrite of live annotations — but the marker/registry
shape genuinely changes, and several consumers embed the trust vocabulary in
prose the engine cannot keep in sync automatically.

### 7.1 Must change (the marker/registry shape changed)

- `src/wardline/decorators/trust.py` — three forms, shared validation, the new
  two-attr marker (§5.1)
- `src/wardline/core/registry.py` — `trusted` entry attrs + `REGISTRY_VERSION`
  bump (§5.2)
- `src/wardline/scanner/taint/decorator_provider.py` — three-form read path +
  §5.0 validation (§5.3)
- `src/wardline/core/taints.py` — the shared validator (§5.0)
- `src/wardline/core/vocabulary.yaml` — regenerated snapshot (byte-identity test)

### 7.2 Should update (additive — teach the `body=/returns=` form)

These currently describe `@trusted(level=...)` only. `level=` stays valid, so
they are *correct but incomplete*; each gains the asymmetric form (and none
should show the illegal `body>returns` shape):

- `src/wardline/core/judge.py` — the LLM-judge prompt explains
  `@trusted(level=L)` semantics (around lines 104-112); add the body/returns
  contract so the judge reasons about asymmetric producers correctly
- `src/wardline/scanner/rules/untrusted_reaches_trusted.py` — `examples_clean`
  (and any `examples_violation`) embed `@trusted(level='ASSURED')`; published via
  the descriptor / SARIF rule help. Add an asymmetric example
- the `wardline install` instruction block and the `wardline-gate` skill
  (`src/wardline/skills/wardline-gate/SKILL.md`) — agent-facing usage guidance
- `README.md`, `CLAUDE.md`, `AGENTS.md` — examples in the developer/usage docs
- `docs/concepts/model.md`, `docs/concepts/rules.md`,
  `docs/reference/vocabulary.md` — the prose vocabulary and rule pages

The teaching line everywhere:

- bare `@trusted` = default trusted producer `(INTEGRAL, INTEGRAL)`
- `@trusted(level=L)` = symmetric producer at tier `L`
- `@trusted(body=..., returns=...)` = explicit contract; `body` at least as
  trusted as `returns`
- `@trust_boundary(to_level=...)` is still the only decorator that *raises* trust

No deprecation language is needed.

---

## 8. Test plan

Implementation is complete when the following are covered.

### 8.1 Decorator unit tests

Update `tests/unit/decorators/test_trust.py` to pin:

- bare `@trusted` marks `(INTEGRAL, INTEGRAL)`
- `@trusted(level=L)` marks `(L, L)` for both allowed tiers (string + `TaintState.*`)
- `@trusted(body=, returns=)` accepts both strings and `TaintState.*`
- `@trusted(body="INTEGRAL", returns="ASSURED")` is accepted (the one legal
  asymmetric pair)
- `@trusted(body="ASSURED", returns="INTEGRAL")` **raises** (trust-raising;
  message points at `@trust_boundary`)
- `level` together with `body`/`returns` **raises**
- exactly one of `body`/`returns` **raises**
- invalid levels raise
- decorator preserves function identity/name

### 8.2 Provider unit tests

Update `tests/unit/scanner/taint/test_decorator_provider.py` to pin:

- bare `@trusted` → `(INTEGRAL, INTEGRAL)`
- readable `level=L` → `(L, L)`
- readable `body=/returns=` → parsed pair
- legal asymmetric `(INTEGRAL, ASSURED)` → that pair
- trust-raising `body>returns` → **no opinion** (`None`)
- partial / `level`+`body` conflict forms → no opinion
- dynamic / unreadable forms → no opinion
- alias-import resolution still works for `level=` and `body=/returns=`

### 8.2a Soundness invariant test (§6.3) — highest-value

A dedicated test that pins the no-silent-over-trust rule:

- a **bare** `@trusted` → `(INTEGRAL, INTEGRAL)`
- an unreadable/invalid `@trusted(...)` **call** (e.g. `@trusted(level=cfg.X)`,
  `@trusted(body="ASSURED", returns="INTEGRAL")`, `@trusted(foo=1)`) → `None`,
  asserting it is **not** the `(INTEGRAL, INTEGRAL)` default
- the shared `is_trusted_order` / `TRUSTED_DECLARABLE_LEVELS` helpers in
  `core/taints.py` have direct unit coverage (so the config provider inherits a
  tested contract)

### 8.3 Descriptor / vocabulary tests

Update descriptor tests so `trusted` now publishes the new attrs, and regenerate
`src/wardline/core/vocabulary.yaml` so the byte-identity snapshot continues to
match the registry.

### 8.4 Regression expectation

`@external_boundary` and `@trust_boundary(to_level=...)` behavior should be
unchanged after the refactor.

---

## 9. Out of scope

This design does **not** include:

- changing `@external_boundary`
- changing `@trust_boundary(to_level=...)`
- adding metadata such as `reason=...`
- adding config-backed declarations (covered by a separate design)
- allowing `@trusted` to express raw/body boundary semantics
- changing the taint lattice or policy rules

---

## 10. Result

Wardline keeps its pedagogically useful three-decorator vocabulary, and its
`@trusted` decorator stops hiding the engine's two-field model behind a single
knob — while the common symmetric path stays terse.

The result:

- a default form (`@trusted`) and a terse symmetric form (`@trusted(level=L)`)
  for the common cases;
- an explicit `@trusted(body=..., returns=...)` form for the asymmetric case
  that resolves the real `PY-WL-101`-vs-`103/104` input tension (§1);
- a single legal asymmetric pair, with trust-raising forbidden and reserved to
  `@trust_boundary` — so `PY-WL-102` can never fire on a `@trusted` (§4.3);
- one shared validator (§5.0) the decorator and the config surface both consume,
  so the two declaration paths cannot drift;
- a tested no-silent-over-trust invariant (§6.3);
- no taint-engine redesign.

## 11. Relationship to the config-backed trust spec

This spec defines the canonical `@trusted` shape and the shared §5.0 validator.
The sibling
[config-backed trust declarations](2026-06-01-wardline-config-trust-declarations-design.md)
adds a *second declaration surface* (`wardline.yaml`) for the **same** vocabulary
and explicitly maps each config `declare:` onto the decorator-equivalent
`FunctionTaint`.

Sequencing and contract:

- **This spec lands first.** The config spec's `trusted` declarations reuse the
  three-form shape and `TRUSTED_DECLARABLE_LEVELS` / `is_trusted_order` from
  §5.0; building the config surface against the old `level=`-only shape would
  force a second migration.
- **One validator, not two.** The config parser must call the §5.0 helpers, not
  re-implement the allowed-levels set or the ordering rule. A test should assert
  a config-declared `trusted(body=..., returns=...)` produces the identical
  `FunctionTaint` to the decorator form.
- The config spec's revision note records the same alignment from its side.
