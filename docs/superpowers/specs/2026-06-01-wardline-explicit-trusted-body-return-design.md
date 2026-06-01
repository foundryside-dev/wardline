# Wardline — explicit body/return `@trusted` declarations (design)

**Date:** 2026-06-01  
**Status:** Approved design (brainstormed; ready for implementation planning)  
**Scope:** Replace Wardline's symmetric `@trusted(level=...)` declaration with a
cleaner in-source surface that matches the engine's existing
`FunctionTaint(body_taint, return_taint)` model.

---

## 1. Goal

Make in-source trust declarations more expressive **without** teaching Wardline
a new trust model.

Wardline already reasons about a function in two parts:

- the trust observed **inside the body**
- the trust of the function's **return value**

But the current `@trusted` decorator mostly collapses that to one knob
(`level=`), even though the analyzer, summaries, and provider seam already
carry two fields.

This design makes the public `@trusted` surface line up with the model:

- keep `@external_boundary`
- keep `@trust_boundary(to_level=...)`
- redefine `@trusted` as either bare or explicit `body`/`returns`

Because the project currently has **no external users**, this is an intentional
spec cleanup, not a compatibility exercise.

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

The following decisions were made during brainstorming and are not re-opened in
this document:

1. **Breaking change is allowed.** No compatibility shim is required for
   `@trusted(level=...)`.
2. **Keep the named trust vocabulary.** Do not collapse the public surface into
   one generic "declare trust" decorator.
3. **Only `@trusted` changes in v1.** `@external_boundary` and
   `@trust_boundary(to_level=...)` remain unchanged.
4. **`@trusted` has exactly two valid forms:** bare `@trusted`, or explicit
   `@trusted(body=..., returns=...)`.
5. **The analyzer stays fail-closed.** Malformed or unreadable source never
   silently grants trust.

Everything below is designed to serve those five constraints.

---

## 4. Public decorator surface

### 4.1 `@trusted` forms

`@trusted` becomes:

```python
from wardline.decorators import trusted


@trusted
def canonical_record(x):
    ...


@trusted(body="ASSURED", returns="INTEGRAL")
def normalize_customer(x):
    ...
```

Meaning:

| Form | Meaning | Emitted `FunctionTaint` |
|---|---|---|
| `@trusted` | common default trusted producer | `(INTEGRAL, INTEGRAL)` |
| `@trusted(body=<L1>, returns=<L2>)` | explicit body/return contract | `(<L1>, <L2>)` |

`body` and `returns` accept either:

- a `TaintState`
- the exact string name of one

### 4.2 Allowed levels

For `@trusted`, both `body` and `returns` remain restricted to the existing
trusted-producer levels:

- `INTEGRAL`
- `ASSURED`

This is deliberate. `@trust_boundary(to_level=...)` remains the way to express
raw-to-validated transitions such as `EXTERNAL_RAW -> ASSURED`.

### 4.3 Removed form

The old symmetric keyword form is removed:

```python
@trusted(level="ASSURED")  # no longer valid
```

This is a conscious simplification. Keeping `level=` would preserve old syntax,
but it would also keep three overlapping authoring forms alive:

- bare `@trusted`
- `@trusted(level=...)`
- `@trusted(body=..., returns=...)`

With no users to preserve, that extra surface is not justified.

---

## 5. Architecture

Four units change, each with one clear responsibility.

### 5.1 `src/wardline/decorators/trust.py`

Redefine `trusted()` so it supports:

- bare decorator use (`@trusted`)
- keyword-only explicit use (`@trusted(body=..., returns=...)`)

Runtime validation should be strict:

- `body` without `returns` is an error
- `returns` without `body` is an error
- `level=` is an error
- disallowed levels are errors

The decorator remains a runtime no-op marker: it stamps Wardline marker attrs on
the function and returns the function unchanged.

Suggested marker attrs for `trusted`:

- `_wardline_body_level`
- `_wardline_return_level`

The legacy `_wardline_level` attr is removed from the registry for `trusted`.

### 5.2 `src/wardline/core/registry.py`

Update the `trusted` registry entry so its attrs describe the new marker shape:

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

Also bump `REGISTRY_VERSION`, because the vocabulary's declaration surface has
changed.

That version bump is load-bearing: the provider fingerprint derives from the
registry version, so summary-cache keys must change with this spec change.

### 5.3 `src/wardline/scanner/taint/decorator_provider.py`

Extend the provider's `trusted` read path:

- bare `@trusted` -> `(INTEGRAL, INTEGRAL)`
- explicit `body` + `returns` -> parsed pair

The provider should **not** support `level=` any longer. When scanning source:

- old `level=` form -> `None` (no opinion)
- only one of `body` / `returns` -> `None`
- dynamic or unreadable values -> `None`
- values outside the allowed set -> `None`

The existing conflict rule remains unchanged: if multiple Wardline trust
decorators appear on one function, the provider resolves the least-trusted value
**per field**. This proposal does not change that safety invariant.

### 5.4 Descriptor / vocabulary surfaces

Because the registry is published through:

- `wardline vocab`
- `src/wardline/core/vocabulary.yaml`
- descriptor tests and any read-instead-of-import consumers

the published vocabulary must change in lockstep with the registry update.

This is a full-surface change, not an internal implementation detail.

---

## 6. Validation and failure handling

Wardline should be strict for authors and conservative for analysis.

### 6.1 Runtime authoring behavior

When Python actually imports and applies the decorator:

- invalid `@trusted(...)` shapes raise `ValueError`
- invalid levels raise `ValueError`
- the function identity remains unchanged for valid declarations

This gives fast feedback to Wardline users authoring declarations by hand.

### 6.2 Static-analysis behavior

When Wardline scans source code statically:

- malformed declarations are treated as **no opinion**
- dynamic values are treated as **no opinion**
- removed legacy syntax (`level=`) is treated as **no opinion**

That asymmetry is correct. The runtime decorator can fail loudly for authors;
the analyzer must remain safe when reading arbitrary source that may not even be
executed.

---

## 7. Documentation surface

The following docs should be updated as part of the implementation:

- `docs/concepts/model.md`
- `docs/reference/vocabulary.md`
- any examples or tests that currently show `@trusted(level=...)`
- `src/wardline/core/vocabulary.yaml`

The docs should explain the design simply:

- bare `@trusted` = default trusted producer
- explicit `@trusted(body=..., returns=...)` = non-default contract
- `@trust_boundary(to_level=...)` is still the boundary decorator

No deprecation language is needed. This is a clean spec replacement.

---

## 8. Test plan

Implementation is complete when the following are covered.

### 8.1 Decorator unit tests

Update `tests/unit/decorators/test_trust.py` to pin:

- bare `@trusted` still marks integral/integral
- explicit `body` / `returns` accepts both strings and `TaintState.*`
- `level=` now raises
- partial `body` / `returns` now raises
- invalid levels still raise
- decorator preserves function identity/name

### 8.2 Provider unit tests

Update `tests/unit/scanner/taint/test_decorator_provider.py` to pin:

- bare `@trusted` -> `(INTEGRAL, INTEGRAL)`
- explicit `body` / `returns` -> parsed pair
- old `level=` form -> no opinion
- partial forms -> no opinion
- dynamic forms -> no opinion
- alias-import resolution still works for the new explicit form

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

Wardline keeps its pedagogically useful three-decorator vocabulary, but its
`@trusted` decorator stops hiding the engine's two-field model behind a mostly
symmetric shorthand.

The result is a cleaner spec:

- one default form (`@trusted`)
- one explicit form (`@trusted(body=..., returns=...)`)
- no compatibility baggage for `level=...`
- no taint-engine redesign

That is the smallest change that materially improves the clarity and power of
in-source trust declarations.
