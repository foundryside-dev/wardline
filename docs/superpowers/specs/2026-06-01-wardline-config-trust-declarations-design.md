# Wardline — config-backed trust declarations (design)

**Date:** 2026-06-01  
**Status:** Revised design (aligned with the explicit-`@trusted` spec; ready for implementation planning)  
**Scope:** Extend Wardline's existing trust-declaration capability so agentic coding
agents can mark code as trust-relevant **without editing source**, using
`wardline.yaml`.

> **Depends on the foundational spec.** The trust vocabulary this surface
> declares is defined by
> [explicit body/return `@trusted` declarations](2026-06-01-wardline-explicit-trusted-body-return-design.md).
> That spec **lands first**; this one reuses its `@trusted` shape and its shared
> validator rather than defining a parallel one (see §0 and §5.2).

---

## 0. Revision note (2026-06-01)

Aligned with the explicit-`@trusted` spec so the two declaration surfaces stay a
single vocabulary, not two that happen to look alike:

1. **`trusted` gains the asymmetric form here too.** A config `declare: trusted`
   accepts either `level:` (symmetric shorthand) or `body:` + `returns:`
   (explicit), exactly mirroring the decorator. See §4.1 and §6.1.
2. **One shared validator.** The `trust:` parser calls the foundational spec's
   `TRUSTED_DECLARABLE_LEVELS` / `is_trusted_order` helpers (`core/taints.py`,
   §5.0 there). It does **not** re-implement the allowed-levels set or the
   `body` ≤ `returns` ordering rule. A config-declared trusted producer must
   yield the byte-identical `FunctionTaint` to its decorator equivalent.
3. **Trust-raising is rejected here too.** A config `trusted` with `body` less
   trusted than `returns` is a hard `ConfigError` — raising trust stays the job
   of `trust_boundary`. See §8.1.

---

## 1. Goal

Add an out-of-source trust-declaration surface to Wardline so agents can mark
parts of the codebase as:

- `external_boundary`
- `trust_boundary(to_level=...)`
- `trusted(level=...)`

(with `trusted` taking either `level:` or `body:`/`returns:`, mirroring the
decorator) and have those declarations change Wardline's normal analysis and
gating behavior exactly the way in-source decorators do.

This is a **Wardline-first** feature. It does not depend on Clarion, Filigree,
or any remote store. It must preserve Wardline's standalone, fail-loud config
discipline and reuse the existing analyzer semantics rather than introducing a
second trust model.

---

## 2. Current capability review

Wardline already has the right extension seam:

1. `TaintSourceProvider` is explicitly documented as the place declarations come
   from, including future declarations from "decorators, annotations, or
   config" (`src/wardline/scanner/taint/provider.py`).
2. `WardlineAnalyzer` already injects a provider into function seeding, so a
   config-backed declaration source can participate without reshaping the engine
   (`src/wardline/scanner/analyzer.py`).
3. `wardline.yaml` is already strict-schema and fail-loud, which is the right
   posture for behavior-affecting trust declarations
   (`src/wardline/core/config.py`, `src/wardline/core/config_schema.py`).
4. SP2 already deferred a `module_default`-style out-of-source declaration
   concept; this design picks up that thread instead of inventing a parallel
   subsystem (`docs/superpowers/specs/archive/2026-05-30-wardline-sp2-rules-and-vocabulary-design.md`).

So the design is not "teach Wardline a new concept." It is "add a new
declaration surface to an existing concept."

---

## 3. Fixed design decisions

The following decisions were made during brainstorming and are not re-opened in
this document:

1. **Behavior changed:** Wardline analysis and gating behavior, not just
   prompting or issue metadata.
2. **Property family:** trust semantics only in v1 (`external_boundary`,
   `trust_boundary`, `trusted`).
3. **Persistence surface:** out-of-source declarations in `wardline.yaml`, not
   inserted decorators or a remote/shared store.
4. **Targeting model:** path globs for broad scope; exact qualnames for precise
   overrides.
5. **Config location:** inline `wardline.yaml`, not a separate `.wardline/*.yaml`
   sidecar.

Everything below is designed to serve those five constraints.

---

## 4. Design posture

### 4.1 One trust vocabulary, two declaration surfaces

Wardline keeps a single trust vocabulary. The config-backed declarations do not
invent new trust kinds or alternative semantics. They map 1:1 onto the existing
decorator shapes:

| Config `declare` | Equivalent decorator | Emitted `FunctionTaint` |
|---|---|---|
| `external_boundary` | `@external_boundary` | `(EXTERNAL_RAW, EXTERNAL_RAW)` |
| `trust_boundary` + `to_level` | `@trust_boundary(to_level=...)` | `(EXTERNAL_RAW, <to_level>)` |
| `trusted` + `level` | `@trusted(level=...)` | `(<level>, <level>)` |
| `trusted` + `body` + `returns` | `@trusted(body=..., returns=...)` | `(<body>, <returns>)` |

This keeps the explainability story intact: the source of the declaration
changes, but the engine's meaning does not. The `trusted` rows reuse the exact
shape and constraints from the foundational spec — including `body` at least as
trusted as `returns` — via the shared validator (§5.2).

### 4.2 Small, explicit scope model

V1 supports exactly two targeting layers:

- **`trust.defaults`** — broad defaults selected by `path_glob`
- **`trust.entities`** — exact function/entity overrides selected by `qualname`

Notably absent in v1:

- module globs
- qualname globs or prefixes
- line/span targeting
- non-trust properties

These are deliberately excluded to keep matching deterministic and reviewable.

### 4.3 Precedence

Declaration precedence is:

**entity config > source decorator > path default > existing fallback**

Rationale:

- entity config is the sharpest tool and is the reason this feature exists;
- in-source decorators should beat broad defaults;
- broad defaults should only fill silence, not silently stomp deliberate source
  declarations;
- the analyzer's existing fallback behavior stays unchanged when nothing matches.

---

## 5. Architecture

Four units, each small and independently testable.

### 5.1 `core/config_schema.py` / `core/config.py`

Add a new top-level `trust` block to the schema and to `WardlineConfig`.

The schema stays fail-loud:

- unknown keys are errors;
- invalid field combinations are errors;
- wrong types are errors.

`WardlineConfig` exposes the raw `trust` mapping, parallel to the existing
`judge`, `filigree`, and `clarion` raw maps.

### 5.2 `core/trust_config.py`

New typed parser for the `trust:` block. Suggested model:

```python
@dataclass(frozen=True, slots=True)
class PathTrustDefault:
    path_glob: str
    declaration: FunctionTaint
    reason: str


@dataclass(frozen=True, slots=True)
class EntityTrustDeclaration:
    qualname: str
    declaration: FunctionTaint
    reason: str


@dataclass(frozen=True, slots=True)
class TrustConfig:
    defaults: tuple[PathTrustDefault, ...]
    entities: Mapping[str, EntityTrustDeclaration]
```

This module owns the typed parse and the *config-shape* validation rules (which
keys are required, duplicate-qualname detection, etc.). It does **not** own the
trust *semantics*: when it builds a `trusted` declaration's `FunctionTaint`, it
calls the shared `core/taints.py` helpers from the foundational spec
(`TRUSTED_DECLARABLE_LEVELS` for the per-field allow-check, `is_trusted_order`
for the `body` ≤ `returns` rule). A config `trusted(body=..., returns=...)` must
construct the same `FunctionTaint` a decorator would — there is exactly one
definition of "what a legal `@trusted` is," consumed by both surfaces.
`config.load()` remains a shape loader, following the existing pattern used for
judge settings and waivers.

### 5.3 `scanner/taint/config_provider.py`

New config-backed providers implementing `TaintSourceProvider`:

- `ConfigEntityTrustProvider`
- `ConfigPathDefaultProvider`

Their responsibilities are intentionally split so the precedence ladder stays
explicit.

- `ConfigEntityTrustProvider.taint_for(entity, ctx)` returns the exact-qualname
  declaration for `entity.qualname`, or `None`.
- `ConfigPathDefaultProvider.taint_for(entity, ctx)` returns the last matching
  path default for `entity.path`, or `None`.

Neither provider inspects decorators. That remains the decorator provider's job.

### 5.4 Composite provider wiring in `scanner/analyzer.py`

`WardlineAnalyzer` switches from a single default provider to a concrete
`CompositeTaintSourceProvider` with this resolution chain:

1. `ConfigEntityTrustProvider`
2. `DecoratorTaintSourceProvider`
3. `ConfigPathDefaultProvider`
4. fallback/default behavior

That order is the contract. The implementation should not collapse it into a
single "do everything" provider, because keeping the chain explicit makes the
precedence easier to test and reason about.

### 5.5 Provider fingerprint and summary cache invalidation

This detail is load-bearing.

The summary cache key already includes `provider.fingerprint()`. Because
`trust:` declarations live outside scanned source, changing `wardline.yaml`
would otherwise leave cached summaries stale.

Therefore the effective provider fingerprint must include a stable digest of the
parsed `trust:` config. A good scheme is:

- build a canonical payload from **behavior-affecting** trust fields only;
- normalize mapping keys to deterministic order;
- preserve source order for any order-significant list, especially
  `trust.defaults`, because **last matching entry wins**;
- hash that payload;
- fold it into the provider fingerprint string.

Changing only `trust:` must invalidate cached summaries.

---

## 6. `wardline.yaml` surface

V1 shape:

```yaml
trust:
  defaults:
    - path_glob: "src/api/**"
      declare: external_boundary
      reason: "HTTP handlers return untrusted request data"

    - path_glob: "src/app/validation/**"
      declare: trust_boundary
      to_level: GUARDED
      reason: "Validation layer raises trust before sinks"

  entities:
    - qualname: "app.storage.save_order"
      declare: trusted
      level: INTEGRAL
      reason: "Trusted commit point"

    - qualname: "app.normalize.canonical_email"
      declare: trusted
      body: INTEGRAL
      returns: ASSURED
      reason: "Operates on pristine data; only promises ASSURED on output"
```

### 6.1 Entry rules

For `trust.defaults`:

- `path_glob` is required
- `declare` is required
- `reason` is required

For `trust.entities`:

- `qualname` is required
- `declare` is required
- `reason` is required

Parameter rules:

- `declare: external_boundary` — forbids `level`, `to_level`, `body`, `returns`
- `declare: trust_boundary` — requires `to_level ∈ {GUARDED, ASSURED}`;
  forbids `level`, `body`, `returns`
- `declare: trusted` — exactly one of:
  - `level ∈ {INTEGRAL, ASSURED}` (symmetric), or
  - `body` **and** `returns`, each `∈ {INTEGRAL, ASSURED}` with `body` at least
    as trusted as `returns`.

  Supplying `level` together with `body`/`returns`, or only one of
  `body`/`returns`, is an error (§8.1). The level-membership and ordering checks
  are the shared `core/taints.py` helpers, not a config-local copy.

### 6.2 Matching rules

- `path_glob` matches the repo-relative POSIX path Wardline already uses in
  findings and discovery.
- `qualname` matches Wardline's existing exact qualname composition.
- In `trust.defaults`, **last matching entry wins**.
- In `trust.entities`, duplicate `qualname` entries are a hard config error.

### 6.3 Why `reason` is required

The declaration changes analysis behavior. Requiring `reason` makes agent-authored
trust shifts auditable in git and keeps the config aligned with Wardline's
existing "required reason" posture for waivers.

`reason` is explanatory metadata only; it does not affect matching or the cache
fingerprint. Editing only `reason` should not invalidate summary-cache reuse.

---

## 7. Analyzer behavior

This feature changes **L1 seeding**, not the downstream engine model.

What changes:

- a function can receive its declared taint from config rather than only from
  an AST decorator.

What does not change:

- the taint lattice
- L2 variable propagation
- L3 project fixed-point behavior
- rule semantics
- explain output shape
- SARIF / Filigree / Clarion transports

This is important: a config-backed `trusted` declaration must behave exactly the
same as an in-source `@trusted` decorator for rule firing and gate behavior.

---

## 8. Validation and error handling

### 8.1 Hard errors

The following are hard `ConfigError`s and exit `2`:

- unknown keys under `trust`
- wrong top-level types
- invalid `declare` values
- invalid `level` / `to_level` combinations
- a `trusted` entry that supplies `level` together with `body`/`returns`, or
  only one of `body`/`returns`
- a `trusted` entry whose `body` is less trusted than its `returns`
  (trust-raising; the error should point at `trust_boundary`)
- a `level` / `body` / `returns` value outside `{INTEGRAL, ASSURED}`
- missing required fields
- duplicate `entities.qualname` entries

Unlike the static decorator read (which is conservative — *no opinion* on a
malformed shape), `wardline.yaml` is fail-loud: a malformed `trust:` entry is a
hard error, not a silently-dropped declaration. That matches the existing config
posture and is safe because config parse happens before analysis, not while
reading arbitrary source.

### 8.2 Non-fatal visibility for unmatched exact qualnames

An exact qualname declaration may fail to match during a given run because:

- the qualname is typo'd, or
- the user scanned only part of the repo.

Failing the whole run would make partial-path scans brittle, so v1 does **not**
turn unmatched entity declarations into exit-2 errors.

Instead Wardline emits a `Severity.NONE` config fact when an exact `qualname`
declaration matches nothing in the scanned set. Suggested shape:

- `rule_id = "WLN-CONFIG-TRUST-NOMATCH"`
- `kind = FACT`
- `properties` include the unmatched `qualname`

This keeps typos observable without breaking narrow scans.

### 8.3 Path defaults that match nothing

Path defaults are broad policy hints. A default that matches nothing in one run
is inert and not an error.

---

## 9. Testing strategy

### 9.1 Config parse tests

- valid examples for every trust declaration kind, including both `trusted`
  forms (`level:` and `body:`/`returns:`)
- reject invalid `declare`/`level`/`to_level` combinations
- reject `trusted` with `level` + `body`/`returns`, or only one of
  `body`/`returns`
- reject trust-raising `trusted` (`body` less trusted than `returns`)
- reject missing required fields
- reject duplicate exact qualnames

### 9.1a Cross-surface parity test

A `trusted(body=B, returns=R)` declared in `wardline.yaml` and the decorator
`@trusted(body=B, returns=R)` must produce the **identical** `FunctionTaint`.
This is the test that proves the two surfaces share one definition (it would fail
if the config parser grew its own allow-set or ordering copy).

### 9.2 Matching tests

- `path_glob` matches repo-relative paths correctly
- last-match-wins for overlapping defaults
- exact qualname match selects the entity declaration

### 9.3 Precedence tests

Pin the full precedence ladder:

1. entity config beats decorator
2. decorator beats path default
3. path default beats fallback

These are the highest-value correctness tests in the design.

### 9.4 End-to-end behavior tests

At least three fixtures:

1. **config-only external boundary** — a function marked only in config as
   `external_boundary` behaves like the decorator case and can taint downstream
   trusted code.
2. **config-only trusted sink** — a function declared only in config as
   `trusted(level=INTEGRAL)` produces the same PY-WL-101 gate behavior as a
   decorated trusted function.
3. **mixed config + decorator** — proves precedence is implemented, not assumed.

### 9.5 Cache invalidation tests

Changing behavior-affecting `trust:` config must change the provider fingerprint
and invalidate summary-cache reuse. Editing explanatory-only fields such as
`reason` must not.

### 9.6 Config fact visibility tests

- unmatched exact qualname emits `WLN-CONFIG-TRUST-NOMATCH`
- the scan still exits normally unless another real error occurs

---

## 10. Non-goals

V1 does **not** include:

- module globs
- qualname globs or prefixes
- line/span declarations
- generic arbitrary properties
- auto-rewriting source to insert decorators
- shared/network-backed declaration stores
- rule-specific behavior knobs beyond trust seeding

Those may become future features, but they are intentionally excluded here.

---

## 11. Risks and mitigations

### 11.1 Hidden divergence from source intent

An out-of-source entity declaration can disagree with source decorators or human
expectation.

Mitigation:

- explicit precedence
- required `reason`
- git-visible config
- tests pinning entity-over-decorator behavior so it is a deliberate contract,
  not accidental shadowing

### 11.2 Broad path defaults can over-taint large areas

A coarse `path_glob` may unexpectedly mark too much code.

Mitigation:

- keep defaults broad but path-only
- keep exact-qualname overrides available
- preserve decorator precedence over path defaults

### 11.3 Silent staleness via the summary cache

Out-of-source config is invisible to source hashes.

Mitigation:

- include normalized `trust:` config in the provider fingerprint
- pin with cache invalidation tests

---

## 12. Forward extension path

This design intentionally stops at trust declarations, but it creates a clean
pattern for future expansion if Wardline later wants more behavior-affecting
properties.

The extension path is:

1. keep **trust** as its own block now;
2. prove the config-backed provider pattern works;
3. if future demand is real, add separate, typed blocks for other behavior
   families rather than collapsing everything into a single generic
   "properties" bag.

Examples of future families that could reuse the pattern:

- generated/third-party/legacy posture
- stricter analysis zones
- rule-scoped policy declarations

But those are future design exercises. V1 should ship only the trust-backed
declaration surface above.
