# Trust vocabulary

Wardline ships exactly three importable decorators. They are the only way you
declare trust in your own code; everything else in the lattice is *inferred* by
the engine. This page documents each one precisely — what it declares, its exact
signature and allowed arguments, and a usage example.

## The three decorators

Import all three from one module:

```python
from wardline.decorators import trusted, trust_boundary, external_boundary
```

These are the exact names exported by `wardline.decorators`. The canonical names
are also discoverable without importing Wardline at all, via
`wardline vocab`, which prints:

```text
version: wardline-generic-1
entries:
- canonical_name: external_boundary
  group: 1
  attrs: {}
- canonical_name: trust_boundary
  group: 1
  attrs:
    _wardline_to_level: TaintState
- canonical_name: trusted
  group: 1
  attrs:
    _wardline_level: TaintState
```

All three belong to group `1`. `trust_boundary` stamps a `_wardline_to_level`
marker; `trusted` stamps a `_wardline_level` marker; `external_boundary` carries
no level attribute.

!!! important "These are static-analysis markers — no runtime behavior"
    Each decorator stamps `_wardline_*` attributes onto the function object and
    **returns the function unchanged**. They do not wrap, validate, sanitise,
    log, or alter the function's behavior at runtime in any way. The analyzer's
    `DecoratorTaintSourceProvider` reads the markers from the *AST* during a
    scan; at runtime your decorated function behaves exactly as if the decorator
    were not there. Adding a decorator can never change what your program does —
    it only changes what Wardline can *prove* about it.

## The four declarable tiers

You only ever write four of the eight lattice tiers directly. The decorators
accept these names (as a `TaintState` enum member or its string form):

| Tier | Declared by | Meaning |
| --- | --- | --- |
| `INTEGRAL` | `@trusted` (the default) | Fully trusted data your code produces and relies on. The most-trusted tier. |
| `ASSURED` | `@trusted(level="ASSURED")` or `@trust_boundary(to_level="ASSURED")` | Trusted after validation — one notch below integral. |
| `GUARDED` | `@trust_boundary(to_level="GUARDED")` | Partially checked — passed a shape/format guard but not fully assured. |
| `EXTERNAL_RAW` | `@external_boundary` | Raw, untrusted data crossing into the system from outside. |

The remaining four tiers (`UNKNOWN_RAW`, `UNKNOWN_GUARDED`, `UNKNOWN_ASSURED`,
`MIXED_RAW`) are never written by you — the engine infers them for undecorated,
unresolved, or provenance-conflicting code. They are documented in the
[trust model](../concepts/model.md).

Each decorator only accepts the subset of tiers that makes sense for it; passing
a tier outside that subset is an error (see the per-decorator sections below).

## `external_boundary`

**Declares:** an external entry point. Its return value carries raw, untrusted
data (`EXTERNAL_RAW`). This is your *source* — the function where data crosses
into the system from the outside world.

**Signature:**

```python
def external_boundary[F: Callable[..., Any]](fn: F) -> F
```

It takes no arguments — apply it bare, never called. There is no level to set:
the return tier is always `EXTERNAL_RAW`.

**Usage:**

```python
from wardline.decorators import external_boundary

@external_boundary
def read_request_body(request) -> str:
    return request.body          # tracked as EXTERNAL_RAW
```

Anything `read_request_body` returns is treated as untrusted from here on. If it
reaches a function declared to produce trusted data without a validation
boundary in between, Wardline reports a finding.

**Anti-pattern:** do not call it with parentheses or arguments —
`@external_boundary()` or `@external_boundary(level=...)` is wrong.
`external_boundary` is the bare-form decorator; it has nothing to parameterise.

## `trust_boundary`

**Declares:** a validation/sanitisation boundary. The function takes input that
may be untrusted and *raises* its trust on the way out, to the tier you name in
`to_level`. This is the only sanctioned way to legitimise untrusted data.

**Signature:**

```python
def trust_boundary(*, to_level: TaintState | str) -> Callable[[Any], Any]
```

`to_level` is **keyword-only and required** — there is no default. It accepts
only two tiers:

- `GUARDED` — partially checked (passed a shape/format guard).
- `ASSURED` — trusted after validation.

Passing any other tier (for example `INTEGRAL` or `EXTERNAL_RAW`) is rejected:
the boundary can only raise trust to `GUARDED` or `ASSURED`, not to fully
integral and not to a raw tier.

**Usage:**

```python
from wardline.decorators import trust_boundary

@trust_boundary(to_level="GUARDED")
def parse_user_id(raw: str) -> int:
    return int(raw)              # return tracked as GUARDED, not raw
```

Once data passes through `parse_user_id`, Wardline treats the result as
`GUARDED` rather than `EXTERNAL_RAW`, so it can flow into code expecting guarded
input without a finding.

**Anti-pattern:** do not omit `to_level` (`@trust_boundary` bare, or
`@trust_boundary()`, raises because `to_level` is required), and do not name a
tier outside `{GUARDED, ASSURED}`. A boundary that claims to produce `INTEGRAL`
from raw input is exactly the over-trust Wardline exists to catch — so it is
disallowed at the declaration site.

## `trusted`

**Declares:** a trusted producer or sink — a function that both operates on and
returns trusted data. Use it on internal code that you assert never handles raw,
untrusted input.

**Signature (two forms):**

```python
@overload
def trusted[F: Callable[..., Any]](fn: F, /) -> F: ...
@overload
def trusted(*, level: TaintState | str = ...) -> Callable[[Any], Any]: ...
```

`trusted` supports both the bare form and the parameterised form:

- **Bare** `@trusted` — declares the default tier, `INTEGRAL`.
- **Parameterised** `@trusted(level="ASSURED")` — declares `ASSURED` instead.

`level` is keyword-only and accepts only two tiers: `INTEGRAL` (the default) or
`ASSURED`. Passing any other tier (for example `GUARDED` or `EXTERNAL_RAW`) is
rejected — a `trusted` producer is, by definition, integral or assured, not
merely guarded and never raw.

**Usage — both forms:**

```python
from wardline.decorators import trusted

@trusted
def build_audit_record(event) -> dict:
    return {"event": event}      # declares it produces INTEGRAL data

@trusted(level="ASSURED")
def normalise_config(cfg: dict) -> dict:
    return dict(cfg)             # declares it produces ASSURED data
```

If anything `EXTERNAL_RAW` reaches the return path of `build_audit_record`
without a `trust_boundary` in between, Wardline reports that the function
declares `INTEGRAL` but actually returns untrusted data.

**Anti-pattern:** do not pass a non-trusted tier such as
`@trusted(level="GUARDED")` or `@trusted(level="EXTERNAL_RAW")`. Those tiers
belong to `trust_boundary` and `external_boundary` respectively; `trusted` is
only for `INTEGRAL` or `ASSURED`.

## How the three fit together

A typical flow uses one of each: `external_boundary` marks where untrusted data
enters, `trust_boundary` marks where it is validated and its trust is raised, and
`trusted` marks the code downstream that is entitled to assume trusted input.

```python
from wardline.decorators import external_boundary, trust_boundary, trusted

@external_boundary
def read_id(request) -> str:
    return request.args["id"]            # EXTERNAL_RAW

@trust_boundary(to_level="GUARDED")
def validate_id(raw: str) -> int:
    return int(raw)                      # raises to GUARDED

@trusted(level="ASSURED")
def load_user(user_id: int):
    ...                                  # entitled to ASSURED input
```

Wardline reads these declarations and the data flow between them, then reports
any path where untrusted data reaches a more-trusting declaration without
crossing a boundary first. For the conceptual model behind the tiers and how
trust combines along a flow, see the [trust model](../concepts/model.md).
