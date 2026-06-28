# Taint & trust model

Wardline reads your Python statically — it never runs your code — and asks one
question of every function: **is the data this function works with as trusted as
the function claims it is?** To answer that, it tracks a *taint* (a trust level)
for every value and propagates it across the whole project.

This page explains the model at a conceptual level. For the exact decorators and
their arguments, see the [trust vocabulary reference](../reference/vocabulary.md);
for the checks built on top of the model, see [Rules](rules.md).

## Trusted vs. untrusted data

"Untrusted" (or **tainted**) data is anything that originated outside your trust
boundary and has not yet been validated — a request body, a file, a CLI
argument, an environment variable. It is not *bad* data; it is *unverified*
data. The danger is letting it flow into a place that assumes it has already
been checked.

Wardline's job is to notice when untrusted data reaches a function that has
*declared* it produces trusted data, with no validation in between.

!!! note "Opt-in by design"
    Wardline is silent until you opt in. Code with no trust decorators sits in
    the **developer-freedom zone** — the engine treats it as unknown-trust and
    raises no policy findings about it. You declare trust on the functions that
    matter, and only then does Wardline enforce it. This is what lets it scan a
    large untouched codebase (including its own source) with zero noise.

## The trust lattice

Internally, every value carries one of eight ordered taint states. They run from
most-trusted to least-trusted:

```
INTEGRAL  →  ASSURED  →  GUARDED  →  UNKNOWN_ASSURED  →  UNKNOWN_GUARDED  →  EXTERNAL_RAW  →  UNKNOWN_RAW  →  MIXED_RAW
(most trusted)                                                                                    (least trusted)
```

"Less trusted" always wins: when values combine, the result is no more trusted
than the weakest input. That ordering is the whole engine in one sentence.

You only ever write three of these levels directly; the rest the engine computes
for you.

| Tier | Who sets it | Meaning |
|---|---|---|
| `INTEGRAL` | You (`@trusted`, the default) | Fully trusted data your code produces and relies on. |
| `ASSURED` | You (`@trusted(level="ASSURED")` / `@trust_boundary(to_level="ASSURED")`) | Trusted after validation — a notch below integral. |
| `GUARDED` | You (`@trust_boundary(to_level="GUARDED")`) / stdlib | Partially checked — passed a shape/format guard but not fully assured. |
| `EXTERNAL_RAW` | You (`@external_boundary`) | Raw, untrusted data crossing into the system from outside. |
| `UNKNOWN_*`, `MIXED_RAW` | The engine | Inferred for undecorated, unresolved, or conflicting code — not levels you write. |

!!! info "What you declare vs. what the engine infers"
    The **declared** tiers (`INTEGRAL`, `ASSURED`, `GUARDED`, `EXTERNAL_RAW`) are
    the ones you attach with decorators. The `UNKNOWN_*` family means "Wardline
    couldn't establish trust here" (undecorated code, or a call it couldn't
    resolve), and `MIXED_RAW` means "values from incompatible trust origins were
    combined." You never write these — they are the engine's honest record of
    what it could and couldn't prove.

You declare trust with three runtime no-op marker decorators. Prefer importing
them from the tiny `weft-markers` package as `weft_markers.*`; Wardline also
recognizes the older `wardline.decorators.*` namespace. Run `wardline vocab` to
emit the canonical list:

```console
$ wardline vocab
schema: wardline.vocabulary/v1
version: wardline-generic-2
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

- **`@external_boundary`** marks a source — a function whose return carries raw,
  untrusted data (`EXTERNAL_RAW`).
- **`@trust_boundary(to_level=...)`** marks a validator — it takes raw input and
  *raises* its trust on the way out (to `GUARDED` or `ASSURED`).
- **`@trusted(level=...)`** marks a trusted producer — it both works on and
  returns trusted data (`INTEGRAL` by default, or `ASSURED`).

## How taint propagates

The core rule is simple: **a function is only as trusted as the least-trusted
value it returns.** When function A calls function B, the trust of B's return
value flows into A — and this carries transitively across files, all the way up
the call graph.

That means you do not have to annotate every function. Decorate your boundaries
and your trusted producers, and the engine works out the trust of everything in
between by following the calls.

Consider this (the exact code Wardline was run against):

```python
from weft_markers import trusted, external_boundary

@external_boundary
def read_request(req):
    return req.body          # returns EXTERNAL_RAW (raw, untrusted)

@trusted(level="ASSURED")
def build_record(req):
    return read_request(req) # claims ASSURED, but returns EXTERNAL_RAW
```

`read_request` is declared a source, so its return is `EXTERNAL_RAW`.
`build_record` declares it produces `ASSURED` data, but the only thing it returns
is `read_request`'s raw output — with no validation in between. The taint flows
through the call, the declared trust and the actual trust disagree, and Wardline
reports it (rule [PY-WL-101](rules.md)):

```
demo.build_record declares return trust ASSURED but actually returns
EXTERNAL_RAW (less trusted) — untrusted data reaches a trusted producer
```

## What a trust boundary is, and why it matters

A **trust boundary** is the point where untrusted data is validated and *becomes*
trusted — the one place where raw input is checked before the rest of your code
is allowed to rely on it. In Wardline you mark it with
`@trust_boundary(to_level=...)`: the function's body sees raw data, and its
return is the higher trust level you declare.

Boundaries matter because they are where trust is *earned*. A function that
raises its declared trust but cannot actually reject anything — no `raise`, no
early failing return — is not validating; it is just relabelling untrusted data
as trusted. Wardline flags exactly that case with its boundary-integrity family
(rules [PY-WL-102 / 111 / 113 / 119](rules.md) — no rejection path, assert-only
rejection, fail-open handler, and the bare no-op `return p` shape, exactly one
of which fires per boundary), so a boundary that claims to validate is held to
actually being able to say "no."

Get your boundaries right and the trust propagation does the rest: everything
downstream of a real boundary is trusted, everything upstream is raw, and
Wardline tells you whenever a value crosses from one to the other without going
through the gate.

## Next steps

- [Rules](rules.md) — the rules built on this model.
- [Trust vocabulary reference](../reference/vocabulary.md) — the decorators and
  their exact arguments.
