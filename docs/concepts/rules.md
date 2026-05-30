# Rules

Wardline ships four policy rules. They consume the [taint & trust
model](model.md): each one looks for a place where a function's *declared* trust
and its *actual* trust disagree, or where a trusted-tier function handles errors
carelessly.

All four are off by default for undecorated code — they only fire where you have
opted in by declaring trust. To turn a rule off entirely, or to change its
severity, see [Configuration](../guides/configuration.md).

## The four rules

| Rule | What it flags | Default severity |
|---|---|---|
| `PY-WL-101` | A trust-anchored function returns data less trusted than the level it declares — untrusted data reaches a trusted producer with no validation. | `ERROR` |
| `PY-WL-102` | A trust boundary (a function that raises declared trust on its return) has no rejection path — no raise, no falsy-constant return — so it cannot validate. | `ERROR` |
| `PY-WL-103` | A broad exception handler (bare except / Exception / BaseException) in a trusted-tier function. | `WARN` |
| `PY-WL-104` | An exception handler that silently swallows the error (only pass/.../continue/break) in a trusted-tier function. | `WARN` |

!!! info "Declaration-gated vs. tier-modulated severity"
    `PY-WL-101` and `PY-WL-102` are **declaration-gated** — the decorator itself
    is the opt-in, so they always fire at their base severity. `PY-WL-103` and
    `PY-WL-104` are **tier-modulated**: their severity scales with the
    function's own trust tier. They report at the base severity in fully trusted
    functions (`INTEGRAL`/`ASSURED`), downgrade one step in partially-trusted
    functions, and are suppressed entirely on undecorated code. The `WARN` above
    is the trusted-tier value.

---

### PY-WL-101 — untrusted data reaches a trusted producer

Fires on a `@trusted` producer whose actual returned value is less trusted than
the level it declares. The function claims to produce trusted data, but the data
flowing out is raw — there is no validation between the untrusted source and the
trusted claim.

```python
@trusted(level="ASSURED")
def build_record(req):
    return read_request(req)   # read_request is @external_boundary -> EXTERNAL_RAW
```

`build_record` declares `ASSURED` but returns the raw output of an
`@external_boundary` function. Wardline reports:

```
demo.build_record declares return trust ASSURED but actually returns
EXTERNAL_RAW (less trusted) — untrusted data reaches a trusted producer
```

The fix is to validate before returning — for example by routing the raw value
through a `@trust_boundary` first.

### PY-WL-102 — trust boundary with no rejection path

Fires on a `@trust_boundary` validator that cannot actually reject anything. The
function declares it raises trust (its return is more trusted than its raw body),
but it contains no `raise` and no falsy-constant `return` — so it has no way to
say "no" to bad input. A validator that cannot reject is not validating.

```python
@trust_boundary(to_level="ASSURED")
def validate(p):
    return p          # no raise, no falsy return — cannot reject
```

Wardline reports:

```
demo.validate declares a trust boundary (EXTERNAL_RAW -> ASSURED) but has no
rejection path (no raise / no falsy return) — it cannot validate
```

The fix is to add a real rejection path:

```python
@trust_boundary(to_level="ASSURED")
def validate(p):
    if not p:
        raise ValueError
    return p
```

### PY-WL-103 — broad exception handler in a trusted-tier function

Fires on a `bare except`, `except Exception`, or `except BaseException` inside a
trusted-tier function. Catching everything hides the failures you did not plan
for, which is especially risky in code you have declared trusted.

```python
@trusted
def handle(p):
    try:
        risky(p)
    except Exception:   # broad — swallows every error class
        h()
```

Wardline reports `demo.handle: broad exception handler at line N`. Narrow the
handler to the specific exception you expect (`except ValueError:`).

### PY-WL-104 — silently swallowed exception in a trusted-tier function

Fires on a handler whose body only `pass`/`...`/`continue`/`break` — it discards
the error with no logging, re-raise, or recovery. The failure vanishes
silently.

```python
@trusted
def handle(p):
    try:
        risky(p)
    except ValueError:
        pass            # error silently swallowed
```

Wardline reports `demo.handle: exception silently swallowed at line N`. At
minimum, log the error or re-raise it.

!!! tip "One handler, two findings"
    A broad handler that is also silent (e.g. `except Exception: pass`) trips
    both `PY-WL-103` and `PY-WL-104` — they are independent checks on the same
    `try`/`except`.

## Configuring rules

Every rule can be disabled or have its base severity overridden per project. See
[Configuration](../guides/configuration.md) for the `rules.enable` and
`rules.severity` settings. For a propagation walkthrough of the PY-WL-101
pattern above, see the [trust model](model.md).
