# Rules

Wardline ships eleven policy rules. They consume the [taint & trust
model](model.md): each one looks for a place where a function's *declared* trust
and its *actual* trust disagree, where untrusted data reaches a dangerous sink,
or where a trusted-tier function handles errors or declarations carelessly.

All of them are off by default for undecorated code — they only fire where you
have opted in by declaring trust. To turn a rule off entirely, or to change its
severity, see [Configuration](../guides/configuration.md).

## The rules

| Rule | What it flags | Default severity |
|---|---|---|
| `PY-WL-101` | A trust-anchored function returns data less trusted than the level it declares — untrusted data reaches a trusted producer with no validation. | `ERROR` |
| `PY-WL-102` | A trust boundary (a function that raises declared trust on its return) has no rejection path — no raise, no falsy-constant return — so it cannot validate. | `ERROR` |
| `PY-WL-103` | A broad exception handler (bare except / Exception / BaseException) in a trusted-tier function. | `WARN` |
| `PY-WL-104` | An exception handler that silently swallows the error (only pass/.../continue/break) in a trusted-tier function. | `WARN` |
| `PY-WL-105` | Untrusted data is passed as an argument to a trusted producer at a call site. | `ERROR` |
| `PY-WL-106` | Untrusted data reaches a deserialization sink (pickle/marshal/yaml.load) in a trusted-tier function. | `WARN` |
| `PY-WL-107` | Untrusted data reaches a dynamic-code-execution sink (eval/exec/compile) in a trusted-tier function. | `WARN` |
| `PY-WL-108` | Untrusted data reaches an always-shell OS-command sink (os.system/os.popen/subprocess.getoutput). | `WARN` |
| `PY-WL-109` | A trusted producer has both a value-bearing return and a None-yielding return — None leaks from a function declaring trusted output. | `WARN` |
| `PY-WL-110` | An entity carries two or more distinct trust markers (e.g. `@trusted` + `@external_boundary`) — a contradictory declaration the engine resolves silently. | `WARN` |
| `PY-WL-111` | A trust boundary's only rejection path is `assert`, which `python -O` strips — the validation silently vanishes in production (CWE-617). | `ERROR` |

!!! info "Declaration-gated vs. tier-modulated severity"
    `PY-WL-101`, `PY-WL-102`, `PY-WL-105`, `PY-WL-109`, `PY-WL-110`, and
    `PY-WL-111` are **declaration-gated** — the decorator itself is the opt-in,
    so they always fire at their base severity. `PY-WL-103`, `PY-WL-104`, and the
    sink rules `PY-WL-106`/`107`/`108` are **tier-modulated**: their severity
    scales with the function's own trust tier. They report at the base severity
    in fully trusted functions (`INTEGRAL`/`ASSURED`), downgrade one step in
    partially-trusted functions, and are suppressed entirely on undecorated code.
    The `WARN` above is the trusted-tier value.

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

### PY-WL-105 — untrusted data passed to a trusted producer at a call site

The call-site counterpart to `PY-WL-101`. Fires when raw data is passed as an
argument to a `@trusted`-style callee whose body operates on trusted data. Where
101 polices a function's *own* return, 105 polices the *arguments* a trusted
callee is handed. Declaration-gated on the callee.

### PY-WL-106 / 107 / 108 — untrusted data reaches a dangerous sink

The three sink rules fire when raw-zone data reaches a named dangerous call
inside a trusted-tier function:

- **`PY-WL-106`** — a deserialization sink (`pickle.loads`, `marshal.loads`,
  `yaml.load`): arbitrary-object construction from untrusted bytes.
- **`PY-WL-107`** — a dynamic-code-execution sink (`eval`, `exec`, `compile`):
  arbitrary code execution (CWE-95).
- **`PY-WL-108`** — an always-shell OS-command sink (`os.system`, `os.popen`,
  `subprocess.getoutput`): shell command injection.

```python
@trusted(level="ASSURED")
def run(req):
    eval(read_request(req))   # read_request is @external_boundary -> EXTERNAL_RAW
```

These are tier-modulated: they speak only where trust is declared and are silent
in the developer-freedom zone. They match curated, importable sink symbols
(framework-specific sinks whose receiver is a runtime object — `cursor.execute`,
`Template().render` — belong in opt-in trust-grammar packs, not the builtin set).

### PY-WL-109 — None leaks from a trusted producer

Fires when a `@trusted` producer has both a value-bearing return and a
None-yielding return (a bare `return` or `return None`). The function declares it
produces trusted output, but one path returns `None` — an untrusted absence that
escapes the trust claim.

### PY-WL-110 — contradictory trust declaration

Fires when an entity carries two or more distinct trust markers (e.g. `@trusted`
together with `@external_boundary`). The combination is contradictory; the engine
resolves it fail-closed but the conflicting intent is declaration hygiene worth
surfacing. Declaration-gated.

### PY-WL-111 — trust boundary whose only rejection is `assert`

A `PY-WL-102`-adjacent refinement. Fires on a `@trust_boundary` whose *only*
rejection path is an `assert`. The validation works in development but is
stripped under `python -O`, so the boundary silently stops rejecting in
production (CWE-617).

```python
@trust_boundary(to_level="ASSURED")
def validate(p):
    assert p          # stripped under python -O — validation vanishes
    return p
```

The two rules partition the space: `PY-WL-102` fires when a boundary cannot
reject *at all*; `PY-WL-111` fires when it *appears* to reject but only via a
guard that disappears in production. A boundary with a real `raise` or a
falsy-constant `return` trips neither — even if it also has an `assert`.

```python
@trust_boundary(to_level="ASSURED")
def validate(p):
    assert isinstance(p, str)   # an internal invariant, not the gate
    if not p:
        raise ValueError        # the real, -O-safe rejection
    return p
```

## Configuring rules

Every rule can be disabled or have its base severity overridden per project. See
[Configuration](../guides/configuration.md) for the `rules.enable` and
`rules.severity` settings. For a propagation walkthrough of the PY-WL-101
pattern above, see the [trust model](model.md).
