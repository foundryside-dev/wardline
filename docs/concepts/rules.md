# Rules

Wardline ships twenty-six Python policy rules, `PY-WL-101` through `PY-WL-126`.
They consume the [taint & trust model](model.md): each one looks for a place
where a function's *declared* trust and its *actual* trust disagree, where
untrusted data reaches a dangerous sink, or where a trusted-tier function
handles errors or declarations carelessly.

All of them are off by default for undecorated code — they only fire where you
have opted in by declaring trust. To turn a rule off entirely, or to change its
severity, see [Configuration](../guides/configuration.md).

## The rules

| Rule | What it flags | Base severity | Maturity |
|---|---|---|---|
| `PY-WL-101` | A trust-anchored function returns data less trusted than the level it declares — untrusted data reaches a trusted producer. | `ERROR` | stable |
| `PY-WL-102` | A trust boundary has no rejection path of any recognised shape — it cannot validate. (The bare `return p` shape is `PY-WL-119`'s.) | `ERROR` | stable |
| `PY-WL-103` | A broad exception handler (bare except / Exception / BaseException) in a trusted-tier function. | `WARN` | stable |
| `PY-WL-104` | An exception handler that silently swallows the error in a trusted-tier function. | `WARN` | stable |
| `PY-WL-105` | Untrusted data is passed as an argument to a trusted producer at a call site. | `ERROR` | stable |
| `PY-WL-106` | Untrusted data reaches a deserialization sink (pickle/marshal/yaml, `pickle.Unpickler`, `shelve.open`, and a curated third-party table) (CWE-502). | `WARN` | stable |
| `PY-WL-107` | Untrusted data reaches a dynamic-code-execution sink (`eval`/`exec`/`compile`, including the `builtins.`/`__builtins__.` spellings) (CWE-95). | `WARN` | stable |
| `PY-WL-108` | Untrusted data reaches a command/program-execution sink — the always-shell string APIs plus `os.exec*`/`os.spawn*`/`os.posix_spawn*`/`pty.spawn` (CWE-78). | `ERROR` | stable |
| `PY-WL-109` | A trusted producer has both a value-bearing return and a None-yielding return — None leaks from a function declaring trusted output. | `WARN` | stable |
| `PY-WL-110` | An entity carries two or more distinct trust markers — a contradictory declaration the engine resolves silently. | `WARN` | stable |
| `PY-WL-111` | A trust boundary's only rejection path is `assert`, which `python -O` strips (CWE-617). | `ERROR` | stable |
| `PY-WL-112` | Untrusted data reaches a `subprocess` call with a literal `shell=True` (CWE-78). | `ERROR` | stable |
| `PY-WL-113` | A trust boundary fails open — an exception handler swallows the failure and substitutes a value, so the boundary can be bypassed by triggering the exception (CWE-636). | `ERROR` | stable |
| `PY-WL-114` | A builtin trust decorator's level argument is statically readable but invalid or out-of-range — the engine would silently drop the declaration. | `ERROR` | stable |
| `PY-WL-115` | Untrusted data reaches a dynamic code/module-load sink (`importlib.import_module`, `__import__`, `runpy.run_path`/`run_module`, `importlib.util.spec_from_file_location`) (CWE-829/CWE-94). | `WARN` | stable |
| `PY-WL-116` | Untrusted data reaches a path/filesystem-traversal sink — open/join/`pathlib.Path`, filesystem mutation, `Path` methods, archive extraction (Zip Slip) (CWE-22). | `WARN` | preview |
| `PY-WL-117` | Untrusted data reaches the URL slot of an HTTP client sink (SSRF: requests/httpx/aiohttp/urllib, including constructed client/session methods) (CWE-918). | `WARN` | preview |
| `PY-WL-118` | Untrusted data reaches a SQL execution sink (`execute`/`executemany`/`executescript`) in the SQL-string position (CWE-89). | `ERROR` | preview |
| `PY-WL-119` | A degenerate (no-op) trust boundary — the body is a bare `return <param>` with no validation at all. | `ERROR` | preview |
| `PY-WL-120` | Stored/persisted taint (file reads, DB cursor fetches) reaches trusted state without validation. | `ERROR` | preview |
| `PY-WL-121` | Untrusted data reaches an XML parsing sink (XXE / billion-laughs) (CWE-611). | `ERROR` (stdlib parsers `WARN`) | preview |
| `PY-WL-122` | Untrusted data is compiled into a server-side template (jinja2/mako) — SSTI (CWE-1336). | `ERROR` | preview |
| `PY-WL-123` | Untrusted data is the attribute NAME in `setattr`/`getattr` — dynamic attribute injection / mass assignment (CWE-915). | `WARN` | preview |
| `PY-WL-124` | Untrusted data reaches a native-library load sink (`ctypes.CDLL` family) (CWE-114). | `ERROR` | preview |
| `PY-WL-125` | Untrusted data is the log MESSAGE format string of `logging` calls — log injection (CWE-117). | `INFO` | preview |
| `PY-WL-126` | Untrusted data reaches the recipient/message of `smtplib` `SMTP.sendmail` — mail/header injection (CWE-93). | `WARN` | preview |

!!! info "Declaration-gated vs. tier-modulated severity"
    `PY-WL-101`, `PY-WL-102`, `PY-WL-105`, `PY-WL-109`, `PY-WL-110`,
    `PY-WL-111`, `PY-WL-113`, `PY-WL-114`, and `PY-WL-119` are
    **declaration-gated** — the decorator itself is the opt-in, so they always
    fire at their base severity. `PY-WL-103`, `PY-WL-104`, and the sink rules
    (`PY-WL-106`/`107`/`108`/`112`/`115`/`116`/`117`/`118`/`120`/`121`–`126`)
    are **tier-modulated**: their severity scales with the function's own trust
    tier. They report at the base severity in fully trusted functions
    (`INTEGRAL`/`ASSURED`), downgrade one step in partially-trusted functions,
    and are suppressed entirely on undecorated code. The base severity above is
    the trusted-tier value.

!!! note "Preview maturity"
    Rules marked **preview** carry `maturity: preview` in the
    [vocabulary descriptor](../reference/vocabulary.md): their charter and
    sink sets are still being calibrated, and their predicates may sharpen
    between releases. They participate in the gate, baseline, waivers, and
    judge exactly like stable rules.

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

## The boundary-integrity family (102 / 111 / 113 / 119)

A `@trust_boundary` declares that it *raises* trust: its body sees raw data and
its return is the higher level it declares. Four rules police whether such a
boundary can actually do that job, and they **partition four ways — at most one
of them fires per boundary**:

- **`PY-WL-119`** — the bare **degenerate** shape: the body is (modulo
  docstrings/`pass`) a single `return <param>`. The more-specific rule wins, so
  102 suppresses itself on this shape. The suppression is structural — keyed on
  the shape, not on whether 119 is enabled.
- **`PY-WL-102`** — every *other* shape with **no rejection path** of any
  recognised kind: the boundary cannot reject at all.
- **`PY-WL-111`** — the only rejection is **`assert`**, which `python -O`
  strips: the validation silently vanishes in production (CWE-617). This
  includes an assert inside a `try` whose handler substitutes — the rejection
  is still assert-only, so 111 wins over 113.
- **`PY-WL-113`** — a **real rejection exists but a fail-open handler defeats
  it**: an `except` swallows the failure and substitutes a value-bearing
  result.

### What counts as a rejection path

A boundary is silent under 102/111 when it has any of these recognised
rejection shapes:

- an own-scope **`raise`** (or an `assert` — but assert-*only* is 111's case);
- a **rejection-shaped `return`** — a falsy constant (`None`/`False`/`0`/`""`,
  or an empty literal container), a **conditional expression with a rejecting
  branch** (`return m.group(0) if m else None` is the ternary form of
  `if not m: return None`), or a curated **raising conversion** — a
  validate-by-construction expression that raises on bad input: `int(p)`,
  `float(p)`, `complex(p)`, `Decimal(p)`, `Fraction(p)`, `UUID(p)`, or a
  subscript lookup with a non-constant key (`Color[p]` raises `KeyError`;
  `ALLOWED[p]` likewise). A *constant* argument or index (`int("3")`,
  `parts[0]`) validates nothing and does not count;
- a **one-hop, same-module call to a raising helper** — a factored-out
  validator whose own body has a real rejection (`_require_nonempty(p)`, a
  raising staticmethod, or wholesale delegation to another raising boundary).
  The helper's body is inspected exactly one hop deep, same module only, and it
  must have a *real* (production-surviving) rejection: a helper that cannot
  raise never counts, and an assert-only helper never counts (its assert
  vanishes under `python -O` exactly like an inline one).

### PY-WL-102 — trust boundary with no rejection path

Fires on a `@trust_boundary` validator that cannot actually reject anything —
no recognised rejection shape at all. A validator that cannot reject is not
validating.

```python
@trust_boundary(to_level="ASSURED")
def v(p):
    x = p
    return x          # no raise, no falsy return — cannot reject
```

(The single-statement `return p` form of this defect is reported as
`PY-WL-119` instead.) Wardline reports:

```
demo.v declares a trust boundary (EXTERNAL_RAW -> ASSURED) but has no
rejection path (no raise / no falsy return) — it cannot validate
```

The fix is to add a real rejection path:

```python
@trust_boundary(to_level="ASSURED")
def v(p):
    if not p:
        raise ValueError
    return p
```

### PY-WL-111 — trust boundary whose only rejection is `assert`

Fires on a `@trust_boundary` whose *only* rejection path is an `assert`. The
validation works in development but is stripped under `python -O`, so the
boundary silently stops rejecting in production (CWE-617).

```python
@trust_boundary(to_level="ASSURED")
def validate(p):
    assert p          # stripped under python -O — validation vanishes
    return p
```

A boundary with a real `raise` or rejection-shaped `return` — or a one-hop
same-module raising helper call (the helper's `raise` survives `-O`) — trips
neither 102 nor 111, even if it also has an `assert`:

```python
@trust_boundary(to_level="ASSURED")
def validate(p):
    assert isinstance(p, str)   # an internal invariant, not the gate
    if not p:
        raise ValueError        # the real, -O-safe rejection
    return p
```

### PY-WL-113 — trust boundary that fails open

Fires on a `@trust_boundary` where a real rejection *exists* but an `except`
handler swallows the failure and **substitutes** a value-bearing result instead
of re-raising — either by returning it directly or by assigning it to a name
the function returns by fall-through. Such a boundary can be bypassed by
*triggering* the exception. The most insidious shape is the self-catch, where
the handler catches the very exception the boundary's own rejection raises:

```python
@trust_boundary(to_level="ASSURED")
def v(p):
    try:
        if bad(p):
            raise ValueError          # the rejection ...
        return p
    except ValueError:
        return p                      # ... immediately caught and bypassed
```

The rule enforces its premise: a real, production-surviving rejection must
exist (no rejection at all is 102's domain; assert-only is 111's), and the
rejection must be lexically *swallowable* by the matching handler. A rejection
wholly outside the `try` cannot be defeated by the handler — the boundary fails
**closed** and the rule stays silent. A handler that re-raises, or that returns
a falsy/empty constant (signalling rejection, not substitution), never matches.

### PY-WL-119 — degenerate (no-op) trust boundary

Fires on the bare degenerate boundary: the body is a single `return <param>` —
no checks, no asserts, no validation of any kind. It is a strict structural
subset of "no rejection path", carved out of `PY-WL-102`'s domain so the family
partitions cleanly: 119 wins on this shape and the same boundary is never
counted twice at `ERROR` in the gate population.

```python
@trust_boundary(to_level="ASSURED")
def validate(x):
    return x          # PY-WL-119: a no-op validator
```

```python
@trust_boundary(to_level="ASSURED")
def validate(x):
    if not x:
        raise ValueError
    return x          # clean
```

---

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

Fires on a handler whose body is only `pass`/`...`/`continue`/`break` or a bare
constant expression (a docstring-like string literal or a number) — it discards
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

## The sink rules

The sink rules fire when raw-zone data reaches a named dangerous call inside a
trusted-tier function. They are tier-modulated: they speak only where trust is
declared and are silent in the developer-freedom zone. Sink matching is
import-alias aware, and most families also resolve the **construct-then-method
form** (`client = httpx.Client(); client.get(url)`, `with smtplib.SMTP(h) as
s`, the chained `Ctor().method(raw)`) and **function-local callable aliases**
(`runner = subprocess.run; runner(...)`). Where only specific argument slots
are dangerous, the rules match by **argument position/keyword** so taint in a
harmless slot (a `timeout=`, a `parser=`, a logging `%`-args parameter) does
not fire.

### PY-WL-106 — untrusted data reaches a deserialization sink (CWE-502)

Deserializing untrusted bytes is a classic remote-code-execution vector. The
sink set covers four families:

- **stdlib direct loaders** — `pickle.load`/`loads`, `marshal.load`/`loads`,
  `yaml.load`/`load_all`/`unsafe_load`/`full_load` (the `safe_*` loaders and
  the *dump* direction are deliberately not sinks; `json.loads` is excluded —
  it does not execute);
- **the OO streaming-unpickle API** — `pickle.Unpickler(stream).load()`,
  chained or stored-instance; the dangerous data is the stream handed to the
  *constructor*, so the taint is read there;
- **`shelve.open`** — pickle-backed: opening a shelf at an attacker-controlled
  *path* then reading keys unpickles attacker bytes (only the path slot is
  dangerous);
- **a curated third-party table** — `dill.load`/`loads`, `jsonpickle.decode`,
  `joblib.load`, `torch.load`, `numpy.load`. Two literal-keyword gates:
  `numpy.load` fires **only** with a literal `allow_pickle=True` (the default
  has been the safe `False` since numpy 1.16.3, so absent/`False`/dynamic
  stays silent); `torch.load` is suppressed by a literal `weights_only=True`
  (the restricted unpickler) and fires otherwise.

Every entry is RCE-equivalent, so all carry the family base severity (`WARN`,
tier-modulated).

```python
@trusted(level="ASSURED")
def f(req):
    return pickle.loads(read_request(req))   # fires

@trusted(level="ASSURED")
def g(path):
    return numpy.load("model.npy")           # clean: no allow_pickle=True
```

### PY-WL-107 — untrusted data reaches a dynamic-code-execution sink (CWE-95)

`eval` / `exec` / `compile` on untrusted input is arbitrary code execution.
Matches the bare builtins (`eval(x)`), the `builtins.eval` forms, and the
`__builtins__.eval` spelling.

```python
@trusted(level="ASSURED")
def run(req):
    eval(read_request(req))   # read_request is @external_boundary -> EXTERNAL_RAW
```

### PY-WL-108 — untrusted data reaches a command/program-execution sink (CWE-78)

Covers two sink shapes, both stdlib:

- **always-shell string APIs** — `os.system`, `os.popen`,
  `subprocess.getoutput`, `subprocess.getstatusoutput`: these take a shell
  *string*, so an untrusted argument is directly injectable;
- **argv-style program execution** — the `os.exec*` and `os.spawn*` families,
  `os.posix_spawn`/`os.posix_spawnp`, and `pty.spawn`: no shell mediates, but
  an attacker-controlled program path or argv element *is* arbitrary-program
  execution.

Base severity is `ERROR`, calibrated with `PY-WL-118` (SQLi): tainted
command/program execution is the same blast-radius exploit class.

The `subprocess.run`/`call`/`Popen`/`check_*` family is intentionally **not**
in this sink set — with the default `shell=False` an argv-list is safe, and the
one condition that makes it injectable (`shell=True`) is policed by
`PY-WL-112`.

**`shlex.quote` semantics (GUARDED, concatenation context only).**
`shlex.quote(x)` neutralizes shell-string taint for the always-shell sinks
*only as a fragment of a constant-shaped command*: a `+` chain or f-string with
at least one constant fragment in which every non-constant leaf is a
`shlex.quote(...)` call is treated as guarded —
`os.system("echo " + shlex.quote(raw))` is clean. A **bare whole-command quote
still fires** (`os.system(shlex.quote(raw))` — a fully-quoted single token
handed to a shell executes that token as the program name, so the attacker
still picks what runs), and the guard never applies to the argv
program-execution sinks (no shell parses the value, so quoting protects
nothing). The guard is inline-syntactic only: a quote result routed through a
variable still fires.

```python
@trusted(level="ASSURED")
def f(p):
    os.execv(read_raw(p), ["prog"])                    # fires (program execution)

@trusted(level="ASSURED")
def g(p):
    os.system("echo " + shlex.quote(read_raw(p)))      # clean (guarded fragment)
```

### PY-WL-112 — untrusted data reaches a `shell=True` subprocess call (CWE-78)

The completion of `PY-WL-108`'s deliberate exclusion: the
`subprocess.run`/`call`/`check_call`/`check_output`/`Popen` family fires only
when **both** a literal `shell=True` keyword is statically visible **and**
untrusted data reaches the call. A `**kwargs` spread, a non-constant
`shell=flag`, or `shell=1` is not matched (a bounded false negative, chosen
over flooding argv-list false positives); a fully-literal
`subprocess.run('ls -la', shell=True)` does not fire either — the rule keys on
untrusted *data*, not on `shell=True` alone. Base severity `ERROR`, calibrated
with 108/118.

```python
@trusted(level="ASSURED")
def f(p):
    subprocess.run(read_raw(p), shell=True)   # fires

@trusted(level="ASSURED")
def g(p):
    subprocess.run(["ls", "-la"])             # clean: argv list, no shell
```

### PY-WL-115 — untrusted data reaches a dynamic code/module-load sink (CWE-829/CWE-94)

The import-and-execute class: `importlib.import_module` and `__import__`
(attacker-chosen module name), `runpy.run_path` / `runpy.run_module`
(import-and-*execute* an attacker-controlled file path / module — blast radius
equivalent to `exec`), and `importlib.util.spec_from_file_location` (a tainted
file-path argument builds a loader for attacker-chosen code).

```python
@trusted(level="ASSURED")
def f(p):
    runpy.run_path(read_raw(p))               # fires

@trusted(level="ASSURED")
def g(p):
    importlib.import_module("sys")            # clean
```

### PY-WL-116 — untrusted data reaches a path/filesystem-traversal sink (CWE-22)

Three sink families:

- **direct dotted calls** with a tainted path argument — `open`, `os.open`,
  `os.path.join`, `pathlib.Path`, plus the filesystem-**mutation** APIs
  (`os.remove`/`unlink`/`rmdir`/`mkdir`/`makedirs`/`rename`/`renames`/`replace`,
  `shutil.rmtree`/`copy`/`copy2`/`copyfile`/`copytree`/`move`), where a tainted
  path is a destructive traversal;
- **`Path` methods** (`read_text`/`read_bytes`/`write_text`/`write_bytes`/
  `open`/`unlink`/`rmdir`/`mkdir`) on a `pathlib.Path` **constructed from
  tainted input** — the dangerous data is the constructor's argument
  (`q = Path(raw); q.read_text()`);
- **archive extraction** (Zip Slip / tarbomb): `extractall`/`extract` on a
  `tarfile.open`/`tarfile.TarFile`/`zipfile.ZipFile` instance whose *archive
  source* is tainted — a malicious archive escapes the target directory via
  `../` member names. **Exemption:** an extraction call passing tarfile's safe
  filter as the literal `filter="data"` (blocks absolute paths, traversal, and
  device members since Python 3.12) does not fire; any other filter value
  (including `"fully_trusted"` or a dynamic expression) still fires.

```python
@trusted(level="ASSURED")
def f(p):
    tf = tarfile.open(read_raw(p))
    tf.extractall("/dst")                     # fires (Zip Slip)

@trusted(level="ASSURED")
def g(p):
    tf = tarfile.open(read_raw(p))
    tf.extractall("/dst", filter="data")      # clean: safe extraction filter
```

### PY-WL-117 — untrusted data reaches an HTTP client sink (SSRF, CWE-918)

Covers `requests`, `httpx`, `aiohttp`, and `urllib` — both the module-level
calls and **constructed client/session instance methods**
(`client = httpx.Client(); client.get(url)`, `async with httpx.AsyncClient()
as c`, `requests.Session().get(url)`, `aiohttp.ClientSession`), plus a client
constructor's `base_url=`. Matching is **URL-slot precise**: only the
request-target argument is an SSRF vector, so a tainted
`timeout=`/`verify=`/`headers=` with a clean literal URL does not fire.

```python
@trusted(level="ASSURED")
def f(p):
    client = httpx.Client()
    client.get(read_raw(p))                            # fires

@trusted(level="ASSURED")
def g(p):
    requests.get("https://example.com", timeout=read_raw(p))   # clean: not the URL slot
```

### PY-WL-118 — untrusted data reaches a SQL execution sink (CWE-89)

Fires when untrusted data reaches the **SQL-string position** of
`cursor.execute`, `cursor.executemany`, or `executescript` (sqlite3 cursor
*and* connection — `executescript` runs a multi-statement script with **no
parameter binding at all**, so it is strictly more dangerous than `execute`).

Three precision guards:

- **operation-slot only** — SQLi is a property of the SQL *string*; untrusted
  data passed as a *bound parameter* (the OWASP-canonical mitigation) cannot
  alter query structure and does not fire. Splatted/`**`-unpacked arguments
  that could supply the operation fail closed (fire);
- **receiver heuristic (fail-closed)** — `.execute` is matched by method name,
  so binding evidence (a constructor from a known DB-driver module fires; one
  from a known executor module suppresses) and exact name-token evidence
  (`cursor`/`conn`/`db`/... fires and wins over mixed names; `pool`/`executor`/
  `worker`/... alone suppresses) keep task pools from firing a CWE-89 `ERROR`.
  Unknown receivers **fire** — when unsure, a missed finding is worse than a
  false positive;
- **constant `text()` exemption** — the canonical SQLAlchemy parameterized
  pattern `conn.execute(text("... :id"), {"id": uid})` wraps a compile-time
  constant in a recognized text-clause constructor and is treated as clean;
  `text(tainted)` / `text(f"...")` still fire (`text()` is not a sanitiser).

```python
@trusted(level="ASSURED")
def f(p, cursor):
    cursor.executescript(read_raw(p))                  # fires

@trusted(level="ASSURED")
def g(p, cursor):
    cursor.execute("SELECT * FROM t WHERE id = ?", (read_raw(p),))   # clean: bound parameter
```

### PY-WL-120 — stored/persisted taint reaches trusted state

Fires when raw data loaded from persistent storage — file reads via
`open`/`read_text` or database cursor fetches (`fetchone`/`fetchall`/
`fetchmany`) — reaches a trusted state (returned by a `@trusted` function or
passed to a `@trusted` callee) without being validated. The storage-read
matcher is **receiver-aware**: an `io.StringIO`/`io.BytesIO` receiver is an
in-memory buffer, never persistent storage, so its `.read()` is exempt. On the
return arm the rule de-conflicts with `PY-WL-101`: where 101 already reports
the trust-claim violation with unresolved provenance, 120 suppresses; where the
storage provenance is substantiated, the pair stands deliberately (101 reports
the trust claim, 120 adds the storage-provenance annotation).

```python
@trusted(level="ASSURED")
def get_config():
    data = open("config.txt").read()
    return data                                # fires
```

## The preview sink expansions (121–126)

Six PREVIEW rules added in the 2026-06-10 coverage-gap pass. All are
tier-modulated, argument-slot precise, and resolve the construct-then-method
form and callable aliases.

### PY-WL-121 — untrusted data reaches an XML parsing sink (CWE-611)

A tainted document/stream reaching an XML parser. Only the DOCUMENT slot
(position 0 / its keyword spelling) is dangerous — taint in a `parser=` or
handler slot is not XXE. Severity is **per-sink**, calibrated to each parser's
*default* posture: `lxml.etree.*` is `ERROR` (resolves external entities by
default, so tainted XML is genuine XXE — local file disclosure / SSRF); the
stdlib `xml.etree.ElementTree` / `xml.dom.minidom` / `xml.sax` parsers are
`WARN` (external general entities have been disabled by default since CPython
3.7.1; the residual default-on risk is the billion-laughs internal-entity
expansion DoS). `defusedxml` is the blessed remediation and is deliberately
not a sink. An operator `rules.severity` override re-bases the whole rule.

```python
from lxml import etree

@trusted(level="ASSURED")
def f(p):
    return etree.fromstring(read_raw(p))       # fires at ERROR

@trusted(level="ASSURED")
def g():
    ET.fromstring("<r/>")                      # clean: constant document
```

### PY-WL-122 — untrusted data compiled into a server-side template (SSTI, CWE-1336)

A tainted string reaching a template **compilation** sink — `jinja2.Template`,
`jinja2.Environment.from_string` (including the construct-then-method form),
`mako.template.Template`. Only the template SOURCE slot is dangerous: tainted
data passed as a *render variable* is the safe idiom and does not fire, and
loading a template *by name* (`env.get_template(raw)`) is not SSTI. Severity
`ERROR`: SSTI in Jinja2/Mako is RCE-adjacent.

```python
@trusted(level="ASSURED")
def f(p):
    return jinja2.Template(read_raw(p)).render()                    # fires

@trusted(level="ASSURED")
def g(p):
    jinja2.Template("Hello {{ name }}").render(name=read_raw(p))    # clean: render variable
```

### PY-WL-123 — tainted attribute NAME reaches `setattr`/`getattr` (CWE-915)

Dynamic attribute injection — an untrusted NAME argument (position 1) to the
builtin `setattr`/`getattr` lets an attacker pick which attribute is
written/read (mass assignment). Only the NAME slot is dangerous: an untrusted
VALUE assigned to a fixed attribute, a tainted `getattr` default, or a tainted
receiver are ordinary data flow and stay silent. Severity `WARN` — a
mass-assignment *vector*, not direct code execution.

```python
@trusted(level="ASSURED")
def f(p, obj):
    setattr(obj, read_raw(p), 1)               # fires: attacker picks the attribute

@trusted(level="ASSURED")
def g(p, obj):
    setattr(obj, "name", read_raw(p))          # clean: fixed attribute name
```

### PY-WL-124 — untrusted path reaches a native-library load sink (CWE-114)

A tainted library path/name reaching `ctypes.CDLL` / `WinDLL` / `OleDLL` /
`PyDLL` or `ctypes.cdll.LoadLibrary`. Loading an attacker-controlled shared
object is arbitrary **native** code execution — the same blast radius as the
command-execution family, so the same `ERROR` base.

```python
@trusted(level="ASSURED")
def f(p):
    return ctypes.CDLL(read_raw(p))            # fires

@trusted(level="ASSURED")
def g():
    ctypes.CDLL("libm.so.6")                   # clean
```

### PY-WL-125 — untrusted data as the log MESSAGE format string (CWE-117)

Log injection / log forging — a tainted value used as the message FORMAT string
of `logging.debug/info/warning/error/critical/exception` (module-level
functions or the Logger-method form, `logger = logging.getLogger(...);
logger.info(raw)`). Newline-spoofed entries forge audit lines and seed
log-viewer XSS downstream. Only the message slot is dangerous: tainted data in
the lazy `%`-args parameters (`logging.info('user=%s', raw)`) is logging's own
parameterization — the canonical safe idiom — and never fires. Severity
`INFO`: the class is real but high-noise by nature, and its blast radius is
forgery/foothold, not execution — visible to agents and to an explicit
`--fail-on INFO` gate without ever tripping the default gate.

```python
@trusted(level="ASSURED")
def f(p):
    logging.info(read_raw(p))                  # fires: tainted format string

@trusted(level="ASSURED")
def g(p):
    logging.info("user input = %s", read_raw(p))   # clean: lazy %-parameterization
```

### PY-WL-126 — untrusted recipient/message reaches `SMTP.sendmail` (CWE-93)

Mail (CRLF/header) injection — tainted data in the `to_addrs` (position 1) or
`msg` (position 2) argument of `smtplib.SMTP.sendmail` /
`smtplib.SMTP_SSL.sendmail`, with the receiver matched through the
construct-then-method machinery. Newlines in a recipient or message inject
spoofed headers / BCC recipients. The envelope sender (`from_addr`) is
deliberately not a dangerous slot in v1, and `send_message` is out of scope
(its header serialization already rejects bare newlines). Severity `WARN` —
real injection, but bounded blast radius (spam/spoofing, not code execution).

```python
@trusted(level="ASSURED")
def f(p):
    s = smtplib.SMTP("localhost")
    s.sendmail("from@example.com", "to@example.com", read_raw(p))   # fires

@trusted(level="ASSURED")
def g():
    s = smtplib.SMTP("localhost")
    s.sendmail("from@example.com", "to@example.com", "body")        # clean
```

---

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

### PY-WL-114 — invalid level on a builtin trust decorator

Fires on any entity carrying a builtin trust decorator (`@trusted` or
`@trust_boundary`) whose level argument is statically readable but not a valid
trust level, or not within the decorator's allowed set. This is a critical
safety defect: a typo (e.g. `level='ASURED'`) causes the engine to silently
drop the decorator, disabling all taint gates on that function. Recognition
resolves the decorator to the builtin FQN (import-alias aware), so an aliased
builtin with a typo still fires while a foreign decorator that merely happens
to be spelled `trusted` does not. A dynamic level (`level=cfg.LEVEL`) is not
statically readable and stays silent.

## Engine diagnostics and the gate

Alongside the policy rules, the engine emits `WLN-ENGINE-*` / `WLN-CONFIG-*`
diagnostics about the scan itself. Two of them are **gate-eligible `ERROR`
defects** (fail-closed — their absence of analysis must not read as green):

- **`WLN-ENGINE-PARSE-ERROR`** — a discovered file could not be read or parsed.
  Its sinks were never analyzed, so a default `--fail-on ERROR` reading green
  over it would be a fail-open. Baseline/waiver still *annotate* it but cannot
  clear the secure gate; `--trust-suppressions` can (an explicit operator trust
  decision).
- **`WLN-ENGINE-FILE-FAILED`** — an unexpected exception while analyzing one
  file. The scan continues (per-file isolation — other files' findings are
  kept) and the failed file is named, counted toward the scan's unanalyzed
  population.

A configuration that silently weakens analysis is also surfaced:
`WLN-CONFIG-SANITISER-SINK-COLLISION` (a fact, not a defect) reports a
configured sanitiser that collides with a built-in serialisation sink of the
same name — the conservative sink classification takes precedence, so the
sanitiser declaration has no effect, and the diagnostic says so instead of
letting the suppression attempt pass silently.

## Configuring rules

Every rule can be disabled or have its base severity overridden per project. See
[Configuration](../guides/configuration.md) for the `rules.enable` and
`rules.severity` settings. For a propagation walkthrough of the PY-WL-101
pattern above, see the [trust model](model.md).
