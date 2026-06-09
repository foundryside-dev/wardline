# Rust support (preview)

Wardline ships a **preview** language frontend for Rust. Point it at a tree of
`.rs` files and it flags command-injection trust-boundary defects — untrusted
data reaching the program or shell command line of `std::process::Command`.

!!! warning "Preview — provisional identity, narrow scope"
    The Rust frontend is an early slice. Its findings (`RS-WL-108` / `RS-WL-112`)
    carry **provisional identity**: their `qualname`/fingerprint is not yet stable
    across releases. They are **baseline-ineligible** — and this is *enforced*, not
    just advised: the engine never matches them against a committed
    baseline/waiver/judged entry and never writes them into a generated baseline, so
    they always stay `active` and always gate (a stale committed suppression can
    never silently clear one). `weft.toml` severity overrides do **not** apply to
    Rust rules yet. Treat a Rust scan as a signal, not a contract.

## Running it

The Rust frontend is gated behind the `rust` extra (tree-sitter is not a base
dependency):

```console
$ pip install 'wardline[rust]'
```

Then select it with `--lang rust`:

```console
$ wardline scan . --lang rust --fail-on ERROR
```

`--lang rust` sweeps `*.rs` (skipping `target/`) instead of `*.py`. Everything
else about the scan is unchanged: `--fail-on`, `--format {jsonl,sarif,agent-summary,legis}`,
`--output`, `--new-since`, Filigree/Loomweave emission, and the exit-code gate all
work exactly as they do for Python. The default (`--lang python`) is untouched.

## What it finds

| Rule | Severity | What it catches |
| --- | --- | --- |
| `RS-WL-108` | ERROR | **Program injection** — untrusted data chooses the executable: `Command::new(tainted)`. An attacker controls *which* binary runs. |
| `RS-WL-112` | WARN | **Shell injection** — untrusted data reaches a `sh -c` style shell command line: `Command::new("sh").arg("-c").arg(tainted)`. An attacker can inject shell syntax. |

De-confliction: when the program itself is tainted (108's territory), 112 stays
silent, so one boundary yields one finding.

## The trust marker

Like the Python frontend, Rust analysis is **default-clean**: taint flows only
from known boundary sources, and a function that declares no trust has its
findings modulated to nothing. Declare a function's trust tier with a doc-comment
marker on the line(s) above it:

```rust
/// @trusted(level=ASSURED)
fn run_user_command() {
    let prog = std::env::var("PROG").unwrap();
    std::process::Command::new(prog).output(); // RS-WL-108 (ERROR)
}
```

- `ASSURED` — full trust; findings fire at full severity.
- `GUARDED` — partial trust; findings are downgraded one step (ERROR → WARN).
- *(no marker)* — the function is treated as outside the trust surface and its
  findings are suppressed.

## Boundary sources

These standard-library calls introduce untrusted (`EXTERNAL_RAW`) data:

`std::env::var`, `std::env::var_os`, `std::env::args`, `std::env::vars`,
`std::fs::read_to_string`, `std::fs::read`.

A local bound directly to one of these — `let t = std::env::var("X").unwrap();` —
is tracked as tainted through stepwise (`let mut c = Command::new(t); c.output();`)
and fluent (`Command::new(t).output()?`) command construction, including the
idiomatic `?`, `.await`, `.unwrap()`, return-position, and tail-expression
terminators.

## Known limitations (this slice)

The frontend reports **provable** taint, not fail-closed unknowns. The following
are **known false-negative families** — deliberately out of scope for the preview
slice, documented so you do not mistake silence for safety:

- **Iterator extraction of `args`/`vars`.** `env::args()`/`env::vars()` are in the
  vocabulary, but multi-hop adapter chains (`.nth(1).unwrap()`, `.collect()`) are
  not yet propagated. A program built from `env::args().nth(1)` may not flag.
- **`.args(vec)` is opaque.** Only per-argument `.arg(x)` calls are inspected; a
  tainted element inside a `.args([...])` vector is not seen.
- **Captured `format!` interpolation.** Only direct interpolation arguments are
  read. The captured form `format!("{t}")` carries no argument token and is not
  tracked.
- **Cross-function and stored taint.** Analysis is per-function and flat-local: a
  tainted value passed *into* another function, or stashed in a field/global, is
  not followed.
- **Out-parameter sources.** `io::stdin().read_line(&mut buf)` writes through an
  out-parameter the flat-local model does not track.
- **Closures and nested `fn`s.** A finding inside a closure or nested function
  attributes to the enclosing named function by line; the inner scope is not
  walked separately.
- **Module routing is path-based, not Cargo-aware.** Qualnames are rooted at the
  scan directory name with no `Cargo.toml`/`#[path]` resolution — another reason
  the identity is provisional.

A `.rs` file that tree-sitter cannot fully parse is **not** half-analyzed: it is
surfaced as a `WLN-ENGINE-PARSE-ERROR` fact, counts toward the "could not be
analyzed" total, and gates under `--fail-on-unanalyzed` — never reported as a
clean result. Likewise, a single file whose analysis fails (for example a
pathologically deep expression that overflows the dataflow walk) is isolated to a
`WLN-ENGINE-FILE-FAILED` fact and counted as under-scanned; it never aborts the
run or loses the other files' findings.
