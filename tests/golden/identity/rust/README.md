# Rust identity parity oracle (the SP2 completion gate)

A byte-exact golden corpus of the Rust frontend's externally-observable
**identity** — the freeze on which `RS-WL-*` findings graduated from
provisional (baseline-ineligible) to real, baseline-eligible, crate-prefixed
identity. Any byte drift here is either a real regression or a deliberate,
`--reason`-stamped rekey — exactly the parent oracle's discipline
(`tests/golden/identity/README.md`, ADR
`docs/decisions/2026-06-05-wardline-finding-identity-frozen-contract.md`).

## What it covers — a PARTIAL mirror, by necessity

`RustAnalyzer.last_context` is `None`: the Rust-native `RustAnalysisContext` is
**not** the Python `AnalysisContext`, so the parent oracle's SARIF code-flows,
taint facts, assure posture, and explain surfaces are *not capturable* for Rust.
The Rust identity surface, captured per fixture crate by `_capture.py`:

- **findings** — the real wire format (`Finding.to_jsonl()`) for the
  identity-bearing population (`RS-WL-* ∧ Kind.DEFECT`), produced by the REAL
  analyzer path (`run_scan(root, lang="rust")`: discovery → Cargo crate roots →
  module routes → per-file pipeline → suppression).
- **entities** — qualname, ADR-049 id-kind (via the `entity_id` mapping, so the
  semantic `method` freezes as `function`), parent, and full span of **every**
  emitted entity (the full ten-kind producer surface, `module → impl → method`
  containment included).
- **edges** — every anchored `imports`/`implements` edge
  (`discover_rust_edges` over the same whole-tree parse products).

Engine diagnostics (`WLN-ENGINE-*`, `WLN-RUST-COVERAGE`, `Kind.METRIC`/`FACT`)
are excluded — same rationale as the parent oracle.

## Inputs

- `fixtures/rustapp/` — vendored crate (`Cargo.toml` `name = "rust-app"` →
  crate `rust_app`; `src/main.rs` + `src/cmd/mod.rs` + `src/cmd/runner.rs`).
  Exercises: RS-WL-108 (tainted program reaching `Command::new`, inside an impl
  method), RS-WL-112 (tainted `sh -c` arg), `/// @trusted(level=ASSURED)`
  markers, an inherent impl + a trait impl (`implements` edge), cross-file
  `use crate::…` imports, a `#[cfg(unix)]`/`#[cfg(windows)]` twin, and the
  `const`/`enum`/`trait`/`struct` leaf kinds.

Fixtures carry **no** `.weft/` or `weft.toml` (a baseline/waiver would
date-poison the corpus via `date.today()`); `.gitattributes` pins them to LF so
tree-sitter byte offsets (frozen in edge spans) stay reproducible across OSes.

### Reserved-colon constraint (do not "fix" this)

The fixture contains **no path-typed generic args** (e.g.
`impl From<std::io::Error> for …`). That rendering is an **un-decided
cross-tool ADR-049 case**: today Wardline renders the `:`-bearing locator
un-gated while Loomweave rejects it at `entity_id` construction and degrades
the whole file — no canonical colon-free form exists yet (see
`docs/integration/2026-06-10-wardline-loomweave-rust-qualname-amendment-requests.md`).
Freezing such a qualname here would unilaterally pre-empt that decision.
`test_fixture_has_no_path_typed_generic_args` guards the constraint; lift it
only after the ADR-049 amendment lands (which will be a versioned rekey).

## Determinism (verified before freezing)

The capture was run twice in separate processes (fresh interpreter each) and
byte-compared before the corpus was committed — mirroring the parent oracle's
discipline. All sorts are content-derived (no engine-emission-order artifacts).

## Regenerating (intentional rekey ONLY)

```bash
cd tests && PYTHONPATH=. python -m golden.identity.rust.regen --reason "<why>"
```
