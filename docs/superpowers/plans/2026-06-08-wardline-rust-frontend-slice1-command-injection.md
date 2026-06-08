# Rust Frontend — Slice 1: Command-Injection (Implementation Plan)

**Status:** Draft for review · **Date:** 2026-06-08 · **Branch:** `feat/rust-plugin`
**Design spec:** `docs/superpowers/specs/2026-06-08-wardline-rust-frontend-design.md` (read first).

This plan cuts a **thin vertical path** through the six sub-projects (SP1→SP6) of the spec to land
**one working Rust finding family** — command-injection via `std::process::Command` — end to end:
discover → parse → index/qualname → seed source → builder-dataflow L2 → sink locator → verdict →
`Finding` → corpus + e2e. It is the **de-risking instrument**, not a sub-project.

### What this slice proves / does not prove

- **Proves:** the plumbing (a second frontend producing real `Finding`s the existing
  SARIF/JSONL/baseline/gate path consumes) **and** real source→propagate→sink taint on Tier-A
  syntax.
- **Does NOT prove:** semantic adequacy for Tier-B (trait dispatch) or Tier-C (macros/derives). A
  green slice is **not** evidence that "the rest is just more vocabulary." (Spec §2, §9.1.)

---

## Process constraints (all work packages)

- **TDD, strictly.** Failing test first, then the implementation that makes it pass. (Skill:
  `superpowers:test-driven-development`.)
- **Subagents NEVER run git** — no `status/add/commit/checkout/stash/restore/reset/worktree`. The
  orchestrator owns all git.
- **All work in the worktree** `/home/john/wardline/.worktrees/rust-plugin` on `feat/rust-plugin`.
- **Base stays zero-dep.** All new runtime deps live behind the **`wardline[rust]` extra** only
  (`tree-sitter`, `tree-sitter-rust`). `import tree_sitter` is lazy/guarded (mirror the `clarion`
  extra's `require_blake3` pattern); a bare `pip install wardline` must not import them.
- **Gates:** full `pytest -q` green; `ruff` + `mypy` clean; the **Python corpus + identity oracle stay
  byte-green** (this slice adds a frontend, it must not perturb Python output); `wardline scan src
  --fail-on ERROR` exit 0.
- **Rust namespace:** rules are `RS-WL-*`; the Rust corpus is a sibling tree
  `tests/corpus/rust/`; the live marker is `rust_e2e`.

---

## Non-goals (explicit, deferred to the named SP)

- Full frontend-seam extraction making Python "frontend #1" (SP1) — slice 1 builds a focused
  `RustAnalyzer` alongside the engine middle and accepts duplication that SP1/SP5 later refactor.
- Multi-file / cross-function / full module-tree route resolution (SP2) — slice 1 is **single-file,
  intra-function**; module route is a `crate`-rooted approximation from the file path (spec §6.3).
- The L3 interprocedural fixpoint — for a call-free single function it is the identity; slice 1
  computes `project_taints` directly from L1 seeds and does **not** invoke
  `propagate_callgraph_taints` (spec §9, §11 SP4-lite note).
- Loomweave Rust entity-ID reconciliation (SP2) — slice 1 pins a **provisional** dotted dialect via
  its own conformance corpus (spec §6.4); cross-tool parity is out of scope.
- `.env()` injection, `.args()` per-element precision, variable-bound shell names, Tier-B/C sinks
  (spec §9.4) — documented FNs.
- In-source `@trust_boundary` markers beyond the single `@trusted` doc-comment the specimen needs to
  enter declared-trust (full marker grammar is SP3).

---

## Architecture of the slice

A focused, self-contained module tree under `src/wardline/rust/` (new), importing the **shared,
neutral** engine pieces and **not** the Python-AST scanner:

```
src/wardline/rust/
  __init__.py
  _tree_sitter.py     # lazy loader: require_rust() -> (Language, Parser); guarded import
  nodeid.py           # NodeId newtype + pre-order minting over a tree-sitter tree
  parse.py            # source bytes -> tree; cursor helpers (scoped_identifier, field_expression…)
  index.py            # function_item -> RustEntity (qualname dialect §6.2) + NodeId stamping
  qualname.py         # the Rust dotted dialect (closures/generics/trait-impl/:trait=)
  vocabulary.py       # rust_taint.yaml loader (sources + sinks) + RUST_TAINT_VERSION
  rust_taint.yaml     # bundled vocabulary (wheel-shipped via hatch force-include)
  provider.py         # RustTrustProvider: doc-comment @trusted marker -> FunctionTaint
  dataflow.py         # builder-dataflow L2: CommandState tracking -> per-trigger arg-taint maps
  rules.py            # RS-WL-108 + RS-WL-112 (reuse modulate/RAW_ZONE/worst-of/Finding)
  analyzer.py         # RustAnalyzer.analyze(files, config) -> list[Finding]
```

Shared imports (reuse verbatim, spec §3.1): `core.taints` (`TaintState`, `TRUST_RANK`, `RAW_ZONE`,
`least_trusted`), `core.finding` (`Finding`, `Location`, `Severity`, `Kind`,
`compute_finding_fingerprint`), `scanner.rules.severity_model.modulate`,
`scanner.taint.function_level.FunctionSeed` (and the `FunctionTaint`/`SeedResult` shapes).

---

## Work packages (each TDD)

### WP0 — Dependency + scaffold + NodeId

**Test first:** `tests/unit/rust/test_tree_sitter_loader.py` — `require_rust()` returns a usable
`(Language, Parser)` and round-trips a trivial `fn main(){}` to a tree whose root kind is
`source_file`; `pytest.importorskip("tree_sitter")`-style skip when the extra is absent.

**Implement:**
- `pyproject.toml`: add `rust = ["tree-sitter>=0.25,<0.26", "tree-sitter-rust==0.24.2"]` to
  `[project.optional-dependencies]`. **Pin rationale (R6):** tree-sitter-rust 0.24.2 is compiled at
  ABI 15, loadable only by tree-sitter core ≥0.25.0 — do **not** trust the grammar's stale
  self-declared `tree-sitter~=0.22`. Prebuilt cp312 wheels exist across linux/macos/win, so **no
  compiler at install** on the supported matrix.
- `rust/_tree_sitter.py`: `require_rust()` lazy import + `RustToolingError` (clean message → install
  `wardline[rust]`) mirroring `clarion.require_blake3`.
- `rust/nodeid.py`: `NodeId = NewType("NodeId", int)` and `mint_node_ids(tree) -> dict[<ts node id>,
  NodeId]` assigning a **deterministic per-file pre-order index** (spec §5). Also add the typed
  `NodeId` alias to the Python side behind the existing `id()` (zero behavior change) so the contract
  is shared.

**Verify:** loader test green under `wardline[rust]`; skips clean without it.

### WP1 — Discovery generalization (suffix-parameterized)

**Test first:** `tests/unit/core/test_discovery.py::test_discover_rust_suffix` — `discover(root,
config, suffixes=frozenset({'.rs'}))` finds `a.rs` and **not** `a.py`; the default call (no
`suffixes`) is unchanged and still finds `.py`; `target/` is skipped.

**Implement:** `core/discovery.py` — add `suffixes: frozenset[str] = frozenset({'.py'})` kwarg;
replace the hardcoded `base.rglob('*.py')` (line 32) with a per-suffix sweep; add `target` to
`_ALWAYS_SKIP`. Preserve the `confine_to_root` symlink guard, missing-source-root surfacing, and
`fnmatch` excludes. **Python default behavior byte-unchanged** (assert via existing discovery tests).

### WP2 — Rust parse + minimal index + qualname dialect

**Test first:**
- `tests/unit/rust/test_qualname.py` — the dialect (spec §6.2): a free `fn foo` in `crate::a` →
  `a.foo` (or `crate.a.foo` per the chosen root); an `impl Foo { fn bar }` → `a.Foo.bar`; an `impl
  Trait for Foo { fn bar }` → `a.Foo.bar:trait=Trait`; a closure inside `foo` →
  `a.foo.<locals>.{closure#0}`; generics stripped (`fn g<T>` → `a.g`). Pin these in
  `tests/conformance/qualnames_rust.json` and assert the producer matches (mirrors the Python parity
  test).
- `tests/unit/rust/test_index.py` — parsing the command-injection specimen yields one `RustEntity` per
  `function_item` with `kind ∈ {function, method}`, a `Location` (relpath + line), and a stable
  `NodeId` map; re-parsing the same bytes yields identical `NodeId`s (intra-scan determinism).

**Implement:** `rust/parse.py` (cursor helpers for `scoped_identifier{path,name}`,
`field_expression{value,field}`, `use_declaration`/`use_as_clause`), `rust/qualname.py`,
`rust/index.py` (walk `function_item`, build `RustEntity{qualname, kind, node_handle, location,
node_ids}`). Module route = `crate`-rooted approximation from the file path (single-file; SP2 owns
the real thing).

### WP3 — Vocabulary (sources + command sinks) + `@trusted` marker

**Test first:**
- `tests/unit/rust/test_vocabulary.py` — `rust_taint.yaml` loads into frozen tables; a source entry
  `{crate: std, path: env::var, returns_taint: EXTERNAL_RAW, rationale: …}` and a sink entry
  `{crate: std, path: process::Command::new, sink_kind: command, rationale: …}` are present;
  `returns_taint` is constrained to `{ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`; duplicate keys
  rejected; `RUST_TAINT_VERSION` exported.
- `tests/unit/rust/test_provider.py` — a function with a `/// @trusted(level=ASSURED)` doc-comment
  seeds `FunctionTaint(ASSURED, ASSURED)`; an unmarked function seeds the fail-closed `UNKNOWN_RAW`
  default (`source='default'`).

**Implement:** `rust/vocabulary.py` (+ bundled `rust_taint.yaml`, wheel-shipped via a
`tool.hatch.build.force-include` entry like the Python `stdlib_taint.yaml`), `rust/provider.py`
(doc-comment `@trusted` recognition → `FunctionTaint`; its own `provider_fingerprint =
f"rust-vocab:{RUST_TAINT_VERSION}"`, spec §7). **Cache-version (spec §8.1):** thread
`RUST_TAINT_VERSION` into whatever cache identity the Rust path uses (slice 1 has no persisted
summary cache, but the version is wired so SP-later does not inherit the Python latent gap).

### WP4 — Builder-dataflow L2 (the hard core)

**Test first:** `tests/unit/rust/test_dataflow.py` — over hand-built specimens, assert the per-trigger
arg-taint map:
- `let mut c = Command::new("sh"); c.arg("-c"); c.arg(tainted); c.output();` → at the `.output()`
  trigger (keyed by its `NodeId`): program = literal `"sh"` (a shell), `shell_flag_seen = True`, and a
  RAW_ZONE arg taint present.
- `Command::new(tainted).output();` → program taint is RAW_ZONE (tainted program).
- `Command::new("ls").arg(tainted).output();` → program literal non-shell, shell flag absent ⇒ the map
  marks this **not** a shell injection and **not** a tainted program (must NOT fire — the safe argv
  case, spec §9.2).
- `let s = format!("rm {}", tainted); Command::new("sh").arg("-c").arg(s).output();` → the `format!`
  heuristic propagates `tainted` into `s` (Tier-A/B lexical, spec §9.3).

**Implement:** `rust/dataflow.py` — intra-function abstract state `local_var ->
CommandState{is_command, program_literal, program_taint, shell_flag_seen, arg_taints:
list[(NodeId, TaintState)]}`; update on `Command::new`, `.arg`/`.args`, terminal
`.output()/.spawn()/.status()`; seed local taint from sources (WP3) and `let` initializers; the
`format!` token-level heuristic. Emit a per-trigger arg-taint map keyed by `NodeId`. Receiver
resolution via `field_expression.value` (there is **no** `receiver` field; R6).

### WP5 — The two rules (verdict layer)

**Test first:** `tests/unit/rust/test_rules.py` — drive `RustAnalyzer` over the WP4 specimens inside a
`@trusted` function and assert:
- `RS-WL-112` fires once on the `sh -c <tainted>` case, `Severity.WARN`, `Kind.DEFECT`, anchored at the
  `.output()` line, fingerprint folds `(rule_id, path, line, qualname, taint_path)`.
- `RS-WL-108` fires once on `Command::new(tainted)`.
- The non-shell `.arg(tainted)` case fires **nothing** (the FP guard).
- An **unmarked** containing function fires **nothing** (`modulate(WARN, UNKNOWN_RAW) == NONE`,
  spec §4).

**Implement:** `rust/rules.py` — two rule objects satisfying the `Rule` protocol (`rule_id` +
`check`-equivalent over the Rust context), each: look up the containing fn tier from L1 seeds
(`project_taints` = `{qualname: seed.body_taint}`, no L3 needed); `modulate(base_severity, tier)`;
skip if `NONE`; consume the WP4 per-trigger maps; `worst-of` (max `TRUST_RANK`) over the arg taints;
fire iff worst ∈ `RAW_ZONE` **and** the shell-vs-program gate matches; emit `Finding` with
`RuleMetadata`-style metadata. Reuse `modulate`, `RAW_ZONE`, `compute_finding_fingerprint` verbatim.

### WP6 — Corpus + CLI wiring + e2e

**Test first:**
- `tests/corpus/rust/MANIFEST.yaml` + a harness variant `tests/corpus/rust/harness.py` (parallels
  `tests/corpus/harness.py`): scan `tests/corpus/rust/fixtures/command_sink.rs` via `RustAnalyzer`,
  reconcile active `RS-WL-*` DEFECTs against the manifest by `(path, rule_id, qualname)`, enforce the
  ≤5% FP gate. The specimen carries TP shapes (sh -c injection, tainted program) **and** clean shapes
  (non-shell argv, literal-only) in one file, all inside `@trusted` fns.
- `tests/e2e/test_rust_live.py` — `pytestmark = pytest.mark.rust_e2e`; resolves the toolchain via the
  `tree_sitter` import (skip-clean if the extra is absent); runs `wardline scan <fixture> --format
  jsonl` and asserts the two findings appear.

**Implement:**
- `pyproject.toml`: register the `rust_e2e` marker + add `and not rust_e2e` to `addopts`.
- CLI: wire `wardline scan` to dispatch `.rs` roots through `RustAnalyzer` (a minimal branch in the
  scan path keyed on discovered suffix; Python path unchanged). Slice 1 may gate this behind an
  explicit `--lang rust` or auto-detect by suffix — **decide in review** (default: auto-detect by
  discovered `.rs`, Python remains default).
- The bundled `rust_taint.yaml` ships in the wheel (force-include).

### WP7 — Docs, CHANGELOG, verification

- `docs/guides/` page: "Scanning Rust (preview)" — the Tier-A scope, the two rules, the `wardline[rust]`
  extra, the doc-comment `@trusted` marker, the explicit FN boundaries (spec §9.4).
- `CHANGELOG.md` `[Unreleased] Added`: Rust command-injection frontend (preview, Tier-A).
- `docs/agents.md`: note `.rs` scanning is preview + opt-in extra.

---

## Verification (end-to-end gate)

1. `.venv/bin/pytest tests/unit/rust tests/corpus/rust -q` green (incl. the qualname conformance +
   NodeId determinism + FP-guard tests).
2. `.venv/bin/pytest -q` **full suite green**; the **Python corpus + `tests/golden/identity` parity
   stay byte-identical** (this slice must not perturb Python output).
3. `WARDLINE_RUST=1 .venv/bin/pytest -m rust_e2e -q` green under `wardline[rust]`; skips clean without.
4. `ruff check` + `ruff format --check` + `mypy` clean.
5. `.venv/bin/wardline scan tests/corpus/rust/fixtures --fail-on WARN` reports exactly the two
   expected `RS-WL-*` findings; `.venv/bin/wardline scan src --fail-on ERROR` still exit 0.
6. `pip install .` (no extras) imports `wardline` without pulling tree-sitter (base stays zero-dep).

---

## Decisions to confirm in review

- **CLI dispatch:** auto-detect `.rs` (recommended) vs explicit `--lang rust`. (WP6)
- **`RS-WL-108` severity:** WARN parity vs raise (spec §12 Q1).
- **Module root spelling:** `crate.a.foo` vs `a.foo` for the single-file approximation (spec §6.3) —
  pick one and pin it in `qualnames_rust.json` now so the fingerprint is stable.
- **`@trusted` is enough for the specimen** to enter declared-trust, or does the slice also need
  `@trust_boundary` (external→to_level) to model the source-at-the-boundary shape? (Default: `@trusted`
  + vocabulary source is sufficient.)
