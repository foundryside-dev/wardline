# Rust Frontend — Slice 1: Command-Injection (Implementation Plan)

**Status:** Draft for review (panel-hardened, round 1) · **Date:** 2026-06-08 · **Branch:** `feat/rust-plugin`
**Design spec:** `docs/superpowers/specs/2026-06-08-wardline-rust-frontend-design.md` (read first).

This plan cuts a **thin vertical path** through the six sub-projects (SP1→SP6) of the spec to land
**one working Rust finding family** — command-injection via `std::process::Command` — end to end:
discover → parse → index/qualname → seed source → builder-dataflow L2 → sink locator → verdict →
`Finding` → corpus + e2e. It is the **de-risking instrument**, not a sub-project.

### What this slice proves / does not prove

- **Proves:** the plumbing (a second frontend producing real `Finding`s the existing
  `run_scan` baseline/waiver/gate/SARIF path consumes) **and** real source→propagate→sink taint on
  Tier-A syntax.
- **Does NOT prove:** semantic adequacy for Tier-B (trait dispatch) or Tier-C (macros/derives), nor
  that the engine middle can be *cleanly factored* for two frontends (that is SP1). A green slice is
  **not** evidence that "the rest is just more vocabulary." (Spec §2, §3.3, §9.1.)

---

## Process constraints (all work packages)

- **TDD, strictly.** Failing test first, then implementation. (Skill: `superpowers:test-driven-development`.)
- **Subagents NEVER run git** — no `status/add/commit/checkout/stash/restore/reset/worktree`. The
  orchestrator owns all git.
- **All work in the worktree** `/home/john/wardline/.worktrees/rust-plugin` on `feat/rust-plugin`.
- **Base stays zero-dep.** New runtime deps live behind the **`wardline[rust]` extra** only
  (`tree-sitter`, `tree-sitter-rust`). `import tree_sitter` is lazy/guarded (mirror `loomweave`'s
  `require_blake3`); a bare `pip install wardline` must not import them. **Every** `tests/unit/rust/`
  test module carries a `pytest.importorskip("tree_sitter")` (or an autouse skip via a
  `tests/unit/rust/conftest.py`) so the default suite skips clean without the extra — not just the
  loader test.
- **Gates:** full `pytest -q` green; `ruff` + `mypy` clean; the **Python corpus + identity oracle stay
  byte-green**; `wardline scan src --fail-on ERROR` exit 0.
- **Rust namespace:** rules `RS-WL-*`; Rust corpus `tests/corpus/rust/`; live marker `rust_e2e`.
- **Identity posture:** `RS-WL-*` findings are **provisional / baseline-ineligible** until SP2 (spec
  §3.6); the slice emits a provisional-identity flag and does not freeze a `golden/identity/rust/`
  corpus.

---

## Non-goals (explicit, deferred to the named SP)

- Full frontend-seam extraction making Python "frontend #1" (SP1) — slice 1 builds a focused
  `RustAnalyzer` alongside the engine middle; SP1 later refactors the shipped code.
- Multi-file / cross-function / full module-tree route resolution (SP2) — slice 1 is single-file,
  intra-function; module route is a **`crate`-rooted approximation** from the file path (spec §6.3).
- The L3 interprocedural fixpoint — for a call-free single function it is the identity; slice 1
  computes `project_taints` directly from L1 seeds and does **not** invoke `propagate_callgraph_taints`.
- Loomweave reconciliation + the frozen `golden/identity/rust/` corpus (SP2).
- `.env()`/`.arg0()`/`.args()`-per-element, `push_str`/`+` concat-built shell strings, variable-bound
  shell names, `libc`/FFI exec, Tier-B/C sinks (spec §9.4) — documented FNs.
- In-source markers beyond the single `@trusted` doc-comment the specimen needs (full marker grammar
  is SP3).
- Auto-detect CLI dispatch (SP6) — slice 1 uses an **explicit `--lang rust`** flag (spec §8.2 / panel:
  avoids the mixed-language `ScanResult`/baseline-intermixing/delta-scoping gaps until the
  multi-frontend pipeline is designed).

---

## Architecture of the slice

A focused module tree under `src/wardline/rust/` (new), importing the **shared, neutral** engine
pieces and **not** the Python-AST scanner:

```
src/wardline/rust/
  __init__.py
  _tree_sitter.py     # require_rust() -> (Language, Parser); guarded import + RustToolingError
  nodeid.py           # NodeId newtype + NodeIdMap + mint_node_ids(tree) -> NodeIdMap (pre-order)
  parse.py            # source bytes -> tree; cursor helpers (scoped_identifier, field_expression…)
  qualname.py         # the Rust dialect (ADR-049: impl[Trait]/impl#<>#0/@cfg; closures NOT entities)
  index.py            # function_item -> RustEntity + NodeId stamping
  vocabulary.py       # rust_taint.yaml loader (sources + sinks) + RUST_TAINT_VERSION
  rust_taint.yaml     # bundled vocabulary (wheel-shipped via hatch force-include)
  provider.py         # RustTrustProvider: doc-comment @trusted -> FunctionTaint; provider_fingerprint
  dataflow.py         # builder-dataflow L2: CommandState + local_string_taints -> per-trigger maps
  rules.py            # RS-WL-108 + RS-WL-112 (RustRule protocol; reuse modulate/RAW_ZONE/Finding)
  context.py          # RustAnalysisContext (minimal) + adapter to AnalysisContext shape
  analyzer.py         # RustAnalyzer.analyze(files, config, *, root) -> list[Finding]; .last_context
```

**`RustAnalyzer` satisfies the full `Analyzer` protocol** (`core/protocols.py:17-21`):
`analyze(self, files, config, *, root: Path) -> Sequence[Finding]` **and** a `last_context` property.
This is mandatory — `run_scan` (`core/run.py:228`) calls `analyzer.analyze(files, cfg, root=root)` and
reads `analyzer.last_context` at `:282`/`:324` for delta-scope and `ScanResult`. So the slice does
**not** sidestep `run_scan` (that would silently skip baseline/waiver/gate/suppression). `last_context`
returns a minimal `AnalysisContext`-shaped stub built from `RustAnalysisContext` (`project_taints:
dict[str, TaintState]`, `entities: dict[str, RustEntity]`, empty `project_edges`/call-site maps); the
delta-scope path degrades gracefully when `project_edges` is empty. Defining `RustAnalysisContext` now
establishes the shape discipline SP1 will unify (panel: prevents ad-hoc divergence).

Shared imports (reuse verbatim, spec §3.1): `core.taints` (`TaintState`, `TRUST_RANK`, `RAW_ZONE`,
`least_trusted`), `core.finding` (`Finding`, `Location`, `Severity`, `Kind`,
`compute_finding_fingerprint`), `scanner.rules.severity_model.modulate`,
`scanner.taint.function_level.FunctionSeed` (+ the `FunctionTaint`/`SeedResult` shapes).

---

## Work packages (each TDD)

### WP0 — Dependency + scaffold + NodeId/NodeIdMap

**Test first:** `tests/unit/rust/test_tree_sitter_loader.py` — `require_rust()` returns a usable
`(Language, Parser)` and round-trips `fn main(){}` to a tree whose root kind is `source_file`;
module-level `pytest.importorskip("tree_sitter")`.

**Implement:**
- `pyproject.toml`: `rust = ["tree-sitter>=0.25,<0.26", "tree-sitter-rust==0.24.2"]`. **Pin rationale
  (R6):** tree-sitter-rust 0.24.2's parser is ABI 15, loadable only by core ≥0.25.0 — do **not** trust
  the grammar's stale self-declared `tree-sitter~=0.22`. Distribution is a **`cp39-abi3` stable-ABI
  wheel** (one wheel runs on CPython 3.9+, incl. 3.12) across linux/macos/win — **no compiler at
  install** on the supported matrix. Add a comment that `<0.26` is a conservative cap (0.26.x ABI/API
  compat unverified; relax after a smoke test).
- `rust/_tree_sitter.py`: `require_rust()` lazy import + `RustToolingError` (clean install message),
  mirroring `loomweave.require_blake3`.
- `rust/nodeid.py`: `NodeId = NewType("NodeId", int)`; a `NodeIdMap` typed wrapper; `mint_node_ids(tree)
  -> NodeIdMap` assigning a **deterministic per-file pre-order index** (spec §5). **`NodeIdMap` is the
  single keying authority** — `dataflow.py` (WP4) and `rules.py` (WP5) both import it; no pass keys on a
  raw `ts_node`. Also add the typed `NodeId` alias on the Python side behind `id()` (zero behavior
  change) so the contract is shared.
- `tests/conformance/qualnames_rust.json` is **vendored from Loomweave** here (a pinned copy of
  `feat/rust-plugin-spec`:`fixtures/qualnames_rust.json`, the extractor-generated oracle) as the
  **format drift-gate** (spec §6.4). Loomweave offered to drop the copy + a
  `test_loomweave_rust_qualname_parity.py` skeleton straight into `tests/conformance/` — accept that or
  vendor it manually; do not author the corpus ourselves (Loomweave is authoritative).

**Verify:** loader test green under `wardline[rust]`; skips clean without it.

### WP1 — Discovery generalization (suffix-parameterized) + security guard

**Test first:** `tests/unit/core/test_discovery.py` —
- `test_discover_rust_suffix`: `discover(root, config, suffixes=frozenset({'.rs'}))` finds `a.rs`,
  **not** `a.py`; the default call (no `suffixes`) is unchanged; `target/` is skipped.
- `test_discover_rust_symlink_confined`: a `.rs` file-symlink resolving **outside** root inside a
  source_root is **skipped with `WLN-ENGINE-FILE-SKIPPED`** under `confine_to_root=True` (mirror the
  Python THREAT-001 test — this is a **security invariant**, not an edge case).

**Implement:** `core/discovery.py` — add `suffixes: frozenset[str] = frozenset({'.py'})`; replace the
hardcoded `base.rglob('*.py')` (line 32) with a per-suffix sweep that **yields `Path`s in the same
sorted order** as before (so finding/entity order is unchanged); keep the per-file `confine_to_root`
symlink guard *inside* the loop; add `target` to `_ALWAYS_SKIP`; preserve `fnmatch` excludes + missing
-source-root surfacing. **Python default behavior byte-unchanged.**

> **Byte-green note (panel):** the existing discovery unit tests assert *sorted names*, not iteration
> order; the real byte-green guard for this change is the **identity oracle**. Run **Verification 2
> (full suite + `tests/golden/identity` parity) immediately after WP1**, not at the end. Also: a
> configured root with no `.rs` files returns zero files silently (`missing_source_roots()` is not
> suffix-aware) — documented as a known limitation; SP6 adds the empty-root warning (slice 1's
> `RustAnalyzer` runs over an explicit fixture, so it never hits this path).

### WP2 — Rust parse + minimal index + qualname dialect

The dialect is **Loomweave's ADR-049** (spec §6), not Wardline's — Wardline is the *second producer*
that **mints the identical string** and never parses the locator. Reserved char is **`:` (invalid)**;
`[ ] # < > @` are legal. `tests/conformance/qualnames_rust.json` is the copy **vendored from Loomweave**
(`/home/john/loomweave` `feat/rust-plugin-spec`:`fixtures/qualnames_rust.json`, extractor-generated);
Wardline reproduces its function-row `qualname`s byte-for-byte.

**Test first:**
- `tests/unit/rust/test_qualname.py` (against the vendored corpus, ADR-049 forms — file-module rooted
  for the single-file slice, e.g. `demo`): inherent method `demo.m.Foo.impl#<>#0.bar`; trait method
  `demo.m.Foo.impl[Display].fmt`; trait collision `…impl[Display].fmt` + `…impl[Debug].fmt`; concrete
  generics `…impl[From<i32>].from` ≠ `…impl[From<u32>].from`; positional generic `…impl#<$0>#0.get`
  (**and the param-renamed source yields the identical string** — rename-stable); multiple inherent
  ordinal `…impl#<>#0.a` + `…impl#<>#1.b` (resets in a nested `mod`); cfg-twin `demo.m.f@cfg(unix)` +
  `…f@cfg(windows)`; `async fn` renders identically to `fn`; **closure → NOT an entity** (only the
  enclosing `demo.m.f`); **nested `fn` → NOT an entity** (only `demo.m.outer`); generics stripped.
- **Comparison rule (do NOT raw-`assert found == expected`):** the corpus rows include `module`/`struct`
  rows Wardline never emits and its `kind` is the locator id-kind (`function` for every callable). So:
  take Wardline's function entities; assert each `qualname` is in the case's set of **non-`module`**
  `expected` qualnames; `kind` is informational (map Wardline's semantic `method` → id-kind `function`,
  or compare qualname-only); never edit the vendored copy to drop rows. (Mirrors the `None ↔ ""`
  accommodation the Python `loomweave_qualname_parity` test already makes.)
- `tests/unit/rust/test_index.py` — the specimen yields one `RustEntity` per emitted callable
  (free fn / inherent / trait / assoc — **closures and nested fns are NOT emitted**), with a `Location`
  and NodeIds. Wardline keeps its semantic `function|method` split in `RustEntity` **metadata**; the
  qualname/id-kind is `function`.
- `tests/unit/rust/test_nodeid_crosspass.py` — **the spec §5 cross-pass agreement test** (not
  re-parse): for a known builder chain, the `NodeId` the (stub) dataflow records for the `.output()`
  trigger **equals** the `NodeId` `mint_node_ids` assigns that CST node, which **equals** the one the
  rule locator looks up. A mismatch is a hard failure.

**Implement:** `rust/parse.py`, `rust/qualname.py` (ADR-049 forms), `rust/index.py`. **Root = the
file-module approximation** (e.g. `demo`) — slice-1-reproducible; the **real crate prefix** from
`Cargo.toml`, cross-file module route, `#[path]`, and cross-file ordinals are **SP2** (spec §6.3), so
slice-1 findings are crate-prefix-provisional (consistent with their baseline-ineligibility). A finding
inside a closure/nested fn attributes to the **enclosing named fn** (`line_start` localises).

### WP3 — Vocabulary (sources + command sinks) + `@trusted` marker + cache-version

**Test first:**
- `tests/unit/rust/test_vocabulary.py` — `rust_taint.yaml` loads into frozen tables; a source
  `{crate: std, path: env::var, returns_taint: EXTERNAL_RAW, …}` and a sink `{crate: std, path:
  process::Command::new, sink_kind: command, …}` present; `returns_taint` constrained to `{ASSURED,
  GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`; duplicate keys rejected; `RUST_TAINT_VERSION` exported.
- `tests/unit/rust/test_provider.py` — `/// @trusted(level=ASSURED)` seeds `FunctionTaint(ASSURED,
  ASSURED)`; an unmarked fn seeds the fail-closed `UNKNOWN_RAW` default (`source='default'`).
  **`provider_fingerprint == f"rust-vocab:{RUST_TAINT_VERSION}"`, and the test asserts it CHANGES when
  `RUST_TAINT_VERSION` is bumped** (closes the cache-version gap now — spec §8.1).

**Implement:** `rust/vocabulary.py` (+ bundled `rust_taint.yaml`, wheel-shipped via
`tool.hatch.build.force-include`), `rust/provider.py`. The vocab version folds into
`provider_fingerprint` (the policy slot `scan_policy_hash` is *separate* — do not overload it).

### WP4 — Builder-dataflow L2 (the hard core)

**Test first:** `tests/unit/rust/test_dataflow.py` — over hand-built specimens, assert the per-trigger
arg-taint map (keyed via `NodeIdMap`):

*Positives:*
- `let mut c = Command::new("sh"); c.arg("-c"); c.arg(tainted); c.output();` → at `.output()`: program
  literal `"sh"` (shell), `shell_flag_seen`, a RAW_ZONE arg taint present.
- `Command::new(tainted).output();` → `program_taint` is RAW_ZONE.
- `let s = format!("rm {}", tainted); Command::new("sh").arg("-c").arg(s).output();` → `s` carries
  taint via `local_string_taints`; reaches the `-c` arg.
- **Two-hop:** `let s = format!("{}", tainted); let s2 = format!("{}", s); … .arg(s2)` → taint flows.

*Negatives (the FP guards — spec §9.2/§9.4):*
- `Command::new("ls").arg(tainted).output();` → non-shell program, no shell flag ⇒ neither rule.
- `Command::new("sh").arg(tainted).output();` (**no `-c`**) → must NOT fire RS-WL-112 (shell-without-flag).
- `Command::new("ls").args(tainted_vec).output();` → non-shell `.args` ⇒ neither rule.
- `…arg(format!("echo {}", sanitize(tainted)))` → **accepted bounded FP** (the sanitizer is invisible):
  pin current behavior with a test AND register it as a TN fixture in the corpus (measured vs ≤5% gate).
- `format!("rm {}", clean_literal)` → no taint propagates (precision).
- `format!("rm {tainted}")` (captured-identifier form) → **documented FN**: assert no propagation
  (pins the boundary).

*FN pin:* `let s = "sh"; Command::new(s).arg("-c").arg(tainted).output();` (variable-bound shell name)
→ asserts it does **not** fire today (so the bounded FN can't silently flip to an FP later).

**Implement:** `rust/dataflow.py` — `local_var → CommandState{is_command, program_literal,
program_taint, shell_flag_seen, arg_taints: list[(NodeId, TaintState)]}` **plus** `local_string_taints:
dict[str, TaintState]`; update on `Command::new`, `.arg`/`.args`, terminal `.output/.spawn/.status`;
seed locals from sources (WP3) and `let` initializers; the `format!` heuristic matches **direct
interpolation argument tokens only**. Receiver via `field_expression.value` (no `receiver` field).

### WP5 — The two rules (verdict layer)

**Test first:** `tests/unit/rust/test_rules.py` — drive `RustAnalyzer` over the WP4 specimens inside a
`@trusted` fn:
- `RS-WL-112` fires once on `sh -c <tainted>`, **`Severity.WARN`**, `Kind.DEFECT`, anchored at
  `.output()`, fingerprint folds `(rule_id, path, line, qualname, taint_path)`.
- `RS-WL-108` fires once on `Command::new(tainted)`, **`Severity.ERROR`**, message text cites **both**
  the `Command::new(...)` constructor line and the terminal trigger line.
- **De-confliction single-fire:** `Command::new(tainted).arg("-c").arg(more_tainted).output();`
  (tainted program AND a `-c` flag) → exactly **one** finding (RS-WL-108), not two (spec §9.2).
- Non-shell `.arg(tainted)` → **nothing**. Unmarked containing fn → **nothing** (`modulate(_, UNKNOWN_RAW)
  == NONE`).
- **Pinned `taint_path` golden strings** for one RS-WL-108 and one RS-WL-112 finding (the Rust analog
  of golden identity entries — spec §3.6 obligation that `taint_path` serialization is pinned).

**Implement:** `rust/rules.py` — two rule objects satisfying a **`RustRule` protocol** (`rule_id: str`
+ `check(self, context: RustAnalysisContext) -> Sequence[Finding]`) — they are **NOT** registered in
the Python `RuleRegistry` and do **NOT** accept `AnalysisContext` (panel: avoid the protocol-conformance
overstatement). Each: look up the containing fn tier from L1 seeds (`project_taints = {qualname:
seed.body_taint}`, no L3); `modulate(base_severity, tier)`; skip if `NONE`; consume the WP4 per-trigger
maps; **RAW_ZONE membership on the *selected* TaintState** (RS-WL-108 → `program_taint`; RS-WL-112 →
worst-of `arg_taints` gated by the shell test); emit `Finding`. Base severities: **RS-WL-108 = ERROR,
RS-WL-112 = WARN.** CWE-78 lives in the **description prose** (no `cwe` field in `RuleMetadata`).
Drafted `examples_violation`/`examples_clean` per spec §9.2. Reuse `modulate`, `RAW_ZONE`,
`compute_finding_fingerprint` verbatim.

### WP6 — Corpus + CLI wiring + e2e + coverage posture

**Test first:**
- `tests/corpus/rust/MANIFEST.yaml` + `tests/corpus/rust/harness.py`: scan
  `tests/corpus/rust/fixtures/command_sink.rs` via `RustAnalyzer`, reconcile active `RS-WL-*` DEFECTs
  by `(path, rule_id, qualname)`, enforce ≤5% FP gate, with a **documented FN section**. The fixture is
  **dense** (≥10 clean fns — non-shell `Command`s, `.args()`, taint-free `format!`, the `sanitize()`
  near-miss, unmarked fns — alongside the TP fns), all in `@trusted` fns. A **second
  `clean_commands.rs`** carries a **hard 0-findings** gate (panel: makes the percentage gate
  non-vacuous).
- `tests/e2e/test_rust_live.py` — `pytestmark = pytest.mark.rust_e2e`; toolchain via the `tree_sitter`
  import (skip-clean without the extra); runs `wardline scan <fixture> --lang rust --format jsonl` and
  asserts the two findings + the **provisional-identity flag** + the **coverage-posture line**.

**Implement:**
- `pyproject.toml`: register the `rust_e2e` marker + `and not rust_e2e` in `addopts`.
- CLI: add an explicit **`--lang rust`** flag to `wardline scan` that routes discovery (`suffixes={'.rs'}`)
  and analysis through `RustAnalyzer` via `run_scan` (Python path unchanged; default unchanged). Emit a
  **coverage-posture line** (`Rust: N fns scanned, M in declared-trust; Tier-A only — macro/trait-dispatched
  sinks not evaluated`) and a **provisional-identity** notice (spec §3.6, §4). Auto-detect is **not**
  done here (SP6).
- Bundle `rust_taint.yaml` in the wheel (force-include).

### WP7 — Docs, CHANGELOG, verification

- `docs/guides/rust-preview.md`: Tier-A scope; the two rules + severities; the `wardline[rust]` extra;
  the `@trusted` doc-comment marker; the **explicit FN families** (Tier-B traits, Tier-C macros/serde,
  `arg0`, `push_str`/`+` concat, `.args` flag, variable-bound shell, `libc`/FFI — spec §9.4); the
  **coverage-posture** meaning ("green = no declared-trust Tier-A command sinks found", not "Rust
  clean"); the **provisional-identity** caveat (baseline-ineligible until SP2).
- `CHANGELOG.md` `[Unreleased] Added`: Rust command-injection frontend (preview, Tier-A, opt-in extra).
- `docs/agents.md`: `.rs` scanning is preview + opt-in + `--lang rust`.

---

## Verification (end-to-end gate)

1. `.venv/bin/pytest tests/unit/rust tests/corpus/rust -q` green (incl. qualname conformance, the
   **NodeId cross-pass agreement** test, the FP/FN guards, the provider-fingerprint-on-bump test).
2. **Immediately after WP1** *and* at the end: `.venv/bin/pytest -q` full suite green; the **Python
   corpus + `tests/golden/identity` parity stay byte-identical**.
3. `.venv/bin/pytest -m rust_e2e -q` green under `wardline[rust]`; skips clean without it.
4. `ruff check` + `ruff format --check` + `mypy` clean.
5. `.venv/bin/wardline scan tests/corpus/rust/fixtures --lang rust --fail-on ERROR` reports the
   RS-WL-108 finding (ERROR) and exits 1; `--fail-on WARN` additionally surfaces RS-WL-112;
   `.venv/bin/wardline scan src --fail-on ERROR` still exit 0.
6. `pip install .` (no extras) imports `wardline` without pulling tree-sitter (base stays zero-dep);
   every `tests/unit/rust/` module skips clean in that env.

---

## Decisions to confirm in review (genuinely open)

- **`format!` heuristic narrowing** (spec §12 Q1): "direct-interpolation-arg tokens only" for slice 1?
- **`@trusted` alone is enough** for the specimen to enter declared-trust (vs also needing
  `@trust_boundary` external→to_level)? (Default: `@trusted` + a vocabulary source is sufficient.)
- **Accept Loomweave's offer** to drop the vendored `qualnames_rust.json` + parity-test skeleton into
  `tests/conformance/`? (Default: yes — they generate it from the oracle; we should not hand-author it.)

(Resolved in the spec, no longer open here: RS-WL-108 = ERROR; **qualname dialect = Loomweave ADR-049**
(Wardline conforms, file-module root for slice 1, crate prefix is SP2); **closures/nested fns are NOT
entities**; **`:` is invalid** (no `:trait=`); corpus vendored from Loomweave; CLI = explicit
`--lang rust`; `RustAnalyzer` satisfies the full `Analyzer` protocol; identity baseline-ineligible until
the SP2 crate-prefix.)
