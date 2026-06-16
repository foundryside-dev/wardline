# Rust Frontend → Full ADR-049 Producer + SP2 Whole-Tree — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Panel-reviewed 2026-06-10** (reality/contract/architecture/quality/systems, all "execute-with-fixes") — every finding folded below. Where a step cites oracle source (file:line in /home/john/loomweave), the executor MUST read that source before implementing; the citations are the contract for behaviors the corpus does not pin.

**Goal:** Take the Rust plugin from "preview / provisional identity, taint-only producer" to a full second ADR-049 producer with real crate-prefixed finding identity — RS-WL-* findings become baseline-eligible.

**Architecture:** Wardline's tree-sitter Rust frontend (`src/wardline/rust/`) grows from callables-only to the full ten-kind ADR-049 entity surface (leaf kinds, the `impl` entity, `module → impl → method` containment) plus the two anchored edge kinds; an SP2 whole-tree pass (Cargo.toml crate roots, cross-file module routes) replaces the directory-name crate stub; identity then graduates (frozen `tests/golden/identity/rust/` corpus, `provisional_identity` plumbing removed). The Loomweave extractor + vendored corpus remain the oracle: where upstream behavior is decided-and-emitted but un-oracled (stacked-cfg fold, cfg reserved-char escape, leaf kinds), we add the corpus rows **upstream first** (verified by Loomweave's own cargo gate), re-vendor, then conform. Where upstream has no decision (reserved-colon path-typed generic args; const-arg spacing), we draft the ADR-049 decision letter and record the dependency — no unilateral normalization.

**Tech Stack:** Python 3.12 (stdlib `tomllib` for manifests — zero new dep), tree-sitter / tree-sitter-rust (preview extra), pytest; Rust/cargo only to run Loomweave's own gates upstream.

**Oracle ground truth (verified 2026-06-10, panel-corrected):**
- Loomweave repo: `/home/john/loomweave`, branch `rc4` @ `510a032` (`feat/rust-plugin-spec` is merged into rc4; the stale branch ref still exists locally — ignore it; the Rust plugin is live on-by-default). Working tree has ONE unrelated dirty file (`.agents/skills/loomweave-workflow/SKILL.md`) — never touch or stash it.
- Upstream corpus `fixtures/qualnames_rust.json` @ blob `a0aaa341041dc66...` (HEAD): 22 entity cases (all slice-1), 6 module_route cases (5 slice-1 + `path_attr_known_gap` sp2/known_gap). vs our vendored copy: ONE new case `generic_self_nested_param`; zero diffs in shared cases.
- The upstream corpus has **no `enum`/`trait`/`type_alias`/`const`/`static` rows** (`macro` IS pinned by `macro_invocation_generates_no_entity`) and **no stacked-cfg or cfg-escape rows** — but the extractor implements all of it (extract.rs:830-843 `cfg_predicates` collects ALL cfg attrs raw; qualname.rs:299-302 `cfg_discriminant` normalises each, sorts, joins `&`; qualname.rs:314-336 `normalise_pred` strips ws → `escape_reserved` (`%`→`%25` then `:`→`%3A`) → any()/all() 1-level arg sort; plugin.toml `entity_kinds` = the ten kinds, `ontology_version = "0.4.0"`).
- **Trait bodies are NOT walked** by the extractor (extract.rs:457 "Trait *bodies* are deliberately NOT walked here"); a trait definition emits only the `trait` entity.
- **cfg-twin suffixing is per-(kind, name) across ALL nine named item kinds** (extract.rs:326-358 `twin_counts`; struct arm :397-400, inline-mod arm :436-439) — suffix applied only on collision, per-kind counted.
- Crate roots (crate_roots.rs:47-95): a dir registers iff (a) `Cargo.toml` **parses as TOML** AND has `[package].name` as a string (toml::Value parse — `name.workspace = true` is a table → falls through), ELSE (b) `src/lib.rs` OR `src/main.rs` exists → directory-name fallback. Virtual workspace roots (no package.name, no src/lib|main.rs) register NOTHING. Names `-`→`_` normalised. Walk skips symlinked dirs (crate_roots.rs:83-94 + dedicated test). File→crate by longest path-prefix.
- Out-of-src files (scope.rs:21-32 `emittable_scope`): loomweave EXCLUDES tests/, benches/, examples/, build.rs, a `src/main.rs` shadowed by sibling lib.rs, and files under no crate root — it emits NOTHING for them. Wardline must NOT mirror that for scan coverage (see Task 4 design).
- Edges (resolve.rs:13-17, :40-49; extract.rs:634-665, :788-794): glob `use a::*` → Ambiguous(in-project module id) else dropped; multi-kind ambiguity to_id = FIRST id by sorted order; use-tree groups fan out, `as` aliases resolve the REAL path, `self` group leaf → the prefix module; trait lookup STRIPS generic args; negative impls emit no edge.
- Reserved-colon (`impl From<std::io::Error>`): upstream renders the colon then REJECTS at `entity_id` construction (`validate_no_colon`, entity_id.rs:140) and degrades the file — **no canonical colon-free form exists**. Genuine ADR-049 amendment needed (Task 9).
- Wardline already byte-conforms on every vendored slice-1 row (suite 3046 passed, 1 xfailed = the `path_attr_known_gap` sp2 module_route row; both xfail code branches exist at test_loomweave_rust_qualname_parity.py:144-145 + :154-155 but only the module_route one fires today).
- **Wardline's `cfg_predicate_of` (qualname.py:99-114) returns the NORMALIZED predicate and index.py stores it** — the stacked-cfg fix must restructure to collect RAW and normalize exactly once (Task 2).
- **analyzer.py has NO kind filter** (analyzer.py:138-153 iterates ALL entities, calls `taint_for(entity.node)` + `child_by_field_name("body")` unconditionally) — Task 3 MUST add the callable guard.
- weft.toml severity overrides still do NOT apply to Rust (analyzer.py:84-85) — the banner's severity-override warning stays after graduation.
- Loomweave CI gate is `cargo nextest run --workspace --all-features --no-tests=pass` (.github/workflows/verify.yml:91) plus lockstep scripts — Task 1 must run the workspace gate, not just the plugin suite.
- No stored state holds RS-WL fingerprints (no `.weft/` in the worktree; no RS-WL entries in any baseline.yaml) — the Task 4 rekey orphans nothing; keep the cheap defensive grep.

**Branch/commit discipline:** all Wardline work on `feat/rust-gold` (worktree `/home/john/wardline/.worktrees/rust-gold`), scoped commits per task, merged to `rc5` at the end. Loomweave-side work is ONE scoped commit on their `rc4` touching only the fixture (+ its header text). The rc5 main checkout has unrelated uncommitted changes (ci.yml, mkdocs.yml, docs/index.md, .gitignore, docs/arch-analysis-2026-06-10/) — never touch them; they are disjoint from this sprint's paths (the sprint touches docs/guides/, docs/reference/, docs/integration/, docs/superpowers/, CHANGELOG.md — NOT docs/index.md or mkdocs.yml).

**Filigree:** sprint label `rust-sp2-2026-06-10` on every issue touched (already applied). Umbrella task `wardline-9f00d5b44b` (claimed). Claim with `--actor rust-gold-sprint` before starting the relevant task; close on completion. Issues: `wardline-be5ee9cc34` (reserved-colon, Task 9), `wardline-4fdad782a7` (stacked-cfg, Tasks 1–2), `wardline-e8f7c0508f` (cfg escape + const spacing, Tasks 1–2 + 9), `wardline-868908944b` (drift alarm, Task 8).

---

## Dependency graph

```
Task 0 (spec amendment) ──────────────────────────┐
Task 1 (loomweave oracle rows) → Task 2 (re-vendor + cfg conformance)
    → Task 3 (producer surface: leaf kinds + impl entity + containment + per-kind twins)
        → Task 4 (SP2 whole-tree: crate roots + analyzer wiring + un-xfail)
            → Task 5 (edges: imports/implements)
            → Task 6 (identity freeze: tests/golden/identity/rust/)
                → Task 7 (graduation: provisional plumbing removal + docs)
Task 1 → Task 8 (drift alarm)
Task 9 (reserved-colon + const-spacing decision letter) — independent
Task 10 (hard-gates sweep + merge to rc5 + filigree closes) — last
```

---

### Task 0: Spec amendment — fold Phase 1b into SP2

**Files:**
- Modify: `docs/superpowers/specs/2026-06-08-wardline-rust-frontend-design.md` (§6.3, §6.4, §11)

- [ ] **Step 0.1:** Amend §11's SP2 bullet to record the user-approved fold: SP2 now also comprises the Phase-1b producer surface (six leaf kinds, the `impl` entity + method re-parenting, the `imports`/`implements` anchored edges, `ontology_version 0.4.0`, `plugin_id rust`), citing `docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md`. Amend §6.3/§6.4 where they say "Wardline never emits struct/module rows" — after this sprint Wardline emits the full ten-kind surface and the conformance comparison graduates from the subset-consumer rule to the full-set rule (§7 rule 1 of the changeset). Note the oracle ground-truth corrections: `feat/rust-plugin-spec` is merged into loomweave `rc4`; the corpus gains `generic_self_nested_param`; leaf-kind/stacked-cfg/cfg-escape rows are added upstream by this sprint (Task 1). Add a §13 changelog entry dated 2026-06-10.
- [ ] **Step 0.2:** `.venv/bin/mkdocs build --strict` passes. Commit: `docs(spec): fold Phase 1b producer surface into SP2 (user-approved) + oracle ground-truth corrections`.

---

### Task 1: Loomweave-side oracle rows (upstream, `/home/john/loomweave`, branch rc4)

Pin four already-emitted-but-un-oracled behaviors with corpus rows, verified by Loomweave's own byte-for-byte gate. **Hand-author the `source`; the extractor dictates `expected`** — pre-derive expected by READING extract.rs/qualname.rs (not guessing), run the gate, and on mismatch adopt the extractor's actual output. Never weaken their test.

**Files:**
- Modify: `/home/john/loomweave/fixtures/qualnames_rust.json` (append 4 entity cases + fix the stale `_dialect_summary.free_items` header text "enum/trait/const/static/type_alias/macro are Phase 1b, not yet emitted" — it already contradicts the live extractor and would contradict the new rows in the same file)
- Read first: `/home/john/loomweave/crates/loomweave-plugin-rust/tests/qualname_conformance.rs` (case schema + how the gate enumerates JSON cases), `src/extract.rs` (esp. :326-358 twin_counts, :457 trait-body comment, :476-492 Item::Trait arm, :830-843 cfg_predicates), `src/qualname.rs` (:299-336 cfg_discriminant/normalise_pred/escape_reserved)

- [ ] **Step 1.1:** Append four cases to `entities` (all `"reproducibility": "slice-1"`, crate `demo`, `rel_path` `src/m.rs`, `module_path` `demo.m`):

1. **`leaf_item_kinds`** — the five missing free-item kinds (NO `macro_rules!` — already pinned by `macro_invocation_generates_no_entity`; NO trait-body method — extract.rs:457 never walks trait bodies):
```rust
pub enum Color { Red }
pub trait Greet {}
pub type Alias = u8;
pub const LIMIT: u32 = 10;
pub static NAME: &str = "x";
```
expected (module row first, then source order): `demo.m` (module), `demo.m.Color` (enum), `demo.m.Greet` (trait), `demo.m.Alias` (type_alias), `demo.m.LIMIT` (const), `demo.m.NAME` (static).

2. **`stacked_cfg_twin`** — source:
```rust
struct Foo;
#[cfg(feature = "a")]
#[cfg(unix)]
impl Foo { pub fn go(&self) {} }
#[cfg(feature = "b")]
#[cfg(unix)]
impl Foo { pub fn go(&self) {} }
```
expected: per `cfg_discriminant` (each pred normalised, set sorted, joined `&`): module + struct rows, then `demo.m.Foo.impl#<>@cfg(feature="a"&unix)` (impl) + `….go` (function), `demo.m.Foo.impl#<>@cfg(feature="b"&unix)` (impl) + `….go` (function). **Adopt the extractor's exact bytes.**

3. **`cfg_escape_reserved_char`** — source:
```rust
#[cfg(feature = "a:b")]
pub fn f() {}
#[cfg(feature = "c")]
pub fn f() {}
```
expected: module row + `demo.m.f@cfg(feature="a%3Ab")` and `demo.m.f@cfg(feature="c")` (function rows; verify exact quoting/escape bytes from `normalise_pred`).

4. **`leaf_kind_cfg_twin`** — pins the per-kind twin counter on a newly-oracled leaf kind (it becomes load-bearing under Wardline's full-set comparison):
```rust
#[cfg(unix)]
pub const LIMIT: u32 = 1;
#[cfg(windows)]
pub const LIMIT: u32 = 2;
```
expected: module row + `demo.m.LIMIT@cfg(unix)` and `demo.m.LIMIT@cfg(windows)` (const rows).

- [ ] **Step 1.2:** Run the gates: `cd /home/john/loomweave && cargo test -p loomweave-plugin-rust --test qualname_conformance`, then the full plugin suite `cargo test -p loomweave-plugin-rust`, then **the actual CI gate** `cargo nextest run --workspace --all-features --no-tests=pass` (fall back to `cargo test --workspace --all-features` if nextest is absent). On mismatch, correct `expected` to the extractor's emission. All green before committing.
- [ ] **Step 1.3:** Commit upstream (ONLY the fixture; never the dirty `.agents/...` file): `git add fixtures/qualnames_rust.json && git commit -m "test(plugin-rust): pin leaf kinds, stacked-cfg fold, cfg reserved-char escape, leaf-kind cfg twin with corpus rows (wardline second-producer conformance)"`. Record the new commit hash and `git rev-parse HEAD:fixtures/qualnames_rust.json` blob hash for Tasks 2/8.

---

### Task 2: Re-vendor + Wardline cfg conformance (stacked-cfg fold, reserved-char escape, nested-param row)

Claims `wardline-4fdad782a7` and the escape half of `wardline-e8f7c0508f` (`filigree start-work <id> --actor rust-gold-sprint --advance`).

**Files:**
- Modify: `tests/conformance/qualnames_rust.json` (verbatim copy of upstream blob)
- Modify: `tests/conformance/test_loomweave_rust_qualname_parity.py` (provenance header; `_KNOWN_KINDS` → the ten-kind set `{module, struct, function, enum, trait, type_alias, const, static, macro, impl}`)
- Modify: `src/wardline/rust/qualname.py` (`_escape_reserved`; `cfg_discriminant`; **`cfg_predicate_of` gains a raw mode** — see the layering note)
- Modify: `src/wardline/rust/index.py` (`_walk_scope` cfg accumulation: last-wins scalar → collect-all RAW list)
- Test: `tests/unit/rust/test_qualname.py`, `tests/unit/rust/test_index.py`

**Layering (locked — mirrors the oracle, prevents the double-escape trap):** loomweave collects predicates RAW (extract.rs:830-843) and normalizes exactly once inside `cfg_discriminant` (qualname.rs:299-302). Wardline's `cfg_predicate_of` currently RETURNS `normalize_cfg_predicate(...)` (qualname.py:99-114) and index.py stores that. Restructure: `cfg_predicate_of` (or a new `raw_cfg_predicate_of`) returns the RAW predicate text; `pending_cfgs: list[str]` accumulates raw strings; `cfg_discriminant(predicates)` = `normalize_cfg_predicate(p)` for each (which now includes `_escape_reserved`), `sorted()`, `"&".join(...)`, wrapped `@cfg(...)`. Normalization+escape happens EXACTLY once. `_escape_reserved` runs after whitespace/paren strip, BEFORE the any()/all() split (qualname.rs:319-336 order).

- [ ] **Step 2.1:** Copy the upstream fixture verbatim: `cp /home/john/loomweave/fixtures/qualnames_rust.json tests/conformance/qualnames_rust.json`. Update the provenance header (source commit + blob hash from Task 1.3). Extend `_KNOWN_KINDS` to the ten-kind set. Run `.venv/bin/pytest tests/conformance/test_loomweave_rust_qualname_parity.py -q` — expect FAILURES on `stacked_cfg_twin` + `cfg_escape_reserved_char` (today: collide on `@cfg(unix)` / no escape); `generic_self_nested_param` must pass immediately (nested-literal rendering already implemented); `leaf_item_kinds`/`leaf_kind_cfg_twin` rows are invisible to the still-function-only comparison (graduates in Task 3).
- [ ] **Step 2.2:** Failing unit tests first (TDD), expected bytes from Task 1's locked gate output:

```python
# tests/unit/rust/test_qualname.py
def test_normalize_cfg_predicate_escapes_reserved_chars() -> None:
    # % before : (order matters — injective, mirrors loomweave escape_reserved)
    assert normalize_cfg_predicate('feature = "a:b"') == 'feature="a%3Ab"'
    assert normalize_cfg_predicate('feature = "a%3Ab"') == 'feature="a%253Ab"'

def test_escape_happens_before_any_all_split() -> None:
    # escape applies to the whole stripped pred BEFORE arg sorting (oracle order)
    assert normalize_cfg_predicate('any(feature = "a:b", unix)') == 'any(feature="a%3Ab",unix)'

def test_cfg_discriminant_folds_all_predicates_sorted() -> None:
    assert cfg_discriminant(['unix', 'feature = "a"']) == '@cfg(feature="a"&unix)'
    assert cfg_discriminant(['feature = "a"', 'unix']) == '@cfg(feature="a"&unix)'  # order-independent

def test_cfg_discriminant_normalizes_exactly_once() -> None:
    # raw input with a reserved char escapes ONCE (no double-escape through the pipeline)
    assert cfg_discriminant(['feature = "a:b"']) == '@cfg(feature="a%3Ab")'
```

```python
# tests/unit/rust/test_index.py
def test_stacked_cfg_twins_get_distinct_folded_suffixes() -> None:
    src = (
        'struct Foo;\n'
        '#[cfg(feature = "a")]\n#[cfg(unix)]\nimpl Foo { pub fn go(&self) {} }\n'
        '#[cfg(feature = "b")]\n#[cfg(unix)]\nimpl Foo { pub fn go(&self) {} }\n'
    )
    names = {e.qualname for e in discover_rust_entities(src, module="demo.m")}
    assert 'demo.m.Foo.impl#<>@cfg(feature="a"&unix).go' in names
    assert 'demo.m.Foo.impl#<>@cfg(feature="b"&unix).go' in names

def test_single_stacked_cfg_impl_without_twin_gets_no_suffix() -> None:
    # dialect: @cfg is a COLLISION discriminator — a lone stacked-cfg impl stays bare
    src = '#[cfg(feature = "a")]\n#[cfg(unix)]\nstruct Foo;\nimpl Foo { pub fn go(&self) {} }\n'
    names = {e.qualname for e in discover_rust_entities(src, module="demo.m")}
    assert 'demo.m.Foo.impl#<>.go' in names
```
Run; verify both new behaviors fail for the right reason.

- [ ] **Step 2.3:** Implement per the locked layering. In index.py the per-item state becomes `pending_cfgs: list[str]` (reset on each non-attribute item; appended per `#[cfg]` attribute); the collision guard is the truthy-list check (`if pending_cfgs:` — NOT `len > 1`); suffix = `cfg_discriminant(pending_cfgs)` applied on collision exactly as today. Run the unit tests, then conformance — `stacked_cfg_twin` + `cfg_escape_reserved_char` rows green.
- [ ] **Step 2.4:** Full quick gate: `.venv/bin/pytest tests/unit/rust tests/conformance -q` green; `.venv/bin/ruff check . && .venv/bin/mypy src` clean. Commit: `fix(rust): fold ALL stacked #[cfg] predicates + mirror cfg reserved-char escape (oracle rows landed upstream) — closes wardline-4fdad782a7`. Filigree: close `wardline-4fdad782a7`; comment on `wardline-e8f7c0508f` (escape half done with oracle row; const-spacing → Task 9 letter).

---

### Task 3: Phase 1b producer surface — leaf kinds, `impl` entity, containment, per-kind twins, full-set conformance

**Files:**
- Modify: `src/wardline/rust/index.py` (emit all ten kinds; parent links; impl entity rows; **generalized per-kind twin counter**)
- Modify: `src/wardline/rust/qualname.py` (constants `RUST_PLUGIN_ID = "rust"`, `RUST_ONTOLOGY_VERSION = "0.4.0"`, and `entity_id(kind, qualname)` — qualname.py is the dialect home, NOT `__init__.py`)
- Modify: `src/wardline/rust/analyzer.py` (**add the callable filter — it does not exist today**)
- Modify: `tests/conformance/test_loomweave_rust_qualname_parity.py` (graduate subset-consumer → full-set comparison)
- Test: `tests/unit/rust/test_index.py`, `tests/unit/rust/test_qualname.py`

**Design (locked):**
- `RustEntity.kind` extends over the full id-kind set (`module|struct|function|enum|trait|type_alias|const|static|macro|impl`; Wardline's semantic `method` kept, mapped to id-kind `function` at emission/comparison) + new field `parent: str | None` (qualname of the containing module or impl entity). All entities carry `node_id`/`location` (needed for edges/federation).
- `entity_id(kind, qualname)` returns `f"rust:{kind}:{qualname}"`, maps `method`→`function` ITSELF, and raises on kinds outside the ten-kind set (mirrors loomweave's build_entity_id validation posture).
- **Emit ordering (matches the corpus — verified against `free_fns_and_struct`, `nested_inline_mod`, `same_type_name_distinct_module_scopes`):** the FILE-SCOPE module entity is emitted FIRST (before any items); inline `mod` entities are emitted AT their source position (before recursing into them); the merged `impl` entity is emitted once at the first contributing block in source order; everything else at its source position.
- **Twin counter generalized per-(kind, name)** over all nine named item kinds (mirror extract.rs:326-358) — `fn S` and `struct S` never interfere; the `@cfg` suffix applies per-kind on collision (struct_cfg_twin + new leaf_kind_cfg_twin rows are the trip-wires).
- **The taint path gets an explicit guard:** analyzer.py:138-153 currently iterates ALL entities calling `taint_for(entity.node)` and `child_by_field_name("body")` unconditionally — add `if entity.kind not in ("function", "method"): continue` at the loop top, and count `functions_total` (the coverage metric) over callables only.

- [ ] **Step 3.1:** Failing unit tests:
  - leaf kinds emission (enum/trait/type_alias/const/static with qualname `<module>.<name>`, parent = module; `macro_rules! name` → `macro` entity; bare invocation → nothing — keep the existing guard test),
  - impl entity rows (post-merge, `…Foo.impl#<>` / `…Foo.impl[Display]` incl. `@cfg` forms),
  - containment (method.parent == impl entity qualname; impl.parent == module; free items' parent == module),
  - `test_merged_impl_emitted_at_first_block_in_source_order` — two same-key inherent blocks: the ONE impl entity appears before both blocks' methods and its `location.line_start` is the FIRST block's line,
  - `test_file_module_entity_emitted_first_and_inline_mods_at_source_position` — pin the ordering rules above,
  - `test_per_kind_twin_counting` — `fn S` + `struct S` with cfg on one: no cross-kind suffix interference,
  - `test_non_callable_entities_do_not_enter_taint_analysis` — a file with struct/enum/const/trait + one tainted `Command::new` function: `RustAnalyzer.analyze` returns exactly the function's findings; no crash, no extra findings,
  - `test_emission_is_deterministic` — `discover_rust_entities` twice on the same source → byte-identical ordered lists,
  - `test_entity_id_maps_method_and_validates_kind` — `entity_id("method", q) == f"rust:function:{q}"`; unknown kind raises.
- [ ] **Step 3.2:** Implement in `index.py` (lift the existing impl-key/merge-triple machinery into emitted `impl` entities; emit the file-scope module first; generalize the twin counter), `qualname.py` (constants + `entity_id`), `analyzer.py` (callable guard + callable-scoped coverage counter). Unit tests green.
- [ ] **Step 3.3:** Graduate the conformance comparison: rewrite `test_entity_qualnames` (and its helper `_expected_function_qualnames` → `_expected_all_pairs(case)`) to compare Wardline's FULL emission as an **ordered list of `(qualname, kind)`** (kind-mapped `method`→`function`) against the corpus `expected` list exactly — this matches loomweave's own ordered gate; the subset-consumer rule in `_consumer_comparison` forbids list-equality only for function-only consumers, which Wardline no longer is. The Step-3.1 ordering tests de-risk this; if a case still fails ONLY on order (qualname sets equal), STOP and check the corpus row's order against `discover_rust_entities` — fix the emitter, never the comparison. Run conformance: ALL rows green including `leaf_item_kinds` + `leaf_kind_cfg_twin`.
- [ ] **Step 3.4:** Full suite + lints (`.venv/bin/pytest -q`, ruff, mypy) — eyeball the conformance output for source-order alignment, not just pass/fail. Commit: `feat(rust): full ADR-049 producer surface — six leaf kinds, impl entity, module→impl→method containment, per-kind cfg twins, full-set conformance`.

---

### Task 4: SP2 whole-tree — crate roots from Cargo.toml, cross-file routes, un-xfail

**Files:**
- Create: `src/wardline/rust/crate_roots.py`
- Modify: `src/wardline/rust/analyzer.py` (`_module_for` → crate-root-aware)
- Modify: `tests/conformance/test_loomweave_rust_qualname_parity.py` (remove BOTH sp2 auto-xfail branches, :144-145 and :154-155)
- Test: `tests/unit/rust/test_crate_roots.py` (new)

**Design (locked, panel-corrected — mirror `/home/john/loomweave/crates/loomweave-plugin-rust/src/crate_roots.rs` exactly; read it first):**
- **Manifest read:** parse `Cargo.toml` with stdlib `tomllib` (the oracle does a real `toml::Value` parse — "read as text" in ADR-049 means "not cargo-metadata", NOT a hand-rolled scan). Take `package.name` only if it parses AND is a string (`name.workspace = true` is a table → falls through to fallback). Unparseable TOML → fallback path.
- **Registration rule (two branches):** a dir is a crate root iff (a) its Cargo.toml yields a string `[package].name` → that name `-`→`_` normalised; ELSE (b) `src/lib.rs` or `src/main.rs` exists → directory-name normalised. A virtual workspace root (no package.name, no src/lib|main.rs) registers NOTHING — member crates own their files outright.
- **Walk:** skip symlinked directories (crate_roots.rs:83-94; use `os.scandir` + `entry.is_symlink()`, never a follow-links walk). File→crate by longest path-prefix match.
- **Scan coverage is NOT narrowed (the panel's must-fix):** loomweave's `emittable_scope` (scope.rs:21-32) EXCLUDES tests/, benches/, examples/, build.rs, shadowed src/main.rs, and no-crate-root files — that is its *federation entity surface*, not a scan filter. Wardline keeps scanning ALL discovered `.rs` files. Routing: files under a crate root's `src/` get the oracle route (`rust_module_route(crate, src_root=<root>/src, file)`); all other files (tests/, build.rs, no-Cargo trees — including today's entire preview population) get a documented wardline-local fallback route (current behavior: crate = owning crate name if any else directory name, mechanical path route) with a module docstring stating those qualnames carry no cross-tool conformance claim (loomweave emits nothing there, so no collision is possible). `#[path]` stays un-honoured (shared known gap — `path_attr_known_gap` pins the mechanical form).

- [ ] **Step 4.1:** Failing tests (`tmp_path` fixtures):
  - single crate: `Cargo.toml` `name = "my-app"` → crate `my_app`; `src/lib.rs` → `my_app`; `src/a/b.rs` → `my_app.a.b`; `src/a/mod.rs` → `my_app.a`,
  - virtual workspace root (`[workspace]`-only Cargo.toml, no src/) with two members → ONLY the members register; `members' src files route to their own crates`,
  - NESTED crates: `outer/Cargo.toml` (`outer`) + `outer/inner/Cargo.toml` (`inner`) → `outer/src/lib.rs` → `outer`, `outer/inner/src/main.rs` → `inner` (longest-prefix),
  - `name.workspace = true` manifest WITH `src/lib.rs` → dir-name fallback; package-less manifest WITHOUT src/lib|main.rs → not a root,
  - symlinked external crate dir under the scan root → NOT registered (mirror loomweave's `does_not_register_crate_roots_reached_through_symlinked_dirs`),
  - **coverage preservation:** `build.rs`, `tests/integration.rs`, and a bare no-Cargo `.rs` tree still produce RS-WL findings via the fallback route (pin that scan population is unchanged).
- [ ] **Step 4.2:** Implement `crate_roots.py`; wire `analyzer.py::_module_for` through it (keeping per-file isolation/error posture). Existing analyzer tests that assumed `crate=root.name` update only where a fixture grows a `Cargo.toml`.
- [ ] **Step 4.3:** Remove BOTH `pytest.xfail("sp2 …")` branches; sp2 rows assert for real (`path_attr_known_gap` passes mechanically). Run conformance: **0 xfail**. Full suite: xfail count 1→0. Defensive check: `grep -rn "RS-WL" .weft/ 2>/dev/null || echo clean` → clean (no stored fingerprints to orphan).
- [ ] **Step 4.4:** Commit: `feat(rust): SP2 whole-tree — Cargo.toml crate roots (tomllib, two-branch registration, symlink-safe), real crate-prefixed routes, sp2 conformance rows un-xfailed`.

---

### Task 5: Anchored edges — `imports` + `implements`

**Files:**
- Create: `src/wardline/rust/edges.py`
- Test: `tests/unit/rust/test_edges.py` (new)

**Design (locked, per changeset §6 + the oracle source for what §6 leaves open — the corpus is entity-only; pin these citations in test docstrings):** `RustEdge` frozen dataclass `{kind: Literal["imports","implements"], from_id: str, to_id: str, source_byte_start: int, source_byte_end: int, confidence: Literal["resolved","ambiguous"]}` (never `inferred`). `discover_rust_edges(...)` resolves against the whole-tree entity index (Tasks 3+4). Semantics:
- `imports`: one per file-scope `use` leaf; `from_id` = enclosing module entity; use-tree GROUPS fan out (`use a::{B, C}` → two edges); `use a::B as C` resolves the REAL path `a::B` (alias dropped); a `self` group leaf (`use a::{self, B}`) → the prefix module `a` (extract.rs:634-665). Glob `use a::*`: in-project module → `ambiguous` edge to that module entity; else dropped (resolve.rs:40-49). Unique in-project target → `resolved`; multi-kind candidate set → `ambiguous` with `to_id` = FIRST id by sorted order — deterministic, never null (resolve.rs:13-17); external/unresolvable → DROPPED. Span = the `use` statement.
- `implements`: one per trait impl whose trait resolves in-project; `from_id` = the trait-impl entity id; trait lookup STRIPS generic args (`impl MyTrait<i32> for Foo` resolves `MyTrait` — extract.rs:788-794); negative impls (`impl !Send for X`) emit NO edge; merged twin blocks emit exactly ONE edge per impl entity. Span = the implemented-trait path node only.
- Path resolution: `crate::`/`self::`/`super::` prefixes + plain relative paths against the module routes; when in doubt, drop (D1). ids via `entity_id()`.

- [ ] **Step 5.1:** Failing tests (multi-file `tmp_path` fixtures): the base two-file resolved case (`use crate::Greet` + `impl Greet for Foo` → one `imports` + one `implements`, both `resolved`, spans pinned); `super::` and nested `super::super::` resolution; use-tree group fan-out + `as`-alias real-path + `self` group leaf; glob in-project → `ambiguous(module)`, glob external → dropped; multi-kind ambiguity → `ambiguous` + first-by-sorted-order to_id; external `use std::fmt` → no edge; generic in-project trait `impl MyTrait<i32> for Foo` → resolved to `MyTrait`; negative impl → no edge; two merged same-key trait-impl blocks → exactly one `implements` edge; `confidence` never `inferred`.
- [ ] **Step 5.2:** Implement `edges.py`. Resolved-or-dropped throughout.
- [ ] **Step 5.3:** Full suite + lints. Commit: `feat(rust): anchored imports/implements edges (resolved-or-dropped, §6 contract + oracle-cited semantics)`.

---

### Task 6: Freeze `tests/golden/identity/rust/` (the SP2 completion gate)

**Files:**
- Create: `tests/golden/identity/rust/{__init__.py,README.md,_capture.py,regen.py,test_rust_identity_parity.py,fixtures/rustapp/...,corpus/...}` — follow the Python oracle's conventions (read `tests/golden/identity/{README.md,_capture.py,regen.py}` first: LF-pinned fixtures via `.gitattributes`, no `.weft/`/`weft.toml` in fixtures, META.json with corpus_version/scheme/reason)

**Design (locked):** the Rust capture is a PARTIAL mirror by necessity: `RustAnalysisContext` is not the Python `AnalysisContext` (analyzer.py last_context → None), so SARIF code-flows / taint facts / explain are NOT capturable — the Rust identity surface is **findings** (`Finding.to_jsonl()` for `RS-WL-* ∧ Kind.DEFECT` — the `is_identity_bearing` predicate filters `RS-WL-*`, not `PY-WL-*`) + **entity rows** (qualname, id-kind, parent, span for EVERY emitted entity) + **edges**. State this in the rust README. Fixture = vendored crate `fixtures/rustapp/` (`Cargo.toml` `name = "rust-app"` → crate `rust_app`; `src/main.rs` + `src/cmd/runner.rs`) exercising: RS-WL-108 (tainted program), RS-WL-112 (tainted sh -c arg), a `/// @trusted(level=ASSURED)` marker, an impl method, a cfg twin, and at least one leaf kind. **Constraint: NO path-typed generic args anywhere in the fixture** (`impl From<std::io::Error>` is the un-decided reserved-colon case — freezing it would pre-empt Task 9's cross-tool decision; record the constraint in the rust README).

- [ ] **Step 6.1:** Write `_capture.py` + `regen.py` + the fixture crate + the parity test; run `regen.py` ONCE to seed `corpus/`.
- [ ] **Step 6.1b (non-vacuity — must pass before freezing):** assert over the seeded JSON: (a) ≥1 finding row per rule (`RS-WL-108` AND `RS-WL-112`), each `fingerprint` non-empty; (b) ≥1 entity row with `kind == "impl"`; (c) ≥1 qualname containing `@cfg(`; (d) ≥1 qualname prefixed `rust_app.cmd.runner` (real crate prefix + cross-file route — NOT a directory name); (e) ≥1 edge. Encode these as permanent structural tests in `test_rust_identity_parity.py` (the analogue of the Python oracle's non-vacuity tests), not a one-off eyeball.
- [ ] **Step 6.2:** Parity test green on a fresh run. Trip-wire proof: mutate a **fingerprint hex char** in the seeded corpus findings (NOT a message string), run → test FAILS; revert; mutate one **qualname** in the entity rows, run → FAILS; revert. Commit: `test(identity): freeze the Rust finding-identity corpus (SP2 completion gate) — crate-prefixed RS-WL-* identity`.

---

### Task 7: Identity graduation — remove provisional plumbing, retire the banner claim, docs

**Files:**
- Modify: `src/wardline/rust/rules.py:141` (remove the `"provisional_identity": True` entry from the `properties` dict in `_finding()`)
- Modify: `src/wardline/core/suppression.py:68-77` (drop the provisional short-circuit — the whole if-block incl. the `continue`; the SEPARATE `Maturity.PREVIEW` guards at :104/:127 are a different mechanism used by Python preview rules — LEAVE THEM)
- Modify: `src/wardline/core/baseline.py:55-62` (drop the provisional exclusion)
- Modify: `src/wardline/cli/scan.py:157-168` (banner: drop ONLY the "provisional identity (baseline-ineligible)" claim. The severity-override claim is STILL TRUE — analyzer.py:84-85: weft.toml severity overrides do not apply to Rust — so KEEP it. New banner: `note: --lang rust covers the command-injection slice (RS-WL-108/112); config severity overrides do not yet apply to Rust findings.`)
- Modify: `tests/unit/rust/test_provisional_identity.py` → rename `test_rust_identity_graduated.py`, INVERT (a matching baseline entry now suppresses; `build_baseline_document` now includes RS findings)
- Modify: `docs/guides/rust-preview.md` (graduate: provisional/baseline-ineligible warning → baseline-eligible statement; KEEP coverage-scope + severity-override warnings), `docs/guides/agents.md:294` (same stale sentence — panel-found), `docs/reference/cli.md`, `CHANGELOG.md` [Unreleased]
- Modify: `src/wardline/rust/qualname.py:20` + `analyzer.py:176` docstrings (stale provisional references)

- [ ] **Step 7.1 (TDD):** Invert the two provisional tests first; watch them fail against current code.
- [ ] **Step 7.2:** Remove the plumbing (4 code sites); tests pass. Scoped grep: `grep -rn "provisional" src/ tests/ docs/guides/ docs/reference/ CHANGELOG.md` — zero hits outside the CHANGELOG's historical entries (archived plans/specs under docs/superpowers/ are exempt history). Verify no other consumer of `provisional_identity` exists anywhere in `src/`.
- [ ] **Step 7.3:** Docs + CHANGELOG (one [Unreleased] entry: full producer surface, SP2 whole-tree identity, baseline eligibility, BREAKING note that RS-WL fingerprints change once — they were never baseline-eligible, no migration needed; severity-override gap persists and is tracked). `mkdocs build --strict` green. Commit: `feat(rust)!: graduate RS-WL-* identity — baseline-eligible, provisional plumbing removed`.

---

### Task 8: Corpus drift alarm (closes `wardline-868908944b`)

**Files:**
- Modify: `tests/conformance/test_loomweave_rust_qualname_parity.py`
- Modify: `pyproject.toml` (register `loomweave_drift` in `[tool.pytest.ini_options].markers` AND append `and not loomweave_drift` to the `addopts` `-m` exclusion — BOTH are required; markers-only would run it in the default suite and fail in CI where the sibling checkout is absent)

**Design (locked, deliberately light):**
1. **Byte-pin:** constant `UPSTREAM_BLOB_SHA = "<hash from Task 1.3>"` + a test computing the git blob hash of the vendored file — read in BINARY mode, `hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()` — asserting equality, plus a sanity assert (40 lowercase hex chars). Cross-check the constant once via `git hash-object tests/conformance/qualnames_rust.json` (the reference oracle for the formula) before committing.
2. **Live recheck (opt-in):** `@pytest.mark.loomweave_drift` test: locate the sibling checkout (`WARDLINE_LOOMWEAVE_REPO` env override, default `/home/john/loomweave`); absent → `pytest.skip`; present → byte-compare `fixtures/qualnames_rust.json` to the vendored copy, FAIL on drift with a "re-vendor + conform (see test header)" message. Document the re-vendor as a release-gate item in the test header.

- [ ] **Step 8.1:** Write both tests; run the blob-pin in the default suite and `-m loomweave_drift -v` live — green against the Task-1 upstream commit. Verify the default suite still deselects it (`pytest -q` collects no loomweave_drift test). Commit: `test(conformance): corpus drift alarm — upstream blob byte-pin + opt-in live recheck (closes wardline-868908944b)`. Filigree: close `wardline-868908944b`.

---

### Task 9: Reserved-colon + const-arg-spacing ADR-049 decision letter (no implementation)

Claims `wardline-be5ee9cc34` (`--advance` walks triage→confirmed; do NOT move to fixing — it stays blocked on the cross-tool decision; release the claim after the letter lands and record the dependency instead).

**Files:**
- Create: `docs/integration/2026-06-10-wardline-loomweave-rust-qualname-amendment-requests.md`

- [ ] **Step 9.1:** Draft the letter (Wardline → Loomweave), three sections:
1. **Reserved-colon path-typed generic args** (the decision request): today `impl From<std::io::Error> for Foo` renders a `:`-bearing locator that Wardline emits un-gated and Loomweave rejects-and-degrades whole-file (`validate_no_colon`, entity_id.rs:140) — both bad endpoints, ubiquitous in real Rust. **Propose:** extend the existing injective `escape_reserved` (`%`→`%25`, `:`→`%3A`) — already the dialect's cfg-predicate precedent — to `type_textual` rendering inside `impl[...]`/`<...>` fragments, so `From<std::io::Error>` → `From<std%3A%3Aio%3A%3AError>`: collision-free (unlike last-segment: `io::Error` vs `fmt::Error`), reversible, one normalizer for both producers. Name the rejected alternatives (last-segment collision; degrade-whole-file loses every entity in the file for one impl). Request corpus rows (`path_typed_generic_arg_inherent`, `path_typed_generic_arg_trait`) and an ADR-049 §2 amendment.
2. **Const-generic-arg spacing**: propose the oracle strip_ws const args (`Foo<{N+1}>` not `Foo<{ N + 1 }>`), converging on the whitespace-free form Wardline already renders; request a corpus row.
3. Record that leaf-kind, stacked-cfg, cfg-escape, and leaf-kind-cfg-twin rows were vendored upstream by this sprint (Task 1 commit hash) — closing those from the amend3 tail.
- [ ] **Step 9.2:** Filigree: comment on `wardline-be5ee9cc34` + `wardline-e8f7c0508f` with the letter path; create a blocker issue "Loomweave ADR-049 reserved-colon decision (letter sent, awaiting amendment + corpus rows)" and `dependency_add` from be5ee9cc34 to it. Commit: `docs(integration): ADR-049 amendment requests — reserved-colon escape proposal + const-arg spacing`.
- [ ] **Step 9.3:** Surface in the final report: the letter needs the user's sign-off before sending/implementing.

---

### Task 10: Hard-gates sweep, merge, filigree closes

- [ ] **Step 10.1:** The full gate matrix, all green, output captured:
  - `.venv/bin/pytest -q` (full suite) — then machine-check the xfail gate: `.venv/bin/pytest -q 2>&1 | tail -2` must show **0 xfailed**, and `grep -c "pytest.xfail" tests/conformance/test_loomweave_rust_qualname_parity.py` must be 0
  - `.venv/bin/pytest -m rust_e2e -v`
  - `.venv/bin/pytest -m loomweave_drift -v` (live oracle check)
  - Python identity oracle: `.venv/bin/pytest tests/golden/identity -q` — all green incl. the 3 byte-identity corpus checks (any byte diff is a sprint-stopping regression)
  - Rust identity oracle: `.venv/bin/pytest tests/golden/identity/rust -q`
  - `.venv/bin/ruff check . && .venv/bin/ruff format --check .`
  - `.venv/bin/mypy src`
  - `.venv/bin/mkdocs build --strict`
  - Self-scan: `.venv/bin/wardline scan . --fail-on ERROR` (exit 0)
- [ ] **Step 10.2:** Merge `feat/rust-gold` → `rc5`: from the MAIN checkout (`/home/john/wardline`), verify `git status` (the dirty files are ci.yml/.gitignore/docs/index.md/mkdocs.yml/docs/arch-analysis — all disjoint from sprint paths), `git merge --no-ff feat/rust-gold`, verify the dirty files are untouched after. **Re-run the gate on the post-merge rc5 tree** (`pytest -q tests/unit/rust tests/conformance tests/golden` + `mkdocs build --strict` — the rc5 checkout's mkdocs.yml differs from the worktree's).
- [ ] **Step 10.3:** Filigree: verify closes (4fdad782a7, 868908944b), comments + dependency on be5ee9cc34/e8f7c0508f, close the umbrella `wardline-9f00d5b44b` only if every gate held; `observation_list` skim per CLAUDE.md.

---

## Self-review notes (spec-coverage check)

- Prompt scope 1 (SP2 whole-tree) → Task 4. Scope 2 (Phase 1b surface) → Tasks 1–3, 5. Scope 3 (identity graduation) → Tasks 4 (rekey), 6, 7. Scope 4 bugs → Tasks 1–2 (4fdad782a7), 2+9 (e8f7c0508f), 9 (be5ee9cc34), 8 (868908944b).
- Known deviations from the sprint prompt, justified by verified oracle ground truth: (a) the `_KNOWN_KINDS` guard does NOT trip on today's upstream corpus (no leaf-kind rows exist upstream) — Task 1 creates the rows the prompt assumed, then Tasks 2–3 do the guard/producer work; (b) "worktree + work directly on rc5" contradiction resolved as worktree branch `feat/rust-gold` merged to rc5 at the end (Task 10).
- Edges have no corpus rows (entity-only corpus) — changeset §6 + cited oracle source (resolve.rs/extract.rs) are the contract; tests pin both, citations in docstrings.
