# Wardline Rust Frontend — Architecture Design

**Status:** Draft for review (panel-hardened, round 1) · **Date:** 2026-06-08 · **Branch:** `feat/rust-plugin`
**Scope of this document:** the program-level architecture (the "ceiling") for giving Wardline a
second language frontend that scans Rust (`.rs`) source for trust-boundary / taint findings, plus
the decomposition into buildable sub-projects. The detailed implementation plan for the first
vertical slice (command-injection) is a sibling document:
`docs/superpowers/plans/2026-06-08-wardline-rust-frontend-slice1-command-injection.md`.

> **Revision note.** This draft incorporates a 7-reviewer adversarial panel (reality / solution-design
> / architecture / systems / quality / rule-designer / security). Decisions previously left open are
> now resolved inline; see the changelog at the end (§13).

---

## 1. Context and the decision that frames this work

Wardline today has exactly one language frontend: CPython's `ast`. There is **no named "frontend"
abstraction** — the AST leaks across nearly every pipeline stage boundary
(`scanner/pipeline.py`, `scanner/analyzer.py`, `scanner/index.py`, and every rule). A "Rust plugin"
means a **second frontend** that produces the same engine-internal facts from Rust source, reusing
the taint lattice, the trust grammar, the L3 fixpoint, the summary cache, and the `Finding` output
contract.

### 1.1 Two interpretations — the chosen one, and its cost

"Rust plugin for wardline" has two orthogonal readings:

- **Rust-as-target** (this document): a language *frontend* so Wardline can **scan** Rust source.
- **Rust-as-implementation**: rewriting the analysis *engine* in native Rust (PyO3 + maturin).

These are independent axes — a Python-core Wardline can scan Rust; a Rust-core Wardline can scan
only Python. Wardline already has a **prepped-but-unstarted native-core migration** (the
`Rust-as-implementation` axis): the identity-parity oracle (`tests/golden/identity/`) and ADR
`docs/decisions/2026-06-05-wardline-finding-identity-frozen-contract.md` ("Python parser gone,
Rust tomorrow") were built specifically to gate that cutover.

**Decision (user, 2026-06-08): build the Rust *frontend* now, as an interim Python frontend
(tree-sitter), on today's Python engine** — accepting that, like the rest of the Python scanner, it
gets re-ported to Rust at the native-core cutover.

**Reversibility / cost of the interim (why it still wins).** The work splits cleanly across the
re-port:

- **Survives the cutover** (engine middle, reused verbatim — §3.1): lattice, L3 kernel, summary
  cache, `Finding`/fingerprint, `modulate`, the rule-verdict core, *and* the design artifacts here
  (the qualname dialect, the vocabulary schema, the tier map, the rule semantics).
- **Re-written in Rust at the cutover** (the Python-hosted frontend logic): the tree-sitter parse +
  index, the builder-dataflow L2 (§9.3, the genuinely new code), the trust provider.

The interim path wins because the native-core cutover is **unstarted with an unknown timeline**,
Rust-scanning value is wanted **now**, and the re-written fraction is exactly the part whose *design*
(not code) is the expensive thing — and that design is captured here and survives. If the native
cutover were imminent, sequencing it first (build the Rust frontend once, in Rust) would be the
better call; it is not, so the interim is chosen with eyes open.

### 1.2 Prior art in-repo (read before implementing)

- `docs/superpowers/plans/2026-06-05-wardline-pre-rust-core-hardening.md` — the native-core prep;
  Task A's identity oracle (built, in CI) is the cross-engine identity contract this frontend must
  honor. Tasks B (vocabulary descriptor) and C (native-module self-scan allowlist) should be
  confirmed complete before SP6's self-scan gate (§11). Note: `tree_sitter` is a *third-party*
  package, not `wardline.core`, so Task C's first-party allowlist does not cover it — but the
  `wardline[rust]` extra is opt-in and the standard self-scan runs in a base env, so this is a
  non-issue for the self-scan path (confirm at SP6).
- `tests/conformance/qualnames.json` + `tests/conformance/test_loomweave_qualname_parity.py` — the
  cross-tool qualname grammar; the Rust qualname dialect (§6) needs a counterpart.
- `docs/decisions/2026-05-31-wardline-taint-lattice-retain.md` — why the 8-member lattice is fixed.

---

## 2. The load-bearing reframe: a semantic-capability ceiling

The single most important design fact: **tree-sitter is a parser, not a compiler frontend.** It
yields a concrete syntax tree — *no types, no name/trait resolution, no macro expansion*. A Rust
sink's reachability depends on how much semantic information you need to *see* it, so the honest
"most general version" is **tiered**, not "all sinks." This tier map governs every promise the spec
is allowed to make.

| Tier | Needs | Example sink families | tree-sitter alone |
|------|-------|----------------------|-------------------|
| **A** | syntax + constructor/`let` type-tracking | command injection (`std::process::Command`), path traversal, `unsafe`/FFI boundaries | ✅ sound enough |
| **B** | trait/type resolution | sinks behind trait methods, `Deref`-hidden receivers, generic dispatch | ⚠️ unsound (cannot resolve dispatch) |
| **C** | macro expansion | `sqlx::query!`/ORM proc-macros, `serde` derive, code generated by declarative macros | ❌ opaque (expansion never runs) |

Calibration (verified, recon R6, reality-panel confirmed):

- **Macro *invocations* are visible as token trees, expansion is not.** `macro_invocation` exposes a
  `token_tree` of **raw tokens** (`repeat($._tokens)`), not parsed expressions. So `format!("rm {}",
  user_input)` shows `user_input` as an `identifier` *token* — a **heuristic, lexical** taint signal
  (Tier-A/B), never structured arg positions or types.
- **SQLi's injectable form is the *function* call** `sqlx::query(runtime_string)` — that callee is a
  plain `call_expression`. The checked-safe `query!` *macro* is the opaque one. So the danger is the
  `format!`/concatenation feeding the function, not the macro.
- **`serde` derive is an `attribute_item`, not a `macro_invocation`** — strictly Tier-C (we see the
  annotation, nothing of the generated impl).

**Parser decision:** tree-sitter-rust for the **Tier-A floor**, with a **named escalation path**
(rust-analyzer / `rustc` MIR / `cargo expand`) documented for Tier-B/C as opt-in depth in later
sub-projects. The spec promises Tier-A soundness, Tier-B/C as explicitly-bounded heuristics.

---

## 3. Architecture: shared engine + an extracted frontend seam

### 3.1 What is already language-neutral (reuse verbatim)

Recon (R1, R3, reality-panel confirmed) shows a clean split. **Reusable as-is, no per-language work:**

- The **taint lattice** — `TaintState` (8 members), `TRUST_RANK`, `RAW_ZONE`, `least_trusted` (the
  live join), `taint_join`, `combine` (`core/taints.py:19-121`). Pure enum + integer-rank lookup.
- The **L3 fixpoint kernel** — `propagate_callgraph_taints(edges, taint_map, taint_sources,
  resolved_counts, unresolved_counts, ...)` (`scanner/taint/propagation.py:189-203`). **AST-free**:
  call-edge graph + `TaintState` maps + counts only.
- The **summary cache** — `FunctionSeed` (`scanner/taint/function_level.py:26-41` — *not* summary.py),
  `FunctionSummary` + `compute_cache_key` (`scanner/taint/summary.py:56-104`), `SummaryCache`,
  `module_summariser.summarise_module` (operates on seeds + counts, not AST).
  **`compute_cache_key` has six inputs**: `module_path`, `source_bytes`, `schema_version`,
  `resolver_version`, `provider_fingerprint`, **`scan_policy_hash`** (the policy-identity slot — do
  not conflate it with the vocabulary version, §8.1).
- The **output contract** — `Finding`, `Location`, `Severity`, `Kind`, `compute_finding_fingerprint`
  (`core/finding.py:79-151`). Fully neutral; Filigree wire-mapping keys off severity only.
- The **severity model** — `modulate(base, taint)` (`scanner/rules/severity_model.py:47-53`), the
  tier-modulation that silences the freedom zone.
- The **rule dispatch seam** — `Rule` protocol (`rule_id` + `check(context) -> Sequence[Finding]`,
  `core/protocols.py:24-27`), `RuleRegistry`, `build_default_registry` (`scanner/rules/__init__.py`).

### 3.2 What is Python-specific (needs a per-language implementation)

- Parse + `discover_file_entities` / `discover_class_qualnames`, `build_import_alias_map`,
  `seed_function_taints` (marker/provider inspection of `decorator_list`).
- `build_call_edges` (call resolution **and node-id minting** — see §5).
- L2 — `analyze_function_variables` (`scanner/taint/variable_level.py`, ~180 `ast.*` references —
  the heaviest single file) + `collect_attribute_writes`.
- `_bind_call_site_arguments_to_parameters` — hard-codes Python parameter kinds
  (posonly/args/kwonly/`*args`/`**kwargs`).
- **All rules** — they walk `entity.node` (raw AST) to **locate** sink call sites, e.g.
  `sql_injection.py:84-117` does `isinstance(node, ast.Call)` / `node.func.attr` / `node.lineno`.

### 3.3 The seam to introduce

There is no `frontend` package today; this work introduces one. The seam is **two interfaces**:

1. **`ParseFrontend`** — given a source file, produce `list[ModuleInput]` + a `ParsedFile`-equivalent,
   where `Entity.node: ast.FunctionDef` is replaced by an **opaque, frontend-owned node handle** and
   each call/statement carries a **stable `NodeId`** (§5). The neutral payload of `ModuleInput`
   (`module_path`, `class_qualnames`, `alias_map`, `seeds: Mapping[str, FunctionSeed]`,
   `source_bytes`) is unchanged; only `entities` becomes frontend-typed.
2. **A per-language analysis family** parameterized over that node handle: the L2 variable analyzer,
   the call-edge builder, the param binder, and the rule sink-locators.

The **engine middle stays shared**: L3 kernel + cache + lattice + `modulate` + `Finding`. The
`FunctionSeed` record is the **one fully-neutral interprocedural contract** every frontend emits.

> **Sequencing reality (panel fix).** The full seam extraction is **SP1**, but SP1 is *not* a forward
> prerequisite — slice 1 builds the Rust path against the engine middle directly and accepts some
> duplication, and SP1 then refactors the *shipped* Python+Rust code into the shared `ParseFrontend`
> (rule of three). **What the slice validates:** that the engine middle can produce real `Finding`s
> from a non-Python source. **What it does NOT validate:** that the engine middle can be *cleanly
> factored* to host two frontends behind one interface — that is SP1's risk and is the reason SP1
> exists as a named refactor (§11), not why it is sequenced first.

### 3.4 The rule, split correctly

Rules do **two** things: (1) **locate** sink call sites by walking the tree (per-language), and (2)
**adjudicate** (neutral). The durable seam is a **neutral verdict core** fed by a **per-language
sink-site locator**. The verdict core is precisely: tier-modulate (`modulate`) + a **`RAW_ZONE`
membership test on a *selected* `TaintState`** + emit a `Finding`. **The selection differs per
rule** — it is *not* always "worst-of-args":

- `RS-WL-108` selects the single **`program_taint`** (the executable identity).
- `RS-WL-112` selects **`worst-of(arg_taints)`** conditioned on the shell gate.

Stating it as "RAW_ZONE on a selected TaintState" (not "worst-of selector") prevents an implementer
from feeding `RS-WL-108` the arg list (which would blur it into `RS-WL-112`). Slice 1 may inline the
verdict core in the Rust rules; SP5 extracts it once the second Rust rule lands.

### 3.5 Reuse boundary diagram (textual)

```
            Rust source (.rs)
                  │
   ┌──────────────▼───────────────┐   PER-LANGUAGE (new, Python-hosted, tree-sitter)
   │ RustParseFrontend            │   - parse → CST (tree-sitter-rust)
   │  · module-route resolution   │   - entities + Rust qualname dialect (§6)
   │  · alias map (use-decls)      │   - L1 seed via RustTrustProvider (§7)
   │  · stable NodeId minting (§5) │   - builder-dataflow L2 (§9)
   │  · call-edge builder          │   - command-injection sink locators (§9)
   └──────────────┬───────────────┘
                  │  ModuleInput(seeds: FunctionSeed, …)  + per-trigger arg-taint maps keyed by NodeId
   ┌──────────────▼───────────────┐   SHARED (reused verbatim)
   │ Engine middle                │   - propagate_callgraph_taints (L3; trivial for slice 1)
   │  · TaintState lattice/combine │   - SummaryCache / compute_cache_key
   │  · modulate / RAW_ZONE gate   │   - Finding / Location / fingerprint
   └──────────────┬───────────────┘
                  │  Finding[]  (rule_id="RS-WL-*", Rust qualname, relpath Location)
                  ▼
        run_scan: baseline / waiver / gate / SARIF / JSONL / Filigree   (unchanged, neutral)
```

### 3.6 Interim status and the cross-engine identity obligation

Because this is the **interim Python frontend** (re-ported at the native-core cutover), two
obligations keep it from creating drift the migration would have to unwind:

- **The dialect is FIXED (Loomweave ADR-049); `RS-WL-*` identity stays baseline-ineligible until SP2
  for a narrower reason.** The Python identity oracle is `PY-WL-* ∧ Kind.DEFECT` only; it excludes
  `RS-WL-*`. As of 2026-06-09 the Rust qualname dialect is no longer the blocker — Loomweave fixed it
  (§6) and published the byte-exact corpus Wardline vendors. What remains provisional is the
  **crate-rooted prefix**, which is SP2 (it needs `Cargo.toml`, §6.3): slice-1 qualnames are
  file-module-rooted and reproducible, but the prefix gains its real crate value at SP2, changing each
  fingerprint once. So **`RS-WL-*` findings stay identity-provisional and baseline-ineligible** until
  SP2 — the CLI/MCP output and preview docs must say so, so users don't accumulate Filigree
  associations / baselines that the SP2 crate-prefix rekey would orphan. The **format drift-gate**
  (`tests/conformance/qualnames_rust.json`, vendored from Loomweave — §6.4) catches accidental dialect
  divergence now; the **frozen** `tests/golden/identity/rust/` finding corpus is the SP2 completion
  gate.
- **Do not produce the unreachable lattice states (with one precise exception).** `UNKNOWN_GUARDED`
  and `UNKNOWN_ASSURED` are **unconditionally** unreachable under sound analysis and the cache
  rehydration guard rejects them (`summary_cache.py:53-85`). **`MIXED_RAW` is unreachable *except*
  under `provenance_clash` mode**, where it is a legal state (`summary_cache.py:75`, gated on the
  `_PROVENANCE_CLASH` contextvar). Slice 1 / the Tier-A Rust frontend **does not support
  provenance-clash** (out of scope), so for the Rust path the practical instruction is: never produce
  any of the three. Stated precisely so the inherited invariant is not subtly wrong.

---

## 4. Soundness / precision posture

Wardline **gates CI** (`wardline scan . --fail-on ERROR`), so the Rust frontend's soundness profile
must be stated explicitly. Wardline's discipline is **fail-closed on uncertainty inside declared-trust
code, and silent in the developer-freedom zone** (`modulate` → `NONE` for undecorated code). The Rust
frontend inherits this:

- **Fail-closed (over-taint) where information is missing**: an unresolved call returns `UNKNOWN_RAW`;
  the flow-insensitive fallback marks every syntactic arg `UNKNOWN_RAW`. A `RAW_ZONE`-gated sink rule
  then still fires.
- **Silent by default**: undecorated Rust functions resolve to `UNKNOWN_RAW` ⇒ `modulate → NONE` ⇒ no
  finding. Self-hosting / unannotated crates do not flood. The rule only "speaks" in declared-trust
  functions (§7).
- **Unsound *by design* at the tier boundary** (documented FNs, not FPs): Tier-B dispatch, Tier-C
  macro/derive-generated sinks, and cross-crate bodies are out of reach for the tree-sitter floor.
- **The NodeId hazard (§5) is the one fail-*quiet* path** — §5 makes it a typed, tested invariant.

**Two false-assurance risks the panel surfaced, and the required mitigation (a coverage-posture
disclosure):** because (a) idiomatic Rust uses traits/macros pervasively (so the Tier-B/C FN surface
grows silently in declared-trust code) and (b) a freshly-enabled scan of an *unannotated* crate
returns zero findings — which reads as "Rust is clean" rather than "Rust is unanalyzed-by-policy" —
the Rust scan path **must emit a coverage/capability line** (e.g. `Rust: N fns scanned, M in
declared-trust; Tier-A only — macro-generated and trait-dispatched sinks not evaluated`). This makes a
silent/green scan *self-describing* at the gate, not only honest in the spec prose. It reuses the
existing `assure` / `decorator_coverage` surface (wired for Rust in SP6; named in slice-1 docs).

---

## 5. The stable `NodeId` contract (the hard requirement)

**Recon's tightest finding (R1), reality-panel confirmed:** the engine correlates the call graph and
the L2 per-argument taint maps **solely** by `int` keys that are CPython `id(ast.Call)` / `id(stmt)`
— in `call_site_callees`, `function_call_site_arg_taints`, `function_call_site_taints`,
`call_site_taints` (`context.py:41-95`). They are **minted in `build_call_edges`
(`scanner/taint/callgraph.py`, `call_site_callees[id(call)] = …`)** and **collected** at
`project_resolver.py:102-114`; they are object identity persisted across the resolver, L2, and rule
passes. If the keys disagree across passes, every join returns nothing and findings vanish —
**fail-quiet**.

A Rust frontend cannot use `id()`. It must mint a **deterministic, per-scan-stable `NodeId`** and use
the **same** value in (a) the call-edge/callee builder, (b) the L2 analyzer's call-site/arg maps, and
(c) the rule's tree re-walk.

**Decision:**

- Introduce a typed `NodeId` (`NewType('NodeId', int)`) **at the seam** so the contract is explicit.
  The Python frontend keeps minting via `id()` behind the newtype (zero behavior change); the Rust
  frontend mints its own as a **deterministic per-file pre-order traversal index** over the CST
  (intra-scan-stable; cross-*scan* stability is the fingerprint's job, §6, not the NodeId's).
- **The threading contract is named, not implicit.** `mint_node_ids(tree) -> NodeIdMap` (a typed
  wrapper over `{ts_node → NodeId}`) is the single source of NodeIds; the L2 dataflow pass and the
  rule locators both import it and key every map through it. No pass may key on a raw `ts_node`.
- **The test is cross-pass agreement, not re-parse determinism.** A focused test asserts the NodeId
  the dataflow pass stores for a known `.output()` trigger **equals** the NodeId the rule uses to look
  up that trigger's arg-taint map (and the builder's). A mismatch is a hard failure — converting the
  engine's one fail-open-quiet path into a loud one. (Re-parse stability is a *weak* substitute and
  must not be mistaken for this.)
- **Cross-frontend disjointness is an SP1 obligation.** Today's shared `AnalysisContext` keys
  `call_site_callees` etc. by a flat `int`. Slice 1's `RustAnalyzer` is **standalone** (it does not
  share that flat dict), so the immediate collision risk is nil. But when SP1 merges the frontends,
  Python's `id()`-ints and Rust's small pre-order ints share one keyspace — SP1 must partition the
  keyspace (or make Python adopt pre-order ids). The WP0 cross-pass test documents that it covers
  Rust-internal consistency only.

---

## 6. The Rust qualname dialect

### 6.1 The constraint, and who owns the dialect

Wardline's *Python* qualname is a **dotted** string byte-identical to CPython `co_qualname`, with
`.<locals>.` for nested scopes (`core/qualname.py:24-83`); the `.` format is load-bearing in ~20 sites
(`split('.<locals>.')[0]` tier-strip; `rsplit('.',1)` enclosing-scope/module recovery — `_sink_helpers.py:202`,
`callgraph.py:93`, `explain.py:56`, etc.). Keeping `.` as the Rust delimiter too lets all of those
sites stay unchanged.

**But for Rust, Wardline is NOT the dialect author — Loomweave is.** The qualname is the SEI *locator*
(`{plugin}:{kind}:{qualname}`, ADR-003/ADR-038); Loomweave's whole-tree `syn` extractor is the oracle
that defines it, and it is **fixed by Loomweave ADR-049** (`docs/loomweave/adr/ADR-049-rust-qualname-canonicalization.md`,
Accepted 2026-06-08). Wardline is the **second producer**: it **mints the identical string** from its
tree-sitter frontend and **must not parse Loomweave's locator** (the ADR-003/038 opacity discipline).
§6.2 below is the ADR-049 form Wardline conforms to, not a Wardline proposal. (The reply that fixed
this is committed at `docs/integration/2026-06-09-loomweave-rust-qualname-dialect-reply.md`.)

### 6.2 The dialect (ADR-049 — normative, Loomweave-authoritative)

> **ADR-049 amendment (Option b), 2026-06-09.** The authoritative extractor (`feat/rust-plugin-spec` @
> `8adb1ee`) **dropped the inherent-impl source-order ordinal**: same-`(type, generic-sig)` inherent
> impls now **MERGE** into one `impl` entity (their methods hang off one `impl#<...>` key, reorder-stable),
> and cfg-twin inherent impls are split by an `@cfg(...)` suffix on the impl key — with the ordinal gone,
> `@cfg` is the **sole** distinguisher for inherent twins. Trait generic args drop lifetimes *and*
> associated-type bindings (keep only concrete Type/Const args), omitting `<...>` when nothing survives
> (`Iterator<Item=u8>` → `impl[Iterator]`, `Trait<'a>` → `impl[Trait]`); positional generics count **type
> params only** (lifetimes/consts do not count). Wardline re-vendored the corpus from `8adb1ee` (blob
> `795ae03`) and conformed. The forms below are the post-amendment (no-ordinal, merge) ones.

`<crate>.<module-path>.<item-path>`, dot-separated. The reserved char is **`:` (rejected by
`entity_id.rs`)**; `[ ] # < > @` are permitted and `.`-split-safe — which is why my earlier
`:trait=`/`:setter` instinct is *invalid* and was replaced.

- **Crate token:** the crate name underscored (`-`→`_`), read from `Cargo.toml [package].name` **as
  text** (reading a manifest is allowed; running `cargo metadata`/registry resolution is not), falling
  back to the dir containing `src/lib.rs`/`src/main.rs`. **Reading the manifest is whole-tree → the
  crate prefix is SP2** (see §6.3).
- **Module path:** the `mod` tree (crate root → item), honoring `#[path]` and file-module
  (`mod foo;` → `foo.rs`/`foo/mod.rs`) boundaries; inline `mod` blocks nest.
- **Trait-impl method:** `<Type>.impl[<TraitPath-with-concrete-generics>].<method>` — concrete generic
  args are **part of the key**: `Foo.impl[Display].fmt`, `Foo.impl[From<i32>].from` ≠
  `Foo.impl[From<u32>].from`. Methods **always** carry the impl discriminator (never bare `Foo.fmt`).
- **Inherent-impl method:** `<Type>.impl#<positional-generic-sig>.<method>` — generics
  rendered **positionally/De-Bruijn** (`$0`,`$1`, so a param *rename* does not churn:
  `impl<T> Foo<T>` and `impl<U> Foo<U>` both → `impl#<$0>`); non-generic → `impl#<>`. **No ordinal**
  (ADR-049 amendment, Option b): same-`(type, generic-sig)` inherent impls **MERGE** into one `impl`
  entity — their methods all hang off the one `impl#<...>` key, reorder-stable (`impl#<>.a`,
  `impl#<>.b`). cfg-twin inherent impls (same type + generic-sig, mutually-exclusive cfgs) are split by
  the `@cfg(...)` suffix on the impl key (`impl#<>@cfg(unix)` vs `impl#<>@cfg(windows)`) — the sole
  distinguisher now that the ordinal is gone.
- **`#[cfg]` twins:** a path-colliding cfg-gated sibling appends a normalised `@cfg(<predicate>)`
  (whitespace-stripped, `any()/all()` args sorted) — for **every** item kind, `fn`/`struct`/inline
  `mod` alike (`f@cfg(unix)`, `S@cfg(windows)`), counted per-kind. Easy to under-implement; the corpus
  carries `cfg_twin` + `struct_cfg_twin` rows so the drift-gate trips if missed.
- **Closures and nested `fn` items are NOT entities.** Loomweave never descends into fn bodies — there
  is **no `.<locals>.{closure#N}`** and no nested-fn entity. A finding inside a closure/nested fn
  **attributes to the enclosing named fn** (`line_start` localises it). (So no Rust qualname contains
  `.<locals>.`, and the Python tier-strip sites are inert for Rust — the enclosing fn's tier gates the
  closure body directly, since Wardline's L2 still analyses that body intra-procedurally.)
- **`async fn`** renders identically to `fn` (no suffix). **Generics** stripped at the definition
  (`crate.mod.func`, never `::<i32>`); lifetimes stripped.
- **id-`kind` is `function` for EVERY callable** (free fn, method, assoc fn) — there is no `method`
  id-kind. Wardline keeps its semantic `function|method` distinction in `Entity` **metadata**, never
  in the qualname.

### 6.3 Module-route resolution + the slice-1 / SP2 reproducibility line

> **Phase-1b fold amendment, 2026-06-10 (user-approved).** SP2 is no longer the qualname-prefix work
> alone: the Phase-1b producer surface folds into it (§11; the change-set is
> `docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md`), so the SP2 entity
> surface is the **full ten-kind set** — Wardline emits `module` and `struct` (and the other leaf)
> rows itself, not just callables. The *reproducibility* line below is unchanged by the fold (the
> Phase-1b rows are all slice-1 modulo the shared crate-prefix caveat); `#[path]` remains the shared
> known gap.

Rust modules are **not 1:1 with files**. The route is the `mod` tree from the crate root (§6.2). Per
the corpus's reproducibility tags, the line between what Wardline reproduces **now** vs at **SP2** is:

- **slice-1 (reproducible single-file now):** the qualname **suffix** — impl discriminator, `@cfg`,
  the merge of same-signature inherent impls (no ordinal), positional generics, the closure/nested-fn
  folding — and a **file-module root** (the corpus roots its single-file cases at the file module, e.g.
  `demo.m.Foo.impl#<>.bar`).
- **SP2 (needs the whole tree):** the real **crate-name prefix from `Cargo.toml`**, the **cross-file
  module route**, and **`#[path]`** (inherent-impl ordinals no longer exist post-amendment — same-signature
  impls merge — so the old cross-file-ordinal SP2 item is moot). *The crate-root prefix of
  every entity is itself SP2.* `#[path]` is a **shared known gap** (Loomweave's `module_path.rs` does
  not honour it yet; the corpus `path_attr_known_gap` row pins the mechanical file-path form with
  `known_gap: true` — both engines match that, and `#[path]`-correct routing is a joint SP2 task).

This is the precise reason `RS-WL-*` stays baseline-ineligible until SP2 (§3.6): the *dialect* is
fixed and slice-1 suffixes are stable, but the **crate prefix gains its real value at SP2**, changing
fingerprints once.

### 6.4 Identity pinning — the corpus is INVERTED (Loomweave seeds, Wardline vendors)

> **Phase-1b fold amendment, 2026-06-10 (user-approved — supersedes the comparison rule in the second
> bullet).** With the Phase-1b producer surface folded into SP2 (§11), Wardline emits the **full
> ten-kind surface** (`module`, `struct`, `function`, `enum`, `trait`, `type_alias`, `const`,
> `static`, `macro`, `impl`), so "rows Wardline never emits" no longer holds and the conformance
> comparison **graduates from the subset-consumer rule to the full-set rule** (change-set §7 rule 1):
> compare Wardline's full ordered emission of `(qualname, kind)` pairs — semantic `method` mapped to
> id-kind `function` — list-equal against `expected`. Oracle ground-truth corrections (verified
> 2026-06-10): `feat/rust-plugin-spec` is **merged into Loomweave `rc4`** (the plugin is live,
> on-by-default; the stale local branch ref is to be ignored); the upstream corpus gained
> `generic_self_nested_param` (zero diffs in shared cases); and the leaf-kind, stacked-cfg,
> cfg-escape, and leaf-kind-cfg-twin rows are added **upstream by this sprint** (the extractor
> already emits all of it, un-oracled), verified by Loomweave's own cargo gate, then re-vendored.

- **Loomweave hosts** `fixtures/qualnames_rust.json` (extractor-**generated**, locked by
  `crates/loomweave-plugin-rust/tests/qualname_conformance.rs`, passing). **Wardline vendors** a pinned
  copy to `tests/conformance/qualnames_rust.json` and reproduces `expected` **byte-for-byte** from its
  frontend. This **inverts** the Python arrangement (Wardline seeded `qualnames.json`, Loomweave
  vendored) because for Rust the whole-tree extractor is the oracle. The existing Python
  `qualnames.json` / `loomweave_qualname_parity.json` and their tests are **untouched**.
- **Comparison rule (do NOT reuse `test_qualname_conformance.py` verbatim — it will fail).** The corpus
  `entities[].expected` is Loomweave's *full* emission: it includes `module` and `struct` rows Wardline
  never emits, and its `kind` is the locator **id-kind** (`function` for every callable). So, per the
  corpus `_consumer_comparison` key: **(1)** the byte-exact obligation is the **`qualname`** of every
  function row (the string folded into `fingerprint`) — match char-for-char; **(2)** `kind` is
  informational — map Wardline's semantic `method` → id-kind `function`, or compare qualname-only;
  **(3)** `module` rows are validated against the `module_route` section, not re-emitted. Recommended
  test: take Wardline's function entities, assert each `qualname` is in the case's set of non-`module`
  `expected` qualnames. **Never edit the vendored copy to drop rows.**
- The **frozen** `tests/golden/identity/rust/` finding-identity corpus remains the **SP2 completion
  gate** (when crate-prefix/cross-file rows stop being provisional). Loomweave offered to drop the
  vendored copy + a `test_loomweave_rust_qualname_parity.py` skeleton into Wardline's tree on request.

---

## 7. Trust declaration model for Rust

Rust has no decorators, and on **stable Rust an unknown `#[trust_boundary]` attribute is a compile
error** (no `register_tool`). So:

- **Builtin vocabulary is primary.** A bundled `rust_taint.yaml` (§8) ships sources / sinks /
  sanitizers for `std` + common crates → **zero-config** Rust findings (the product thesis: power via
  activation, not configuration). The L1 seed (sources) and the sink rules (sinks) both read it.
- **Opt-in in-source markers use doc-comments, not attributes.** App-defined boundaries are declared
  with `//! @trust_boundary(...)` / `/// @trusted(...)` doc-comments, which cannot break compilation.
  These feed the same `BoundaryType` grammar shape (`scanner/grammar.py:39-133`) via a
  `RustTrustProvider`. (Rejected: a published no-op proc-macro crate — adds a dep + build step;
  `cfg`-gated attributes — fragile. §12 Q4 confirms.)
- The `RustTrustProvider` supplies its **own** `provider_fingerprint` (`rust-vocab:{RUST_TAINT_VERSION}`,
  §8.1) — it cannot reuse the Python `_grammar_digest`, which hashes `co_code.hex() | repr(co_consts)`
  (both bytecode structure *and* embedded grammar string literals — `decorator_provider.py:188-194`).
  No cross-runtime cache interop is assumed on a custom-grammar path.
- Builtin seed **semantics** are replicated byte-compatibly: `external → (EXTERNAL_RAW, EXTERNAL_RAW)`;
  `boundary → (EXTERNAL_RAW, to_level)`; `trusted → (level, level)`.

Slice 1 needs only the **source** half (e.g. `std::env::args`/`var`, `std::fs::read_to_string` →
`EXTERNAL_RAW`) plus the command-injection **sink** set, and the single `@trusted` doc-comment marker
the specimen uses to enter declared-trust.

---

## 8. Vocabulary, discovery, corpus, e2e (the harness changes)

### 8.1 `rust_taint.yaml`

Mirror `stdlib_taint.yaml`: top-level `version: int` + `entries: list`. Two **distinct** entry shapes:

- **Sources:** `{crate, path, returns_taint, rationale}` (`crate`/`path` replace `package`/`function`,
  e.g. `crate: std, path: env::var`); `returns_taint` ∈ the legal-return subset `{ASSURED, GUARDED,
  EXTERNAL_RAW, UNKNOWN_RAW}`.
- **Sinks:** `{crate, path, sink_kind, rationale}` — `sink_kind` ∈ {`command`, `shell`, …}.

**Cache-version gap to NOT inherit silently (recon R5):** `stdlib_taint.yaml`'s `version` is **not**
folded into `compute_cache_key`; invalidation relies on a manual `_RESOLVER_VERSION = "sp1d"` bump
(`project_resolver.py:43`). `compute_cache_key`'s sixth input, `scan_policy_hash`, is the *policy*
slot — **not** the vocabulary version. So the Rust path folds `RUST_TAINT_VERSION` into its
**`provider_fingerprint`** (`rust-vocab:{RUST_TAINT_VERSION}`), and a test asserts the
`provider_fingerprint` value changes when `RUST_TAINT_VERSION` bumps. This closes the gap **now**
(testable even though slice 1 has no persisted cache), so SP3/SP6's disk cache cannot inherit it.

### 8.2 Discovery generalization

`discover()` **hardcodes `base.rglob('*.py')`** (`core/discovery.py:32`); `WardlineConfig` has **no
`language` field**. Generalize discovery to be **suffix-parameterized**, frontend-owned:
`discover(root, config, *, suffixes=frozenset({'.py'}))` (Python default preserved) with the Rust path
passing `{'.rs'}`. Preserve the `confine_to_root` symlink guard (THREAT-001 — a `.rs` symlink escaping
root must still be skipped with `WLN-ENGINE-FILE-SKIPPED`; this is a **security invariant** with its
own test, not an assumption), the `fnmatch` excludes, and **add `target/` to `_ALWAYS_SKIP`**.
**`missing_source_roots()`** (`discovery.py:51-68`) is *not* suffix-aware — a configured root that
exists but contains no `.rs` is not "missing", so a Rust scan of it returns zero files silently
(false-clean). SP6 must add an empty-root warning for the Rust path; slice 1 documents this as a known
limitation (its `RustAnalyzer` runs over an explicit fixture, so it does not hit the empty-root path).

### 8.3 Corpus + e2e

- **Corpus:** Rust specimens live in a **sibling** dir `tests/corpus/rust/fixtures/*.rs` with their
  own `MANIFEST.yaml` (keyed by `(path, rule_id, qualname)`, `TRUE_POSITIVE`/`FALSE_POSITIVE` labels,
  ≤5% FP gate) plus a **documented FN section**, and a harness variant that runs `RustAnalyzer`. To
  make the ≤5% gate non-vacuous on a small corpus, the fixture is **dense** (≥10 clean functions —
  non-shell `Command`s, `.args()`, taint-free `format!`, unmarked fns — alongside the TP functions),
  *and* a second `clean_commands.rs` fixture carries a **hard 0-findings** negative gate.
- **e2e:** register a `rust_e2e` pytest marker (`pyproject.toml` markers + `addopts` deselect via `and
  not rust_e2e`); test file sets `pytestmark = pytest.mark.rust_e2e`; toolchain resolved via the
  `tree_sitter` import (skip-clean if the extra is absent). **Correction (reality-panel):** the
  `conftest.py` hookwrapper iterates markers generically, so *registering* the marker is enough for
  slice 1 — but **promoting `rust_e2e` to a CI-*required* live oracle later** also requires adding it
  to the hardcoded `LIVE_ORACLE_MARKERS` set (and its enumerating test). Slice 1 only registers the
  marker; CI-required promotion is a named follow-on, not automatic.

### 8.4 Rule-id namespace

Rust rules use the **`RS-WL-*`** namespace (disjoint from `PY-WL-*`; the prefix is part of the
fingerprint tuple, so identities never collide). The corpus MANIFEST and `rules.enable`/`severity`
globs treat the prefixes as disjoint namespaces (confirm in SP6).

---

## 9. The first slice: command-injection (Tier A)

### 9.1 Why this slice

`Command::new(x).arg(tainted)` is **constructor-tracked plain method calls — zero traits, zero
macros** (squarely Tier-A). The source side is clean (`std::env::args`/`var`). It has direct Python
analogs to match discipline against (`untrusted_to_shell_subprocess.py` = PY-WL-112,
`untrusted_to_command.py` = PY-WL-108). It exercises the **full vertical**.

**Proves:** the plumbing **and** real source→propagate→sink taint. **Does NOT prove:** semantic
adequacy for Tier-B/C. A green slice is not evidence that "the rest is just more vocabulary."

### 9.2 Two distinct findings (do not blur them)

Rust's `std::process::Command` is **always argv-based — there is no implicit shell.** Therefore:

- **`RS-WL-108` — Tainted program name.** `Command::new(tainted)` — the attacker chooses the
  executable. Any `RAW_ZONE` taint on the **program** value fires. **Severity: ERROR.** This is a
  **new threat class enabled by Rust's argv model — not a port of PY-WL-108** (which is a *fixed*
  always-shell program with a tainted *argument*). A fully attacker-controlled executable is arbitrary
  code execution with no shell-metachar dependency — strictly worse than shell-string injection — so
  it gates at ERROR. (Resolved §12; was an open question. `modulate` still narrows the blast radius to
  declared-fully-trusted fns, so the gate impact is bounded.)
- **`RS-WL-112` — Shell-string injection** (mirrors PY-WL-112): the program is a **shell**
  (`sh`/`bash`/`/bin/sh`/`cmd`/`cmd.exe`/`powershell`/`pwsh`, **matched case-insensitively** — Windows
  resolution is case-insensitive) **and** a shell flag arg is present (`-c` / `/C` / `-Command`,
  case-folded) **and** a tainted command string reaches that shell. Literal-only shell-program
  detection (accepts the bounded FN of a variable-bound shell name, §9.4). **Severity: WARN.**

**De-confliction (panel fix — state it, don't leave it emergent).** The two rules are **mutually
exclusive on the program axis**: `RS-WL-112` requires a *clean literal* shell program; `RS-WL-108`
requires a *tainted* program. A value cannot be both, so they cannot double-fire — *while 112 stays
literal-only*. **Forward-guard:** if SP-later lifts 112's literal-only restriction (the §9.4 FN), a
tainted-variable-that-is-also-a-shell would satisfy both — at that point 108 must suppress when 112
fires on the same terminal `NodeId` (or 112 yields to 108 on a tainted program). A slice-1 test pins
single-fire on a tainted-program-plus-`-c` specimen (108 only).

**Hard FP rule:** **do NOT fire on plain `.arg(tainted)` / `.args(tainted_vec)` to a NON-shell
program** — the safe `shell=False` argv list. `.env(k, tainted)` is **out of scope** for slice 1.

**CWE / metadata.** CWE-78 is pinned in the rule **description prose** (matching PY-WL-108/112) —
`RuleMetadata` has **no `cwe` field**, and adding one is a separate cross-language NG-25 descriptor
change, not smuggled into slice 1.

**Drafted examples** (these make the rules falsifiable; all inside a `@trusted` fn so the tier gate is
exercised):

- `RS-WL-108` violation: `Command::new(std::env::var("X").unwrap()).output();`
  clean: `Command::new("ls").arg(i).output();`
- `RS-WL-112` violation: `let i = std::env::var("X").unwrap(); Command::new("sh").arg("-c").arg(format!("echo {}", i)).output();`
  clean (non-shell argv): `Command::new("ls").arg(i).output();`
  clean (literal command, no taint): `Command::new("sh").arg("-c").arg("echo hi").output();`

### 9.3 The builder-dataflow layer (the genuinely new work)

Python's `resolved_arg_taints` is keyed to **one** `ast.Call`. The Rust sink is **spread across
statements** bound to a `let`:

```rust
let mut cmd = Command::new("sh");   // program identity = "sh" (a shell)
cmd.arg("-c");                      // shell flag present
cmd.arg(user_input);               // tainted arg reaches the shell  → RS-WL-112
cmd.output();                       // terminal trigger: anchor the finding here
```

The Rust L2 runs a small **intra-function abstract state**:

- `local_var → CommandState{ is_command, program_literal, program_taint, shell_flag_seen,
  arg_taints: list[(NodeId, TaintState)] }`, updated on `Command::new(...)`, `.arg(...)`/`.args(...)`,
  and the terminal `.output()`/`.spawn()`/`.status()`.
- `local_string_taints: dict[str, TaintState]` — **string-valued locals carry taint** so a command
  string built into a separate `let` and then `.arg`'d is tracked: `let s = format!("rm {}", tainted);
  … .arg(s)` must propagate. The two-hop case (`let s2 = format!("{}", s)`) is tested.

At the terminal call it emits a **per-trigger arg-taint map keyed by `NodeId`** (§5) and feeds it to
the verdict core (§3.4). The finding **anchors at the terminal trigger line** (fingerprint stability),
but **`RS-WL-108`'s message cites the `Command::new(...)` constructor line** as the entering position
(the `CommandState` already tracks it) — otherwise the developer is sent to `.output()` where no
tainted token is visible.

CST shapes (verified, R6): method calls are `call_expression{ function: field_expression{ value:
<receiver>, field: 'arg'/'args' }, arguments }` — **no `method_call` node, no `receiver` field**; the
receiver is `field_expression.value`. `Command::new` is a `call_expression` whose `function` is a
`scoped_identifier{ path, name }`. `use std::process::Command [as Alias]` is a `use_declaration`
(`use_as_clause{ path, alias }`) — resolve aliases here so `C::new` canonicalizes.

**The `format!` heuristic — precise scope and its two error directions.** A tainted identifier
appearing as a **direct interpolation token** inside `format!(…)` is treated as taint reaching the arg.
This is a **lexical token-tree heuristic** (Tier-A/B). It is bounded on **both** sides, and slice 1
states both:

- **FN:** the Rust-2021 captured form `format!("rm {user_input}")` embeds the identifier *inside the
  string-literal token*, not as a separate arg token — slice 1 does **not** see it (pinned as a
  documented FN with a test asserting no propagation, so the boundary is explicit).
- **FP (accepted, bounded):** a sanitizer wrapping the token —
  `…arg(format!("echo {}", sanitize(user_input)))` — is invisible to a token scan, so the heuristic
  over-taints. This is traded for catching the common direct-interpolation case; the heuristic matches
  **direct interpolation argument tokens only** (not any token anywhere in the token-tree) to cut the
  FP surface, and a `sanitize()` near-miss is a **measured TN fixture** in the corpus (against the ≤5%
  gate). Because `RS-WL-112` is WARN (annotate), this lexical heuristic never feeds the ERROR-gating
  population.

### 9.4 Tier-A boundaries the slice declares up front (documented FNs, not bugs)

- Trait-method-hidden Command receivers (Tier-B); macro/proc-macro-generated command execution (Tier-C).
- Cross-function builder flow (a `Command` returned from a helper).
- **`Command::arg0(tainted)`** — argv[0] spoofing / login-shell coercion. Same `CommandState`
  receiver, so a cheap near-term `RS-WL-108`-family extension; explicitly cut from slice 1 to keep it
  tight.
- **Shell strings built by `push_str` / `+` concatenation** (a `call_expression`/`binary_expression`,
  not a `macro_invocation`) — the `format!` heuristic does not touch them. **Struck from the §9.3
  in-scope claim and listed here as a documented FN** (slice 1 = `format!`-only lexical heuristic).
- **`Command::new("cmd").args(["/C", tainted])`** — the shell flag arriving via `.args` (per-element
  precision is deferred); documented FN.
- Variable-bound shell program names (`let s = "sh"; Command::new(s)`) — mirrors PY-WL-112's
  literal-only discipline (bounded FN over FP), pinned with an FN test.
- **Raw `libc::system` / `exec*` FFI** and process spawning outside `std::process::Command` — out of
  slice 1; a named Tier-A expansion under SP5.

---

## 10. Risks

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| R-1 | NodeId minting disagrees across passes → findings silently vanish (fail-quiet) | High | §5 typed `NodeId` + named `NodeIdMap` threading + cross-pass agreement test |
| R-2 | ~~Unfixed dialect~~ **RESOLVED 2026-06-09** (Loomweave ADR-049 fixed the dialect, §6). Residual: the **crate-prefix** is SP2-provisional → one fingerprint rekey at SP2 | Med | §3.6/§6.3: `RS-WL-*` baseline-ineligible until SP2; vendored `qualnames_rust.json` drift-gate; frozen `golden/identity/rust/` an SP2 gate |
| R-3 | Builder-dataflow under/over-approximates → FN or the argv-list FP flood | Med-High | §9.2 shell-gated hard FP rule; dense corpus + 0-finding clean fixture; ≤5% gate; FP/FN tests incl. `.args`/no-flag/`format!` negatives |
| R-4 | tree-sitter core/grammar ABI mismatch at install → load failure | Med | §11 SP6 pins `tree-sitter>=0.25,<0.26` + `tree-sitter-rust==0.24.2` (ABI-15 floor); not the grammar's stale `~=0.22` self-pin |
| R-5 | Interim Python frontend orphaned/duplicated at native cutover | Med (accepted) | §1.1 cost analysis (design survives; only frontend code re-written); native cutover unstarted |
| R-6 | Cache-version gap (`rust_taint.yaml` change doesn't invalidate) → stale-clean | Med | §8.1 fold `RUST_TAINT_VERSION` into `provider_fingerprint` + assert-on-bump test now |
| R-7 | Tier ceiling / freedom-zone silence oversold → users read green as "Rust clean" on a CI gate | Med | §4 coverage-posture disclosure in scan output; documented FN families in the guide + MANIFEST FN section |

---

## 11. Decomposition — the program (the "ceiling")

Six sub-projects, each its own spec→plan→build cycle:

- **SP1 — Frontend seam extraction** *(post-slice-1 refactor, NOT a forward prerequisite — runs after
  slice 1 lands, before SP2 full multi-file)*. Introduce the `frontend` package + the typed `NodeId`;
  make today's Python path "frontend #1" behind the seam, **behavior-preserving**; **partition the
  shared-context keyspace** so two frontends' NodeIds cannot collide (§5). **Gate: Python corpus +
  identity oracle stay byte-green.**
- **SP2 — Rust parse + index** . tree-sitter-rust → entities; the ADR-049 qualname dialect (§6) incl.
  the **whole-tree** pieces that are SP2 by construction — crate-name-from-`Cargo.toml`, cross-file
  module route, `#[path]` (shared known gap) (§6.3); **the full Phase-1b producer surface**
  *(amended 2026-06-10 — user-approved fold;
  `docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md`)* — the six leaf kinds
  (`enum`/`trait`/`type_alias`/`const`/`static`/`macro`), the `impl` entity with
  `module → impl → method` re-parenting, the anchored `imports`/`implements` edges, and
  `ontology_version 0.4.0` under `plugin_id rust`, taking the conformance comparison from
  subset-consumer to full-set (§6.4); and **the
  frozen `tests/golden/identity/rust/` finding corpus** (§6.4). These are the SP2 *completion gates*,
  the point at which the crate-prefixed `RS-WL-*` identity stops being provisional.
- **SP3 — Rust trust vocabulary** . `rust_taint.yaml` + `RustTrustProvider` (doc-comment markers) +
  `RUST_TAINT_VERSION`-in-`provider_fingerprint` (§8.1).
- **SP4 — Rust L2 builder-dataflow** *(the hard core, §9.3)*.
- **SP5 — Rust sink rules** . `RS-WL-108` + `RS-WL-112`; extract the neutral verdict core (§3.4) once
  the second rule lands; then Tier-A expansion (path traversal, `Command::arg0`, `libc::system`/FFI,
  `unsafe`) and the named Tier-B/C escalation hooks.
- **SP6 — CLI / MCP / packaging integration** . `wardline[rust]` extra (pins, R-4); `.rs` discovery +
  `missing_source_roots` empty-root warning (§8.2); coverage-posture disclosure (§4); `rust_e2e`
  marker + corpus harness; rule-id namespace disjointness; confirm hardening Tasks B/C (§1.2); docs +
  CHANGELOG.

**The first vertical slice (the sibling plan) cuts a thin path through SP1→SP6** for command-injection
only. It is the de-risking instrument, not a sub-project.

---

## 12. Open questions for review

1. **`format!` heuristic narrowing** (§9.3) — confirm "direct-interpolation-arg tokens only" is the
   right precision/effort point for slice 1, vs a broader token-tree scan (more FN-resistant, more FP).
2. **Doc-comment markers over a proc-macro crate** (§7) — confirm, given the agent-first/zero-config
   thesis.
3. **SEI cross-rename baseline policy** (forward, non-gating — §3.6) — when Loomweave ships its SEI
   *resolve* oracle (currently deferred their side), do we re-key historical `RS-WL-*` findings through
   it on rename/move, or accept churn-on-rename as a baseline reset? Tracked, not blocking slice 1.

(Resolved, no longer open: **Q1 Loomweave dialect → FIXED** by ADR-049, 2026-06-09 — Wardline conforms
(§6), blocker dropped; RS-WL-108 severity → **ERROR**; CLI dispatch → **explicit `--lang rust`**;
identity → **baseline-ineligible until the SP2 crate-prefix lands**; SEI fold → **keep folding the
qualname, do NOT fold Loomweave's SEI token** (Wardline can't reproduce it single-file); RS-WL-108/112
de-confliction → **stated + forward-guarded**.)

---

## 13. Review changelog

**Round 1 — 7-reviewer panel.** Corrected citations (FunctionSeed → `function_level.py`; NodeId mint →
`callgraph.py build_call_edges`; cache-key 6th input `scan_policy_hash`; `_grammar_digest` hashes
`co_code|co_consts`; live-oracle marker promotion; wheel tag cp39-abi3; qualname sites ~20 not ~12).
Resolved deferred decisions (RS-WL-108 ERROR + reframed as a new threat class; CLI `--lang rust`).
Added: `RustAnalyzer` must satisfy the full `Analyzer` protocol (plan); NodeId `NodeIdMap` threading +
cross-pass test; `local_string_taints` for `format!`-through-`let`; format! FP/FN both directions;
de-confliction + forward-guard; Windows case-fold + `pwsh`; `arg0`/concat/FFI/`args`-flag FNs;
coverage-posture disclosure; dense corpus + clean-fixture hard gate; symlink-confinement +
`missing_source_roots` notes; `MIXED_RAW`-under-provenance-clash precision; interim cost analysis; SP1
relabelled post-slice refactor.

**Round 2 — Loomweave ADR-049 conformance (2026-06-09).** The "Loomweave dialect unfixed" blocker is
GONE — Loomweave fixed the Rust qualname dialect (ADR-049) and Wardline now **conforms** (it is the
*second producer* that mints the same string; it never parses the locator). Replaced my proposed forms
with the normative ADR-049 ones: trait impl `Foo.impl[Display].fmt` (concrete generics kept), inherent
`Foo.impl#<>.bar` (positional `$0` generics, **no ordinal** — Option-b amendment: same-signature
inherent impls merge), `@cfg(pred)` twins for all item
kinds, **closures/nested-fns are NOT entities** (dropped `.<locals>.{closure#N}`; attribute to the
enclosing fn), id-kind always `function`, **`:` is reserved/invalid** (killed `:trait=`/`:setter`).
Corpus **inverted**: Loomweave hosts `fixtures/qualnames_rust.json` (extractor-generated), Wardline
vendors + reproduces byte-for-byte under the documented comparison rule (qualname-only on function
rows). Reproducibility tiers pinned: slice-1 = the file-module-rooted suffix; **SP2 = the crate
prefix + cross-file route + `#[path]`** (so R-2 downgrades to Med). SEI fold resolved: keep folding the
qualname, never Loomweave's SEI token. Reply committed at
`docs/integration/2026-06-09-loomweave-rust-qualname-dialect-reply.md`.

**Round 3 — Phase 1b folded into SP2 + oracle ground-truth corrections (2026-06-10).** The
user-approved fold: SP2 (§11) now also comprises the **Phase-1b producer surface** from
`docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md` — six leaf kinds, the
`impl` entity + method re-parenting, the anchored `imports`/`implements` edges, `ontology_version
0.4.0` under `plugin_id rust`. Consequence for §6.3/§6.4: Wardline emits the **full ten-kind
surface**, so the "module/struct rows Wardline never emits" premise is retired and the conformance
comparison graduates from the subset-consumer rule to the **full-set rule** (change-set §7 rule 1).
Oracle ground truth corrected (verified 2026-06-10): `feat/rust-plugin-spec` is **merged into
Loomweave `rc4`** (plugin live, on-by-default); the upstream corpus gained
`generic_self_nested_param`; the leaf-kind / stacked-cfg / cfg-escape / leaf-kind-cfg-twin rows —
emitted by the extractor but un-oracled — are added **upstream by this sprint**, gated by
Loomweave's own cargo suite, then re-vendored.
