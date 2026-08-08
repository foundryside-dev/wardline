# Declaration Surface v2 — schema contracts, facets, restoration, sensitivity, dependency taint

**Date:** 9 August 2026
**Status:** DESIGN — approved decisions recorded; implementation not started
**Program:** designed-unbuilt completion (`wardline-aee6ae068b`, label `unbuilt-2026-08-09`), Phase 0 deliverable (`wardline-3baba7e42f`)
**Provenance:** 7-perspective design panel (Solution Architect, Systems Thinker, Python Engineer, Quality Engineer, Security Architect, Static Analysis Dev, IRAP Assessor), 2026-08-09. All engine claims in this document were verified in source by at least one panellist; measurements are from a 3,017-site `.get`-corpus over wardline/legis/filigree.
**Decisions by John, 2026-08-09:** (D1) approved defaults **downgrade, never suppress**; (D2) institutional evidence is a **record-only token with zero uplift** in v1; (D3) attest bundles are **domain-internal** — asymmetric signing stays a roadmap item.

---

## 1. Scope

Extend wardline's declaration surface — today exactly three function-level decorators — to carry five new declaration kinds, so the admission-test-passing slice of the designed-but-unbuilt annotation groups (as-built spec §10) becomes buildable:

1. **Schema contracts** — per-source, per-field three-state classification enabling WL-001 (`PY-WL-127`) and WL-002 (`PY-WL-128`).
2. **Sensitivity marks** — values that must not reach disclosure sinks; also the per-field "may never be defaulted" mechanism for contracts.
3. **Facets** — audit-primacy and operation-semantics markers enabling WL-005 (ACF-R1/R2).
4. **Restoration boundaries** — evidence-based declarations producing the two reserved lattice states `UNKNOWN_ASSURED` / `UNKNOWN_GUARDED`.
5. **Dependency-taint declarations** — caller-granted claims about third-party call returns.

**Out of scope** (John, program scope decision): the runtime structural layer; any governance apparatus (reviewer identity, approvals, ratification — legis's jurisdiction; wardline stays "No governance"); the type-system layer.

## 2. Design principles

These are the rules every section below conforms to. Each is anchored in a mechanism that already ships.

**P1 — Obligation vs exemption decides the grant axis.** A declaration that creates *obligations the engine checks* (required fields, audit-primacy, sensitivity) lives in source and needs no grant — the review of the declaration is the review of the code, in the same diff. A declaration that grants *exemptions or uplift the engine honours* (dependency-taint; any future restoration uplift past the cap) is caller-granted, and its state caps are enforced at the parser regardless of grant — a grant cannot buy past a soundness invariant. Net new grant flags in this program: **one** (dependency-taint, §9), shipping in the final phase.

**P2 — A declaration may reduce a finding's severity, never its existence (D1).** The three shipped suppression channels act on findings that already exist, which is what lets the gate evaluate a separately built unsuppressed population (§7.3 of the as-built spec). A contract acts *before* finding generation — upstream of that split — so contract-driven suppression would be the only repo-authored channel with full gate authority by default. Therefore: a matching approved default **downgrades to INFO**; it never removes the finding. This mirrors the vocabulary's existing asymmetry (a boundary may raise trust to `ASSURED` but never `INTEGRAL`), one layer up.

**P3 — One readability rule for the entire surface.** The analyser reads exactly three forms, everywhere: a **literal constant** (`"OFFICIAL"`, `42`, `True`, `None`); a **namespaced attribute token** whose receiver alias-resolves to an exact known export (`Field.REQUIRED`, `Evidence.SEMANTIC` — the existing `TaintState.ASSURED` discipline); a **constrained marker call** whose callee is an exact known export and whose every argument is a literal (`Field.default("OFFICIAL")`). Bare names are rejected even when resolvable. A partially-readable declaration is wholly unreadable and **fails loud** (rule/FACT per §10), never partially honoured.

**P4 — New axes are new types with empty defaults; existing readers are never widened.** `_read_level`, `LevelArg`, and the three existing markers' signatures are untouched (with one exception — the restoration phase's `LevelArg` generalisation, §8). Every new field on `SeedResult`/`FunctionTaint`/`AnalysisContext` defaults empty. Consequence, and shipping gate: on a declaration-free tree, the byte-identity golden corpus changes **zero bytes**.

**P5 — Labels are not taint.** Contract identity and sensitivity ride a parallel side-channel (§6.2), never `var_taints`, never `combine()`/`least_trusted`, and never `FunctionSummary` — so the summary cache carries only taint, labels are recomputed fresh every scan, and a stale cache structurally cannot produce a false-green WL-001.

**P6 — Every declaration is a ledger entry.** Every declaration kind emits into one deterministic inventory — `(declaration_id, content_digest, verification_class)` — built by a single factory and consumed by attest, assure/dossier, and the legis artifact (§11). Wardline supplies the *subject* of an approval; it never holds the approval. Legis holds approved digests and computes drift; wardline must not.

**P7 — Every group ships with the metric that proves it is live, in the same change.** Per-kind declaration counts enter the resolution posture and the signed attest payload; the inertness machinery gains per-group arming (§11.4). A group without its liveness metric recreates the green-gate-over-nothing failure one layer in.

## 3. The four engine channels

| Channel | Kinds | Cached? | Engine surface touched |
|---|---|---|---|
| **L1 seed plane** | restoration boundaries only | yes (summary cache) | `BoundaryType` generalisation, `_CACHE_LEGAL_TAINT`, reachable-set invariant |
| **Facet plane** | audit-primacy, operation semantics | no | new `FacetType` registry + `SeedResult.facets`; rules read via `AnalysisContext` |
| **Value-label plane** | schema contracts, sensitivity | no | L2 side-channel contextvar + analyzer L2 fixed point; never `FunctionSummary` |
| **Config plane** | dependency-taint | keyed via `scan_policy_hash` | `weft.toml` table + caller grant |

Restoration is the only kind that touches taint, the cache, or the lattice — which is why it ships **last** (§12), not first.

## 4. Vocabulary, packaging, and version skew

### 4.1 weft-markers 0.2.0 (additive only)

New exports: `Contract`, `Field`, `FieldRule`, `Evidence`, `Sensitivity`, `Semantics`, `schema`, `restoration_boundary`, `audit_record`, `operation`, `sensitive`. All runtime no-ops (stamp `_wardline_*` attrs, return the function unchanged), all keyword-only, zero-dependency, Python-3.9-floor (frozen dataclasses without `slots`; `class Evidence(str, Enum)`-style tokens). The existing three markers' signatures are frozen — **no new kwarg is ever added to a level-bearing marker** (see 4.3).

### 4.2 Registry and vocabulary

- `vocabulary.yaml` → `schema: wardline.vocabulary/v2`; new entries use new `group` numbers (contracts group 2, facets group 3, restoration group 4, sensitivity group 5); a `facets:` section joins `entries:`.
- `REGISTRY_VERSION` → `wardline-generic-3`. **Mandatory**, not hygiene: `DecoratorTaintSourceProvider.fingerprint()` short-circuits to `decorator-vocab:{REGISTRY_VERSION}` for a builtin-only grammar, so growing `BUILTIN_BOUNDARY_TYPES` without the bump serves warm pre-upgrade caches against new seeding. `_RESOLVER_VERSION` bumps alongside (the documented sp1f→sp1g precedent). Changelog states plainly: cold rescan, no finding-byte change, no baseline impact.
- `RegistryEntry` gains `kwargs: frozenset[str]` — the declared-keyword set per marker, powering the unknown-kwarg rule (§10.1).
- **Extension checklist** (all move in one commit, pinned by a conformance test): `REGISTRY`, `BUILTIN_BOUNDARY_TYPES`/facet registry, `vocabulary_star_exports()`, `diagnostics._BUILTIN_MARKER_IMPORTS`, the `boundary_types.py` drift tripwire, and the **Rust provider** (see 4.4). Missing the star-export site creates a silent recognition hole that fails green.
- **Shadow discipline extends to the new vocabulary**: `Contract`/`Field`/`Evidence`/`Sensitivity` and all new markers are recognised only via exact known-export FQNs, and rejected entirely when their marker root is project-shadowed (`_shadowed_builtin_roots`). Fail-closed direction: no contract known → WL-001 fires. This is a security requirement — contract recognition runs in the suppressing direction, and a project-local `weft_markers` shim must not be able to forge approved defaults.

### 4.3 Version skew (the live bug, and the contract)

Verified end-to-end: an unknown kwarg or any positional arg on `@trusted` today silently drops the seed, removing the function from the anchored set and suppressing every tier-modulated rule — **the scan goes greener with no diagnostic** (`wardline-4928b75782`, P1). Two rules therefore ship **before any new marker**:

1. **`PY-WL-130` unknown-marker-argument** (ERROR, DEFECT; id provisional): a builtin marker call carrying an undeclared keyword or any positional argument. Not silenced by the builtin-stays-quiet convention (that convention preserves the byte-identity oracle; a new rule id is covered by no golden). Retroactively protects today's three markers.
2. **`WLN-ENGINE-UNKNOWN-MARKER`** (FACT): an unrecognised decorator whose resolved FQN root is `weft_markers`/`wardline.decorators` — almost certainly a marker newer than this scanner. Count surfaced in `decorator_coverage`. This is how an agent learns its declarations are being ignored.

Compat matrix after this program: new stacked marker + old wardline → unknown decorator, no opinion, co-located boundary seeds intact, `UNKNOWN-MARKER` FACT under a new-enough scanner (capability lost loudly, correctness kept); old markers + new wardline → byte-identical.

### 4.4 The Rust frontend story (decided at design time)

The Rust provider recognises markers as doc-comment text with no import provenance — none of the Python shadow/exact-export hardening transfers. Decision: the **new vocabulary is Python-only in this program**. The Rust provider is *not* extended to recognise any new marker; `rust/vocabulary.py`'s legal-return set is widened for the two restoration states only when restoration ships (frontend parity of the *lattice*, not of the *declarations*). A `WLN-RUST-COVERAGE`-style note names the asymmetry. Cross-language contract/label propagation stays governed by §10.5 of the as-built spec (taint resets at language boundaries).

## 5. Kind 1 — schema contracts and WL-001/WL-002

### 5.1 Declaration

```python
# myapp/contracts.py
from weft_markers import Contract, Field

ORDER_CONTRACT = Contract(
    name="orders.v3",
    fields={
        "order_id":                Field.REQUIRED,
        "security_classification": Field.default("OFFICIAL"),   # optional-with-approved-default
        "discount_code":           Field.OPTIONAL_EXPLICIT,     # absence must be represented
    },
    declared_against="https://schemas.example/orders/v3",       # recorded, unverified
)

# myapp/intake.py
from weft_markers import external_boundary, schema
from myapp.contracts import ORDER_CONTRACT

@external_boundary
@schema(ORDER_CONTRACT)
def fetch_order(raw: bytes) -> dict[str, object]:
    return json.loads(raw)
```

- **Attachment is a stacked `@schema(...)` marker, uniformly** — never a kwarg on the existing three. Rationale: kwargs on level-bearing markers are a verified silent gate-drop under skew (4.3); a single form works on `@external_boundary`, `@trust_boundary`, and `@trusted` alike; the original markers stay frozen. (Rejected alternative: `contract=` kwarg on `@external_boundary` only — skew-safe there because `level_args=()`, but it cannot attach to validators and puts a per-marker safety asterisk on the API.)
- **References resolve by name** through the existing alias map to a module-level `NAME = Contract(<literals only>)` assignment, collected by a `discover_project_contracts` pre-pass modelled on pydantic discovery and exposed as an additive `AnalysisContext` field. Inline `Contract(...)` literals in the decorator call are accepted as the always-readable floor. Dotted-string references are rejected (a second namespace no tool validates — no import error, no rename safety). Direct top-level single-`Name` assignments only; conditional/try-wrapped/rebound definitions are unreadable (P3).
- **Resolution failures are loud**: unresolvable reference or partially-readable contract → the whole contract is discarded, `WLN-ENGINE-UNREADABLE-CONTRACT` FACT names it, and WL-001 fires across that source's accesses (fail-closed = the rule fires, never silent). Duplicate contract FQNs, and a project-local contract shadowing a pack-supplied one, are hard errors (the lineless engine-path DEFECT posture, which gates).
- **Pydantic**: v1 contracts name fields explicitly; `model=` is accepted and recorded but unused. v2 cross-checks declared field names against the model's fields and fires a DEFECT on a field the model lacks (the typo'd-field-name answer). v3 (only after v2) lets the model supply shape while the contract carries only policy. Shape is derivable; the approved default is an institutional decision and never derivable.

### 5.2 Label mechanics (the value-label plane)

- A `_CURRENT_VAR_CONTRACTS` contextvar mirrors the shipped `_CURRENT_VAR_TYPES` trio exactly: arm-local branch copy, **union** merge with a **poison** sentinel on partial/conflicting arms (poison ⇒ silent but explainable — distinguishable from "no label"), strong update/copy/invalidate discipline. `combine`/`least_trusted` never see a label.
- Label survives exactly: `Name` read, `x = y` copy, `ast.Await` unwrap (122 of the measured candidate sites are await-bound), `Starred` unwrap, and a labelled call's return. Every aggregation and value-merge **drops** the label (mapping-level identity, not field sensitivity — the honest FN, documented in the rule).
- **Interprocedural via the analyzer's existing L2 fixed point, not L3 summaries**: `param_contracts`, `function_return_contracts`, and `class_attr_contracts` ride as siblings of `param_meets`/`function_return_taints`/`class_attr_taints`. Measured necessity: param-in receivers are ~24% of candidate sites in two of three repos, call-return receivers ~50%, `self.attr` 25% of legis's — intraprocedural-only would miss half the target. **Hard constraints**: the label merge is monotone with finite height (union-over-declared-ids + poison), labels enter the convergence check and the `_L2InputKey` memo, and label maps are list-ordered, never set-iterated (byte-identity oracle).
- The `.get`-site is exposed to rules via a sibling of the existing call-site side-channel (`call_site_receiver_contracts`, keyed on `id(call)`); the taint combiner is not modified.
- L2 work-budget charging extends to the label plane explicitly (branch copies double).

### 5.3 Rule semantics — `PY-WL-127` (WL-001)

Fires at `d.get(k, default)` (and `.pop` with default) where the receiver carries a contract, `k` is a literal string, and the default is statically readable (94.8% of measured defaults are):

| Declared state of `k` | Code | Verdict |
|---|---|---|
| `Field.REQUIRED` | any default | **ERROR** — absence is an integrity failure; fabricating a value converts it to silent corruption |
| `Field.default(v)` | code default ≠ `v` | **ERROR**, distinguished as a policy contradiction (`contradiction` property; the sharpest finding in the family) — fingerprint carries the declared default (§5.5). Outranks the undeclared case (WARN) per the archived design; `CRITICAL` stays operator-override-only, catalogue-wide |
| `Field.default(v)` | code default == `v`, lexically inside a declared validation boundary | **INFO** — downgraded, never removed (D1/P2) |
| `Field.default(v)` | code default == `v`, outside a boundary | **WARN** |
| `Field.OPTIONAL_EXPLICIT` | any default | **ERROR** — absence must be represented, never substituted |
| field not in contract | any default | **WARN** — undeclared default on a contracted source (weaker claim than a declared-state violation; the contract had no opinion on this field) |
| no contract on receiver | anything | **silent** — the load-bearing sentinel; opt-in preserved |

- A field carrying a sensitivity mark (§6) can **never** be downgraded below its base — per-field "this may never be defaulted" policy; for those fields the contract-edit escape does not exist.
- **`.setdefault` is a distinct finding** (same rule id, distinct message/shape): it writes the fabricated value back, so every downstream reader inherits the substitution — strictly worse than `.get`.
- **Modulation anchors on the contract, not the enclosing tier.** Verified: every existing `modulate()` site passes the enclosing entity's tier, which would silence WL-001 in `@external_boundary` functions — the natural home of the flagship example. WL-001 instead follows the `enclosing_declared_tier` pattern with a contract-declared set: the opt-in is the contract. §6.2's "the claim is total" is preserved for the tier-modulated families; the contract family's modulation input is the declaration that created the obligation.
- `d[k]` with `KeyError` semantics is **never** a finding — absence raises, which *satisfies* `REQUIRED`; it is the fix, not the defect.
- Named, accepted FNs (documented in rule metadata; counts surfaced as a `WLN-ENGINE-*` FACT so silence is visible): non-literal keys (~24% of default-carrying sites), `try/except KeyError: return default` (the rewrite-pressure gap — a paired detection is a fast-follow), aggregation-severed labels, chained-attribute receivers, dict unpacking.

`PY-WL-128` (WL-002): existence-probing (`k in payload` as a gate) on a `REQUIRED` field of a contracted source — masking or redundancy, graded by the same anchor. Ships with 127; shares the reader and the label plane.

### 5.4 Contract-edit visibility (mechanical, no governance)

Three layers, none of which gates by itself: per-declaration `WLN-ENGINE-DECLARATION` FACTs; the signed `declarations[]` ledger in attest (§11) — a contract edit is a digest change, diffable bundle-to-bundle; a declaration-digest section in the baseline document that is **compared and reported, never suppressible**. An `optional-with-approved-default` entry additionally carries a **mandatory `reason`** and optional `expires` (the waiver contract, reusing `parse_waivers`' reject-on-load-and-before-write discipline), and approved-default entries count against the waiver-discipline ceiling — the ceiling itself is decoupled from raw rule count and re-derived deliberately (§12, QE-P13).

### 5.5 Identity

New rule ids mint new fingerprints — **no rekey, no `wlfp2` bump**. The plain WL-001 finding keys on the site (contract renames must not orphan suppressions); the **mismatch** finding carries the contract id and declared default in `taint_path` (a policy change makes conforming sites' findings genuinely new, never resurrected suppressions). Contract id rides `properties` in all cases for `explain_taint`.

## 6. Kind 2 — sensitivity marks (same phase as contracts)

```python
@sensitive(marks=(Sensitivity.PII, Sensitivity.CREDENTIAL))
@external_boundary
@schema(CUSTOMER_CONTRACT)
def fetch_customer(customer_id: str) -> dict[str, object]: ...
```

- **Sensitivity never enters the lattice** — it is orthogonal to trust (PII can be `INTEGRAL`). It rides the same value-label side-channel; ordered, taking the **maximum** on merge (conservative for disclosure).
- Three states — `SENSITIVE(level)` / `EXPLICITLY_NOT_SENSITIVE` / undeclared — so *unmarking is a positive assertion*, not an absence. `NOT_SENSITIVE` may silence only the sensitivity-specific rule; it can never suppress an existing sink finding.
- Consumers in this phase: severity escalation on the existing disclosure-adjacent sinks (log content — complementing PY-WL-125's injection focus — exception/error-response construction, SMTP), plus the per-field no-downgrade policy in §5.3. A coverage FACT fires when an *undeclared* field reaches a disclosure sink.
- The mark vocabulary is **project-defined ordinal levels** — never Australian ISM classification names as wardline-defined lattice members; any mapping to a classification scheme lives in project config/legis.
- Redaction idiom (logging a hash/prefix) is a sentinel, not a finding.

## 7. Kind 3 — facets: audit-primacy and operation semantics

```python
@audit_record
def write_audit_event(event: AuditEvent) -> None: ...

@operation(semantics=Semantics.ATOMIC)
def transfer_funds(src, dst, amount) -> None: ...
```

- A **facet seeds no taint**. `FacetType` registry (engine floor, sibling of `BoundaryType`), `SeedResult.facets: frozenset[Facet] = frozenset()`, rules read via `AnalysisContext`. Registered in its own vocabulary group so `apply_marker` rejects level attributes on it — a facet can never become a trust claim.
- **`WL-005` (`PY-WL-129`)**: a call resolving to an `@audit_record` function lexically inside a broad/silencing exception handler in a trusted-tier function — the repudiation vector PY-WL-103/104 cannot single out. Reuses the shipped handler traversal + `call_site_callees`. Must reason about exception subsumption (a narrow `except` that subsumes the audit sink's exception type still fires), pinned by a paired specimen/sentinel. De-conflicts with 103/104 in the fail-safe direction per the PY-WL-120/101 precedent: both fire, distinct fingerprints, and WL-005 never suppresses the generic finding when disabled.
- Every facet marker ships **with a consuming rule in the same release** — a marker with no rule is documentation wearing a decorator (`@audit_record` + WL-005 first; `@operation` lands only when its ACF-R2 sequencing rule is specified; `@sensitive` is consumed in §6). Emitted text says "the code declares X is the legal record; wardline verified the failure-handling discipline around X" — never "wardline verified the legal record."

## 8. Kind 4 — restoration boundaries (ships last)

```python
@restoration_boundary(evidence=(Evidence.STRUCTURAL, Evidence.SEMANTIC, Evidence.INTEGRITY))
def restore_order(blob: bytes) -> Order: ...
```

### 8.1 Semantics — the normative evidence→state table (v1)

The author declares **evidence, never a level**. The seed derives the state; `to_level` does not exist on this marker.

| Evidence set (v1) | Resulting seed |
|---|---|
| ∅, or any set lacking `STRUCTURAL` | no uplift — fail-closed `EXTERNAL_RAW` seed + `WLN-ENGINE-UNPROVABLE-RESTORATION` DEFECT-class signal (a bare assertion buys nothing, loudly) |
| `STRUCTURAL` | `UNKNOWN_GUARDED` (rank 4) |
| `STRUCTURAL + SEMANTIC` (± `INTEGRITY`) | `UNKNOWN_ASSURED` (rank 3) — **the v1 ceiling** |
| `INSTITUTIONAL` (any combination) | contributes **zero** trust (D2). Recorded verbatim in the declarations ledger with `verification_class: recorded_unverified`; claimed-categories vs resulting-state is a visible attest line item. A future caller grant may consume it; none ships now. |

Unbacked evidence yields **zero uplift, not partial** — degrading a shotgunned claim to "whatever the checker confirmed" rewards over-claiming. Per-category structural checks are required for the claim to count: `STRUCTURAL`/`SEMANTIC` require a real shape-check/rejection path (reusing PY-WL-102/119's machinery — a restoration boundary claiming `SEMANTIC` with no rejection path is the same defect as a trust boundary with none); `INTEGRITY` requires a verify-shaped call in the body or one same-module hop with a rejection path reachable from its failure (the fail-open shape is PY-WL-113's).

The 16-row evidence-vector table is pinned by a unit-level table-driven test on the seed function; this section is its normative source.

### 8.2 Engine and invariant consequences (all explicit, none incidental)

- **Type generalisation**: `LevelArg`/seed callables cannot express evidence tokens (verified refutation of "just a new BoundaryType"). A `TokenSetArg` sibling and a widened seed signature are engine-floor changes; `_grammar_digest`'s per-arg schema line and `_seed_value_identity` extend in the **same commit** (the cache-under-invalidation false-green: a completeness test asserts every `FunctionTaint`/arg field appears in the identity functions).
- **`summary_cache._CACHE_LEGAL_TAINT` is a hard blocker**: a restored `UNKNOWN_ASSURED` in a cached summary is currently dropped as corrupt. Widen the set + bump `_CACHE_FILE_SCHEMA_VERSION`. (`stdlib_taint._STDLIB_LEGAL_RETURN` is *not* touched — it constrains the stdlib table, which remains four-state.)
- **Invariant amendment is a split, never a widening**: `NEVER_PRODUCED = {MIXED_RAW}` (the `taint_join` falsification record — its test survives byte-for-byte under its own name) vs `RESTORATION_ONLY = {UNKNOWN_ASSURED, UNKNOWN_GUARDED}`. The existing no-declaration pipeline test stays unchanged (it still asserts all three absent on its own corpus); new tests assert the restoration fixture produces exactly the mapped state, `MIXED_RAW` still never, and — the witness invariant — every produced `UNKNOWN_*` carries a seed witness naming its restoration declaration. An ADR records the reachable-set change as a deliberate amendment of the 2026-05-31 decision.
- **`taint_join` completion**: the `_JOIN_TABLE` lacks `UNKNOWN_*` × known-family rows and falls through to `MIXED_RAW`, which would activate the documented modulate/PY-WL-101 disagreement under `provenance_clash`. Completed and the ADR amended **before** restoration ships.
- **`RAW_ZONE` decision, pinned by a fires/silent matrix test**: both states stay **outside** `RAW_ZONE` (they passed structural validation, which is what the raw-tier rules are about), and **PY-WL-120 fires on the uplift at the boundary** when evidence is thin — the finding moves to where the fix belongs. Verified: PY-WL-101 already polices declared-`UNKNOWN_ASSURED` correctly (rank comparison), so no rule-family disagreement analogous to `MIXED_RAW` arises. Severity model already handles both states (`_PARTIAL`, one-step downgrade) — noted as a deliberate policy: findings inside a restoration boundary report one step below `@trusted`.
- **Posture**: restoration declarations count as a **separate bucket** from checked boundaries in `resolution_posture` — declaring uplift can never clear an inertness trip. `dossier`/`assure` classify restoration entities distinctly (today's `UNKNOWN_TIERS` would report them "unprovable"; the ledger gives them their own honest category: *restored, unknown provenance*).

## 9. Kind 5 — dependency-taint declarations (config plane)

```toml
[wardline.dependency_taint]
"thirdparty.client.fetch_config" = { returns = "EXTERNAL_RAW", version = "2.31.*", reason = "returns remote config verbatim", reviewed_by = "john@wardline.dev", expires = "2027-01-01" }
```

- **Grant the table, cap the states.** One new flag (working name `--trust-dependency-taint`; declared-but-ungranted is a `ConfigError` naming the grant, the pack pattern). Legal `returns` values mirror `_STDLIB_LEGAL_RETURN` verbatim — `{ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`; never `INTEGRAL`, never the `UNKNOWN_*` family (restoration is their only producer). The cap is parser-enforced **regardless of grant**. Mandatory non-empty `reason`; duplicate keys are hard errors; the table digest folds into `scan_policy_hash` (already the cache-correct path).
- **The version pin is machine-checked against the lockfile/installed version** — a stale pin is a finding, giving this recorded-claim kind the live staleness detector the others lack. `expires` lapses like a waiver's.
- A dependency declaration conflicting with an in-repo marker on the same symbol fires (PY-WL-110's contradictory-declaration analogue). Trust-lowering entries (the `untrusted_sources` generalisation) remain ungranted — they only make the scan stricter (P1).
- This kind is the designated home for the elspeth low-resolution problem (`wardline-373a64920d`): a pack-side vocabulary assist is exactly this table.

## 10. Validation rules (the PY-WL-114 analogue, whole surface)

The validator **shares the provider's reader** — one grammar, with a recogniser-agreement test (the shipped `invalid_decorator_level` anti-drift construction; this program either replicates its private-symbol coupling or promotes the predicates to a public engine-floor API in the same pass).

Malformed-shape taxonomy (each with a positive and negative specimen): computed field name; non-literal approved default; unknown evidence category; duplicate field entries (same-kind = DEFECT; conflicting-kind = elevated, the PY-WL-110 analogue); unresolvable contract reference (**FACT** — scope-artefact-tolerant, so partial scans aren't punished, but observable); field kind out of range; `OPTIONAL_EXPLICIT` carrying a default; empty evidence list; unknown sensitivity level; dependency entry for a never-called symbol (FACT); two contracts for one source; contract on a shadowed root (fail closed). **Asymmetry, pinned by a named test**: malformed *builtin* declarations are ERROR DEFECTs (the PY-WL-114 path); malformed *custom/pack* ones are FACTs (the unprovable path). Declaration-layer soundness failures that must gate (duplicate FQN, state-cap violation, unprovable evidence claim) use the lineless engine-path DEFECT mechanism — gate authority is a property of `Kind`, and these are `DEFECT`s at `ENGINE_PATH`.

Stale-declaration observability: `WLN-CONTRACT-UNUSED-FIELD` per never-matched field (the `WLN-CONFIG-UNUSED-SANITISER` shape), unused-contract and unused-dependency-entry FACTs likewise.

## 11. Evidence, attestation, and the legis seam

### 11.1 The declarations inventory (one factory, three consumers)

Every declaration emits `{declaration_id, kind, content_digest, verification_class, subject}` — id = `(kind, subject)` with SEI when available, qualname/source-key fallback; digest over canonical content (reformat-stable); `verification_class ∈ {machine_verified, structurally_verified, recorded_unverified}` per element. Built once (alongside `classify_entity_trust`'s home), consumed by attest, assure/dossier, and the legis artifact — the `gate_decision()` no-drift precedent.

### 11.2 Attest — one schema break (`wardline-attest-3`)

Taken **once**, carrying: the sorted `declarations[]` ledger; per-kind `declaration_counts`; **declaration debt** in the posture (contracts past `expires`/review interval, stale dependency pins, ungranted-institutional claims — the `waiver_debt` shape, surfaced honestly, never dropped); a **payload-resident** HMAC disclaimer (tamper-evidence within a key-holding domain, not authorship — travels with the bundle, covered by the MAC) and the git-as-authorship framing (D3: bundles are domain-internal; asymmetric signing remains §10.8 roadmap); **legible grant-state fields** (`trusted_packs`, `trust_dependency_taint`, `strict_defaults`) — a digest is not legible evidence. Bundle-to-bundle inventory diff is the assessor operation for declaration change, including the **silent-deletion** direction (removing an `@audit_record` or a contract reduces findings; the ledger diff is what makes a recordkeeping downgrade visible).

### 11.3 Legis

The legis artifact gains an additive, **signed** `declarations` member (today it carries none — legis cannot govern declaration change it has never seen). Lockstep with the frozen `_BASE` conformance test; gate-of-record scope only (the existing `--affected` refusal — a partial inventory over-claims worse than partial findings do). Division of labour: wardline records, analyses, enumerates; legis holds approved digests, computes drift, owns approvers/expiry/adjudication. Wardline never stores approved state. The new vocabulary must not collide with legis's trust vocabulary (no `tier=` argument anywhere in the new surface; one judge).

### 11.4 Posture and honesty controls

Per-kind declaration counts enter `resolution_posture.to_dict()` (folded from `WLN-ENGINE-METRICS`, zero new analysis — the shipped inertness pattern); `--fail-on-inert` gains per-group arming (an *armed* group — one whose rules are enabled — recognising zero declarations trips; nothing can clear it); uplift-only declarations sit in a separate bucket that can never de-inert a scan; `--strict-defaults` **reports the count of declarations it dropped** (silent scope reduction is the §7.7 false-green shape); `coverage_pct` never absorbs the new kinds into one denominator (per-kind, `None` over an empty denominator, never a vacuous 100%).

## 12. Verification obligations (shipping gates)

**Program prerequisites (before any kind ships):**
P1 the corpus harness reconciles PREVIEW findings (manifest gains `maturity`; preview rules gate builds but are currently invisible to the FP gate and both reconciliation directions — landing this may turn the corpus red on PY-WL-116..126 and that work is budgeted on the critical path); P2 manifest entries gain `kind` + `interaction` fields; P3 per-kind FP rate computed and gated alongside the aggregate (WL-001 must not capture the denominator); P4 the two-run determinism guard covers `sentinels/`; P5 the invariant split (§8.2) with `MIXED_RAW` untouched; P6 the `RAW_ZONE` × new-states matrix test; P7 canonical orderings pinned (evidence categories in the §8.1 order, contract fields as sorted triples, sensitivity marks sorted — in `properties`, fingerprints, and `explain`); P8 provider-fingerprint mutation table (one row per mutable declaration element), collision pairs, reformat-stability; P9 shared-reader recogniser-agreement test; P10 the builtin/custom malformity asymmetry pinned; P11 cross-version conformance both directions (`test_unknown_marker_is_no_opinion_never_a_crash`; an unknown evidence category under a known marker renders the whole declaration unreadable per P3 — no partial honouring); P12 the inertness-denominator decision pinned (contracts count as recognised declarations, in their own group); P13 the waiver ceiling decoupled from raw rule count and re-derived deliberately.

**Per-kind gates:** ≥3 attributed sentinels; ≥5 attributed TP specimens; ≥1 interaction specimen **plus its single-declaration sibling** with the opposite label (for WL-001: the mismatch/match pair is the floor); bidirectional reconciliation clean; per-kind FP ≤5% over a ≥10-defect denominator (below that, sentinel-silence-gated and stated); two-run byte identity over fixtures **and** sentinels; all applicable validation rules with paired specimens; **self-hosting scan green at `--fail-on ERROR` with zero committed suppressions** (wardline's own `.get(field, default)` sites meet WL-001 first — by design; if it cannot survive its own source it ships preview/opt-in, never with a first waiver); `tests/golden/identity/corpus/` **zero bytes changed** on the no-declaration path (the adversarial opt-in proof), with at most one deliberate reviewed rekey per kind that adds a declaration-bearing fixture; grammar goldens re-frozen once per kind via `regen.py --reason`. WL-001 is multi-emit: entity-relative ordinal discrimination (two `.get` on one line → distinct fingerprints), added to the rekey/collision-pair suites; a fixture with ≥3 contract accesses across a branch join pins source-order emission.

CODEOWNERS for the identity corpus (recommended by its own README, still unwired) lands **before** this program starts — five kinds of re-freeze traffic is the strongest argument yet.

**Recall**: still unmeasured, and this program is the best raw material yet for the §10.8 synthetic-failure injector — contracts are machine-readable ground truth for what *should* be found. Filed as a program follow-on, not blocking.

## 13. Sequencing

Panel-forced order (differs from the original phase numbering; filigree tickets re-sequenced to match):

| Stage | Content | Filigree |
|---|---|---|
| **S0 — hardening pre-phase** | unknown-kwarg DEFECT rule + `UNKNOWN-MARKER` FACT (`wardline-4928b75782`); QE prerequisites P1–P4, P7–P10, P13; CODEOWNERS; version-bump discipline | new task under the epic |
| **S1 — facets** | `FacetType` channel, `@audit_record`, WL-005, vocabulary v2 + registry v3, extension-checklist conformance test, inventory factory (first consumer), per-kind posture counts | was Phase 4 (`wardline-7342234667`) |
| **S2 — contracts + sensitivity** | label plane (SAD work items W1–W8), `Contract`/`Field`/`@schema`/`@sensitive` in weft-markers 0.2.0, `PY-WL-127`/`128` + `.setdefault` variant, downgrade-never-suppress, contract-anchored modulation, FN-gap FACTs, contract-edit visibility, attest schema break (`wardline-attest-3`) + legis `declarations` member | Phases 1+2+5 merged (`wardline-ac5f22e4f1`, `wardline-a72fd8c917`, `wardline-1c0524c578`) |
| **S3 — restoration** | `TokenSetArg` generalisation, evidence table + per-category checks, cache-guard widening + schema bumps, invariant split + witness, `taint_join` completion + ADR amendment, `RAW_ZONE` matrix, separate posture bucket | was Phase 3 (`wardline-b9d70c6a3a`) |
| **S4 — dependency taint** | granted table + caps + lockfile staleness + expiry; elspeth vocabulary assist | was Phase 6 (`wardline-383e3cc80d`) |

S1 before S2 because facets prove the extension path (registry, vocabulary v2, shadow discipline, inventory) with zero engine risk. S3 last because it alone touches taint, the disk cache, and a security invariant. The largest single technical risk is S2's fixed-point label work (W4): non-monotone merge or a missed memo/convergence hook is an iteration-order determinism bug that surfaces as an oracle break — the most expensive place to find one.

## 14. Rejected alternatives (with the reason, so they stay rejected)

- **Kwargs on the level-bearing markers** — verified silent seed-drop under version skew; the false-green class (§4.3).
- **Dotted-string contract references** — a second namespace with no import error, no rename safety, no mypy; the alias map already resolves real names for free.
- **Contracts as trust-grammar packs** — packs are operator-granted code-execution artefacts; contracts are per-application data that changes with every schema change. Behind `--trust-pack`, the flagship rule is off by default. Packs extend the grammar; contracts are instances in it.
- **Contracts in `weft.toml`** — the designed manifest reborn: forfeits same-diff review, recreates the poisoning surface §5.2 closed, and the ungranted trust-adjacent `sanitisers` precedent is a warning, not a licence.
- **Designed approved-default suppression** (D1) — contracts act before finding generation, upstream of the unsuppressed-population split; and the mismatch-escalation deterrent is inert under agent authorship (both sides edited in one commit match by construction).
- **Institutional evidence as an uplift input, in-source** (D2) — an unverifiable-by-any-tool assertion must not raise trust from source; it is the one move §5.2 exists to prevent. Record-only in v1.
- **Restoration reaching `ASSURED`/`GUARDED` from a bare declaration** — capped at `UNKNOWN_ASSURED`; the caller-grant route is also the only uplift mechanism that works identically on both frontends (the Rust marker channel has no import provenance to harden).
- **Widening `var_taints` to `(TaintState, label)`** — threads through ~40 functions and every `combine` site; the side-channel gets branch/merge/poison semantics from a shipped pattern and keeps `least_trusted` untouched by construction.
- **Labels in `FunctionSummary`** — inherits the disk-cache envelope, HMAC, schema versions, and the whole stale-cache false-green analysis; the largest cost lever in the design, kept firmly off.

## 15. Open items (tracked, non-blocking)

1. "Inside a declared validation boundary" is **lexical** in v1 (deterministic, cheap); the dataflow-reachable variant is a recorded refinement candidate.
2. Measure WL-001 candidate volume on two third-party codebases with real external-data boundaries before finalising the INFO-stream calibration (the fallback ladder if intolerable: sensitivity-gated per-field policy → posture count `contract_defaulted: N` → never plain suppression).
3. The `try/except KeyError` paired detection (the rewrite-pressure FN).
4. `Field.default` non-scalar defaults (`[]`/`{}` are cheaply readable) — decide at implementation.
5. Synthetic-failure recall injector using contracts as ground truth.
6. Future institutional-uplift grant (consumes the recorded token; not designed here).
