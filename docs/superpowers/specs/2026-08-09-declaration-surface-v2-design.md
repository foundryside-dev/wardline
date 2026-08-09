# Declaration Surface v2 — schema contracts, facets, restoration, sensitivity, dependency taint

**Date:** 9 August 2026
**Status:** DESIGN, revision 4 — rev 2 (`ed7bfe86`) was reworked after a changes-requested ultra review (three independent reviews, nine blocking findings, all addressed; see §16). Rev 3 (`1244f627`) added the registry-owned call-form and splat-reading grammar. Rev 4 reconciles the complete S0 hardening and consumer-preparation contract back into this specification: builtin/custom compatibility, exact cache/version ownership, P11's S2/S3 token-domain gates, quantitative QE floors, pair-aware descriptor acceptance, attestation verification profiles, Legis digest semantics, and the local-versus-published rollout fence (§17).
**Program:** designed-unbuilt completion (`wardline-aee6ae068b`, label `unbuilt-2026-08-09`), Phase 0 deliverable (`wardline-3baba7e42f`)
**Provenance:** 7-perspective design panel (Solution Architect, Systems Thinker, Python Engineer, Quality Engineer, Security Architect, Static Analysis Dev, IRAP Assessor), 2026-08-09, plus ultra-review revision. All engine claims were verified in source; measurements are from a 3,017-site `.get`-corpus over wardline/legis/filigree.
**Decisions by John, 2026-08-09:** (D1) approved defaults **downgrade, never suppress**; (D2) institutional evidence is a **record-only token with zero uplift** in v1; (D3) attest bundles are **domain-internal** — asymmetric signing stays a roadmap item.

---

## 1. Scope

Extend wardline's declaration surface — today exactly three function-level decorators — to carry five new declaration kinds, so the admission-test-passing slice of the designed-but-unbuilt annotation groups (as-built spec §10) becomes buildable:

1. **Schema contracts** — per-source, per-field three-state classification enabling WL-001 (`PY-WL-127`) and WL-002 (`PY-WL-128`).
2. **Sensitivity marks** — values/fields that must not reach disclosure sinks; also the per-field "may never be defaulted" mechanism for contracts.
3. **Facets** — audit-primacy (and, later, operation-semantics) markers enabling WL-005.
4. **Restoration boundaries** — evidence-based declarations producing the two reserved lattice states `UNKNOWN_ASSURED` / `UNKNOWN_GUARDED`.
5. **Dependency-taint declarations** — caller-granted claims about third-party call returns.

### 1.1 Non-goals (unmissable version)

- **No governance apparatus** — no reviewer identity, approvals, expiry *adjudication*, or ratification anywhere in wardline; that is legis's jurisdiction and wardline stays "No governance". Mechanical expiry-lapse (a lapsed entry stops taking effect and resurfaces, the shipped waiver pattern) is not adjudication and is permitted. No declaration format carries a `reviewed_by`-style identity field.
- **No runtime structural layer and no type-system layer** — the surface remains static-analysis markers that are runtime no-ops.
- **The existing three markers' signatures are frozen** — `@external_boundary`, `@trust_boundary`, `@trusted` gain no arguments, ever (§4.3 is why).
- **No contract inheritance** — a `Contract` cannot extend or compose another contract in v1; every contract states its fields in full. Deliberate surface-minimalism; revisit only with real duplication evidence.
- **No field-sensitive taint** — labels carry mapping-level identity only.
- **No new Rust declaration surface** — the Rust frontend recognises none of the new vocabulary, and its legal-state sets are **unchanged** (§4.4): Rust cannot produce restoration states in this program.

## 2. Design principles

**P1 — Obligation vs exemption decides the grant axis.** A declaration that creates *obligations the engine checks* (required fields, audit-primacy, sensitivity marks) lives in source and needs no grant — the review of the declaration is the review of the code, in the same diff. A declaration that grants *exemptions or uplift the engine honours* (dependency-taint; any future restoration uplift past the cap; any future consumption of record-only tokens) is caller-granted, and its state caps are enforced at the parser regardless of grant. Net new grant flags in this program: **one** (§9).

**P2 — A declaration may reduce a finding's severity, never its existence (D1).** The three shipped suppression channels act on findings that already exist, which is what lets the gate evaluate a separately built unsuppressed population. A contract acts *before* finding generation — upstream of that split — so contract-driven suppression would be the only repo-authored channel with full gate authority by default. Therefore: a matching approved default **downgrades to INFO**; it never removes the finding. No declaration of any kind in this program silences an existing rule (this binds sensitivity unmarking too, §6).

**P3 — One readability rule for the entire surface.** The analyser reads exactly **four** forms, everywhere:
1. a **literal constant** (`"OFFICIAL"`, `42`, `True`, `None`) — `ast.Constant`;
2. a **value token**: a namespaced attribute whose receiver alias-resolves to an exact known export (`Field.REQUIRED`, `Evidence.STRUCTURAL` — the existing `TaintState.ASSURED` discipline). Bare names are rejected in value positions;
3. a **constrained marker call** whose callee is an exact known export and whose every argument (positional or keyword, including tuple elements) is one of forms 1–3, recursively (`Field.default("OFFICIAL")`, `Field.default("OFFICIAL", sensitivity=(Sensitivity.of("classification"),))`) — recursion is bounded by the AST and each level fail-closes independently;
4. a **declaration reference**, legal only in an argument slot typed `RefArg` (§4.2): a bare `Name` or dotted `Attribute` that alias-resolves to a **module-level declaration assignment** (`NAME = Contract(<forms 1–3 only>)`, direct top-level, single-`Name` target, unconditional, not rebound). This is the one place a bare name is legal, because a reference *must* be indirected to be shared — and it resolves through the import system, so a typo is an `ImportError` and a rename is refactorable.

A declaration that is partially readable is **wholly unreadable** and fails loud (§5.2's `UNREADABLE` label state; §10's rules) — never partially honoured.

**P4 — New axes are new types with empty defaults; runtime signatures and serialized S0 contracts stay frozen.** S0 promotes the existing `LevelArg` reader into the shared public engine-floor `marker_reader` and tightens analyzer call-shape handling to agree with the three frozen runtime decorator signatures. It does not change those signatures, descriptor bytes, or the builtin provider fingerprint. Every new field on `SeedResult`/`FunctionTaint`/`FunctionSummary`/`AnalysisContext` defaults empty. Shipping gate: on a declaration-free tree, the byte-identity golden corpus has a **zero-byte delta** and requires no regeneration.

**P5 — Labels are not taint.** Contract identity and sensitivity ride a parallel side-channel (§5.2), never `var_taints`, never `combine()`/`least_trusted`, and never `FunctionSummary` — labels are recomputed fresh every scan, so a stale cache structurally cannot produce a false-green WL-001. (The single exception is the restoration **witness**, which is taint provenance, not a label — §8.3.)

**P6 — Every declaration is a ledger entry, and consumers upgrade first.** Every declaration kind emits into one deterministic inventory (§11.1) built by a single factory and consumed by attest, assure/dossier, and the legis artifact. Cross-product contract changes (vocabulary version, attest schema, legis wire) follow **consumer-first dual-read**: the consumer learns to accept both versions, with the contract-appropriate preview artifact and coordinated receipt, before wardline emits the new one (§13.1).

**P7 — Every group ships with the metric that proves it is live, in the same change.** Per-kind declaration counts enter the resolution posture and the signed attest payload; the inertness machinery gains per-group arming (§11.4).

## 3. The four engine channels

| Channel | Kinds | Cached? | Engine surface touched |
|---|---|---|---|
| **L1 seed plane** | restoration boundaries only | yes (summary cache) | `TokenSetArg`, seed generalisation, witness field, `_CACHE_LEGAL_TAINT`, reachable-set invariant |
| **Facet plane** | audit-primacy (operation later) | no | `FacetType` registry + `SeedResult.facets`; rules read via `AnalysisContext` |
| **Value-label plane** | schema contracts, sensitivity | no | L2 side-channel + analyzer L2 fixed point; never `FunctionSummary` |
| **Config plane** | dependency-taint | keyed via `scan_policy_hash` | `weft.toml` table + caller grant |

## 4. Vocabulary, packaging, and version skew

### 4.1 weft-markers — staged, consumer-matched releases

Exports are staged so no marker ships before its consuming rule (a marker with no rule is documentation wearing a decorator):

| weft-markers | Ships with | Exports added |
|---|---|---|
| **0.2.0** | S1 | `audit_record` |
| **0.3.0** | S2 | `Contract`, `Field`, `FieldRule`, `Sensitivity`, `schema`, `sensitive` |
| **0.4.0** | S3 | `restoration_boundary`, `Evidence` |
| *(unscheduled)* | when its ACF-R2 rule is specified | `operation`, `Semantics` — **not exported before then** |

All exports: runtime no-ops, **strictly keyword-only call forms**, zero-dependency, Python-3.9 floor (frozen dataclasses without `slots`; `class Evidence(str, Enum)`-style tokens).

### 4.2 Marker-argument grammar (engine floor)

Three argument kinds drive the generic reader (the registry encodes them as `ArgKind.LEVEL` / `ArgKind.TOKEN_SET` / `ArgKind.REF` — one concept, declaration-class name and registry enum name); each is fail-closed on any deviation:

- **`LevelArg`** — S0 promotes the shipped AST reader to the shared engine floor without widening its accepted level-token domain. Declared sibling arguments are legal; an undeclared keyword or extraction defect makes a custom level-bearing declaration unprovable rather than partially readable. No ignored or compatibility keyword path exists.
- **`TokenSetArg`** — a tuple of value tokens from a declared set (`evidence=`, `marks=`). Any non-token element, any bare name, any positional arg → unreadable.
- **`RefArg`** — a declaration reference (P3 form 4). Resolves via the existing alias map to a module-level declaration FQN; the referenced assignment is read by the shared declaration reader. Unresolvable, ambiguous, conditional, rebound, or shadowed-root reference → `UNREADABLE` (§5.2), never silence.

S0 registers all three `ArgKind` tags so the registry shape is stable, but only `LEVEL` has a live consumer in S0. The generic `REF` and `TOKEN_SET` readers ship in S2 with their first consuming markers; later token domains reuse the same `TOKEN_SET` reader and repeat their own domain-integration gate.

**Positional arguments are illegal on every marker in the new vocabulary**, and on the existing three (`PY-WL-130`, §4.3). Canonical forms:

```python
@schema(contract=ORDER_CONTRACT)          # RefArg, keyword-only
@sensitive(marks=(Sensitivity.PII,))      # TokenSetArg
@restoration_boundary(evidence=(Evidence.STRUCTURAL, Evidence.INTEGRITY))
@audit_record                             # bare form, no call
```

`RegistryEntry` carries the whole builtin call grammar as three registry-owned properties: `kwargs: frozenset[str]` (the declared keyword set per marker), `arg_kinds: Mapping[str, ArgKind]` (the reading discipline per declared keyword), and `call_form: MarkerCallForm` ∈ {`BARE_ONLY`, `CALL_ONLY`, `BARE_OR_CALL`} (whether the marker is legal bare, called, or either). The shipped three mirror their frozen runtime signatures: `@external_boundary` is `BARE_ONLY` (`external_boundary(fn)`), `@trust_boundary` is `CALL_ONLY` (`trust_boundary(*, to_level)`), `@trusted` is `BARE_OR_CALL` (`trusted(fn=None, /, *, level=INTEGRAL)`).

Registry entries are immutable snapshots; `arg_kinds.keys() == kwargs`; no ignored or compatibility keyword category exists. The load-time tripwire covers both builtin roots and requires every builtin `BoundaryType.level_args` schema to equal the registry keyword set with `LEVEL` kinds.

A call-form violation is a call-**shape** offence like every other — `call_not_allowed` for a called bare-only marker, `call_required` for a bare call-only marker — and one shared validator decides every shape offence. Call form is decided first, so a called `BARE_ONLY` marker is `call_not_allowed` whatever it carries. Otherwise the validator reports positional arguments, extraction offences in source order, keyword classification and duplicate events in source order, then missing names in sorted order; it does not emit a missing-name offence when an unreadable splat might supply that name. The stable reason vocabulary is `call_not_allowed`, `call_required`, `positional_args`, `invalid_splat_key`, `unreadable_splat`, `undeclared_kwarg`, `duplicate_kwarg`, and `missing_kwarg`; `PY-WL-130` emits one finding per offence in this deterministic order. The reader and `PY-WL-130` consume that one verdict, so a rule can never disagree with seeding about a shape. **Value problems are not shape problems**: an unreadable value (`level=CFG`) is the reader's fail-closed `None` — no opinion — and a readable-but-invalid token (`level='ASURED'`) is `PY-WL-114`'s DEFECT; neither is a shape offence.

**The statically readable keyword grammar.** Direct keywords and **literal** `**{...}` dict splats are readable. One literal dict is normalised with Python's own insertion-order/last-value semantics before its items count: repeated keys *within a single literal dict* are legal Python and the last value wins, while a direct-keyword/literal-splat collision on the same name is a `duplicate_kwarg`; a non-string literal key is `invalid_splat_key`. A **dynamic** `**mapping` — any splat whose value is not a literal dict, and any nested `**` inside one — is outside the statically readable declaration grammar: it may be perfectly valid at runtime, but wardline cannot statically prove it satisfies the declaration, so the seed drops and the diagnostic states that analyzer limitation. Diagnostics stay truthful: `PY-WL-130` calls a shape runtime-invalid only for a proved runtime-invalid reason, and `unreadable_splat` says only that wardline cannot statically read the mapping.

**Builtin/custom compatibility boundary.** Registry call-form validation and `PY-WL-130` apply only to builtin markers. Custom `BoundaryType` packs retain their released `level_args` contract. An unreadable custom level value or foreign metadata on a level-bearing custom marker takes the `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT channel and seeds `UNKNOWN_RAW`; it never becomes `PY-WL-130`. A custom type with no level arguments may carry foreign metadata kwargs that Wardline ignores and may still seed.

### 4.3 Registry, versions, and the skew contract

- **S0 hardening:** `REGISTRY_VERSION`, `ATTEST_SCHEMA`, `DESCRIPTOR_SCHEMA`, `vocabulary.yaml`, descriptor serialization, and the builtin provider fingerprint remain unchanged. `_RESOLVER_VERSION` bumps because builtin seeding semantics change; old warm summaries must miss even though descriptor bytes do not move.
- **S1 emission:** `vocabulary.yaml` moves to `wardline.vocabulary/v2`; new groups are contracts 2, facets 3, restoration 4, and sensitivity 5; a `facets:` section joins `entries:`. `REGISTRY_VERSION` moves to `wardline-generic-3`, and `_RESOLVER_VERSION` bumps again because the new vocabulary changes seeding.
- **Pair-aware consumer contract:** Loomweave accepts exactly `(wardline.vocabulary/v1, wardline-generic-2)` and `(wardline.vocabulary/v2, wardline-generic-3)`. An absent schema denotes v1. Cross-pairs and unknown pairs report version skew; loose version-only acceptance is forbidden. Loomweave lands this reader expansion before Wardline emits generic-3 (§13.1).
- The live false-green (`wardline-4928b75782`, verified): an unknown kwarg or positional arg on `@trusted` silently drops the seed and the scan goes greener with no diagnostic. Two ids are reserved and ship **before any new marker**: **`PY-WL-130`** (ERROR DEFECT) — a builtin marker whose call **shape** is statically malformed per §4.2: an illegal call form, any positional argument, an undeclared or duplicated keyword, a missing required keyword, or a keyword expansion wardline cannot statically read (value-level problems stay with the reader's fail-closed `None` and `PY-WL-114`; not silenced by the builtin-stays-quiet convention; a new rule id is covered by no golden); **`WLN-ENGINE-UNKNOWN-MARKER`** (FACT) — an unshadowed decorator that resolves strictly beneath `weft_markers` or `wardline.decorators` but is not an exact registered export.
- The unknown marker itself seeds nothing and takes no opinion. It does not cancel a separate valid stacked marker. A malformed known marker takes `PY-WL-130`, never the unknown-marker channel. Configuration may override taint but must preserve both unknown-marker and unprovable-boundary observability. `decorator_coverage.summary.unknown_markers` counts these FACTs; unknown-marker entities do not become provider-seeded rows, do not increase `summary.total`, and do not arm or de-inert a scan.
- Extension checklist pinned by a conformance test, all in one commit: `REGISTRY`, boundary/facet registries, `vocabulary_star_exports()`, `diagnostics._BUILTIN_MARKER_IMPORTS`, the drift tripwire.
- Accepted builtin exports are exactly `wardline.decorators.<name>`, `wardline.decorators.trust.<name>`, and `weft_markers.<name>`; `weft_markers.trust.<name>` is not an export. Shadow discipline applies per vocabulary root: shadowing disables candidates from that root and never suppresses genuine imports from the other root. The same exact-export rule covers `Contract`/`Field`/`Evidence`/`Sensitivity` and every new marker; rejected declarations fail closed to `UNREADABLE`.

### 4.4 Rust

No new markers, no doc-comment recognition of the new vocabulary, and **`rust/vocabulary.py`'s legal sets are unchanged** — the Rust frontend can neither declare nor mint restoration states (a widened Rust legal-return set would let `rust_taint.yaml` mint unwitnessed `UNKNOWN_*` states; refused). A `WLN-RUST-COVERAGE` note names the asymmetry. Cross-language propagation stays governed by §10.5 of the as-built spec.

## 5. Kind 1 — schema contracts and WL-001/WL-002

### 5.1 Declaration

```python
# myapp/contracts.py
from weft_markers import Contract, Field, Sensitivity

ORDER_CONTRACT = Contract(
    name="orders.v3",
    fields={
        "order_id":                Field.REQUIRED,
        "security_classification": Field.default("OFFICIAL", sensitivity=(Sensitivity.of("classification"),)),
        "currency":                Field.default("AUD"),
        "discount_code":           Field.OPTIONAL_EXPLICIT,
    },
    declared_against="https://schemas.example/orders/v3",   # recorded, unverified
)

# myapp/intake.py
from weft_markers import external_boundary, schema
from myapp.contracts import ORDER_CONTRACT

@external_boundary
@schema(contract=ORDER_CONTRACT)
def fetch_order(raw: bytes) -> dict[str, object]:
    return json.loads(raw)
```

- Attachment is the stacked, keyword-only `@schema(contract=…)` marker — never a kwarg on the existing three (§4.3's verified skew false-green) and never positional (§4.2).
- References are `RefArg`s (P3 form 4). Inline `Contract(...)` literals in the `contract=` slot are the always-readable floor. Dotted-string references are rejected (a second namespace with no import error and no rename safety).
- Reader limits inherited from the shipped module-level reader: direct top-level statements only, single-`Name` targets, no conditional/`try`-wrapped definitions, last-binding-wins rejected as a rebind → `UNREADABLE`.
- Approved-default values are limited to `str`/`int`/`bool`/`None` and empty containers; `float` defaults are excluded in v1 (literal-equality hazard). Comparison is by canonical literal identity (§11.1's encoding).
- Duplicate contract FQNs, and a project-local contract shadowing a pack-supplied one, are lineless engine-path DEFECTs (they gate).
- Pydantic: v1 explicit fields; `model=` recorded but unused; v2 cross-checks field names against the model (typo DEFECT); v3 model-supplies-shape/contract-carries-policy. Shape is derivable; policy never is.

### 5.2 The label algebra (normative)

Each tracked variable carries exactly one label state; the algebra is the whole story of what WL-001 may conclude:

| State | Meaning | Introduced by | WL-001 verdict at an access site |
|---|---|---|---|
| `ABSENT` | no declaration anywhere | default | **silent** — the opt-in sentinel |
| `VALID{c}` | exactly one resolved contract | a readable `@schema` boundary; survives copy/`Await`/`Starred`/labelled-call-return | adjudicate per §5.3 |
| `POISON` | conflicting or partial-arm labels (branch union with disagreement; two different contracts merged) | `_merge`-style union on branch joins; any multi-label set | **silent**, but distinguishable: surfaced via `explain_taint` and counted in a `WLN-ENGINE-LABEL-POISON` FACT |
| `UNREADABLE` | a declaration **exists** but could not be honoured (unresolvable/ambiguous/rebound/shadowed reference; partially-readable contract; duplicate FQN) | the boundary whose `@schema` matched but failed to read; propagates exactly as `VALID` does | **fires at base severity** (the fail-closed direction: the author claimed a contract; the engine cannot honour it, so every defaulted access on that source is an undeclared default) + `WLN-ENGINE-UNREADABLE-CONTRACT` FACT naming the reference |

Merge rules: `ABSENT` is the identity; `UNREADABLE` absorbs `VALID` and `POISON` (a partially-honoured source must not be quieter than an honoured one); `VALID{a}` ∪ `VALID{b}` (a≠b) = `POISON`; `POISON` ∪ `VALID` = `POISON`. All four states are monotone under union with this ordering (`ABSENT < VALID < POISON < UNREADABLE`), which is what the L2 fixed point needs (§5.4). Every aggregation and value-merge resets to `ABSENT` (mapping-level identity only — the honest FN, counted in a FACT).

### 5.3 Rule semantics — `PY-WL-127` (WL-001)

Fires at `d.get(k, default)` / `d.pop(k, default)` where the receiver's label is `VALID{c}` (or `UNREADABLE`, per §5.2), `k` is a literal string, and the default is statically readable (94.8% measured):

| Declared state of `k` in `c` | Code | Verdict |
|---|---|---|
| `Field.REQUIRED` | any default | **ERROR** — absence is an integrity failure; fabricating a value converts it to silent corruption |
| `Field.default(v)` | code default ≠ `v` | **ERROR**, distinguished as a policy contradiction (`contradiction` property) — fingerprint carries the declared default (§5.5). Outranks the undeclared case; `CRITICAL` stays operator-override-only |
| `Field.default(v)` | code default == `v`, lexically inside a declared validation boundary | **INFO** — downgraded, never removed (D1/P2) |
| `Field.default(v)` | code default == `v`, outside a boundary | **WARN** |
| `Field.OPTIONAL_EXPLICIT` | any default | **ERROR** — absence must be represented, never substituted |
| field not in contract | any default | **WARN** — the contract had no opinion on this field |
| *(receiver `UNREADABLE`)* | any default | **ERROR at base** — undeclared-default posture, per the algebra |

- A field carrying a sensitivity mark (§6) can never be downgraded below its base — the per-field no-escape policy.
- `.setdefault` is a distinct finding shape (it writes the fabrication back; every downstream reader inherits it).
- **Modulation anchors on the contract, not the enclosing tier** (verified necessity: enclosing-tier modulation silences the rule in `@external_boundary` functions — the flagship example's home). The mechanism is the shipped `enclosing_declared_tier` pattern with a contract-declared set; opt-in is preserved because the contract *is* the opt-in.
- `d[k]` (`KeyError` semantics) is never a finding — absence raises, which satisfies `REQUIRED`.
- Named accepted FNs, counted in FACTs: non-literal keys (~24% of default-carrying sites), `try/except KeyError: return default` (paired detection is a fast-follow), aggregation-severed labels, chained-attribute receivers, dict unpacking.
- Worked call-boundary example (carried in rule metadata): `order = fetch_order(req)` then `order.get("order_id", 0)` fires — `fetch_order`'s return label enters `function_return_contracts` via the L2 fixed point, the assignment copies it, the `.get` site sees `VALID{ORDER_CONTRACT}`. Same through `await`.

`PY-WL-128` (WL-002): existence-probing (`k in payload` as a gate) on a `REQUIRED` field — same reader, same algebra, ships with 127.

### 5.4 Label mechanics

A `_CURRENT_VAR_CONTRACTS` contextvar mirrors the shipped `_CURRENT_VAR_TYPES` trio (arm-local branch copy, union merge, poison), holding §5.2 states. Interprocedural via the analyzer's L2 fixed point — `param_contracts` / `function_return_contracts` / `class_attr_contracts` as siblings of the shipped maps (measured necessity: param-in ~24%, call-return ~50%, `self.attr` up to 25% of candidate sites). Hard constraints: the §5.2 union is monotone with finite height; **labels enter the convergence predicate and the `_L2InputKey` memo**; label maps are list-ordered, never set-iterated; L2 work-budget charging extends to label branch copies. A complete **carrier/convergence matrix** — every L2 construct × its label behaviour — is a required S2 planning artifact before implementation starts (§15).

### 5.5 Identity

New rule ids mint new fingerprints — no rekey, no `wlfp2` bump. The plain finding keys on the site (contract renames don't orphan suppressions); the **contradiction** finding carries the contract id and declared default in `taint_path` (a policy change makes conforming sites' findings genuinely new). Contract id rides `properties` in all cases.

## 6. Kind 2 — sensitivity marks (same stage as contracts)

Sensitivity has **two attachment points**, matching what each consumer needs:

1. **Per-field, inside the contract** — `Field.default("OFFICIAL", sensitivity=(...,))` / `Field(required=True, sensitivity=…)`. This is what the WL-001 no-downgrade policy reads (§5.3), and the disclosure rules read at field-access sites on contracted sources.
2. **Per-function return** — `@sensitive(marks=(Sensitivity.PII,))` marks a function's whole return value; the mark rides the same value-label side-channel.

Model, resolved: **categories with union**. Marks are an unordered set of project-defined category tokens (`Sensitivity.of("classification")`, or project packs may mint tokens); merge is set-union (conservative for disclosure — a value that might carry a credential is treated as carrying it). There is no ordinal ordering and no "maximum". Category names are project-defined; wardline ships no classification scheme and Australian ISM names never appear as wardline-defined vocabulary.

**Unmarking has no mechanical power.** There is no `NOT_SENSITIVE` state that silences anything — that would be a repo-authored exemption, violating P1/P2. Absence of a mark is just absence; the declarations ledger records what is marked, and the coverage FACT (an unmarked value reaching a disclosure sink from a contracted source) is what makes non-marking visible. If a future need for attested non-sensitivity emerges, it is a record-only token and any consumption of it is caller-granted (P1).

Consumers in this stage: severity escalation on the disclosure-adjacent sinks (log content — complementing PY-WL-125's injection focus — exception/error-response construction, SMTP), the WL-001 per-field policy, and the coverage FACT. Redaction idioms (hash/prefix logging) are sentinels.

## 7. Kind 3 — facets: audit-primacy

```python
@audit_record
def write_audit_event(event: AuditEvent) -> None: ...
```

- A facet seeds no taint. `FacetType` registry (engine floor), `SeedResult.facets: frozenset[Facet] = frozenset()`, rules read via `AnalysisContext`. Registered in its own vocabulary group so `apply_marker` rejects level attributes — a facet can never become a trust claim.
- **`WL-005` (`PY-WL-129`)**: a call resolving to an `@audit_record` function inside a broad/silencing/subsuming exception handler in a trusted-tier function. Reuses the shipped handler traversal + `call_site_callees`; reasons about exception subsumption (pinned by paired specimens); de-conflicts with 103/104 fail-safe (both fire, distinct fingerprints; disabling WL-005 never drops the generic finding).
- `@operation(semantics=…)` is **specified here but not shipped and not exported** until its ACF-R2 sequencing rule is written (§4.1). Emitted text discipline: "the code declares X is the legal record; wardline verified the failure-handling discipline around X" — never "wardline verified the legal record."

## 8. Kind 4 — restoration boundaries (last engine stage)

```python
@restoration_boundary(evidence=(Evidence.STRUCTURAL, Evidence.INTEGRITY))
def restore_order(blob: bytes) -> Order: ...
```

### 8.1 Semantics — the normative evidence→state table (v1)

The author declares **evidence, never a level** (`to_level` does not exist on this marker). v1 admits **only evidence the L1 provider can verify body-locally at seed time** — the provider holds the decorated function's AST when it seeds, so a body walk is available; nothing else is (§8.2).

| Evidence category | v1 verification | Uplift contribution |
|---|---|---|
| `STRUCTURAL` | **body-local**: a genuine rejection path in the decorated body (the PY-WL-102/119 predicate, run at seed time) | base requirement for any uplift |
| `INTEGRITY` | **body-local**: a verify-shaped call (hmac/signature/digest-compare set) in the decorated body with a rejection path reachable from its failure (the PY-WL-113 fail-open predicate, inverted) | the step from `UNKNOWN_GUARDED` to `UNKNOWN_ASSURED` |
| `SEMANTIC` | **none exists** — no static predicate distinguishes "the right domain constraint" from "a shape check"; the as-built spec says so (§3, §9.1). **Record-only in v1**: ledger entry, zero uplift | none |
| `INSTITUTIONAL` | not verifiable by any tool (D2). **Record-only**: ledger entry, zero uplift; future caller-granted consumption possible, none ships | none |

| Declared, verified evidence | Resulting seed |
|---|---|
| ∅, or `STRUCTURAL` claimed but not verified | no uplift — fail-closed `EXTERNAL_RAW` seed + a lineless engine-path DEFECT (`WLN-ENGINE-UNPROVABLE-RESTORATION`) — a bare or unbacked assertion buys nothing, loudly, and gates |
| `STRUCTURAL` verified | `UNKNOWN_GUARDED` (rank 4) |
| `STRUCTURAL` + `INTEGRITY` verified | `UNKNOWN_ASSURED` (rank 3) — **the program ceiling** |

Unbacked evidence yields zero uplift, not partial (degrading a shotgunned claim rewards over-claiming). This table gives every uplift step a **distinct machine-verified predicate** — the structural step and the integrity step verify different things, and the two unverifiable categories verify nothing. The 16-row evidence-vector pin reduces in v1 to this table plus record-only entries; the unit test pins all rows.

**Deferred design (v2, recorded not built):** a pre-L3 verification phase that re-derives restoration seeds after call resolution, enabling one-hop helper recognition (validator/verifier in another function) and possibly a `SEMANTIC` predicate. It requires seeds that can be *revised downward* between L1 and L3 with cache-correct invalidation — a real architecture change, not a bolt-on, which is exactly why v1 is body-local.

### 8.2 Why body-local: the seeding-order constraint

Seeding happens per-file at parse time, before the project call graph or any rule context exists. A one-hop helper check therefore *cannot* inform the seed without a new phase. v1 restricts the grammar to what the provider can prove from the decorated body alone — the same place `LevelArg` reading already happens — so verification and seeding are simultaneous and the seed is final. No verified-later-revised-earlier machinery, no ordering hazard.

### 8.3 The witness, carried durably

Every `UNKNOWN_ASSURED`/`UNKNOWN_GUARDED` value must be attributable to the restoration declaration that minted it. The witness is **taint provenance, not a label** (P5's stated exception), so it rides the cached path:

- `FunctionSummary` gains `restoration_witness: str | None` (the declaration id, §11.1) — required non-`None` whenever body or return taint is in the `UNKNOWN_*` family, `None` otherwise.
- The cache serialisation carries it; `SUMMARY_SCHEMA_VERSION` bumps because `FunctionSummary`'s structural shape changes. The outer `_CACHE_FILE_SCHEMA_VERSION` moves only when the cache-envelope shape changes. `_parse_cache_taint`/validation widens to admit the two states **only when accompanied by a witness** — an `UNKNOWN_*` without one is a corrupt file, dropped with a warning (fail-closed, the shipped posture).
- Cold/warm equivalence: a warm scan reproduces the cold scan's witnesses byte-identically (pinned alongside the existing warm-run byte-identity property).
- The invariant test (`test_only_restoration_declarations_produce_unknown_family`) asserts every scan-emitted `UNKNOWN_*` carries a witness resolving to a declaration in the inventory.

### 8.4 Engine and invariant consequences

- The generic `TokenSetArg` reader lands with its first consumer in S2. S3 wires that existing argument kind into restoration's seed-signature generalisation; `_grammar_digest` and `_seed_value_identity` extend in the same S3 commit, with a completeness test (every field of `FunctionTaint`/every arg kind appears in the identity functions).
- Invariant amendment is a **split**: `NEVER_PRODUCED = {MIXED_RAW}` (the `taint_join` falsification record, its test surviving byte-for-byte) vs `RESTORATION_ONLY = {UNKNOWN_ASSURED, UNKNOWN_GUARDED}`; the existing no-declaration pipeline test unchanged; an ADR records the amendment of the 2026-05-31 decision.
- `taint_join`'s `_JOIN_TABLE` completed for `UNKNOWN_*` × known-family pairs before shipping (else `provenance_clash` re-activates the documented modulate/PY-WL-101 disagreement via `MIXED_RAW` fall-through); ADR amended.
- `RAW_ZONE` decision pinned by a fires/silent matrix test: both states stay outside `RAW_ZONE`; PY-WL-120 fires on thin-evidence uplift at the boundary. Verified: PY-WL-101 already polices declared-`UNKNOWN_ASSURED` by rank; severity model already handles both states (`_PARTIAL`, one step down — a deliberate, stated policy).
- Posture: restoration declarations are a **separate bucket** — uplift can never clear an inertness trip; dossier/assure classify restoration entities as *restored, unknown provenance*, never "clean".

## 9. Kind 5 — dependency-taint declarations (config plane)

```toml
[wardline.dependency_taint]
"thirdparty.client.fetch_config" = { returns = "EXTERNAL_RAW", distribution = "thirdparty-client", version = "2.31.*", reason = "returns remote config verbatim", expires = "2027-01-01" }
```

- **Grant the table, cap the states.** One new flag (working name `--trust-dependency-taint`); declared-but-ungranted is a `ConfigError` naming the grant. Legal `returns` mirror `_STDLIB_LEGAL_RETURN` — never `INTEGRAL`, never `UNKNOWN_*` (restoration is their only producer); parser-enforced regardless of grant. Mandatory non-empty `reason`; duplicate keys hard-error; table digest folds into `scan_policy_hash` and appears as a **legible attest field**, which is also the content-binding story: the boolean grant authorises *a* table, the signed digest records *which*, and legis's approved-digest mismatch is the drift detector (wardline holds no approved state). The reflexive-grant residual (§9.3-9 of the as-built spec) applies and is recorded.
- **No `reviewed_by` field** — who accepted a claim lives in git/legis, never in the declaration (non-goal). `expires` stays: mechanical lapse-and-resurface is the shipped waiver pattern, not adjudication.
- **Deterministic staleness checking, specified**: each entry names its `distribution` explicitly (no module-name→distribution guessing); the pin is matched against the installed distribution version (importlib.metadata) of the environment wardline runs in. Version-spec grammar is PEP 440 specifiers. Mismatch → finding; unresolvable distribution → FACT (scope-tolerant, observable). This is the one recorded-claim kind with a live staleness detector.
- A dependency declaration conflicting with an in-repo marker on the same symbol fires (PY-WL-110 analogue). Trust-lowering entries remain ungranted (P1). Designated home for the elspeth low-resolution work (`wardline-373a64920d`).

## 10. Validation rules

The validator and provider import the same public engine-floor `marker_reader` — one grammar and one recogniser-agreement test. S0 promotes the existing level-token logic into that module; later `REF` and `TOKEN_SET` consumers extend the shared reader rather than replicating it.

Malformed-shape taxonomy (each with paired specimens): computed field name; non-literal or out-of-range approved default (incl. `float`); unknown evidence category; duplicate field entries (same-kind DEFECT; conflicting-kind elevated, PY-WL-110 analogue); unresolvable/ambiguous/rebound contract reference (→ `UNREADABLE`, FACT + fail-closed firing per §5.2); field kind out of range; `OPTIONAL_EXPLICIT` with a default; empty evidence tuple; unknown sensitivity token; dependency entry missing `distribution`/`reason`, or for a never-imported distribution (FACT); two contracts for one source (lineless engine-path DEFECT — gates); declaration under a shadowed root (→ `UNREADABLE`). Asymmetry pinned by a named test: malformed **builtin** declarations are ERROR DEFECTs; malformed **custom/pack** ones are FACTs (the unprovable path). Stale-declaration observability: `WLN-CONTRACT-UNUSED-FIELD`, unused-contract, unused-dependency-entry FACTs (the `WLN-CONFIG-UNUSED-SANITISER` shape).

## 11. Evidence, attestation, and the legis seam

### 11.1 The declarations inventory (one factory, three consumers)

Every declaration emits `{declaration_id, kind, content_digest, verification_class, subject, sei?}`:

- **`declaration_id` is tool-independent and deterministic**: `sha256("wlds1" ‖ kind ‖ subject ‖ field?)` where `subject` is the scan-root-relative qualname (functions) or contract FQN (contracts) or table key (dependency entries). **SEI is optional metadata alongside, never the id** — an id must not change because optional Loomweave enrichment came or went. A rename changes the id (as it changes fingerprints today); continuity across renames is legis's re-binding concern, not wardline's.
- **`content_digest`**: SHA-256 over a canonical encoding — sorted keys, type-tagged scalars (so `"1"` ≠ `1`), NFC-normalised strings, evidence/marks in their declared canonical order, defaults as their canonical literal text. Reformat-stable (whitespace/comment changes don't churn it), value-change-sensitive.
- **`verification_class`** ∈ `{machine_verified, structurally_verified, recorded_unverified}` per element.

One factory builds it; attest, assure/dossier, and the legis artifact consume it (the `gate_decision()` no-drift precedent).

### 11.2 Attest — one schema break (`wardline-attest-3`), consumer-first

Carries: the sorted `declarations[]` ledger; per-kind `declaration_counts`; declaration debt in the posture (lapsed `expires`, stale dependency pins, record-only claims); the payload-resident HMAC disclaimer + git-as-authorship framing (D3); legible grant-state fields (`trusted_packs`, `trust_dependency_taint`, `strict_defaults`) and the dependency-table digest.

**Rollout and verification profiles:** consumer preparation is S0; the declaration-bearing attest-3 producer and emission remain S1. S0 authors a DRAFT, non-normative attest-3 contract and signed preview vector. The key-holding Wardline verifier dual-accepts attest-2 and attest-3 and reports `schema_recognized` independently from `signature_valid`; `signature_valid` may be true only for a recognised schema with a valid HMAC. A missing or unknown schema sets both fields false, including when the bundle was correctly re-signed over its own unknown schema tag. Attest-2 continues to verify and attest-1 remains rejected.

Warpline is a non-key-holding consumer of pushed, untrusted bundles. It accepts attest-2 and attest-3 for schema, commit/tree, Stable Entity Identity (SEI), verdict, and current-content checks, but never performs runtime HMAC verification and always reports `signature_verified: false`; its `source` names the schema actually consumed. Independent HMAC derivation with the public test-vector key is conformance-only. Wardline owns the preview vector and Warpline vendors it byte-identically. S1 compares its first real attest-3 serialization semantically and bytewise with the preview before replacing and freezing it.

The baseline document's new declaration-digest section is behind a `baseline.yaml` `version: 2` bump with a defined migration: version-1 baselines load unchanged (no declaration section = no comparison); the section is additive, **compared and reported, never suppressible**.

### 11.3 Legis

The legis artifact gains an additive signed `declarations` member (it currently carries none). Lockstep with the frozen `_BASE` conformance test; gate-of-record scope only (the existing `--affected` refusal). Wardline records/analyses/enumerates; legis holds approved digests, computes drift, owns approvers and adjudication. No `tier=` argument anywhere in the new vocabulary — one judge.

S0 pins Legis's additive-key behavior precisely: `declarations` is accepted without changing the active-defect gate population, but every non-signature member remains signature-covered and contributes to `scan_digest`; adding `declarations` therefore shifts the digest by design. The S0 preview vector signs and verifies live without a pinned signature hex. When S1 adds real declaration content to the main scan-artifact vector, its expected signature and resulting digest are re-pinned on both sides in one coordinated change.

### 11.4 Posture honesty

Per-kind counts in `resolution_posture.to_dict()` (folded from `WLN-ENGINE-METRICS`, zero new analysis): the histogram gains one counter per declaration group (`contracts`, `facets`, `restoration`, `sensitivity`, `dependency_taint`). The base denominator remains exact: a scan becomes non-trivial at five analysed functions; only the `anchored` and `config` source buckets count as recognised boundaries; `module_default` and `callgraph` do not clear inertness. **Per-group arming** extends this base contract: a group is *armed* iff any of its consuming rules is enabled; `--fail-on-inert` trips when any armed group recognised zero declarations at or above the same floor; nothing clears it. Uplift-only declarations sit in a bucket that never de-inerts a scan. `--strict-defaults` reports the count of declarations it dropped. `coverage_pct` stays per-kind, `None` over empty denominators. `wardline-7e0a3b1e3d` tracks the current config/callgraph metric-emission gap; that defect does not alter the denominator contract.

## 12. Verification obligations (shipping gates)

**Program prerequisites (S0):**

- **P1 — complete finding population.** Every active, unsuppressed DEFECT over fixtures and sentinels participates in reconciliation and false-positive arithmetic regardless of STABLE/PREVIEW maturity; preview findings enter both numerator and denominator.
- **P2 — closed manifest.** The manifest carries `maturity`, `kind`, and `interaction` (legacy omissions default to stable, core, and no interaction), rejects live-rule maturity drift, and never assigns an unaccounted finding to `core`.
- **P3 — exact reconciliation before rates.** Global and per-kind rates are evaluated only after bidirectional reconciliation is clean: every fired DEFECT has exactly one manifest row, unmatched TP rows are stale failures, unaccounted findings fail, and a silent clean/FP sentinel passes.
- **P4–P7.** Two-run determinism covers `sentinels/`; the invariant split keeps `MIXED_RAW` untouched; the `RAW_ZONE` × new-states matrix is pinned; canonical orderings are pinned everywhere they serialize.
- **P8 — durable custom-grammar identity.** The provider fingerprint covers canonical name, module prefix, group, builtin flag, ordered argument schema, and structural seed identity. It is full SHA-256 over unambiguous type-tagged structured canonical bytes: semantic or nesting changes move it; path, line, comments, and layout do not. Delimiter-joined and truncated preimages are forbidden.
- **P9–P10.** Shared-reader recogniser agreement and the builtin/custom malformity asymmetry are pinned.
- **P11a — forward marker skew.** A decorator rooted in the vocabulary (`wardline.decorators`/`weft_markers`) that the running engine does not recognise takes no opinion, never crashes, and leaves the `WLN-ENGINE-UNKNOWN-MARKER` FACT (`test_unknown_marker_is_no_opinion_never_a_crash`).
- **P12 — inertness denominator.** The exact base contract is §11.4; S1 per-group arming extends it.
- **P13 — fixed waiver ceiling.** The repository-wide ceiling is the reviewed constant **5** (S0 usage: **0**), never a function of rule count. Raising it requires a dedicated review with a named owner and rationale; a new rule creates no suppression headroom. This repository ceiling does not relax any new kind's zero-committed-suppression self-hosting gate.
- **P14 — one marker grammar.** The §4.2 `ArgKind` registry, call form, and keyword-only enforcement land with `PY-WL-130`; they are the same change.

**P11b — unknown `TokenSetArg` token (S2 release gate):** before the first `TokenSetArg` consumer emits, an unknown value token in any known marker makes the whole declaration unreadable under P3; nothing is partially honoured. S2 proves the generic reader with an unknown `Sensitivity` token on `@sensitive`. Every later `TokenSetArg` consumer repeats an integration specimen for its own token domain; S3 therefore proves an unknown `Evidence` token on `@restoration_boundary` before emission. A LEVEL-token typo is not a `TokenSetArg` proxy.

**Per-kind gates:** ≥3 distinct attributed clean/FALSE_POSITIVE sentinel files; ≥5 attributed TP specimens; ≥1 interaction specimen + its opposite-label sibling (WL-001's floor: the contradiction/match pair); bidirectional reconciliation clean; per-kind FP ≤5% over ≥10 active defects. Below 10, make no measured-rate claim: the implementation receipt records the kind, active-defect count, FP count, distinct clean-sentinel count, TP-specimen count, and status `sentinel-gated-low-sample`. Two-run byte identity covers fixtures and sentinels; all applicable §10 validation rules have paired specimens; **self-hosting is green at `--fail-on ERROR` with zero committed suppressions** (WL-001 meets wardline's own `.get` sites first — if it cannot survive its own source it ships preview/opt-in, never with a first waiver). The checked-in identity corpus has a **zero-byte delta** on the no-declaration path — byte-identical to the pre-kind baseline, not an empty output stream — with at most one reviewed rekey per kind; grammar goldens re-freeze once per kind via `regen.py --reason`. WL-001 multi-emit ordinal discrimination (two `.get` on one line → distinct fingerprints) lives in the rekey/collision suites; a ≥3-access branch-join fixture pins source-order emission. Restoration adds witness presence/validation tests, cold/warm witness equivalence, the 16-row evidence pin, and the bare-assertion sentinel (maximal declaration, no verified evidence → no uplift + gating DEFECT). CODEOWNERS for the identity corpus lands in S0.

Recall stays unmeasured and honestly stated; the contract-driven synthetic-failure injector is the recorded follow-on.

## 13. Sequencing

### 13.1 Cross-product prep (in S0, consumer-first — P6)

1. Loomweave accepts exactly `(wardline.vocabulary/v1, wardline-generic-2)` and `(wardline.vocabulary/v2, wardline-generic-3)`, with absent schema treated as v1. Its S0 generic-3 fixture is semantic and non-normative; Wardline's real S1 producer bytes provide the later byte freeze.
2. Wardline authors the DRAFT/non-normative attest-3 contract and signed preview vector, and its key-holding verifier dual-accepts attest-2 and attest-3 with separate `schema_recognized` and `signature_valid` results. Warpline vendors the vector byte-identically and dual-accepts both schemas as a non-key-holding, untrusted relay.
3. Wardline authors the declarations preview vector. Legis vendors it byte-identically and proves that `declarations` is accepted, signature-covered, digest-shifting, and inert with respect to active-defect selection.

Cross-product prep is complete only when the Wardline–Warpline and Wardline–Legis vectors are byte-identical, their coordinated tests pass without skips, and the actual consumer commits are recorded. The attest seam remains `gap` until the Wardline–Warpline receipt passes; only then may it become `at_bar`. These receipts do not authorize public producer emission.

### 13.2 Stages

| Stage | Content | Filigree |
|---|---|---|
| **S0 — hardening + cross-product prep** | `PY-WL-130` + `WLN-ENGINE-UNKNOWN-MARKER` (`wardline-4928b75782`); the §4.2 ArgKind and call-form grammar (P14); QE prerequisites P1–P10, P11a, P12–P13; CODEOWNERS; §13.1 consumer prep | `wardline-5a795253f1` |
| **S1 — facets + evidence spine** | `FacetType`, `@audit_record` (weft-markers 0.2.0), WL-005; vocabulary v2 + `wardline-generic-3` (consumers ready per §13.1); **the inventory factory, `wardline-attest-3`, the legis `declarations` member, baseline v2, and per-group posture counts** — the evidence spine ships with the first declaration kind so no declaration ever exists outside the ledger (P6/P7) | `wardline-7342234667` |
| **S2 — contracts + sensitivity** | label plane (carrier/convergence matrix first — §15), `Contract`/`Field`/`@schema`/`@sensitive` (weft-markers 0.3.0), generic `RefArg` and `TokenSetArg` readers + P11b unknown-`Sensitivity` gate, `PY-WL-127`/`128` + `.setdefault` shape, the §5.2 algebra, contract-anchored modulation, FN FACTs, contract-edit visibility | `wardline-ac5f22e4f1`, `wardline-a72fd8c917`, `wardline-1c0524c578` |
| **S3 — restoration** (last engine-touching stage) | restoration wiring of the existing `TokenSetArg` reader + unknown-`Evidence` integration gate, body-local evidence checks, §8.1 table, witness carrier + `SUMMARY_SCHEMA_VERSION` bump, invariant split + ADR, `taint_join` completion, `RAW_ZONE` matrix, separate posture bucket (weft-markers 0.4.0) | `wardline-b9d70c6a3a` |
| **S4 — dependency taint** (engine-independent; may run in parallel with S2/S3 once S1's evidence spine exists) | granted table + caps + distribution-pinned staleness + expiry; elspeth vocabulary assist | `wardline-383e3cc80d` |

The largest technical risk is S2's fixed-point label work; the ordering rationale is unchanged (S1 proves the extension path with zero engine risk; S3 alone touches taint, the disk cache, and a security invariant).

### 13.3 Rollout gates

The local-coordination and published-release gates are cumulative and not interchangeable.

- **Local coordination:** the consumer task commits are ancestors of their designated integrated branches; cold installs are built from archives of those recorded heads rather than dirty checkout bytes; installed-package probes and both cross-repository receipts pass; long-running federation processes are restarted. Passing this gate permits local S1 development and coordinated local emission only.
- **Published emission:** before any published Wardline release emits generic-3 or attest-3, published Loomweave, Warpline, and Legis releases must contain the recorded consumer commits. The exact published distributions are cold-installed and probed, vector receipts are rerun against archives of the exact release tags, tag/version/commit and distribution-hash evidence is recorded, and the release-train owner authorizes emission. S0 performs no consumer release bumps and closes with `published_emission_ready=false`.
- **S1 producer preflight:** the first real generic-3 and attest-3 outputs are compared semantically and bytewise with their non-normative previews before the previews are replaced and the producer formats are frozen.
- **Rollback:** revert the Wardline producer first so emission returns to generic-2/attest-2. Leave surplus consumer dual-acceptance deployed; never revert consumers while a producer still emits the new formats.

## 14. Rejected alternatives

- **Positional/bare-name marker syntax** (`@schema(ORDER_CONTRACT)`) — violates the reader's fail-closed grammar and `PY-WL-130`; keyword-only `contract=` with `RefArg` is the lawful form (rev-2 correction).
- **Undeclared kwargs on level-bearing markers** — verified silent seed-drop under version skew. Declared runtime kwargs such as `@trusted(level=...)` and `@trust_boundary(to_level=...)` remain lawful.
- **Dotted-string contract references** — a second namespace with no import error, no rename safety, no mypy.
- **Contracts as trust-grammar packs** — packs are granted code-execution artefacts; contracts are per-app data; behind `--trust-pack` the flagship rule is off by default.
- **Contracts in `weft.toml`** — the designed manifest reborn; forfeits same-diff review and recreates the poisoning surface.
- **Designed approved-default suppression** (D1) — upstream of the unsuppressed-population split; mismatch-escalation is inert under agent authorship.
- **Institutional or semantic evidence as uplift inputs** (D2, rev 2) — no distinct machine predicate exists for either; an unverifiable assertion must not raise trust from source.
- **One-hop evidence checks at seed time** (rev 2) — seeding precedes call resolution; needs the deferred pre-L3 verification phase, not a bolt-on.
- **Restoration reaching `ASSURED`/`GUARDED` from a bare declaration** — capped at `UNKNOWN_ASSURED`; the caller-grant route is also the only cross-frontend-consistent uplift mechanism.
- **Widening Rust legal-state sets** (rev 2) — would let `rust_taint.yaml` mint unwitnessed restoration states.
- **Ordinal sensitivity with max-merge, and silencing `NOT_SENSITIVE`** (rev 2) — categories are unordered (union), and unmarking must not be a repo-authored exemption.
- **SEI as primary declaration id** (rev 2) — availability-dependent identity makes declarations appear deleted/recreated when optional enrichment changes.
- **`reviewed_by` in dependency entries** (rev 2) — reviewer identity is governance; git/legis own who.
- **Single big-bang weft-markers 0.2.0** (rev 2) — staged exports so no marker ships before its consuming rule.
- **Widening `var_taints` / labels in `FunctionSummary`** — the side-channel keeps `least_trusted` untouched by construction and the cache label-free (witness excepted, §8.3).

## 15. Open items (tracked)

1. "Inside a declared validation boundary" is lexical in v1; dataflow-reachable is a recorded refinement.
2. Measure WL-001 candidate volume on two third-party codebases before finalising the INFO-stream calibration (fallback ladder: per-field sensitivity policy → posture count → never plain suppression).
3. The `try/except KeyError` paired detection.
4. The **L2 label carrier/convergence matrix** — every L2 construct × label behaviour, authored and reviewed before S2 implementation begins (promoted from prose requirement to a named artifact).
5. Measure the label plane's L2 work-budget cost during S2 (before it ships).
6. The pre-L3 restoration verification phase (v2 design sketch; unlocks one-hop evidence and a possible `SEMANTIC` predicate).
7. Contract-driven synthetic-failure recall injector.
8. Future caller-granted consumption of record-only tokens (institutional, semantic, attested-non-sensitive).
9. P11a's known star-import blind spot: a newer name introduced only through `from weft_markers import *` cannot be attributed by an older engine because its star-export map contains only names it already knows.

## 16. Revision 2 disposition of the ultra-review findings

| # | Finding | Disposition |
|---|---|---|
| 1 | Canonical syntax violated P3/PY-WL-130 | Fixed: keyword-only everywhere; `RefArg` added to the grammar (P3 form 4); `arg_kinds` registry; P14 ties the grammar to S0 |
| 2 | Restoration verification later than seeding | Fixed: v1 evidence is body-local at seed time (§8.2); one-hop/pre-L3 phase deferred and recorded |
| 3 | STRUCTURAL/SEMANTIC same proof, different uplift | Fixed: SEMANTIC is record-only; each uplift step has a distinct machine predicate (§8.1) |
| 4 | Witness had no durable carrier; Rust could mint states | Fixed: `FunctionSummary.restoration_witness` + cache schema + validation + cold/warm equivalence; Rust legal sets unchanged (§8.3, §4.4) |
| 5 | Sensitivity not executable; NOT_SENSITIVE violated P1/P2 | Fixed: per-field + per-return attachment; categories-with-union; unmarking has no mechanical power (§6) |
| 6 | Label states collapsed | Fixed: normative four-state algebra with per-state verdicts and monotone ordering (§5.2) |
| 7 | Cross-product rollout incomplete | Fixed: consumer-first dual-read in S0 (§13.1); evidence spine (attest-3, legis member, baseline v2) ships in S1 with the first declaration kind |
| 8 | Declaration id availability-dependent | Fixed: tool-independent deterministic id; SEI demoted to optional metadata; digest schema specified (§11.1) |
| 9 | Governance/sequencing contradictions | Fixed: `reviewed_by` dropped; expiry-lapse explicitly mechanical (non-goals); staged weft-markers exports; `@operation` unexported; S4 declared engine-independent/parallel; grant-content binding via signed table digest + legis (§9) |

## 17. Revision 4 S0 contract reconciliation

| Area | Decision now owned by this specification |
|---|---|
| S0 engine floor | Exact builtin call forms, shared reader, literal/dynamic splat partition, builtin/custom compatibility, stable diagnostic channels, and resolver-only S0 invalidation (§4) |
| QE gates | Closed STABLE/PREVIEW reconciliation, fixed per-kind floors, exact inertness denominator, fixed waiver ceiling, and explicit low-sample receipts (§11.4–§12) |
| Token domains | Generic `TokenSetArg` compatibility lands in S2 with sensitivity; S3 repeats the integration gate for evidence (§12–§13.2) |
| Consumer contracts | Exact descriptor pairs, separate attestation recognition/validity, key-holding versus keyless profiles, and Legis signature/digest behavior (§4.3, §11, §13.1) |
| Release authority | Non-normative S0 previews, mandatory two-sided receipts, cumulative local/published gates, producer-first rollback, and `published_emission_ready=false` at S0 close (§13.3) |
