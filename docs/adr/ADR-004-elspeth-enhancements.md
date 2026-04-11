# RFC: Restoration Symmetry and Deep Immutability Rules

**Status:** Revised
**Author:** ELSPETH project (consumer of wardline Python binding)
**Target:** Wardline specification v1.0 (prime) and Part II-A (Python binding)
**Date:** 2026-04-09
**Revised:** 2026-04-09 — Resolved all open questions; corrected manifest field references to match codebase (`boundaries`/`BoundaryEntry`, not `boundary_declarations`); extended WL-009 scope to include `@integral_construction`; added detection scope limitations (§2.3.6) and self-hosting impact analysis (§2.3.7); added extensible mutable container type list for SUP-010.

## Abstract

This RFC proposes three additions to the wardline framework:

1. **WL-009** (prime spec, §7): A structural verification rule requiring that integral-read paths through serialization boundaries declare commensurate restoration evidence. Closes a gap where `@integral_read` permits Tier 1 authority claims on deserialized data without evidence, contradicting the restoration model in §5.3.

2. **Non-normative note** (prime spec, §8): Guidance that bindings whose target language has shallow immutability mechanisms SHOULD define supplementary rules detecting false structural guarantees on Tier 1 data.

3. **SUP-010 and SUP-011** (Python binding, Part II-A): Two supplementary rules detecting missing deep-freeze enforcement in frozen dataclass `__post_init__` methods. These use the supplementary rule prefix (consistent with SCN-021 and SUP-001) because they are binding-specific rules with no framework-level counterpart, not implementations of a framework WL-* rule.

All three proposals are derived from enforcement gaps discovered while applying wardline's tier model to a production audit-trail system (ELSPETH), where the write/read asymmetry and shallow immutability gaps produced integrity violations that the current rule set does not detect.

---

## 1. Motivation

### 1.1 The restoration symmetry gap

The wardline specification establishes a rigorous model for restoration boundaries (§5.3). Four evidence categories — structural, semantic, integrity, and institutional — determine what tier a deserialized representation may claim. WL-007 requires that declared restoration boundaries contain rejection paths. The model is sound.

The gap is upstream of the model: **there is no rule that requires a restoration boundary to exist when one is needed.**

Consider the following annotated code:

```python
@integral_writer
def write_audit_record(event: AuditEvent) -> None:
    """Write to the audit trail. Construction includes __post_init__
    validation: enum range checks, non-null invariants, hash verification."""
    db.insert(event.to_row())

@integral_read
def load_audit_record(run_id: str) -> AuditEvent:
    """Read from the audit trail. No validation — trusts the database."""
    row = db.fetch("audit_events", run_id=run_id)
    return AuditEvent(**row)
```

The write path constructs `AuditEvent` through validated construction — `__post_init__` enforces invariants. The read path deserializes from the database and stamps the output as INTEGRAL via `@integral_read`. But the read path performs no validation. The invariants established at construction time are not re-verified after deserialization.

This code is well-annotated. The scanner sees `@integral_read` and treats the output as Tier 1. WL-001 through WL-008 fire normally within the function body. But no rule detects the structural gap: **the read side claims the same authority as the write side without providing the same evidence.**

The consequence is precisely what §5.3 warns against: "a mere assertion of internal origin does not suffice." The `@integral_read` annotation is that mere assertion. Without a `@restoration_boundary` declaration specifying evidence categories, the scanner cannot verify — and governance cannot review — the adequacy of the restoration act.

### 1.2 Why this is a framework concern, not a binding concern

The restoration symmetry gap is language-agnostic:

- **Python:** `dataclass.__post_init__` validation on write, bare `dict(**row)` construction on read.
- **Java:** `@PrePersist` validation on JPA entity write, bare `ResultSet` mapping on read.
- **Go:** Struct constructor with validation on write, bare `json.Unmarshal` on read.

In every case, serialization strips runtime invariants, and the read path must re-establish them. The wardline already models this (§5.3) — the missing piece is a rule that detects when the model is not applied.

### 1.3 The shallow immutability problem

Python's `frozen=True` on dataclasses prevents attribute *reassignment* but does nothing about mutable *contents*. A frozen dataclass with a `dict` field is a false structural guarantee: the field reference cannot be reassigned, but the dict's contents can be freely mutated through the existing reference.

This matters for Tier 1 data because immutability is part of the integrity contract. An audit record whose fields can be silently mutated after construction — even if the dataclass is declared frozen — has a weaker integrity guarantee than the declaration implies. The `frozen=True` attribute is the Python-level assertion of immutability; if the assertion is false, downstream code that trusts it (including the wardline scanner, which may use `frozen=True` as a signal for structural soundness) is operating on a false premise.

The principle — "declared immutability must be deep, not shallow" — applies to any language where the immutability mechanism is shallow. But the detection is inherently language-specific because the immutability mechanisms differ across languages. This makes it a candidate for a framework-level non-normative note (establishing the principle) with binding-level supplementary rules (implementing detection).

---

## 2. Proposed Changes

### 2.1 WL-009: Integral restoration without declared evidence (prime spec)

#### 2.1.1 Rule definition

**Proposed addition to §7.1:**

| Rule | Pattern | Why It Is Dangerous |
|------|---------|---------------------|
| **WL-009** | Integral-read function on a serialization path without declared restoration evidence | The function claims Tier 1 authority for deserialized data on assertion alone — no evidence categories are declared, no governance review of the restoration act is possible, and the scanner cannot verify that write-side invariants are re-established on read. This is the restoration-symmetry failure: write-side construction includes validation that serialization strips, and the read side silently re-stamps the deserialized representation as authoritative without re-verifying the invariants. The severity of the gap is proportional to the write-side validation depth — a construction path with semantic validation, integrity checks, and cross-field invariants that is paired with a bare deserialization path creates a wider integrity gap than a construction path with only structural checks. |

#### 2.1.2 Detection semantics

WL-009 is a **structural verification rule** (like WL-007 and WL-008), not a pattern rule. It operates on the annotation topology, not on AST patterns within function bodies.

WL-009 fires when **all three** of the following conditions hold:

1. A function is declared `@integral_read` or `@integral_construction` (Group 1). See §2.1.2b for `@integral_construction` rationale.
2. The function's data source crosses a serialization boundary — determined by manifest declaration. The overlay manifest's `boundaries` entries (each a `BoundaryEntry` with a `serialization_boundary: true` flag) identify which data sources involve serialization (databases, files, message queues, caches). Functions whose Group 1 decorator data source is an in-memory Tier 1 structure (no serialization) are not subject to WL-009.
3. The function does **not** co-declare `@restoration_boundary` (Group 17) with evidence categories, **and** the function's inputs do not trace through a declared restoration boundary with sufficient evidence within the two-hop analysis scope (§8.1).

**The manifest dependency is intentional.** WL-009 requires the manifest to declare which data sources involve serialization. Without this declaration, the scanner cannot distinguish an `@integral_read` on an in-memory cache (no serialization, no WL-009) from an `@integral_read` on a database query (serialization, WL-009 applies). This is consistent with the framework's design: the manifest declares the trust topology, and the scanner enforces rules against it.

**Resolution chain.** The scanner resolves the serialization-path condition through the following steps:

1. **Manifest loader** reads the overlay's `boundaries` entries and builds an index of `BoundaryEntry` objects where `serialization_boundary: true`. Each entry identifies a function (e.g., `myapp.db.fetch`) as a serialization source via its `function` field.
2. **Annotation discovery** identifies all functions with `@integral_read` (or `@integral_construction` — see §2.1.2b) and builds the restoration-boundary index (functions with `@restoration_boundary` and their evidence parameters).
3. **Call-graph extraction** builds the forward adjacency list for each `@integral_read` function within the two-hop analysis scope.
4. **Serialization-path test:** For each `@integral_read` function, the scanner checks whether any function in its two-hop call graph (measured as call-site hops from the `@integral_read` function outward) appears in the serialization-boundary index. If no serialization source is reachable, WL-009 does not apply (in-memory read path).
5. **Restoration-evidence test:** For functions that reach a serialization source, the scanner checks whether (a) the function co-declares `@restoration_boundary` with at least one evidence category, or (b) any function in the two-hop call graph between the `@integral_read` function and the serialization source declares `@restoration_boundary` with evidence. If neither condition holds, WL-009 fires.

#### 2.1.2a Base rule and two-hop enhancement

WL-009's detection has two tiers of implementation complexity:

**Base rule (co-declaration check).** Condition (a) — the `@integral_read` function itself co-declares `@restoration_boundary` — is a trivial annotation-topology check with no data-flow analysis. This catches the common case: a developer adds `@integral_read` but forgets `@restoration_boundary`. A conformant tool MAY implement only the base rule and declare this limitation in its rule-subset documentation.

**Two-hop enhancement (delegated restoration).** Condition (b) — the function's inputs trace through a restoration boundary in a called function — requires the same two-hop call-graph analysis that PY-WL-008 uses for delegated rejection paths and PY-WL-009 uses for validation ordering. This is the more complex case but reuses existing infrastructure. A tool that already implements two-hop analysis for WL-007/WL-008 can extend it to WL-009 with minimal additional work.

Conformant tools that implement only the base rule will produce false positives on correctly-delegated restoration paths. This is acceptable: the false-positive is conservative (it demands explicit co-declaration rather than trusting delegation), and the developer can resolve it by adding `@restoration_boundary` to the `@integral_read` function itself — a governance improvement, not a burden.

#### 2.1.2b Scope: `@integral_construction` inclusion

WL-009 also fires when `@integral_construction` (the T2→T1 promotion decorator, Group 1) reads from a manifest-declared serialization boundary without restoration evidence. The rationale is identical: `@integral_construction` claims Tier 1 authority for its output. If the inputs arrive from a serialized source, the same evidence gap exists — serialization may have stripped the invariants that the construction path relies on, and the T2→T1 promotion re-stamps the data as authoritative without verifying that the invariants survived the round-trip.

The detection conditions for `@integral_construction` are identical to those for `@integral_read` (conditions 1-3 in §2.1.2), substituting `@integral_construction` for `@integral_read` in condition 1. The severity is the same (E/U across all taint states) because the structural deficiency — absence of restoration evidence on a Tier 1 promotion from a serialized source — is the same regardless of which Group 1 decorator is used.

**Note:** `@integral_writer` is not subject to WL-009. Writers produce data for serialization; they do not consume serialized data. The restoration symmetry gap is a read-side problem.

#### 2.1.3 Severity matrix

WL-009 is a structural verification rule. Like WL-007 and WL-008, its severity is **ERROR/UNCONDITIONAL** across all eight taint states.

| Rule | INTEGRAL | ASSURED | GUARDED | Ext. Raw | Unk. Raw | Unk. Guarded | Unk. Assured | Mixed Raw |
|------|----------|---------|---------|----------|----------|--------------|--------------|-----------|
| **WL-009** | E/U | E/U | E/U | E/U | E/U | E/U | E/U | E/U |

**Rationale:** Like WL-007 (boundaries must reject) and WL-008 (semantic validation requires prior shape validation), WL-009 enforces a framework invariant — the restoration model's evidence requirement — rather than a context-dependent pattern judgement. A bare `@integral_read` on a serialization path is structurally unsound regardless of the enclosing taint state, because the deficiency is in the annotation topology, not in the code patterns within the function body.

#### 2.1.4 Interaction with existing rules

- **WL-007** continues to apply to declared `@restoration_boundary` functions — WL-009 ensures a restoration boundary exists; WL-007 ensures it contains a rejection path. The two rules are complementary: WL-009 catches the case where no restoration boundary is declared at all; WL-007 catches the case where one is declared but is structurally unsound.
- **§5.3 evidence categories** remain the authority on what evidence is required for each restoration tier. WL-009 does not duplicate that specification — it enforces that the evidence framework is *invoked*, not that the evidence is *sufficient*. Sufficiency remains a governance-reviewed claim (§12, residual risk 10).
- **Coherence checks (§9.2)** already detect orphaned annotations and undeclared boundaries. WL-009 is distinct: it detects a *missing* annotation (no restoration boundary) rather than a *mismatched* annotation (boundary declared but not found in code).

#### 2.1.5 Conformance implications

WL-009 is a structural verification rule. Under §15.2 criterion 3, conformant tools that implement structural verification MUST enforce WL-009 alongside WL-007 and WL-008. The Wardline-Core enforcement profile (§15.3.1) includes WL-009 when the tool's declared rule set includes structural verification rules.

**Golden corpus requirement (§10):** WL-009 requires specimens in the INTEGRAL taint state at minimum:

- **True positive:** `@integral_read` function reading from a manifest-declared serialized store, no `@restoration_boundary`.
- **True positive:** `@integral_read` function with `@restoration_boundary` that declares no evidence categories (degenerate restoration — structurally equivalent to no boundary).
- **True positive:** `@integral_construction` function whose T2 inputs come from a manifest-declared serialized store, no `@restoration_boundary`.
- **True negative:** `@integral_read` function that co-declares `@restoration_boundary` with structural + semantic + integrity evidence.
- **True negative:** `@integral_read` function whose data source is not manifest-declared as a serialization boundary (in-memory Tier 1 read).
- **True negative:** `@integral_construction` function whose T2 inputs come from in-memory sources (no serialization).
- **Adversarial false positive:** `@integral_read` function whose inputs trace through a restoration boundary in a called function (two-hop satisfaction — should not fire).
- **Adversarial false positive:** `@integral_writer` function writing to a serialized store (writers are not subject to WL-009 — see §2.1.2b).

#### 2.1.6 Manifest schema change

The root manifest schema (`wardline.schema.json`) requires no change. The overlay schema's `BoundaryEntry` structure (mapped from the `boundaries` array in `WardlineOverlay`) already carries fields for `function`, `transition`, `from_tier`, `to_tier`, `restored_tier`, `provenance`, and `validation_scope`. Adding a `serialization_boundary: bool` field (default `false`) to `BoundaryEntry` is a minimal, backward-compatible extension. Existing manifests without the flag are unaffected — WL-009 only fires when a serialization boundary is positively declared.

The corresponding JSON Schema change adds an optional boolean property to the boundary entry object in `overlay.schema.json`:

```json
"serialization_boundary": {
  "type": "boolean",
  "default": false,
  "description": "Whether this boundary involves serialization/deserialization."
}
```

The corresponding Python model change adds the field to `BoundaryEntry` in `manifest/models.py`:

```python
serialization_boundary: bool = False
```

#### 2.1.7 Adoption impact

WL-009 activates only when `@integral_read` is used. Projects that have not yet annotated their Tier 1 read paths are unaffected — the rule fires on the annotation, not on the code pattern. This means WL-009 has zero adoption friction for projects in early annotation stages, and creates a natural incentive to annotate read paths correctly: when you add `@integral_read`, you are prompted to also declare the restoration evidence.

For projects with existing `@integral_read` annotations that lack `@restoration_boundary` co-declarations, WL-009 findings surface the gap for governance review. The remediation path is to add `@restoration_boundary` with appropriate evidence categories — a governance decision, not a code change (though the restoration boundary function itself may need structural modification to include rejection paths per WL-007).

---

### 2.2 Non-normative note: Deep immutability at Tier 1 (prime spec)

#### 2.2.1 Proposed text

**Proposed addition to §8 (Enforcement Layers), as a binding guidance note.** §8 is the appropriate location because the note is implementation guidance directed at binding authors, not a foundational property of the tier model. §4 defines what tiers mean; §8 defines how tools enforce them. Deep immutability is an enforcement concern — it tells binding authors what to check, not what tiers are.

> *Non-normative.* Language-level immutability mechanisms may provide only shallow guarantees — preventing attribute reassignment or reference rebinding while permitting mutation of contained values (nested dictionaries, lists, or equivalent mutable containers). When Tier 1 data structures rely on such mechanisms to establish their integrity contract, the declared immutability may be a false structural guarantee: downstream code — including the enforcement tool — treats the structure as immutable, but its contents can be silently modified after construction.
>
> Bindings whose target language has shallow immutability mechanisms SHOULD define supplementary rules that detect Tier 1 and Tier 2 data structures whose declared immutability does not achieve deep immutability. The detection criteria are necessarily language-specific — Python's `frozen=True` on dataclasses, Java's `final` on reference fields, Kotlin's `val` on collection properties — and belong in the binding, not the framework. The framework principle is: **if a data structure's immutability declaration is part of its Tier 1 integrity contract, the declaration must be truthful.**
>
> Bindings for languages where the immutability mechanism is inherently deep (e.g., Rust's ownership model, Haskell's persistent data structures) need not define such rules — the language guarantee is sufficient.

#### 2.2.2 Rationale for non-normative status

This note is non-normative because:

1. **Not all languages have the problem.** Rust's ownership model, Haskell's persistent data structures, and similar mechanisms provide deep immutability by default. A normative requirement would impose a burden on bindings where the problem does not exist.
2. **Detection is entirely language-specific.** The patterns that constitute "shallow freeze" differ fundamentally across languages. Python's `MappingProxyType` wrapping, Java's `Collections.unmodifiableMap()`, and Kotlin's `toList()` all share the same semantic problem but have no syntactic commonality.
3. **The principle cascades.** A non-normative note in the prime spec creates a clear mandate for bindings to address the gap, without prescribing how. Binding authors can cite the note as the framework-level justification for their supplementary rules.

---

### 2.3 SUP-010 and SUP-011: Deep immutability enforcement (Python binding)

These rules implement the deep immutability principle from §2.2 for the Python binding. They use the **SUP-*** (supplementary) rule prefix because they are Python-specific rules with no framework-level counterpart — consistent with the existing convention where SCN-021 (contradictory decorators) and SUP-001 (call-graph enforcement) use non-PY-WL-* prefixes for binding-specific rules. SUP-010/SUP-011 are not mandatory for framework conformance; they are opt-in supplementary enforcement for bindings that target languages with shallow immutability.

#### 2.3.0 Detection model: absence of deep-freeze (inverted detection)

The original ELSPETH proposal detected specific shallow-freeze *patterns* (`MappingProxyType` wrapping, `isinstance` guards). This approach is fragile — it matches specific AST shapes that are easily circumvented by helper functions, loop indirection, or custom `__init__` methods that bypass `__post_init__` entirely. The spec's own §7 warns that "models that learn to avoid flagged patterns will produce semantic equivalents."

**The revised detection model is inverted:** instead of detecting *presence of shallow-freeze patterns*, SUP-010/SUP-011 detect the *absence of deep-freeze enforcement*. The question is not "did you use MappingProxyType?" but "does this frozen dataclass with mutable container fields call a recognised deep-freeze function?"

This approach is:
- **More robust** — new shallow-freeze variants (helper wrappers, loop indirection, `tuple(self.x)` on lists of mutable containers) are caught automatically because the absence of deep-freeze is the trigger, not a specific AST shape.
- **Simpler to implement** — check for presence of a recognised function call rather than enumerating and matching multiple shallow-freeze patterns.
- **Lower false-positive surface** — fires only on frozen dataclasses with mutable container type annotations, and only when no deep-freeze call is found. Scalar-only frozen dataclasses are unaffected.

**Deep-freeze function recognition** uses manifest-declared function paths (option (a) from §6 Open Question 3). The scanner configuration or manifest declares which functions qualify as deep-freeze implementations. This is consistent with the manifest-driven design — the manifest already declares boundaries, validators, and data sources. Example:

```yaml
# In scanner configuration or manifest overlay
deep_freeze_functions:
  - "myapp.utils.deep_freeze"
  - "myapp.utils.freeze_fields"
```

#### 2.3.1 SUP-010: Frozen dataclass with mutable container fields and no deep-freeze

**Pattern:** A frozen dataclass (`@dataclass(frozen=True)`) with one or more fields whose type annotations indicate mutable containers (`dict`, `list`, `set`, `Mapping`, `MutableMapping`, or parameterised variants), where the `__post_init__` method does not call a recognised deep-freeze function on those fields.

**Why it is dangerous:** `frozen=True` prevents attribute *reassignment* but does nothing about mutable *contents*. A frozen dataclass with a `dict[str, Any]` field creates a false structural guarantee: the field reference cannot be rebound, but the dict's contents can be freely mutated through the existing reference. For Tier 1 data, this means the integrity contract is a lie — a nested dict on an audit record can be silently modified after construction, and the modification is invisible to any code that trusts the `frozen=True` declaration. The danger compounds with nesting depth: `MappingProxyType(dict(self.x))` freezes one level but leaves nested structures mutable; `tuple(self.x)` on a list of dicts freezes the list but not the dicts.

**Detection:** AST visitor that:
1. Identifies `ClassDef` nodes with `@dataclass(frozen=True)` in their decorator list.
2. Inspects field type annotations for mutable container types (`dict`, `list`, `set`, `Mapping`, `MutableMapping`, and their parameterised forms).
3. For each mutable-container field, checks whether the `__post_init__` method contains a call to a recognised deep-freeze function (from the manifest-declared `deep_freeze_functions` list) with `self.<field>` as an argument.
4. **Fires when** a mutable-container field has no corresponding deep-freeze call in `__post_init__`.

**Exclusions:** Fields with immutable container annotations (`tuple`, `frozenset`, `MappingProxyType`) are not flagged. Classes without `__post_init__` that have no mutable container fields are not flagged. Non-frozen dataclasses are not flagged.

**Remediation:** Add a `__post_init__` method (or extend the existing one) that calls a deep-freeze function on each mutable-container field. The deep-freeze function should recursively convert `dict` to `MappingProxyType`, `list` to `tuple`, and `set` to `frozenset` through arbitrary nesting depth, and should be idempotent (identity-preserving on already-frozen values).

#### 2.3.2 SUP-011: Conditional freeze guard in `__post_init__`

**Pattern:** An `isinstance` type guard in `__post_init__` of a frozen dataclass that conditionally skips freezing based on the container type of a field.

**Why it is dangerous:** Type guards used to conditionally skip freezing are fragile across two dimensions. First, they check the *container type* but not the *content types* — a `tuple` of mutable dicts passes an `isinstance(self.x, tuple)` guard but its contents are fully mutable. Second, they are not exhaustive — a `Mapping` subclass that is not `dict` or `MappingProxyType` may pass through unfrozen. The correct approach is an idempotent deep-freeze function that handles all container types unconditionally — if the value is already deeply frozen, the function returns it unchanged; if not, it freezes it. No type guard is needed because the operation is safe on all inputs.

**Detection:** AST visitor within `__post_init__` methods of frozen dataclasses. Match `isinstance` calls where:
- The first argument is `self.<field>`
- Any of the type arguments are in the set `{dict, tuple, MappingProxyType, frozenset, Mapping, list, set}`
- The `isinstance` call is the test expression of an `if` statement whose body contains `object.__setattr__` calls (the frozen-dataclass mutation pattern)

SUP-011 fires independently of SUP-010. A frozen dataclass may have a recognised deep-freeze call (passing SUP-010) but still use `isinstance` guards to conditionally skip freezing for certain types (failing SUP-011). The two rules address different aspects of the same problem: SUP-010 enforces that deep-freeze exists; SUP-011 enforces that it is applied unconditionally.

**Remediation:** Replace the `isinstance`-guarded conditional with an unconditional call to an idempotent deep-freeze function.

#### 2.3.3 Severity matrix

Both rules share the same severity profile. The tier-sensitivity gradient reflects that shallow immutability is an integrity violation at Tier 1 (where the immutability contract is part of the authority guarantee), suspicious at Tier 2/3 (where it weakens but does not destroy structural guarantees), and suppressed at Tier 4 (where data has not been promoted and container mutability is expected).

**Derivation from first principles.** The gradient parallels WL-001's profile but is independently derived. WL-001's gradient follows the principle "fabricating data is worst where data authority is highest." SUP-010/SUP-011's gradient follows the principle "false structural guarantees are worst where structural guarantees are most trusted." Both principles produce the same shape — ERROR at Tier 1, declining through Tier 2/3, SUPPRESS at Tier 4 — because trust and authority increase together through the tier model. The coincidence is structural, not borrowed.

| Rule | INTEGRAL | ASSURED | GUARDED | Ext. Raw | Unk. Raw | Unk. Guarded | Unk. Assured | Mixed Raw |
|------|----------|---------|---------|----------|----------|--------------|--------------|-----------|
| **SUP-010** | E/U | E/St | W/R | Su/T | Su/T | W/R | E/St | Su/T |
| **SUP-011** | E/U | E/St | W/R | Su/T | Su/T | W/R | E/St | Su/T |

**INTEGRAL (E/U):** Shallow immutability on a Tier 1 record is an unconditional integrity violation. The immutability declaration is part of the audit-trail contract. A frozen dataclass with mutable nested contents can be silently modified after construction — the audit record is not tamper-resistant as declared.

**ASSURED (E/St):** Tier 2 data has passed semantic validation. Shallow immutability weakens the structural guarantee that downstream code relies on, but the data is not part of the legal record. Standard exception governance applies — the project MAY accept this risk with documented rationale (e.g., the mutable contents are never accessed after construction in the project's specific usage).

**GUARDED (W/R):** Tier 3 data has structural guarantees but not semantic guarantees. Shallow immutability is suspicious but the structural guarantee is already limited. Relaxed exception governance.

**EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW (Su/T):** Data at these taint states has not been promoted. Container mutability is expected — the data is being processed, not preserved. Suppress.

#### 2.3.4 Relationship to framework rules

SUP-010 and SUP-011 are **not** sub-rules of any framework WL-* rule. They are Python-specific supplementary enforcement rules that implement the non-normative deep-immutability principle (§2.2). They have no framework-level counterpart and do not appear in the framework conformance criteria (§15.2). A conformant Wardline-Core tool is not required to implement them. The SUP-* prefix signals this status — consistent with the existing convention where SUP-001 (call-graph enforcement) is opt-in supplementary enforcement.

#### 2.3.5 Golden corpus specimens

**SUP-010 specimens:**

- **True positive (INTEGRAL):** Frozen dataclass with `dict[str, Any]` field, `__post_init__` uses `MappingProxyType(dict(self.data))` but no recognised deep-freeze function.
- **True positive (INTEGRAL):** Frozen dataclass with `list[dict[str, Any]]` field, `__post_init__` uses `tuple(self.data)` — freezes the list but not its dict elements.
- **True positive (INTEGRAL):** Frozen dataclass with `Mapping[str, Any]` field and no `__post_init__` at all — mutable container field with no freeze of any kind.
- **True negative (INTEGRAL):** Frozen dataclass with `deep_freeze(self.data)` in `__post_init__` where `deep_freeze` is in the manifest's `deep_freeze_functions` list.
- **True negative (INTEGRAL):** Frozen dataclass with scalar-only fields (`str`, `int`, `float`, `bool`) — no mutable container fields.
- **Adversarial false positive:** `MappingProxyType(dict(self.data))` in a non-frozen dataclass (not subject to freeze rules).
- **Adversarial false positive:** Frozen dataclass with `tuple[str, ...]` field annotation (immutable container — not flagged).

**SUP-011 specimens:**

- **True positive (INTEGRAL):** `if isinstance(self.data, dict): object.__setattr__(self, "data", MappingProxyType(dict(self.data)))` — type guard skips freezing for non-dict types.
- **True positive (INTEGRAL):** `if not isinstance(self.data, tuple):` guard that skips freeze for tuples (tuple of mutable dicts passes unfrozen).
- **True negative (INTEGRAL):** Unconditional `freeze_fields(self, "data")` call with no `isinstance` guard.
- **True negative:** `isinstance` check in `__post_init__` that is not a freeze guard (e.g., validation logic unrelated to `object.__setattr__`).
- **Adversarial false positive:** `isinstance` check in `__post_init__` of a non-frozen dataclass.

#### 2.3.6 Detection scope and known limitations

**SUP-010 mutable container type list.** The default mutable container types checked in field annotations are: `dict`, `list`, `set`, `Mapping`, `MutableMapping`, and their parameterised forms (e.g., `dict[str, Any]`, `list[dict[str, Any]]`). This list is **extensible** via scanner configuration:

```yaml
# In scanner configuration or manifest overlay
mutable_container_types:
  - "collections.OrderedDict"
  - "collections.defaultdict"
  - "myapp.types.MutableBuffer"
```

Fields annotated with `Any` or `object` are **not** flagged by default — while these could hold mutable containers at runtime, flagging them would produce false positives on scalar fields with loose annotations. Projects that require stricter enforcement on `Any`-annotated fields can opt in via scanner configuration.

Union types where any branch is a mutable container (e.g., `dict[str, Any] | None`) **are** flagged — the mutable branch is sufficient to trigger the rule.

**SUP-011 detection scope.** SUP-011 matches `isinstance` calls where the first argument is `self.<field>`, a checked type is in the freeze-guard set, and the call is the test of an `if` whose body has `object.__setattr__` calls. This direct-match approach has known blind spots:

- `isinstance` results stored in intermediate variables (`is_dict = isinstance(self.data, dict); if is_dict: ...`)
- `type()` checks (`if type(self.data) is dict: ...`)
- Custom guard functions (`if needs_freeze(self.data): ...`)

These are accepted limitations. SUP-011 is a **code quality** rule that flags a known anti-pattern, not a security gate. The primary defence is SUP-010 (absence of deep-freeze) — SUP-011 provides additional signal on conditional freezing patterns even when SUP-010 passes. Projects should not interpret "no SUP-011 findings" as "no conditional freeze guards exist."

#### 2.3.7 Self-hosting impact

The wardline reference implementation's own manifest models use the exact patterns that SUP-011 targets. In `src/wardline/manifest/models.py`:

- `ExceptionEntry.__post_init__` uses `isinstance` guards with `object.__setattr__` to coerce enum-typed fields (`RuleId`, `TaintState`, `Exceptionability`, `Severity`).
- `BoundaryEntry.__post_init__` uses `isinstance` guards with `object.__setattr__` to wrap `dict` fields in `MappingProxyType`.

These are frozen dataclasses in the manifest loading path. If the wardline project enables SUP-010/SUP-011 in its self-hosting scan, these models will produce findings.

**Resolution options for self-hosting:**

1. **Refactor** — Replace `isinstance`-guarded `object.__setattr__` with unconditional deep-freeze calls. This is the approach SUP-011's remediation guidance recommends and would make the wardline project a clean consumer of its own rules.
2. **Exception** — Grant governance exceptions for internal manifest models under the rationale that enum coercion in `__post_init__` is structurally distinct from container freeze guards (the `isinstance` checks are type-narrowing for deserialization, not conditional immutability enforcement). This is defensible but weakens the self-hosting signal.
3. **Rule scope** — Restrict SUP-011 to fire only when the `isinstance`-checked types are container types (`dict`, `list`, `set`, `Mapping`, etc.), not scalar-coercion types (`RuleId`, `TaintState`). This would exclude the `ExceptionEntry` pattern while still catching the `BoundaryEntry` pattern.

**Recommendation:** Option 1 (refactor) for `BoundaryEntry`; option 3 (scope refinement) for `ExceptionEntry`. The `BoundaryEntry` pattern is genuinely shallow-freeze. The `ExceptionEntry` pattern is enum coercion — structurally different from the freeze-guard anti-pattern, and the `isinstance` check is against user-defined enum types, not container types already in the freeze-guard set. Refining SUP-011's type-set check to exclude non-container types would naturally resolve this without special-casing.

---

## 3. Excluded From This RFC

### 3.1 Frozen annotation enforcement

Detecting mutable container type annotations (`list[...]`, `dict[...]`, `set[...]`) on fields of frozen dataclasses — where `__post_init__` converts them to immutable types but the type annotation still permits mutation through the type checker — is a **type-system hygiene concern**, not a trust-tier concern.

The invariant being enforced ("type annotations must not lie about mutability") is orthogonal to the wardline's enforcement surface. It does not depend on tier classification, taint state, or boundary declarations. It belongs in the type-checking layer (mypy plugin, ruff rule, or equivalent linter) rather than the wardline binding.

### 3.2 Layer-boundary import enforcement

While ELSPETH's layer dependency enforcement (L0 contracts → L1 core → L2 engine → L3 plugins) maps to wardline's Group 6 (Layer Boundaries), this RFC does not propose changes to Group 6. The existing Group 6 annotation vocabulary and enforcement consequences are sufficient — ELSPETH's layer enforcement would be a consumer of Group 6, not a change to it.

---

## 4. Implementation Sketch

This section is non-normative. It describes one possible implementation path for a wardline Python binding scanner implementing the proposed rules.

### 4.1 WL-009 implementation

1. **Manifest loader** reads overlay `boundaries` entries and identifies `BoundaryEntry` objects where `serialization_boundary is True` (see §2.1.6). Builds a set of serialization-source function names from their `function` field.
2. **Annotation discovery** identifies functions with `@integral_read` or `@integral_construction` (see §2.1.2b) and `@restoration_boundary`.
3. **Coherence check** cross-references: for each Tier 1 promotion function whose data source is a declared serialization boundary, verify that the function either (a) co-declares `@restoration_boundary` with at least one evidence category, or (b) its inputs trace through a declared restoration boundary within two-hop scope.
4. **Finding emission** produces SARIF output with `ruleId: "PY-WL-010"` (Python binding mapping of framework WL-009), the function's location, and remediation guidance pointing to §5.3.

### 4.2 SUP-010 / SUP-011 implementation

Both rules are intraprocedural AST visitors scoped to `__post_init__` methods of frozen dataclasses. The existing scanner infrastructure for rule visitors (the `BaseRule` class and `ScanContext`) is sufficient — no new scanner architecture is required.

1. **Configuration loading:** Read `deep_freeze_functions` from scanner configuration or manifest overlay. Build a set of recognised deep-freeze function names (both fully-qualified and terminal names).
2. **Class identification:** Walk AST for `ClassDef` nodes with `@dataclass(frozen=True)` in their decorator list.
3. **Field analysis:** Inspect field type annotations for mutable container types (`dict`, `list`, `set`, `Mapping`, `MutableMapping`, parameterised variants). Build a set of fields requiring deep-freeze.
4. **SUP-010 (absence of deep-freeze):** For each mutable-container field, check whether `__post_init__` contains a call to a recognised deep-freeze function with `self.<field>` as an argument. Fire when no such call is found.
5. **SUP-011 (conditional freeze guard):** Within `__post_init__`, match `isinstance` calls where the first argument is `self.<field>`, any checked type is in the freeze-guard type set, and the `isinstance` appears as the test of an `if` statement whose body contains `object.__setattr__` calls. Fire regardless of whether a deep-freeze call is present — conditional freezing is independently problematic.
6. **Taint context:** The enclosing class's tier is determined by module-level manifest assignment. The severity matrix cell is looked up from the rule's matrix row and the effective taint state.

---

## 5. Summary of Proposed Spec Changes

| Change | Spec location | Appendix | Type | Impact |
|--------|--------------|----------|------|--------|
| WL-009 rule definition | §7.1 (rule table) | A.1 | Normative | New row in rule table |
| WL-009 structural verification | §7.2 | A.2 | Normative | New paragraph after WL-008 |
| WL-009 severity matrix | §7.3 (severity matrix) | A.3 | Normative | New row: E/U across all states; update preamble |
| Rule count update | §7 (intro paragraph) | A.4 | Normative | "eight rules" → "nine rules"; "Two structural" → "Three structural" |
| Deep immutability note | §8 | A.5 | Non-normative | Binding guidance paragraph |
| WL-009 static analysis | §8.1 (requirements list) | A.6 | Normative | New bullet after WL-008 |
| WL-009 conformance | §15.2 criterion 3 | A.7 | Normative | Add WL-009 to structural verification criterion |
| WL-009 manifest schema | §13 / overlay schema | A.8 | Normative (minimal) | `serialization_boundary` flag on `BoundaryEntry` |
| WL-009 severity rationale | §7.5 (worked examples) | A.9 | Non-normative | Update WL-007/WL-008 paragraph to include WL-009 |
| SARIF presentation | §10.1 | A.10 | Normative | Add WL-009 to taint-state omission guidance |
| Python binding conformance | Part II-A (criterion table) | A.11 | Binding-normative | Add PY-WL-010 to criterion 3 row |
| SUP-010 rule definition | Part II-A | — | Binding-supplementary | New Python-specific supplementary rule |
| SUP-010 mutable type list | Part II-A | — | Binding-supplementary | Default + extensible via `mutable_container_types` |
| SUP-011 rule definition | Part II-A | — | Binding-supplementary | New Python-specific supplementary rule |
| SUP-010/011 severity matrix | Part II-A | — | Binding-supplementary | New rows in Python binding supplementary matrix |
| SUP-010/011 corpus specimens | Part II-A / corpus/ | — | Binding-supplementary | ~16 specimens across both rules |
| Self-hosting impact | Part II-A | — | Informative | wardline models trigger SUP-011 (§2.3.7) |

---

## 6. Open Questions

1. **~~WL-009 manifest mechanism.~~** *Resolved.* Use `serialization_boundary: true` flag on `BoundaryEntry` in the overlay's `boundaries` array (see §2.1.6 and A.8). The flag is minimal, backward-compatible, and handles all serialization media (databases, files, message queues, caches) without a new top-level section.

2. **~~WL-009 scope for `@integral_construction`.~~** *Resolved.* Yes — WL-009 fires on both `@integral_read` and `@integral_construction` when the data source is a manifest-declared serialization boundary. The restoration symmetry gap is identical: any Tier 1 promotion from a serialized source requires restoration evidence. See §2.1.2b.

3. **~~SUP-010/011 deep-freeze function recognition.~~** *Resolved.* Use manifest-declared function paths (option (a)). The `deep_freeze_functions` list in scanner configuration or manifest overlay declares which functions qualify. This is consistent with the manifest-driven design. See §2.3.0.

4. **~~SUP-010 scope beyond `MappingProxyType`.~~** *Resolved.* The inverted detection model (§2.3.0) renders this question moot. SUP-010 flags absence of deep-freeze on mutable-container fields, regardless of which shallow-freeze pattern is used. `MappingProxyType`, `tuple`, or no freeze at all — the trigger is the same: no recognised deep-freeze call.

---

## Appendix A: Proposed Spec Text (Exact Deltas)

This appendix provides the exact text changes to each affected spec section. Insertions are marked with `[+]` prefix. Unchanged surrounding text is included for placement context.

### A.1 §7.1 — Rule table: Insert WL-009 row

**Location:** After the WL-008 row in the §7.1 rule table.

**Current text (last row):**

| **WL-008** | Semantic validation without prior shape validation | Data reaching a declared semantic-validation boundary ... |

**Insert after WL-008:**

[+] | **WL-009** | Tier 1 promotion on serialization path without restoration evidence | A function declared `@integral_read` or `@integral_construction` (or binding equivalent) whose data source is a manifest-declared serialization boundary, and which neither co-declares `@restoration_boundary` with at least one evidence category nor traces its inputs through a declared restoration boundary within the two-hop analysis scope (§8.1). The function claims Tier 1 authority for deserialized data on assertion alone — the restoration model (§5.3) requires evidence-backed provenance claims, but no evidence is declared, no governance review of the restoration act is possible, and the scanner cannot verify that write-side invariants are re-established on read. This is the restoration-symmetry failure: construction paths include validation that serialization strips, and the read side re-stamps the deserialized representation as authoritative without re-verifying. WL-009 enforces that the restoration model is *invoked*, not that the evidence is *sufficient* — sufficiency remains a governance-reviewed claim (§12, residual risk 10). |

---

### A.2 §7.2 — Structural verification: Add WL-009 paragraph

**Location:** After the WL-008 paragraph in §7.2.

**Insert after the WL-008 paragraph:**

[+] **WL-009: Tier 1 promotion paths through serialization boundaries MUST declare restoration evidence.** This is a topology constraint, not a body-content check. The scanner cross-references `@integral_read` and `@integral_construction` annotations against manifest-declared serialization boundaries and `@restoration_boundary` annotations. WL-009 fires when all three conditions hold: (1) a function is declared `@integral_read` or `@integral_construction` (Group 1); (2) the function's data source is a manifest-declared serialization boundary (identified via `BoundaryEntry` objects in the overlay's `boundaries` array with `serialization_boundary: true`); (3) the function does not co-declare `@restoration_boundary` (Group 17) with at least one evidence category, and its inputs do not trace through a declared restoration boundary with sufficient evidence within the two-hop analysis scope (§8.1). Functions whose Group 1 decorator data source is not manifest-declared as a serialization boundary (e.g., in-memory Tier 1 reads) are not subject to WL-009. The manifest dependency is intentional: serialization boundaries are part of the trust topology and are declared in the manifest, not inferred by the scanner.

---

### A.3 §7.3 — Severity matrix: Insert WL-009 row

**Location:** After the WL-008 row in the §7.3 severity matrix.

**Current text (last rows):**

| **WL-007** | Validation with no rejection path | E/U | E/U | E/U | E/U | E/U | E/U | E/U | E/U |
| **WL-008** | Semantic validation without shape validation | E/U | E/U | E/U | E/U | E/U | E/U | E/U | E/U |

**Insert after WL-008:**

[+] | **WL-009** | Integral-read without restoration evidence | E/U | E/U | E/U | E/U | E/U | E/U | E/U | E/U |

**Update the paragraph above the matrix** (currently reads "WL-007 and WL-008 are structural verification rules"):

**Current:**
> WL-007 and WL-008 are structural verification rules (not pattern rules) and apply only to declared boundary functions, but are shown in the matrix for completeness. Their severity is UNCONDITIONAL across all contexts because they are framework invariants rather than context-dependent judgements.

**Proposed:**
> [+] WL-007, WL-008, and WL-009 are structural verification rules (not pattern rules) and apply only to declared boundary functions, but are shown in the matrix for completeness. Their severity is UNCONDITIONAL across all contexts because they are framework invariants rather than context-dependent judgements.

---

### A.4 §7 introductory paragraph: Update rule count

**Current (§7, first sentence):**
> This section defines eight rules in two categories. **Six pattern rules** (WL-001 through WL-006) detect syntactic proxies for semantic violations in declared semantic contexts. ... **Two structural verification rules** (WL-007 and WL-008) enforce invariants on declared boundary functions ...

**Proposed:**
> [+] This section defines nine rules in two categories. **Six pattern rules** (WL-001 through WL-006) detect syntactic proxies for semantic violations in declared semantic contexts. ... **Three structural verification rules** (WL-007, WL-008, and WL-009) enforce invariants on declared boundary functions ...

---

### A.5 §8 — Non-normative note on deep immutability

**Location:** §8 (Enforcement Layers), after the binding implementation guidance paragraph. §8 is the appropriate location because this note is directed at binding *implementers* — it tells them what supplementary rules to consider, not what tiers mean. The tier model (§4) defines authority levels; §8 defines how tools enforce them. Deep immutability is an enforcement concern.

**Insert:**

[+] *Non-normative.* Language-level immutability mechanisms may provide only shallow guarantees — preventing attribute reassignment or reference rebinding while permitting mutation of contained values (nested dictionaries, lists, or equivalent mutable containers). When Tier 1 data structures rely on such mechanisms to establish their integrity contract, the declared immutability may be a false structural guarantee: downstream code — including the enforcement tool — treats the structure as immutable, but its contents can be silently modified after construction. Bindings whose target language has shallow immutability mechanisms SHOULD define supplementary rules that detect Tier 1 and Tier 2 data structures whose declared immutability does not achieve deep immutability. The detection criteria are necessarily language-specific — Python's `frozen=True` on dataclasses, Java's `final` on reference fields, Kotlin's `val` on collection properties — and belong in the binding, not the framework. The framework principle is: if a data structure's immutability declaration is part of its Tier 1 integrity contract, the declaration must be truthful. Bindings for languages where the immutability mechanism is inherently deep (e.g., Rust's ownership model, Haskell's persistent data structures) need not define such rules — the language guarantee is sufficient.

---

### A.6 §8.1 — Static analysis requirements: Add WL-009 bullet

**Location:** After the WL-008 enforcement bullet in the §8.1 requirements list.

**Current (WL-008 bullet):**
> - MUST enforce validation ordering (WL-008): data reaching a declared semantic-validation boundary MUST have passed through a declared shape-validation boundary *(framework invariant)*. Combined validation boundaries (T4→T2) satisfy this requirement internally

**Insert after:**

[+] - MUST enforce restoration symmetry (WL-009): a function declared `@integral_read` or `@integral_construction` whose data source is a manifest-declared serialization boundary (identified via `BoundaryEntry` objects with `serialization_boundary: true`) MUST co-declare `@restoration_boundary` with at least one evidence category, or its inputs MUST trace through a declared restoration boundary within the two-hop analysis scope *(framework invariant)*. WL-009 is a topology check on the annotation surface and does not require body-content analysis beyond what taint-flow tracing already provides

---

### A.7 §15.2 — Conformance criterion 3: Update to include WL-009

**Current:**
> 3. Structural verification: WL-007 is enforced on all validation boundary functions (shape, semantic, combined, and restoration) and WL-008 (validation ordering) is enforced on semantic-validation boundaries (§7.2, §8.1)

**Proposed:**
> [+] 3. Structural verification: WL-007 is enforced on all validation boundary functions (shape, semantic, combined, and restoration), WL-008 (validation ordering) is enforced on semantic-validation boundaries, and WL-009 (restoration symmetry) is enforced on `@integral_read` and `@integral_construction` functions whose data sources are manifest-declared serialization boundaries (§7.2, §8.1)

---

### A.8 §13 — Manifest overlay schema: Add serialization_boundary flag

**Location:** Within the boundary entry object schema in `overlay.schema.json` (the JSON Schema for `BoundaryEntry` objects in the `boundaries` array).

**Proposed addition to boundary entry properties:**

```json
"serialization_boundary": {
  "type": "boolean",
  "default": false,
  "description": "Whether this boundary involves serialization/deserialization (database read/write, file I/O, message queue, cache). When true, @integral_read and @integral_construction functions using this boundary as a data source are subject to WL-009 (restoration symmetry). In-memory data sources should not set this flag."
}
```

**Corresponding Python model change** in `src/wardline/manifest/models.py`, `BoundaryEntry`:

```python
serialization_boundary: bool = False
```

This is a backward-compatible, optional addition. Existing manifests without `serialization_boundary` entries are unaffected — WL-009 only fires when a serialization boundary is positively declared.

---

### A.9 §7.5 — Worked example rationale: Update WL-007/WL-008 paragraph

**Location:** §7.5 (or §7.4 depending on section numbering), the paragraph explaining structural verification severity.

**Current:**
> WL-007 (validation boundary structural verification) and WL-008 (semantic validation ordering) are both UNCONDITIONAL across all eight states. A validation function that contains no rejection path is structurally unsound regardless of context. Semantic validation applied to structurally unverified data is a category error regardless of context. These are framework invariants, not context-dependent judgements.

**Proposed:**
> [+] WL-007 (validation boundary structural verification), WL-008 (semantic validation ordering), and WL-009 (restoration symmetry) are all UNCONDITIONAL across all eight states. A validation function that contains no rejection path is structurally unsound regardless of context. Semantic validation applied to structurally unverified data is a category error regardless of context. A Tier 1 promotion function (`@integral_read` or `@integral_construction`) on a serialization path without declared restoration evidence is a topology deficiency regardless of context. These are framework invariants, not context-dependent judgements.

---

### A.10 §10.1 — SARIF finding presentation: Update taint-state omission guidance

**Location:** §10.1, the paragraph on taint state omission for structural verification rules.

**Current:**
> For WL-007 (validation boundary integrity) and WL-008 (restoration boundary integrity), bindings SHOULD omit the taint state from primary finding messages. These structural verification rules are UNCONDITIONAL across all eight effective states — the taint state of the enclosing context is irrelevant to the finding because the rule fires on structural properties (boundary declaration completeness, rejection-path reachability) rather than data-flow properties.

**Proposed:**
> [+] For WL-007 (validation boundary integrity), WL-008 (validation ordering integrity), and WL-009 (restoration symmetry), bindings SHOULD omit the taint state from primary finding messages. These structural verification rules are UNCONDITIONAL across all eight effective states — the taint state of the enclosing context is irrelevant to the finding because the rule fires on structural properties (boundary declaration completeness, rejection-path reachability, restoration evidence presence) rather than data-flow properties.

**Current (next paragraph):**
> Including the taint state in WL-007/WL-008 primary messages trains developers to believe it matters for structural verification, creating a false mental model of how these rules operate.

**Proposed:**
> [+] Including the taint state in WL-007/WL-008/WL-009 primary messages trains developers to believe it matters for structural verification, creating a false mental model of how these rules operate.

---

### A.11 Part II-A — Python binding conformance table: Update criterion 3

**Location:** Part II-A, conformance criterion table, row 3.

**Current:**
> | 3 | Structural verification WL-007/WL-008 | PY-WL-008 (rejection path), PY-WL-009 (validation ordering) | `wardline corpus verify`; engine L3 integration tests |

**Proposed:**
> [+] | 3 | Structural verification WL-007/WL-008/WL-009 | PY-WL-008 (rejection path), PY-WL-009 (validation ordering), PY-WL-010 (restoration symmetry) | `wardline corpus verify`; engine L3 integration tests |

**Note on rule numbering:** WL-009 maps to **PY-WL-010** in the Python binding, preserving the established offset pattern (framework WL-* numbers + 2 = Python PY-WL-* numbers, due to the WL-001 split into PY-WL-001/002). The deep-immutability rules use the **SUP-*** prefix (SUP-010, SUP-011) because they are binding-specific supplementary rules with no framework counterpart — consistent with the existing convention where SCN-021 and SUP-001 use non-PY-WL-* prefixes for Python-specific enforcement. SUP-010/SUP-011 are not part of the framework conformance criteria and are opt-in supplementary enforcement.
