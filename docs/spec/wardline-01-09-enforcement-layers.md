### 9. Enforcement layers

A wardline can be enforced at three layers, each catching different classes of violation. The layers are orthogonal: each catches things the others cannot. A single tool that implements only one layer still gains value; the combination closes residual risk surfaces that any single layer leaves open. In most language ecosystems, different tools will implement different layers — a type checker handles the type-system layer, a linter or pattern-matching tool handles static analysis, and a CI orchestrator handles governance. An enforcement regime (§15.4) is the set of tools that collectively cover all three layers.

These three layers implement a natural escalation path: institutional knowledge that is *machine-readable* (the wardline manifest) becomes *machine-checkable* (type system enforcement at development time) and *machine-enforceable* (static analysis at CI time, runtime structural enforcement at access time). The wardline manifest is the stable artefact; the enforcement layers are the graduated mechanisms that make its declarations progressively harder to violate.

Requirements within each layer are classified using a three-part taxonomy:

- **Framework invariant** — a requirement that any conforming implementation MUST satisfy regardless of language or toolchain. These are non-negotiable properties of the wardline model itself.
- **Binding requirement** — a requirement that language-specific bindings SHOULD satisfy using language-native mechanisms. The requirement is stable; the implementation varies by language.
- **Tool quality target** — a desirable property that improves enforcement quality but is not required for conformance. Implementations MAY pursue these as maturity targets.

The MUST/SHOULD/MAY gradient reflects achievability: static analysis is MUST because AST access, intraprocedural pattern matching, and the framework's minimum explicit-flow tracing requirements are achievable in every language with a parser; full interprocedural analysis remains a SHOULD/MAY capability. Type system enforcement is SHOULD because type system capabilities vary significantly across languages; runtime structural enforcement is SHOULD/MAY because it depends on the target language's object model and runtime architecture.

> *Non-normative.* Language-level immutability mechanisms may provide only shallow guarantees — preventing attribute reassignment or reference rebinding while permitting mutation of contained values (nested dictionaries, lists, or equivalent mutable containers). When Tier 1 data structures rely on such mechanisms to establish their integrity contract, the declared immutability may be a false structural guarantee: downstream code — including the enforcement tool — treats the structure as immutable, but its contents can be silently modified after construction. Bindings whose target language has shallow immutability mechanisms SHOULD define supplementary rules that detect Tier 1 and Tier 2 data structures whose declared immutability does not achieve deep immutability. The detection criteria are necessarily language-specific — Python's `frozen=True` on dataclasses, Java's `final` on reference fields, Kotlin's `val` on collection properties — and belong in the binding, not the framework. The framework principle is: if a data structure's immutability declaration is part of its Tier 1 integrity contract, the declaration must be truthful. Bindings for languages where the immutability mechanism is inherently deep (e.g., Rust's ownership model, Haskell's persistent data structures) need not define such rules — the language guarantee is sufficient.

#### 9.1 Static analysis

| Property | Requirement |
|----------|-------------|
| **Enforcement point** | CI/commit time |
| **What it catches** | Pattern rule violations in annotated code; taint flow between declared boundaries |
| **Language requirement** | Parse tree or AST access; ability to read annotation metadata |

Requirements:

- MUST detect the six active pattern rules (WL-001 through WL-006) within annotated function and method bodies — intraprocedural analysis *(framework invariant)*
- SHOULD detect pattern rule violations that span function boundaries — interprocedural analysis *(binding requirement)*
- MAY provide context-sensitive analysis where a function's findings depend on the tier of its call site *(tool quality target)*
- MUST perform structural verification (WL-007) on all validation boundary functions — shape-validation, semantic-validation, combined-validation, and restoration boundary functions (§6.3) *(framework invariant)*. WL-007 is primarily intraprocedural: a validation function that delegates to a called function for rejection (e.g., calling a schema validator that raises on failure) does not satisfy WL-007 unless the delegation is resolvable via two-hop call-graph analysis. For this minimum requirement, a call is resolvable when the call target can be determined from static analysis of the AST and local type information without whole-program analysis. Binding references (Part II) specify which call forms are resolvable in their language — e.g., direct function calls, method calls on statically typed receivers, and locally bound callables where supported. Two-hop delegation satisfies the requirement; deeper delegation requires full interprocedural analysis. The two-hop limit captures the common pattern of validator → schema library → actual check without requiring expensive full call-graph traversal. Scaling cost is linear in k, and WL-007 only applies to declared boundary functions (a small subset of the codebase)
- MUST enforce validation ordering (WL-008): data reaching a declared semantic-validation boundary MUST have passed through a declared shape-validation boundary *(framework invariant)*. Combined validation boundaries (T4→T2) satisfy this requirement internally
- MUST enforce restoration symmetry (WL-009): a function declared `@integral_read` or `@integral_construction` whose data source is a manifest-declared serialization boundary (identified via `BoundaryEntry` objects with `serialization_boundary: true`) MUST co-declare `@restoration_boundary` with at least one evidence category, or its inputs MUST trace through a declared restoration boundary within the two-hop analysis scope *(framework invariant)*. WL-009 is a topology check on the annotation surface and does not require body-content analysis beyond what taint-flow tracing already provides
- MUST trace explicit-flow taint between declared boundaries — at minimum: direct flows and two-hop through unannotated intermediaries; ideally: full transitive inference across the call graph *(framework invariant for direct flows; tool quality target for full transitive inference)*. Unannotated intermediaries are functions within the enforcement perimeter that lack wardline annotations. Functions outside the enforcement perimeter (for example, third-party libraries) are governed by `dependency_taint` declarations (§6.5), not by intermediary tracing
- SHOULD distinguish `join_fuse` from `join_product` operations (§6.1) when computing taint joins. `join_fuse` applies to operations that genuinely merge data (string concatenation, dict merge, format-string interpolation); `join_product` applies to product-type composites where components retain their identity (dataclass construction, named-tuple packing, typed constructor invocation). Bindings that implement this distinction MAY define a `MIXED_TRACKED` extension state for `join_product` on named product types where the binding can statically resolve field membership. Bindings that do not implement the distinction treat all cross-tier joins as `join_fuse`, producing MIXED_RAW — the conservative fallback *(binding requirement)*
- MUST produce deterministic, auditable output in SARIF v2.1.0 as specified in §11.1, or in an equivalent structured format that satisfies §11.1's interchange requirements and documents an explicit mapping to the required wardline properties *(binding requirement — the framework does not produce output; tools do)*
- SHOULD support incremental analysis — analysing only changed files and their transitive dependents rather than the full codebase on every commit *(binding requirement — critical for CI adoption at scale)*

**Scaling characteristics:** Pattern detection scales linearly with the annotated surface area; taint analysis scales O(V+E) with the call graph. These are desirable properties but not enforceable as framework invariants.

#### 9.2 Type system

| Property | Requirement |
|----------|-------------|
| **Enforcement point** | Development/compile time |
| **What it catches** | Tier mismatches in function signatures; unvalidated data reaching typed sinks |
| **Language requirement** | Structural or nominal type system with metadata capabilities |

Requirements:

- SHOULD make tier mismatches visible at development time — passing raw data where guarded data is expected, or guarded data where assured data is expected, SHOULD produce a type error or equivalent diagnostic *(binding requirement)*
- SHOULD support metadata on type annotations that carries tier information (1, 2, 3, 4) through the type system *(binding requirement)*
- SHOULD enable structural typing that distinguishes raw, guarded, and assured records — records at different tiers with identical field structures SHOULD be distinguishable types *(binding requirement)*

Where a binding's type system enforces tier distinctions at development time, WL-006 findings at the corresponding taint states may be narrowed through binding-level matrix deviations (§8.3), because runtime type-checking becomes structurally redundant rather than merely suspicious.

#### 9.3 Runtime structural

| Property | Requirement |
|----------|-------------|
| **Enforcement point** | Definition/access time |
| **What it catches** | Fabricated defaults on authoritative fields; unannotated subclass methods; serialisation boundary violations |
| **Language requirement** | Object model with descriptor, metaclass, or equivalent structural enforcement machinery |

Requirements:

- SHOULD make fabricated defaults on authoritative (Tier 1) fields structurally impossible — accessing an unset authoritative field raises an error rather than returning a default *(binding requirement)*
- SHOULD enforce that subclasses of protected base classes cannot add unannotated methods — preventing bypass of the wardline through inheritance *(binding requirement)*
- SHOULD make serialisation boundary violations detectable at access time — deserialised data that claims a tier it has not earned produces an error. Bindings that implement this layer MUST include restoration boundary verification: deserialised data passing through a declared restoration boundary MUST satisfy the structural evidence requirement (§6.3) *(binding requirement)*
- MAY provide optional runtime enforcement that complements static analysis for contexts where static analysis alone is insufficient *(tool quality target)*

#### 9.4 Orthogonality principle

Static analysis cannot cross serialisation boundaries. Mainstream type systems cannot enforce behavioural constraints (dependent types and session types can, but are not available in the languages this framework targets). Runtime enforcement cannot catch patterns that succeed silently (a `.get()` with a default *works* — it just produces the wrong value). Each layer's blind spots are another layer's coverage area.

The orthogonality principle has a direct structural consequence for implementation: because each layer catches what the others cannot, there is no requirement — and no advantage — in building a single tool that spans all three. A multi-tool enforcement regime where a type checker handles §9.2, a linter handles §9.1, and a runtime library handles §9.3 achieves the same coverage as a monolithic tool, with the additional benefit that each component can evolve independently and that adopters can deploy layers incrementally as their annotation investment grows. The conformance profiles (§15.3; see §15.3.1 for the normative profile definitions) encode this principle: Wardline-Type, Wardline-Core, and Wardline-Governance correspond to the natural tool boundaries that the orthogonality principle predicts.

#### 9.5 Pre-generation context projection (advisory mechanism — not an enforcement layer)

The three enforcement layers above operate on code that has already been written. The following mechanism is **not a fourth enforcement layer** — it is an advisory, read-only projection that operates upstream of code generation. It does not enforce constraints, block merges, or produce findings. It reduces the volume of violations that reach the enforcement layers by shaping the information available during code generation. A complementary mechanism may operate upstream of generation by projecting the resolved governance state onto a specific file before modification.

The projection is a read-only query over existing wardline state. It is a lens over the enforcement surface, not a control surface itself. It does not modify the manifest, annotations, or exception register, and it introduces no policy artefacts. Its inputs are the same structured declarations that the enforcement layers consume; its output is a resolved summary tailored to a specific file at a specific point in time.

##### 9.5.1 Projection content

For a given file path, the projection resolves:

- **Taint state summary.** Per-region taint states resolved from the current manifest state and the latest available derived state (the taint-state map computed by the most recent static-analysis run, typically extracted from SARIF output or an equivalent state cache; it may also incorporate the fingerprint baseline, §10.2). Where annotations are absent, the module-level default taint from the governing overlay (§14.1.2) applies.
- **Active rules.** The severity matrix (§8.3) projected onto the resolved taint states — which rules are active, at what severity, and whether each is UNCONDITIONAL or STANDARD in this context.
- **Live exceptions.** Exceptions from the exception register (§14.1.3) resolved against the current date. Expired exceptions do not appear.
- **Boundary context.** Any transition boundaries (§6.2) declared in this file, with source and destination tiers.
- **Optional-field classification.** For validation and normalisation boundaries that carry structural-contract declarations (§8.2.1), the projection SHOULD include the field-level classification needed to avoid WL-001 noise: required fields, optional fields with approved defaults, and optional fields with no approved default. Where approved defaults exist, the projection SHOULD surface the default values and their governing boundary context so that generated code can apply the institutionally approved default at the boundary rather than inventing one ad hoc in downstream logic.
- **Rationale.** Narrative sufficient to explain the operational significance of active constraints in the current context, assembled from the manifest's `threat_model` metadata and the rule descriptions (§8.1).
- **Currency.** The commit at which the derived state was last computed (or a timestamp where commit identity is unavailable), so the consumer can assess alignment between the projection and the current repository state.

##### 9.5.2 Relationship to enforcement

Pre-generation projection does not replace post-generation enforcement. The enforcement layers remain the terminal control — an agent or developer that receives the projection may still produce a violation, and the static analysis, type system, and runtime structural layers detect it as before.

The projection reduces the volume of violations that reach those layers. Local projection of the governance state at the point of modification reduces reliance on persistent recall of constraints encountered earlier in the generation context. This has a compounding effect: fewer violations at the enforcement gate reduces fix-and-retry cycles, which reduces pressure on human review capacity.

Pre-generation projection is the primary mechanism for making the governance model sustainable at LLM code volumes. Without operational projection, violation volume is unmitigated and governance burden scales with code volume rather than annotation coverage. The capacity baseline (§3) establishes that human review has already failed at scale; projection is the mechanism that prevents the wardline from simply adding another layer of unscalable review on top of the existing overwhelmed process.

**Manifest poisoning amplification.** When LLMs consume wardline declarations via projection, a manifest error does not merely cause enforcement to miss violations — it causes the LLM to actively generate code conforming to the wrong policy at scale. The generated code passes enforcement (because enforcement faithfully implements the manifest) and appears correct to reviewers (because it is consistent with its declared context). This amplifies the consequences of residual risk 1 (declaration correctness, §13) when LLMs are active consumers of the projection. The accidental defensive patterns that would otherwise serve as symptoms of misclassification — patterns that a human reviewer might notice as anomalous — are eliminated by the projection, because the LLM generates code that is stylistically consistent with the (wrong) declared tier.

**Conformance tracking.** Under the Assurance governance profile (§15.3.2), deployments SHOULD track whether pre-generation projection is operational and report its availability in SARIF run-level properties (`wardline.projectionAvailable: true|false`). When `wardline.projectionAvailable` is `true`, the SARIF run properties SHOULD also include `wardline.projectionCurrency` containing the commit hash or timestamp at which the projection was last computed. This is not an enforcement requirement — the projection has no findings, no blocking behaviour, and no conformance criteria. However, because it is the primary mechanism for reducing violation volume upstream of enforcement, its operational status is a meaningful governance signal. A deployment that removes projection without explanation may see increased finding volume, governance load, and exception pressure — all indicators the governance model monitors. Under the Lite governance profile, projection tracking is RECOMMENDED but not required.

##### 9.5.3 Delivery mechanisms

The projection may be delivered through any mechanism that interposes between the agent and the file at read or edit time. MCP tool servers (§14.1.3), IDE extensions, editor hooks, and agentic harness hooks are all valid delivery mechanisms. The specific mechanism is an implementation choice; the projection content (§9.5.1) is the stable interface.

For agentic development environments, delivery at file-read time is preferable to delivery at edit time. The agent reads the file, forms its editing plan, then modifies. Context that arrives at read time shapes the plan; context that arrives at edit time competes with it.
