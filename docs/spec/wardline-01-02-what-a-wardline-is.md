### 2. What a Wardline is

**Normative language.** This specification uses MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY, REQUIRED, RECOMMENDED, and OPTIONAL as defined in RFC 2119 and clarified in RFC 8174. When these words appear in uppercase, they carry normative force. Lowercase equivalents carry no normative weight and are used in their ordinary English sense.

#### 2.1 Terms and definitions

The following terms carry specific meaning in this specification. Where a term is used in its everyday sense, it appears in lowercase without emphasis; where it carries its defined meaning, the surrounding tier, boundary, or annotation context makes this clear.

Before the individual terms, the high-level model is simple: a wardline declares a trust topology for the application, expresses the validation scopes and boundary contracts through which data may move, and supplies the governance artefacts that make those declarations assessable. The framework then applies rule-based and structural enforcement to the declared topology. The terms below formalise the pieces of that model.

| Term | Definition |
|---|---|
| **Authority tier** | One of four hierarchical classifications (Tier 1 through Tier 4) that describe the level of trust a system is entitled to assume about a data value. See §5.1 |
| **Annotation coverage** | The proportion of the intended enforcement perimeter whose trust topology has been made explicit through wardline declarations. Coverage is a governance and adoption measure, not a direct correctness guarantee. See §4, §10.2 |
| **Boundary contract** | A named semantic identifier declaring what data crosses a boundary and at what tier, replacing the previous function-name consumer list. Each contract specifies a contract name (e.g., `"landscape_recording"`, `"partner_reporting"`), the data tier expected, and the direction of flow. See §6.2, §14.1.2 |
| **Validation scope** | Formerly 'bounded context' in prior drafts; renamed to avoid collision with the Domain-Driven Design term of the same name. The declared set of boundary contracts for which a semantic validation boundary establishes domain-constraint satisfaction. A validation is comprehensive within its validation scope — it establishes that data satisfies every domain constraint for every intended use within the declared scope. See §6.2, §14.1.2 |
| **Coding posture** | The programming style appropriate to a given tier: strict [offensive] (T1), governance-assured [confident] (T2), structure-verified [guarded] (T3), or untrusted-input [sceptical] (T4). See §5.1. The primary term (e.g., 'strict') is the canonical identifier used in machine-readable output; the bracketed term (e.g., 'offensive') describes the programming paradigm and is used as a human-readable label in prose and documentation |
| **Effective state** | One of eight enforcement contexts produced by combining trust classification and validation status. The eight states are enumerated in §6.1 (Table: Trust classification and validation status); conformant implementations MUST treat this as a closed set. The severity matrix (§8.3) maps pattern rules to effective states |
| **Enforcement perimeter** | The set of source files, modules, or packages that a wardline declaration covers. Code outside the enforcement perimeter is not analysed; data crossing the perimeter boundary is treated as UNKNOWN |
| **Exception** (governance) | A documented, time-limited override of a scanner finding, managed through the exception register (§10, §14.1.3). Distinct from a programming-language exception |
| **Fingerprint baseline** | A cryptographic record of the annotation surface at a governance checkpoint. Baseline diffs surface all wardline-relevant changes for review. See §10.2 |
| **Governance capacity** | The available reviewer attention, decision authority, and process bandwidth needed to ratify manifests, review boundary changes, and assess exceptions. Governance capacity constrains how quickly annotation coverage and supplementary enforcement can grow without degrading review quality. See §3, §10.4 |
| **Mixed** | A trust classification assigned to data that merges values from different trust classifications. Once mixed, always mixed — MIXED_RAW is the absorbing element of the join operation. See §6.1 |
| **Normalisation boundary** | A declared boundary that collapses MIXED-taint inputs into a new Tier 2 artefact. Normalisation is semantically a new construction, not a passthrough. See §6.1 |
| **Overlay** | A YAML file (`wardline.overlay.yaml`) that narrows or extends the root manifest for a specific module, boundary, or data source. See §14.1.2 |
| **Rejection path** | A control-flow path within a validation boundary function that terminates without producing the function's normal return value (e.g., `throw`, guarded early return). See §8.2 |
| **Restoration boundary** | A declared function that reconstitutes a previously serialised artefact, reinstating a tier classification supported by evidence categories. See §6.3 |
| **Semantic boundary** | A point in the codebase where data crosses between authority tiers or where institutional meaning is assigned. Wardline annotations make semantic boundaries explicit and machine-readable |
| **Structural guarantee** | The set of structural guarantees that a data representation provides after shape validation — field presence, type correctness, schema conformance |
| **Taint state** | The effective state assigned to a data value by the taint analysis engine. Determined by the value's trust classification and validation status. See §6.1 |
| **Non-normative** | Content that advises or recommends but does not impose requirements on implementations. In Part II, sections not marked "This section is normative" are non-normative. Non-normative sections use "recommended", "preferred", "avoid" — never uppercase RFC 2119 keywords |
| **Trust classification** | The dimension of the effective-state model that describes what guarantees the system is entitled to assume about a data value. Five values: Tier 1 (authoritative internal), Tier 2 (semantically validated), Tier 3 (guarded), Tier 4 (external raw), Unknown (provenance not established), and Mixed (values from different classifications merged). See §6.1 |
| **Trust topology** | The complete set of tier assignments, boundary declarations, and data-flow constraints declared in a project's wardline manifest and overlays |
| **Unknown** | A trust classification assigned to data whose provenance has not been established — typically data crossing the enforcement perimeter from outside, or return values from unannotated third-party libraries. Distinguished from the four named tiers (T1–T4) in that no institutional trust claim has been made. See §6.1 |
| **Validation boundary** | A declared function that transitions data from one tier to another through structural (shape) or domain-constraint (semantic) verification |
| **Validation status** | The dimension of the effective-state model that describes what processing a data value has received. Three values: raw (no validation), shape-validated (structural guarantee verified), semantically validated (domain constraints verified). Combines with trust classification to produce the eight effective states (§6.1) |
| **Wardline manifest** | The root YAML file (`wardline.yaml`) that declares a project's trust topology, enforcement configuration, and governance policy. See §14 |

A wardline is the set of declarations an application makes about how it classifies and protects the semantic boundaries of its data and code paths. A complete wardline declaration includes all of the following components:

- Which data belongs to which authority tier
- Which code paths must fail in which ways
- Which patterns are prohibited in which contexts
- What governance surrounds exceptions to those rules
- Where serialised representations of authoritative artefacts may be restored to a tier supported by available evidence (restoration boundary declarations)

All five elements above are REQUIRED components of a complete wardline declaration. The conformance profiles in §15 specify the minimum enforcement and governance expectations for each profile, not an alternate five-part definition of what a wardline declaration contains.

An application that has declared a wardline has made its institutional knowledge machine-readable. An application without one has that knowledge in prose, in people's heads, or nowhere.

At system level, the wardline is primarily an information-flow intervention: it takes semantic boundary knowledge that would otherwise remain tacit and routes it into machine-readable declarations, enforcement output, and assessable governance artefacts. The framework does not create institutional knowledge; it creates explicit channels through which that knowledge can influence tooling and review.

The wardline is the *classification*, not the enforcement tool. A wardline declares that deserialised audit records carry Tier 1 authority and that accessing their fields with fallback defaults is prohibited. An enforcement tool reads that declaration and produces findings when the codebase violates it. The relationship is analogous to a security classification guide and the systems that enforce it: the guide defines the policy; the systems implement it. Replacing the enforcement tool does not change the classification. Changing the classification changes what every enforcement tool MUST check.

This distinction matters because institutional knowledge outlives any particular toolchain. A wardline expressed as a machine-readable manifest can be consumed by static analysers, type checkers, runtime enforcement layers, prompted review systems, or assessment tooling — serially or in parallel, in any language. The manifest is the stable artefact. The tools are disposable.

A wardline is therefore a prescriptive declaration: it describes what the application *commits to*, not what it currently achieves. The gap between declaration and enforcement is measurable, auditable, and — critically — visible to assessors who have no access to the development team's tacit knowledge.
