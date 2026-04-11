### 15. Conformance

#### 15.1 Conformance model

Wardline conformance is assessed through an **obligation catalog** and a
**compliance ledger**. A tool or deployment does not become conformant because
its authors believe the major pieces are present, or because a release checklist
looks green. It becomes conformant only when the obligations in its claimed
surface are cataloged, evidenced, reviewed, and current.

An **obligation** is a single normative requirement drawn from Part I, Part II,
or a declared governance profile. Each obligation record MUST carry:

| Field | Required content |
|---|---|
| **Obligation ID** | Stable identifier for the requirement record |
| **Source reference** | Exact clause, criterion, profile requirement, or binding contract being claimed |
| **Requirement summary** | Plain-language summary of the obligation |
| **Claim scope** | Tool, regime, binding, profile, or rule surface to which the obligation applies |
| **Implementation surface** | Code, manifest artefact, workflow, or tool output that satisfies the claim |
| **Evidence classes** | Assessor-runnable proof needed for the obligation |
| **Compliance state** | One of the states defined in §15.6 |
| **Freshness binding** | Commit, manifest hash, corpus hash, tool version, and any other evidence identity required to know whether the record is current |
| **Reviewer metadata** | Reviewer identity, review date, and independence metadata when required |

The obligation catalog is the source of truth. The following are **derived
views**, not primary truth stores:

- a human certification matrix
- a release projection
- a profile-specific compliance summary
- a ship/no-ship gate

This distinction is mandatory. A matrix is useful because humans read rows. A
ledger is required because assessors, automation, and future reviewers need to
see the complete compliance state, including obligations that are failed,
waived, stale, or not yet assessed.

Any derived view used to authorize a release MUST remain assessor-runnable. At
minimum, a release-authorizing matrix or projection MUST expose:

- the row or surface identifier
- the claimed release scope for that row
- the backing obligations
- the current state or result
- the current disposition or next action when the row is not green
- reviewer or sign-off status
- explicit `not_applicable` rows or states where a surface is intentionally out
  of scope

**Catalog completeness.** A regime MUST record whether its obligation catalog is
complete for the claimed surface.

- A catalog is **complete** when every obligation in the claimed Part I, Part II,
  and governance-profile surface has a record.
- A catalog is **partial** when some obligations are not yet enumerated.

A regime with a partial catalog MAY make a limited, explicitly scoped claim, but
it MUST NOT present that state as full compliance visibility.

**Requirement ID scheme.** Obligation IDs are stable repo or regime identifiers,
not line numbers. A conformant regime MUST define and publish its ID scheme. For
example:

- `P1-S6-TAINT-JOIN-ABSORBING`
- `P2A-A3-L1-MINIMUM-CONFORMANCE`
- `C-CRIT-7-SELF-HOSTING`
- `G-LITE-EXCEPTION-REGISTER`
- `R-REGIME-COVERAGE-COMPLETE`

Changing evidence or implementation does not change the obligation ID. If a
chapter is renumbered, the source reference changes; the obligation record does
not disappear.

#### 15.2 Conformance criteria

Ten criteria define the Wardline conformance surface. They are grouped as
expressiveness, enforcement capability, and governance infrastructure.

**Expressiveness**

1. The ecosystem can express all 17 annotation groups at the function, class,
   field, or equivalent binding-defined location using language-native
   mechanisms (§7).

**Enforcement capability**

2. Pattern rule detection: the active pattern rules WL-001 through WL-006 are
   detected intraprocedurally within annotated bodies (§8, §9.1).
3. Structural verification: WL-007, WL-008, and WL-009 are enforced where
   their preconditions apply. A binding MAY rename or split the rules, but the
   framework-level obligation remains unchanged (§8.2, Part II).
4. Taint-flow tracking: explicit-flow taint between declared boundaries is
   traced for at minimum direct flows and two-hop unannotated intermediaries
   (§6.2, §9.1).
5. Precision and recall are measured, tracked, and published per measurement
   cell for each tool that claims enforcement (§11).
6. A golden corpus of labelled specimens exists and is maintained (§11),
   including adversarial specimens for any claimed semantic-equivalent rule
   coverage.
7. Each enforcement tool passes its own rules where applicable (self-hosting
   gate) (§11).
8. Enforcement output is deterministic SARIF v2.1.0 with the Wardline-specific
   property bags defined in §11.1.

**Governance infrastructure**

9. The governance model supports, at minimum, protected-file review, temporal
   separation, exception tracking, and annotation change tracking at the level
   required by the declared governance profile (§10, §15.3.2).
10. The Wardline manifest system (§14) is consumed by the tools that depend on
    it, and JSON Schema validation is performed either by that tool or by a
    declared Wardline-Governance tool in the same regime. A tool that relies on
    delegated validation MUST document that delegation.

Each criterion MUST map to one or more obligation records in the compliance
ledger. Criteria are not a substitute for the finer-grained obligations they
summarize.

#### 15.3 Conformance profiles

The criteria above describe the full surface. Conformance profiles partition
that surface into implementable slices so that partial but honest claims are
possible.

##### 15.3.1 Enforcement profiles

Four enforcement profiles are defined:

| Profile | Minimum criteria | Typical implementer |
|---|---|---|
| **Wardline-Core** | 2, 5, 6, 8, 10; and 3, 4, 7 when the tool claims structural verification, taint-aware enforcement, or self-hosting applicability | AST scanner, linter plugin, semantic rule pack |
| **Wardline-Type** | 1 at the type layer for the core classification groups, plus 5 and 6 for the type-enforced surface | Type checker or checker plugin |
| **Wardline-Governance** | 9 and 10 | CLI orchestrator, CI policy tool, governance runner |
| **Wardline-Full** | All ten criteria | Complete regime, or a monolithic tool that truly covers the full surface |

Profile rules:

- A Wardline-Core tool MAY implement a declared subset of rules. Its
  documentation MUST name the exact rules it covers.
- A Wardline-Core tool that claims semantic-equivalent coverage beyond the base
  syntax of a rule MUST carry matching corpus evidence for that extra claim.
- Criterion 3 applies to a Wardline-Core tool when it claims WL-007, WL-008,
  WL-009, or binding-defined equivalents.
- Criterion 4 applies to a Wardline-Core tool when its severity or detection
  depends on taint context.
- Criterion 7 applies per tool, not once per regime.
- Wardline-Full is normally a regime claim, not a marketing label for any tool
  that covers "most of the interesting bits."

##### 15.3.2 Governance profiles

Every deployment MUST declare a governance profile in the root manifest, in SARIF
run-level properties, and in its compliance ledger:

- `lite`
- `assurance`

**Wardline Lite** is the small-team and early-adopter governance profile. It
requires a minimal but assessable governance surface. Lite does not relax
criterion 8: run-level SARIF properties, including `wardline.governanceProfile`
and `wardline.controlLaw`, remain mandatory under the general conformance
criteria. The Lite-specific governance checklist is:

| # | Requirement | Lite status | Assessment expectation |
|---|---|---|---|
| 1 | Manifest validity and current ratification | MUST | Root manifest is schema-valid and ratification age is within the declared review interval |
| 2 | Governance artefact protection | MUST | CODEOWNERS or equivalent protects `wardline.yaml`, overlays, the exception register, and any checked-in governance evidence used for sign-off |
| 3 | Exception register integrity | MUST | Every active exception records reviewer identity, rationale, and expiry |
| 4 | Temporal separation or documented alternative | MUST | Alternative is declared in the root manifest; same-actor approval is permitted only for enforcement-artefact changes and MUST carry retrospective review within the declared window; policy-artefact changes still require different-human-actor approval |
| 5 | Annotation-change review in the assessment window | MUST | Recent annotation changes were visible to and reviewed by a designated reviewer through PR history, commit review, or equivalent evidence |
| 6 | Bootstrap corpus correctness | MUST | The bootstrap corpus covers the highest-consequence claimed cells and the current tools classify those specimens correctly |
| 7 | Expedited and degraded-governance closure | MUST | Expedited exceptions are documented and retrospective review occurred; any alternate-law or direct-law window is closed by the verifiable retrospective scan required by §10.5 before release sign-off |

Lite defers, but does not erase, the Assurance-level artefacts:

- full fingerprint baseline with canonical hashing
- full 126+ specimen corpus with the full adversarial surface
- automated expedited-ratio threshold findings

Projects that do not yet compute the expedited governance ratio MUST still
document their expedited approval process and review it at each manifest
ratification cycle.

**Wardline Assurance** is the full governance profile. It strengthens Lite and
adds the full governance surface:

| Requirement | Assurance status |
|---|---|
| Temporal separation | MUST, no alternatives |
| Manifest coherence as a gate before code-level enforcement | MUST |
| Full golden corpus with adversarial coverage | MUST |
| Structured fingerprint baseline with canonical hashing | MUST |
| Expedited governance ratio, declared threshold, and automated findings | MUST |
| SIEM export of governance events | SHOULD; MUST for formally accredited systems |

A deployment is assessed against the profile it declares. Lite is not
"Assurance with paperwork removed." It is a narrower but still testable set of
controls.

##### 15.3.3 Governance profile graduation

Graduation from Lite to Assurance occurs when governance capacity and risk
context justify the full surface.

Graduation triggers include:

- formal security accreditation
- data at PROTECTED classification or above
- sustained contributor growth beyond small-team governance assumptions
- operation through multiple ratification cycles with a stable Wardline program
- explicit organisational risk appetite for Assurance-level controls

Before changing the declared profile from `lite` to `assurance`, the following
MUST be satisfied:

1. The corpus has expanded from bootstrap coverage to the full rule and
   adversarial surface.
2. A structured fingerprint baseline is established and has completed at least
   one review cycle.
3. Temporal separation is operational without alternatives.
4. The expedited governance ratio threshold is declared and enforced.
5. Lite-era exceptions have been re-reviewed under Assurance expectations.

#### 15.4 Enforcement regimes

An **enforcement regime** is the set of tools that collectively enforce a
Wardline deployment for a language ecosystem.

An enforcement regime is conformant only when all of the following hold:

- **Coverage completeness.** Every required criterion is mapped to at least one
  tool and at least one obligation record.
- **Rule coverage completeness.** The union of the regime's rule-implementing
  tools covers the full claimed rule surface.
- **Catalog completeness visibility.** The regime states whether its obligation
  catalog is complete for the claimed surface.
- **Corpus union.** The union of tool-specific corpora satisfies the minimum
  measurement and coverage obligations for the claimed surface.
- **SARIF aggregation.** Multi-tool regimes produce a SARIF log or equivalent
  aggregated evidence set that preserves per-tool provenance.
- **Per-tool self-hosting.** Every tool that analyses code in its own
  implementation language passes the rules it claims.

The regime documentation MUST identify:

- the tools in the regime
- the profile claimed by each tool
- the rules or enforcement surface each tool owns
- the criteria each tool satisfies
- the obligation ID ranges or obligation sets each tool owns
- any remaining gaps, waived obligations, stale evidence, or compensating
  controls

The regime documentation is the assessor's map. It is not optional explanatory
material.

#### 15.5 Supplementary group enforcement scope

Criterion 1 requires that the binding can express all 17 annotation groups.
Criteria 2 through 8 do not require uniform enforcement depth for supplementary
groups 5 through 15.

This distinction is mandatory in the compliance ledger and in any derived
matrix:

- supplementary groups with active enforcement MUST appear as explicit
  obligations or explicit rows
- supplementary groups that are expressiveness-only MUST be marked as such
- a regime MUST NOT imply enforcement coverage for supplementary groups it has
  not actually specified and measured

This keeps incremental adoption honest. A deployment may start by enforcing the
core classification surface and later add supplementary-group checks. What it
must not do is silently blur "expressible" into "enforced."

#### 15.6 Assessment procedure

Assessment proceeds obligation by obligation. The assessor creates or refreshes
the obligation catalog before evidence collection begins.

Compliance states:

| State | Meaning |
|---|---|
| `unassessed` | Assessment has not yet been completed |
| `implemented_no_evidence` | Claimed implementation exists, but assessor-runnable evidence is missing |
| `evidenced` | Evidence exists, but review or freshness checks are incomplete |
| `verified` | Requirement, evidence, freshness binding, and reviewer checks all align |
| `non_compliant` | Evidence contradicts the claim or the implementation does not satisfy the requirement |
| `waived` | Requirement is not met, but an explicit waiver with scope, approver, rationale, and expiry exists |
| `not_applicable` | Not required for the declared profile or claimed surface |
| `stale` | Previously evidenced or verified, but drift invalidated the record |

Remediation planning is separate from compliance state. Local workflows MAY use
labels such as `fix-code`, `fix-spec`, `narrow-claim`, or `seek-waiver`, but
those labels MUST NOT be treated as compliance outcomes.

**Step 1: Catalog completeness review**

- Build or refresh the obligation catalog for the claimed profile, binding, and
  rule surface.
- Verify that every claimed criterion maps to obligation records.
- Record whether the catalog is complete or partial for the claimed surface.

**Step 2: Manifest validation**

- Run manifest schema validation against `wardline.yaml` and all overlays.
- Verify ratification age, governance profile declaration, and required
  governance artefacts for the declared profile.
- Mark manifest and governance obligations `verified` only when the manifest is
  both valid and current.

**Step 2.5: Manifest coherence verification**

- Run coherence checks against manifest declarations, overlays, and code
  annotations.
- Verify absence of orphaned annotations, undeclared boundaries, contradictory
  contracts, and stale bindings.
- Under the Assurance profile, manifest coherence is a blocking gate.

**Step 3: Golden corpus verification**

- Verify corpus integrity against the specimen hash manifest and the declared
  specification or matrix revision.
- Run `wardline corpus verify` or the binding-equivalent corpus verifier.
- Record pass/fail per specimen and per tool.
- Measure precision and recall per measurement cell. Precision MUST meet the
  applicable minimum floor: `>= 0.80` generally and `>= 0.65` only for
  `MIXED_RAW` cells. Recall MUST meet the applicable minimum floor: `>= 0.70`
  for `STANDARD` and `RELAXED` cells and `>= 0.90` for `UNCONDITIONAL` cells.
- Verify adversarial coverage: at least one `adversarial_false_positive` and at
  least one `adversarial_false_negative` specimen per claimed framework rule or
  binding-equivalent rule, plus any binding-defined
  `suppression_interaction` minimums.
- Mark corpus obligations only from assessor-runnable output, never from
  informal spot checks.

**Step 4: Enforcement execution**

- Run the regime against the target codebase.
- Verify required SARIF properties and any other mandated output metadata.
- Verify that the release-signoff run reports `wardline.controlLaw: "normal"`.
  Release sign-off MUST NOT be taken from alternate-law or direct-law output.
- If any alternate-law or direct-law window occurred after the last accepted
  normal-law run, verify that the first returning normal-law run carries
  `wardline.retroactiveScan: true` and the matching retrospective-scan range.
- Re-run the same inputs and verify deterministic output in verification mode.
- Confirm that findings, declared gaps, claimed profile, and claimed release
  surface match the compliance ledger.

**Step 5: Governance artefact review**

- Inspect CODEOWNERS or equivalent review protection.
- Inspect exception registers, fingerprint baselines, retrospective reviews, and
  expedited governance evidence.
- Verify that governance artefacts match the declared profile, that any Lite
  alternatives are documented, and that any degraded-window retrospective review
  is closed before release sign-off.

**Step 6: Self-hosting verification**

- For each applicable tool, run the tool against its own source.
- Record pass/fail by tool, not just once for the regime.
- Define the self-hosting gate in explicit SARIF or equivalent output terms.
- Document exemptions explicitly when a tool is implemented in a different
  language or performs governance-only work.

**Release-critical gate checks**

| Gate | Pass condition | Fail condition |
|---|---|---|
| Claimed release surface is explicit | Release projection names the claimed profiles, required rule surface, active binding-specific rows, and explicit out-of-scope rows | Claimed profile or scope is ambiguous |
| Derived release projection is runnable | Release matrix exposes row identifier, scope, backing obligations, state, next action, reviewer status, and explicit `not_applicable` rows | Release matrix is only a catalogue or summary |
| Corpus verification is current | Corpus integrity is verified, per-cell floors are met, and required adversarial/suppression-interaction minima are present | Integrity, floor, or minimum-coverage checks fail |
| Control law is normal for sign-off | Release-signoff run reports `wardline.controlLaw: "normal"` | Sign-off relies on alternate-law or direct-law output |
| Retrospective scan closure is verifiable | Any degraded window is closed by the first returning normal-law run with `wardline.retroactiveScan: true` and matching range | Required retrospective scan is missing or unbounded |
| Lite or Assurance governance checklist passes | Every item in the declared governance-profile checklist is evidenced for the assessment window | Any checklist item is missing, undocumented, or stale |

**Freshness binding.** A `verified`, `waived`, or `stale` obligation MUST bind
to the evidence identity required to know whether it is current. For code-scoped
claims this normally includes:

- commit reference
- tool version
- manifest hash
- corpus hash, if corpus evidence is involved
- input hash or equivalent run identity, if scan output is involved
- evidence artefact identifiers or hashes

If the implementation surface or any bound evidence input changes without
re-verification, the obligation becomes `stale`.

**Reviewer independence.** Every verified or waived obligation MUST record the
reviewer identity and review date. For Assurance-profile claims, and for any
formally accredited claim, the record MUST also identify whether the reviewer is
independent of the implementation author for that obligation.

**Derived views.** After the ledger is current, the regime MAY generate:

- a certification matrix for human review
- a release projection
- a profile-specific compliance summary
- a ship/no-ship gate

Those views MUST be reproducible from the ledger. They MUST NOT hide failed,
waived, stale, or unassessed obligations.

Where a derived view is used for release authorization, it MUST also expose the
row state, current disposition or next action, reviewer status, and explicit
`not_applicable` rows or states for intentionally unclaimed surfaces.

#### 15.6.1 Worked example: ledger excerpt

The following excerpt shows the minimum shape of a useful compliance ledger:

| Obligation ID | Source | Summary | State | Freshness binding |
|---|---|---|---|---|
| `C-CRIT-5-PER-CELL-MEASUREMENT` | `§15.2(5)` | Per-cell precision and recall are published | `non_compliant` | corpus hash + conformance report |
| `P1-S6-TAINT-JOIN-ABSORBING` | `§6` | Taint propagation preserves the normative join algebra | `verified` | commit + taint-flow corpus evidence |
| `C-CRIT-8-DETERMINISTIC-SARIF` | `§15.2(8)` | Verification-mode SARIF is deterministic | `stale` | prior input hash no longer matches current scan inputs |
| `G-LITE-EXCEPTION-REGISTER` | `§15.3.2` | Lite exception register requirements are satisfied | `verified` | manifest hash + exception register review |

This example is intentionally mixed-state. A useful ledger shows the full truth,
not only the green entries.

#### 15.6.2 Worked example: release projection

A release projection is derived from obligation records:

| Release row | Backing obligations | Result |
|---|---|---|
| Claimed surface and profile | `R-*` claim-surface obligations | green only if the claimed profiles, active rows, and out-of-scope rows are explicit |
| Manifest and governance | `G-*`, `C-CRIT-9`, `C-CRIT-10` | green only if all applicable obligations are `verified` or `not_applicable` |
| Pattern rules and corpus | `C-CRIT-5`, `C-CRIT-6`, rule-specific obligations | blocked if any obligation is `non_compliant`, `waived`, `stale`, or missing required adversarial minima |
| SARIF and control law | `C-CRIT-8` and control-law obligations | blocked until determinism evidence is current and sign-off occurs under normal law |
| Self-hosting | `C-CRIT-7` and tool-specific self-hosting obligations | blocked until the per-tool gate is explicitly defined and satisfied |

The release view is therefore a query over the ledger, not a second system of
truth.

#### 15.6.3 Navigating to Part II

Part I defines the framework-level contract. Part II maps that contract to each
language ecosystem. The binding reference names the tools in the regime, defines
binding-specific rule identifiers, and provides the regime composition material
an assessor uses in Step 1.

When a binding statement conflicts with this chapter, Part I governs. When a
binding adds stricter obligations for its own rule surface, both the binding and
this chapter apply.

#### 15.7 Partial conformance

Partial conformance is expected during adoption, but it must be explicit.

A tool or regime is **partially conformant** when one or more applicable
obligations are `unassessed`, `implemented_no_evidence`, `evidenced`,
`non_compliant`, `waived`, or `stale`, or when the catalog itself is partial for
the claimed surface.

Partial conformance is legitimate only when the documentation clearly states:

- which profiles are claimed
- whether the obligation catalog is complete or partial for the claimed surface
- which rules are implemented
- which obligations remain unverified, non-compliant, waived, or stale
- which compensating controls, if any, are in place

What partial conformance does **not** permit is aspirational language. A tool
that hopes to satisfy Wardline-Core after future work is not Wardline-Core
today. A release projection that looks green while the obligation ledger is
partial, stale, or non-compliant is not a conformant release.
