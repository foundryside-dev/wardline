# ADR-005: Bootstrap Assurance Reference for single-maintainer reference implementations

**Status**: Proposed
**Date**: 2026-04-12
**Deciders**: Project Lead (pending panel review)
**Context**: v1.0 reference-implementation recertification under §15.3.2 Assurance

## Summary

A single-maintainer reference implementation of the Wardline specification cannot
satisfy §15.6 "Reviewer independence" in its default reading, which assumes
independence is provided by a second human actor. This ADR amends §15.3 to
introduce a named, tightly-scoped variant of the Assurance profile —
**Bootstrap Assurance Reference (BAR)** — that grounds independence in the two
*properties* §15.6 actually protects (no vested interest, full reproducibility)
rather than in the mechanism the spec assumed.

Under BAR, independence is provided by a named, versioned, deterministic review
pipeline with full input provenance and a mandatory graduation commitment to
human-independent review. BAR is structurally stricter than §15.3.2 Lite in
every dimension where the two overlap. It does not relax any other §15.3.2
Assurance MUST.

## Context

### The single-maintainer problem

§15.6 "Reviewer independence" reads:

> Every verified or waived obligation MUST record the reviewer identity and
> review date. For Assurance-profile claims, and for any formally accredited
> claim, the record MUST also identify whether the reviewer is independent of
> the implementation author for that obligation.

§15.3.2 "Assurance" reinforces this with:

> Temporal separation | MUST, no alternatives

The spec was drafted assuming the normal case: a project with at least two
human maintainers, where independence is provided by "different human reviewer,
separated in time, with no vested interest in the claim passing."

The Wardline reference implementation is currently maintained by a single
person. It is, however, the canonical implementation of the specification, and
its conformance ledger is the exemplar other regimes will use as a template. A
Lite ledger would undersell the reference claim. A falsified Assurance ledger
would be dishonest and an IRAP assessor would — correctly — reject it at the
first independence check.

### The escape-hatch trap

The existing `compliance-ledger.schema.json` carries an independence enum value
`tool_assisted` with the comment *"used during single-maintainer Lite
recertification"*. This value is a structural loophole:

- It is not named in §15.6, so it has no normative meaning
- Its description imports a Lite-only framing into Assurance contexts
- It does not constrain the reviewing tool, the policy version, or the
  reproducibility of the review
- It carries no graduation commitment
- It is not surfaced in summary counts, so a ledger could claim N obligations
  verified while hiding the fact that 0.95 × N of them are tool-assisted

A reference implementation that ships with `tool_assisted` behind an Assurance
label gives future regimes permission to do the same, worse. The spec must
either name this case out loud or disallow it entirely.

### Why independence is required at all

The §15.6 independence MUST exists to enforce two underlying properties:

1. **No vested interest.** The reviewer does not benefit from the claim passing.
   The default mechanism (different human) satisfies this because a second
   maintainer's reputation is not staked on the author's work being green.
2. **Reproducibility by a later assessor.** An assessor arriving later can
   re-run the same check and get the same answer. The default mechanism
   satisfies this because a human review leaves an artifact (PR comment, sign-off
   record) that a later assessor can re-read.

A same-actor human reviewer fails property (1). An opaque LLM critique with no
provenance fails property (2). A named, versioned, deterministic review
pipeline with captured input hashes **can satisfy both properties**, and in
the reproducibility dimension it satisfies property (2) more rigorously than
a human second reviewer (whose judgment is not re-runnable).

§10 already makes this property-vs-mechanism distinction for temporal
separation. §15.6 never extended the distinction to independence. That is the
gap this ADR closes.

## Decision

Amend §15.3 of the specification to introduce §15.3.4 "Bootstrap Assurance
Reference" as a named sub-profile *under* Assurance (not a third governance
profile, not a downgrade). The sub-profile applies when, and only when, all
of the following are true and declared in the root manifest:

1. The deployment is a reference implementation of the Wardline specification
   itself.
2. The project has a single declared human maintainer.
3. Independence for BAR obligations is provided by an **automated conformant
   review pipeline** with these required properties:
   - Named tool, tool version, and review-policy hash captured per obligation
   - Deterministic verdict: same inputs produce the same output, reproducible
     by a later assessor
   - No dependency on any artefact produced by the implementation author within
     the same commit being reviewed
   - Full input provenance bound into the ledger: commit ref, manifest hash,
     corpus hash, review-policy hash, tool version
4. A graduation commitment is declared with a named target date, by which
   either:
   - a second human maintainer is onboarded and re-reviews all BAR-attested
     obligations under the normal §15.6 independence rules, or
   - a named external auditor performs independent review under the normal
     §15.6 independence rules.
5. The count of obligations in the BAR-attested state is surfaced in the
   ledger summary as a distinct count, not folded into `verified` and not
   buried in per-row notes.
6. Every BAR-attested obligation names the review pipeline, policy version,
   and graduation target date in its `reviewer_metadata`.

BAR does **not** relax any other §15.3.2 Assurance MUST:

- Manifest coherence remains a blocking gate (§15.6 step 2.5)
- Full golden corpus with adversarial coverage remains required (§11, §15.3.2)
- Structured fingerprint baseline with canonical hashing remains required
- Expedited governance ratio threshold remains declared and enforced
- SIEM export remains SHOULD (MUST for formally accredited systems)
- Temporal separation across commits still applies — a single-actor workflow
  satisfies temporal separation trivially because commits are separated in
  time; the only constraint BAR relaxes is the actor-identity requirement,
  and it substitutes a stricter mechanism for the property that requirement
  was protecting

BAR obligations automatically transition to `stale` the day after the declared
graduation target date passes without re-review. The ledger's freshness
binding records the target date; the coherence layer enforces the transition.

## Alternatives Considered

### Option A: Ship under Lite

Declare `governance_profile: lite` and accept that the reference implementation
of the full spec is not itself a full-spec exemplar.

Rejected because the project's stated purpose is to serve as the reference
implementation of the full specification. Lite is a "narrower but still
testable set of controls" (§15.3.2), not a reference-grade claim. Other regimes
building Assurance ledgers would have no canonical example to follow.

### Option B: Invent a second reviewer

Create a nominal second-maintainer identity and use it to rubber-stamp reviews.

Rejected outright. This is the falsification case §15.6 exists to prevent. An
IRAP assessor inspecting the commit history would identify the pattern in one
audit cycle, and the reference claim would be permanently discredited. The
project lead explicitly declined this option.

### Option C: Keep `tool_assisted` as schema vocabulary without spec amendment

Leave the schema as-is; let the ledger assert `tool_assisted` independence under
`assurance` governance without a named spec clause authorizing it.

Rejected because (a) it violates §15.6 as currently written, (b) it gives
future regimes implicit permission to do the same with no constraints, and
(c) it exposes the reference implementation to a legitimate audit finding
that cannot be defended without retroactive spec amendment. If we need to
amend the spec to defend the ledger, we should amend it first.

### Option D (chosen): Amend §15.3 to name Bootstrap Assurance Reference

Fix the problem at the abstraction layer where it lives — the conformance
profile. The spec already models sub-profiles of Assurance implicitly (Lite
and Assurance); BAR becomes an explicit, strictly-constrained sub-profile of
Assurance itself. The §15.6 independence MUST stays intact as the default,
and BAR declares its alternative mechanism out loud with stronger
reproducibility constraints than the default provides.

This option preserves:
- §15.6 as the unambiguous default rule
- §15.3.2 Assurance as the unrelaxed surface for every other MUST
- §15.3.2's "no alternatives" clause on temporal separation (BAR satisfies
  temporal separation trivially through commit ordering)
- The integrity of the reference claim
- Honest representability in the compliance ledger

And introduces:
- A named, bounded governance compromise that any future reference
  implementation can adopt with the same constraints
- A structurally stricter alternative than Lite's same-actor allowance
- A graduation commitment that prevents BAR from being an indefinite state

## Consequences

### Positive

- v1.0 can ship as a legitimate Assurance-reference claim without a fabricated
  second reviewer
- The single-maintainer bootstrap problem that every reference implementation
  historically faces is now named and bounded in the spec
- Future reference implementations (including the Java binding, when it
  begins) inherit the same constrained mechanism with no ambiguity
- IRAP assessors and equivalent formal reviewers see a named, documented,
  time-bounded compromise rather than an undisclosed one
- BAR's reproducibility properties are, in the specific dimension of
  "re-runnability by a later assessor," stricter than the default Assurance
  independence mechanism
- The schema can encode BAR as a structurally valid state with required
  sibling fields, turning a governance question into a validation question

### Negative

- The spec gains a conformance profile whose correct application requires
  assessor judgment about whether the graduation plan is credible. This is
  the standard cost of any named exception
- BAR's constraint set is easy to read but harder to automate end-to-end —
  verifying determinism of the review pipeline is itself a non-trivial
  obligation
- If graduation dates slip, BAR obligations automatically become `stale`,
  which will surface as non-conformance in the ledger. This is a feature
  (forcing function) but it creates a hard deadline the project must meet
- A reference implementation operating under BAR cannot claim formal
  accreditation until graduation completes — the two statuses are mutually
  exclusive by design

### Process gaps identified

- The review pipeline named by BAR must itself be specified as a separate
  document (pipeline identity, policy versioning scheme, determinism
  verification method). This is a follow-up artefact, not part of this ADR
- The schema's independence enum currently contains values (`same_actor`,
  `not_required_lite`, `tool_assisted`) that predate BAR. Migrating to BAR
  requires deleting the first two and renaming the third to match the new
  spec vocabulary
- The compliance ledger summary currently does not break out tool-assisted
  counts. BAR requires the summary to expose BAR-attested counts distinctly
  from `verified` counts

## Panel Input

Pending review by the project's default seven-role panel:

| Role | Status |
|------|--------|
| Solution Architect | Pending |
| Systems Thinker | Pending |
| Python Engineer | Pending |
| Quality Engineer | Pending |
| Security Architect | Pending |
| Static Analysis Dev | Pending |
| IRAP Assessor | Pending |

The IRAP Assessor review is particularly important. The pitch to assessors is
framed in §15.3.4 and summarized here:

> "BAR does not skip independence. It formalizes a second independence
> mechanism whose underlying properties — no vested interest, full input
> reproducibility, bounded lifetime, summary-level disclosure — are at least
> as strong as the default same-actor-with-retrospective-review allowance
> Lite already permits. Every use is declared, counted, hashed, and
> time-bounded. The graduation plan is in the root manifest and the ledger
> summary publishes the count at a glance."

A panel that accepts this framing is accepting a clearly bounded, disclosed
compromise. A panel that rejects it is implicitly rejecting every
single-maintainer reference implementation in computing history (TeX, early
Git, CPython), which is not a defensible position. What the panel can
legitimately demand is that the window is bounded, the count is disclosed,
the pipeline is reproducible, and the graduation plan names a real target.
§15.3.4 makes all four of these MUSTs.

## Related

- §15.3.2 Governance profiles — BAR sits under Assurance as a named sub-profile
- §15.3.3 Governance profile graduation — BAR adds a parallel graduation path
  (BAR → default Assurance) that complements the existing Lite → Assurance path
- §15.6 Reviewer independence — the paragraph is amended to reference §15.3.4
  as the named exception
- §10 Governance model — BAR does not modify temporal separation semantics;
  single-actor commits satisfy temporal separation through commit ordering
- `src/wardline/manifest/schemas/compliance-ledger.schema.json` — the schema
  requires the changes listed under "Schema changes" below
- `docs/governance/bar-review-pipeline.md` — the normative specification of
  the BAR review pipeline referenced by §15.3.4. Written and landed in the
  same work package as this ADR
- `docs/governance/README.md` — charter for the `docs/governance/` directory,
  establishing what belongs there and why the BAR pipeline spec lives there
  rather than under `docs/spec/`

## Schema changes implied by this ADR

The compliance-ledger schema requires the following changes to match §15.3.4.
These are listed here for traceability; the implementation is tracked in a
separate work package.

1. Rename `reviewer_metadata.independence` enum value `tool_assisted` to
   `bootstrap_attested`. The rename is not cosmetic — the new name binds to
   §15.3.4's property set, the old name does not
2. Delete `reviewer_metadata.independence` enum values `same_actor` and
   `not_required_lite`. Neither has a role in a §15.3.4 (or default Assurance)
   ledger
3. Add a conditional `if/then` gate: when `independence == "bootstrap_attested"`,
   the following sibling fields on `reviewer_metadata` are required:
   - `review_pipeline` (string — tool name)
   - `review_pipeline_version` (string)
   - `review_policy_hash` (string)
   - `graduation_target_date` (date)
   - `graduation_mechanism` (enum: `second_maintainer`, `external_audit`)
4. Add a top-level `bootstrap_reference_declaration` object, required iff any
   obligation uses `bootstrap_attested`, containing:
   - `sole_maintainer` (identity)
   - `declared_at` (date)
   - `graduation_target_date` (date — MUST match per-obligation dates)
   - `graduation_mechanism` (enum — MUST match per-obligation mechanism)
   - `graduation_plan_ref` (source ref pointing to the written plan, normally
     this ADR)
   - `slip_count` (integer, minimum 0, maximum 2) — mandatory. The schema
     refuses values above 2. Monotonic non-decrease is enforced by the
     coherence layer against the prior ledger snapshot
5. Extend the top-level `summary` object to count `bootstrap_attested`
   obligations separately from `verified`. The `slip_count` is surfaced in
   the summary alongside the BAR-attested count. Both MUST be exposed at the
   top of any derived release projection
6. Define staleness propagation: `bootstrap_attested` obligations automatically
   transition to `stale` the day after `graduation_target_date` passes without
   re-review. The schema expresses the target date as part of the freshness
   binding; the coherence layer enforces the transition
7. Enforce the graduation-date change procedure from §15.3.4:
   - Changing `graduation_target_date` at the snapshot or per-obligation
     level MUST increment `slip_count` by exactly 1
   - A change that would take `slip_count` above 2 MUST be refused at schema
     validation time
   - Each change requires a corresponding ratification event recorded through
     the existing §15.3.2 row 1 manifest ratification process
   - Each change requires an appended reason-for-slip entry in the document
     referenced by `graduation_plan_ref`; the coherence layer verifies the
     entry count matches `slip_count`
