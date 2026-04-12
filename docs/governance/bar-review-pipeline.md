# BAR review pipeline specification

**Status**: Proposed
**Date**: 2026-04-12
**Binds**: §15.3.4 Bootstrap Assurance Reference
**Consumers**: `compliance-ledger.schema.json`, `wardline.yaml`,
`docs/adr/ADR-005-bootstrap-assurance-reference.md`

## 1. Purpose and binding

§15.3.4 Bootstrap Assurance Reference permits a reference implementation to
substitute an **automated conformant review pipeline** for the default §15.6
independence mechanism (a second human reviewer), under tightly constrained
conditions. This document is the normative specification of the automated
review pipeline used by the Wardline reference implementation to satisfy
that substitution.

Throughout this document, "the pipeline" refers to the BAR review pipeline
specified here. A compliance ledger MAY claim `independence: bootstrap_attested`
on an obligation only when every BAR pipeline MUST in this document is
satisfied for that obligation.

This specification does not define the implementation of the pipeline. It
defines the contract the implementation MUST satisfy. The implementation is
captured in a separate, version-locked policy tree (§7) whose hash is bound
into every BAR-attested obligation record.

## 2. Pipeline identity

**Canonical name.** The pipeline is named `wardline-bar-panel`. This name
MUST appear verbatim in every BAR-attested obligation's
`reviewer_metadata.review_pipeline` field.

**Version scheme.** Pipeline versions use a date-based scheme
`YYYY.MM.DD[-N]` where the date is the activation date of the policy tree and
`-N` is an optional same-day revision suffix. Examples: `2026.04.12`,
`2026.04.12-1`. The version MUST appear in `reviewer_metadata.review_pipeline_version`.

**Policy hash.** Every pipeline version has a corresponding policy hash
(§7.4). The policy hash is the authoritative identity of the pipeline's
decision behaviour; the version string is a human-readable alias. When the
policy tree changes, the policy hash changes; when the policy hash changes,
the version MUST change; the reverse is not required. A version bump without
a policy hash change is allowed only for documentation or metadata fixes
that do not affect decision behaviour.

**Model pin.** Every pipeline version MUST pin the exact LLM model identifier,
temperature, top-p, and (where supported) seed used for all reviewer
invocations. Provider-call guardrails that affect assessor reproducibility
(for example, per-call timeout and retry budget) are part of the same pinned
configuration. The model pin is part of the policy tree and contributes to the
policy hash. A model version change or provider-guardrail change MUST trigger
a policy hash change and a pipeline version bump.

## 3. Inputs

For each obligation review, the pipeline receives exactly the following
inputs and no others:

| Input | Source | Purpose |
|---|---|---|
| `obligation_id` | The obligation record under review | Routing; not part of the review content |
| `obligation_record` | The §15.1 obligation record excluding its `reviewer_metadata` | The thing being reviewed |
| `source_refs_content` | Deterministically extracted clause excerpts resolved from `source_refs`, read at `commit_ref` | The normative text the obligation claims to satisfy |
| `implementation_surface_content` | The file contents referenced by `implementation_surface`, read at `commit_ref` | The code or artefact claimed to satisfy the obligation |
| `evidence_class_outputs` | The outputs of running each `evidence_class` against the current commit | Runnable proof that the implementation satisfies the claim |
| `commit_ref` | The git SHA being reviewed | Input identity |
| `manifest_hash` | Hash of `wardline.yaml` at `commit_ref` | Input identity |
| `corpus_hash` | Hash of the corpus at `commit_ref` | Input identity (when corpus evidence is involved) |
| `policy_hash` | Hash of the active policy tree at review time | Pipeline identity |

**Snapshot-bound freshness.** `manifest_hash` and `corpus_hash` are
properties of the materialized reviewed inputs at `commit_ref`, not trusted
ledger literals. A conformant BAR runner MUST materialize the reviewed
snapshot, recompute those hashes from that snapshot, and refuse the review if
the ledger's freshness binding disagrees with the recomputed value or omits a
required `corpus_hash`.

The pipeline MUST NOT receive any other input. In particular:

- It MUST NOT receive conversation history from prior reviews of the same
  obligation
- It MUST NOT receive the author's commit messages or PR descriptions
- It MUST NOT receive the maintainer's prior opinions about the obligation
- It MUST NOT receive prospective or aspirational documentation that is not
  yet merged at `commit_ref`

This constraint exists to preserve the author-isolation property (§6) and the
determinism property (§5).

**Deterministic source extraction.** `source_refs_content` is not an
implementation-defined line scrape. Each `source_refs` entry in the ledger
MUST resolve to a deterministic clause selector at `commit_ref` (for example
`§15.2(5)` in a spec chapter or a concrete `WL-FIT-*` identifier in a
requirements file), and the pipeline input MUST include the corresponding
excerpt for that selector. If a `source_refs` entry cannot be resolved
deterministically, the pipeline input for that obligation is incomplete and
the obligation MUST NOT produce a `pass` verdict.

## 4. Review policy

The review policy is a 7-role reviewer panel. Every BAR-attested obligation
MUST be reviewed by all 7 roles. No subset is permitted.

**Panel composition.** The reviewer roles are:

| Role | Primary concern |
|---|---|
| Solution Architect | Architectural fit, integration with the surrounding system, abstraction boundaries |
| Systems Thinker | Second-order effects, feedback loops, archetype detection, unintended consequences |
| Python Engineer | Python-specific correctness, idiom, type safety, performance |
| Quality Engineer | Test coverage, oracle validity, verification vs validation, evidence quality |
| Security Architect | Threat model coverage, trust boundaries, STRIDE/attack-tree surface |
| Static Analysis Engineer | Rule detection soundness and completeness, AST analysis correctness, SARIF conformance |
| IRAP Assessor | Conformance to §15 obligations, assessor-runnable evidence, audit defensibility |

The IRAP Assessor role is a conservatism check: its job is to read each
review as an external auditor would, and to challenge any claim that would
not survive accreditation scrutiny. A pipeline version that removes the
IRAP Assessor role is a material policy change and MUST be refused until a
panel review of the change itself is completed.

**Prompt contract.** Each reviewer role has an associated prompt template
stored in the policy tree. The shared reviewer discipline layered across all
roles MUST also live in the policy tree as a versioned **skill pack**; it
MUST NOT be injected as an untracked runtime string. Every reviewer prompt
MUST therefore be composed from the shared preamble, the active skill pack,
and the role-specific prompt template. Every prompt template MUST:

- State the role's primary concern explicitly
- Instruct the reviewer to cite specific file paths, line numbers, or
  evidence-class outputs when making findings
- Require the reviewer to output a structured verdict in one of the four
  values defined below
- Require the reviewer to emit an explicit `CITATIONS:` section containing
  only allowed citation tokens from the supplied citation-token list
- Forbid the reviewer from asking clarifying questions back to the caller
  (the pipeline is one-shot per reviewer; clarification loops break
  determinism)
- Forbid the reviewer from suggesting fixes as a substitute for a verdict
  (fixes are post-review work, not review output)

**Verdict vocabulary.** Each reviewer MUST output exactly one of:

| Verdict | Meaning |
|---|---|
| `pass` | Obligation is satisfied; evidence is assessor-runnable; claim holds |
| `fail` | Obligation is not satisfied; evidence contradicts the claim or the implementation is incorrect |
| `insufficient_evidence` | Cannot determine from the provided inputs; the pipeline is missing input, not the reviewer's judgment |
| `refer` | Outside the reviewer's role; the pipeline's input scoping is incorrect |

A reviewer MUST NOT output any other verdict. A reviewer MUST NOT output a
verdict that is a mix or a conditional (e.g., "pass if X is done later").
Conditional verdicts are fails.

**Aggregation rule.** The aggregate pipeline verdict for an obligation is
computed as follows:

1. If any reviewer outputs `refer`, the aggregate is `refer` and the
   pipeline's input scoping for that obligation is broken; the obligation
   MUST NOT be marked `bootstrap_attested` and the pipeline version MUST be
   re-scoped before re-review.
2. If any reviewer outputs `fail`, the aggregate is `fail`. The obligation
   MUST be recorded in the ledger as `non_compliant`, not `bootstrap_attested`.
3. If any reviewer outputs `insufficient_evidence`, the aggregate is
   `insufficient_evidence`. The obligation MUST be recorded as
   `implemented_no_evidence` or `unassessed` as appropriate, not
   `bootstrap_attested`.
4. If and only if all 7 reviewers output `pass`, the aggregate is `pass` and
   the obligation MAY be recorded in the ledger as `state: verified` with
   `reviewer_metadata.independence: bootstrap_attested` — provided the
   determinism property (§5) is also satisfied.

Unanimity is mandatory. Majority-pass is not a valid BAR outcome. The
reasoning is structural: BAR substitutes for a second human reviewer's
independence judgment, and a non-unanimous panel is strictly weaker
evidence than a single human reviewer's considered opinion. The only panel
outcome strong enough to substitute for human independence is unanimous
agreement after empirical determinism verification.

## 5. Determinism property

Large language model outputs are not deterministic at the text level even
under fixed model, temperature 0, and pinned seed. This specification does
not claim text-level determinism. It claims **verdict-level empirical
stability**, verified as follows.

**Self-assessment stability check.** During self-assessment, the pipeline
MUST be run **three independent times per obligation**, with full input
identity held constant (same commit_ref, same manifest_hash, same
corpus_hash, same policy_hash, same model pin). An obligation passes the
stability check if and only if:

1. All three runs produce the same aggregate verdict.
2. When the aggregate is `pass`, all three runs have the same 7-reviewer
   vote (every reviewer role produced `pass` in every run).

An obligation that fails the stability check MUST NOT be marked
`bootstrap_attested`. Its `independence` value MUST be `pending` and its
state MUST reflect the actual evidence situation (`implemented_no_evidence`,
`evidenced`, etc.). A future run after the policy is tightened or the
obligation's evidence is improved may allow the stability check to pass.

**Assessor re-verification.** During external audit (graduation or earlier),
the assessor MUST run the pipeline at least once per BAR-attested obligation
using the captured input identity. The assessor's re-run verdict MUST match
the captured aggregate verdict from the ledger's evidence artefact (§8).
Any discrepancy invalidates the BAR attestation for that obligation and
requires the obligation to be re-reviewed under the default §15.6
independence rules.

**Why this is honest.** The pipeline does not claim "the LLM is
deterministic." It claims "over three independent runs with identical
inputs, the pipeline produced identical verdicts on this specific
obligation, and an assessor can re-run and confirm." That claim is
falsifiable, runnable, and bounded. Obligations where it does not hold are
excluded from BAR, not smuggled through.

## 6. Author isolation

The pipeline MUST satisfy the author-isolation property: its decision
behaviour MUST NOT depend on any artefact produced by the implementation
author within the commit being reviewed, other than the code and evidence
explicitly enumerated in §3.

Concretely:

- The **policy tree** (§7) MUST live in a version-locked location that is
  not modified by the same commit as the code being reviewed. A commit that
  modifies both the policy tree and code implementing an obligation MUST
  NOT be used as the `commit_ref` for a BAR review of that obligation.
- The **prompt templates** MUST be loaded from the policy tree at review
  time, not composed from strings that appear in the reviewed commit.
- The **persona specifications** MUST be loaded from the policy tree at
  review time. Persona specs MUST NOT reference the reviewed commit, the
  sole maintainer's identity, or any project-specific context that could
  encode the implementation author's preferences.
- The **skill-pack assets** MUST be loaded from the policy tree at review
  time. A runtime-only prompt suffix or ad-hoc citation rule invalidates
  the BAR attestation.
- The **model pin** MUST be part of the policy tree. An ad-hoc model or
  temperature override at review time invalidates the BAR attestation.
- The **aggregation rule** (§4 aggregation rule) MUST be enforced by code
  living in the policy tree, not by a script in the implementation
  repository.

A pipeline run is author-isolated if, and only if, reproducing the run
requires only: (a) the policy tree at the captured policy hash, (b) the
reviewed code at the captured commit_ref, (c) the captured manifest and
corpus hashes, and (d) the captured model pin. No other inputs from the
implementation author are permitted.

## 7. Policy tree

The BAR policy tree is a version-locked directory containing everything
that defines the pipeline's decision behaviour for a given version.

**Contents.** A policy tree MUST contain:

1. `persona-specs/` — one file per reviewer role, each containing the role
   name, primary concern, prompt template, verdict grammar, and any
   role-specific instructions.
2. `shared-preamble.md` — the common preamble injected before every
   reviewer's prompt, including the input scoping rules, the verdict
   vocabulary, and the clarification prohibition.
3. `skill-pack.json` — the manifest naming the active reviewer skill-pack
   identity and the ordered set of skill-pack assets injected into every
   reviewer prompt.
4. `skill-pack/` — versioned shared reviewer instructions, such as citation
   discipline, that apply to all roles without being duplicated across the
   persona specs.
5. `aggregation.py` (or equivalent) — the implementation of the §4
   aggregation rule. This file is executable and its behaviour is the
   authoritative aggregation semantics.
6. `model-pin.json` — the exact model identifier, temperature, top-p, seed
   configuration, and provider-call guardrails (such as timeout and retry
   budget) used for every reviewer invocation.
7. `version.json` — the pipeline version string, activation date, and the
   content hash of the rest of the policy tree.

A policy tree MUST NOT contain:

- References to the sole maintainer's identity or working context
- Implementation code from the project being reviewed
- Any input that is also an input under §3

**Canonical location.** The active policy tree for the Wardline reference
implementation lives at `docs/governance/bar-policy/<version>/`. Historical
policy trees MUST be retained at their version-specific paths after
superseding versions activate. An assessor arriving later MUST be able to
retrieve any referenced policy hash by loading its version directory.

**Policy hash computation.** The policy hash is the SHA-256 of a canonical
serialization of the policy tree. The canonical serialization is produced
by:

1. Walking the policy tree recursively in sorted relative-path order,
   with POSIX path separators, UTF-8 encoding.
2. Skipping any file whose relative path is in the normative exclusion
   list below.
3. For each remaining file, emitting its relative path bytes followed by
   a single NUL byte (`0x00`) followed by the file's raw byte content.
4. Concatenating all emissions and hashing the resulting byte stream with
   SHA-256. The policy hash is the hex-encoded digest (64 lowercase
   characters).

**Exclusion list.** The following files MUST be excluded from the hash
input. Exclusions are intentionally narrow: they cover files that cannot
encode policy content because they are either circular (the hash cannot
include itself) or mechanically recreated from source files at runtime
(Python bytecode, OS metadata).

- `version.json` at the policy tree root — this file records the hash and
  cannot be one of its own inputs
- Any file whose relative path contains a component named `__pycache__`
- Any file whose relative path contains a component named `.DS_Store`
  (macOS Finder metadata)
- Any file whose relative path contains a component named `Thumbs.db`
  (Windows Explorer metadata)
- Any file whose relative path ends with `.pyc` or `.pyo` (Python
  bytecode)

The exclusion list is closed. A policy tree MUST NOT contain files of
other types that would need ad-hoc exclusion. If such a file appears, it
is either policy content (and belongs in the hash) or an error (and
should be removed from the tree). Extending the exclusion list is a
material policy change that triggers a pipeline version bump.

The policy hash is recomputed and verified on every pipeline invocation.
A pipeline run whose recomputed policy hash differs from the hash recorded
in `version.json` MUST refuse to produce a verdict.

**Policy tree changes.** Any change to a file in the policy tree is a
material policy change. Material policy changes MUST:

1. Bump the pipeline version (new version directory, new activation date).
2. Re-run the self-assessment stability check (§5) against all obligations
   previously marked `bootstrap_attested` under the prior version.
3. Invalidate the BAR attestation for any obligation that does not survive
   the re-run.

Pipeline version bumps are not free; they are the primary mechanism that
prevents the policy tree from drifting without re-review.

## 8. Evidence artefact

Every BAR pipeline run MUST produce an evidence artefact captured in the
verification directory. The artefact format is structured JSON.

**Location.** Evidence artefacts live at
`docs/verification/bar-pipeline-runs/<YYYY-MM-DD>/<OBLIGATION-ID>/`.
Self-assessment runs write exactly three files:

- `run-1.json`
- `run-2.json`
- `run-3.json`

Assessor re-runs write:

- `audit-rerun.json`

The path shape is normative. A BAR implementation MUST NOT collapse multiple
runs into a single mutable file.

**Required fields.** An evidence artefact MUST contain:

- `obligation_id`
- `pipeline_name` (`wardline-bar-panel`)
- `pipeline_version`
- `policy_hash`
- `commit_ref`
- `manifest_hash`
- `corpus_hash` (null if corpus evidence is not involved)
- `model_pin` (full pin details: model ID, temperature, top-p, seed if
  supported, and any provider guardrails such as timeout/retry settings)
- `skill_pack` (the active skill-pack identity: ID, skill-pack version, and
  ordered asset list)
- `reviewed_at` (ISO 8601 timestamp)
- `stability_run_index` (1, 2, or 3 for stability-check runs; `audit`
  for assessor re-runs)
- `reviewer_verdicts` — an object mapping each of the 7 reviewer roles to
  a sub-object containing:
  - `verdict` (one of the four values)
  - `rationale` (the reviewer's full written rationale)
  - `citations` (ordered array of strings naming the exact allowed citation
    tokens the reviewer referenced; these MAY be file paths, clause
    selectors, or evidence-class tokens, but MUST NOT be free-form prose)
  - `citation_validation` — an object containing:
    - `raw_citations` (ordered array of raw citation tokens supplied in the
      reviewer's `CITATIONS:` section before normalization)
    - `dropped_citations` (ordered array of tokens removed during
      normalization because they were invalid, duplicate, or otherwise not
      persisted)
- `aggregate_verdict`
- `pipeline_duration_seconds`

`citations` MUST preserve reviewer order. A set-like or de-duplicated
serialization is not permitted because it weakens rerunnability and can hide
which evidence the reviewer actually relied on. A BAR runner MAY discard
citations that are not present in the prompt's allowed citation token list,
but it MUST NOT silently invent replacement citations.

In the Wardline reference implementation, citation normalization happens
immediately before artefact persistence. The runner builds an allowed token
list from the deterministic source-ref selectors, implementation-surface
paths, and evidence-class tokens supplied to the reviewer, and only those
exact tokens listed in the reviewer's `CITATIONS:` section are persisted into
the artefact's `citations` arrays. A `pass` or `fail` verdict whose
`CITATIONS:` section yields no valid tokens after normalization MUST be
downgraded to `insufficient_evidence`. The artefact MUST also retain the reviewer's raw
citation tokens and the dropped-token list so a later assessor can see
whether normalization removed substantial evidence references or only noise.

Provider guardrails are fail-closed. In the Wardline reference
implementation, each reviewer invocation is bounded by the timeout and retry
budget declared in the policy tree. If the provider path exhausts that budget
without producing a parseable reviewer response, the reviewer result MUST be
`insufficient_evidence`, not a silent hang and not an implicit pass.

**Retention.** Evidence artefacts MUST be retained for the lifetime of the
BAR declaration plus the retention period required by the assessor's audit
process, whichever is longer. Artefacts MUST NOT be rewritten after
capture; a re-run produces a new artefact, not a mutation of an old one.

**Ledger binding.** The obligation's
`reviewer_metadata.review_policy_hash` and
`freshness_binding.commit_ref`/`manifest_hash`/`corpus_hash` (when corpus
evidence is involved) in the compliance ledger MUST match the evidence
artefact. A mismatch invalidates the BAR attestation.

**Failure-to-input rule.** The BAR pipeline is not permitted to guess around
missing evidence plumbing. If any required evidence class cannot be executed,
or any `source_refs_content` excerpt cannot be resolved deterministically,
the obligation MUST resolve to `insufficient_evidence` or `refer`, never
`pass`.

**Operational entry points.** In the reference implementation, the BAR
pipeline is exposed through three commands:

- `wardline bar status` resolves the active BAR policy tree and reports the
  pipeline name, policy version, policy hash, skill-pack identity, pinned
  provider/model, and timeout/retry guardrails.
- `wardline bar review` executes the mandatory three-run self-assessment and
  writes `run-1.json`, `run-2.json`, and `run-3.json`.
- `wardline bar rerun` loads a prior evidence artefact, verifies the
  ledger-to-artefact binding across captured input identity, executes the
  single assessor re-run path against those captured inputs, compares the
  re-run aggregate verdict to the captured aggregate verdict, and writes
  `audit-rerun.json`.

The status surface `wardline regime status --json` MUST expose
`bar_runner_ready`, `bar_policy_version`, and a BAR runtime-identity object
whenever BAR is declared so an assessor can distinguish a manifest that
merely names BAR from a repository that can actually load and execute the
active BAR policy tree. That runtime-identity object MUST include the active
policy hash, skill-pack identity, pinned provider/model, and timeout/retry
guardrails.

## 9. Lifecycle and versioning

**Activation.** A new pipeline version becomes active when its policy tree
is committed at its canonical location and `version.json` declares the
activation date. Obligations reviewed under the new version use the new
policy hash in their evidence artefacts.

**Supersession.** A newer version supersedes an older one. After
supersession, new BAR attestations MUST use the newer version. Existing
BAR attestations under the older version remain valid until the next
material event (see below).

**Re-review triggers.** An existing BAR attestation becomes `stale` and
MUST be re-reviewed when any of the following happens:

1. The `commit_ref` changes (code under the implementation surface was
   modified)
2. The `manifest_hash` changes (governance configuration changed)
3. The `corpus_hash` changes, for obligations where corpus evidence is
   bound
4. The active policy version changes and the obligation has not been
   re-verified under the new version
5. The model pin changes (new model version, different temperature)
6. The graduation target date passes (staleness per §15.3.4)

**Policy deprecation.** A policy version MAY be deprecated (marked no
longer usable for new reviews) but MUST NOT be deleted. Historical
evidence artefacts reference the hash of the policy version under which
they were produced; assessors MUST be able to retrieve that policy to
verify the captured run.

## 10. Graduation semantics

At graduation, the external auditor (the graduation mechanism declared
in `bootstrap_reference_declaration` is `external_audit`) MUST perform
the following steps for every BAR-attested obligation:

1. Load the obligation's evidence artefact from its canonical path.
2. Verify the policy hash referenced by the artefact matches the policy
   tree at the referenced version.
3. Re-run the pipeline using the captured inputs (§8 `reviewer_verdicts`
   is NOT a re-run input; the re-run uses the same raw inputs the
   original run received).
4. Compare the re-run aggregate verdict to the captured aggregate verdict.
5. Independently assess the obligation under the default §15.6 independence
   rules (human judgment, not pipeline verdict).

**Graduation outcomes per obligation:**

- **Re-run matches AND independent human assessment agrees:** BAR
  attestation is validated. The obligation transitions from
  `bootstrap_attested` to `verified` with `independence: independent` under
  the auditor's identity.
- **Re-run matches BUT independent human assessment disagrees:** The
  obligation's BAR attestation is invalidated. The auditor's human
  assessment is authoritative. The obligation MUST be re-evaluated and
  either remediated or marked `non_compliant`.
- **Re-run does not match captured aggregate:** The pipeline's determinism
  claim is falsified for this obligation. The obligation's BAR
  attestation is invalidated. The auditor's human assessment is
  authoritative.

**Graduation does not retroactively approve BAR.** Graduation is a
handover to default-independence review, not a rubber stamp on the
automated substitution. The pipeline's role ends at graduation; the
auditor's role begins.

## 11. Non-goals

This specification deliberately does NOT define:

- A general-purpose LLM code review tool. The BAR pipeline is narrowly
  scoped to §15.3.4 bootstrap substitution for reference implementations.
- A substitute for ongoing human review after graduation. Post-graduation
  review follows default §15.6 rules.
- A model-selection rubric or an LLM benchmarking framework. The pipeline
  pins a specific model; choosing that model is a separate decision.
- A review workflow for non-reference deployments. Production deployments
  and non-reference projects MUST NOT use this pipeline for independence
  substitution.

A future specification may address any of these; this one does not.

## 12. Forward work (non-binding)

The following are known limitations or extension points that are **not**
part of the current normative content but are recorded here so future
iterations can address them deliberately:

- **Sub-milestones within a BAR window.** The current slip mechanism in
  §15.3.4 treats all graduation-date changes uniformly. A richer model
  would distinguish slip causes — e.g., "auditor scheduling conflict"
  versus "implementation author did not manage the project to the
  committed timeline." Sub-milestones within a single BAR window would
  let an auditor attribute slip causes at a finer granularity and would
  let the schema enforce stricter treatment of some slip causes than
  others. This is a known limitation; the current flat slip counter is
  sufficient for the reference implementation's first BAR declaration
  but is not expected to be sufficient for any future BAR declaration
  involving a longer window or a multi-phase graduation.
- **Partial-panel re-reviews.** The current specification requires all 7
  reviewer roles for every run. A richer model might allow a single
  reviewer role to be re-run when a targeted change is made to a single
  aspect of the obligation (e.g., a Security Architect re-review after a
  threat-model change). This would reduce re-review cost but adds
  complexity around partial-hash tracking. Not in scope for the reference
  implementation's first BAR window.
- **Cross-obligation batching.** The current specification treats each
  obligation as an independent pipeline run. A future version could
  define a batch mode where multiple related obligations are reviewed in
  a single pipeline invocation with shared context. This would reduce
  cost but requires careful input-isolation guarantees between
  obligations.
- **Non-Python bindings.** When Part II-B (Java) begins its own reference
  implementation bootstrap, that project will declare its own BAR window
  and presumably its own pipeline specification. The framework-level
  reasoning here (property-vs-mechanism reframing, unanimity rule,
  determinism verification, author isolation) is expected to generalize.
  Whether this specification or a sibling document binds the Java
  reference implementation is a future decision.

Forward work items MUST NOT be treated as authorization to bypass the
current normative content. Until a future specification addresses them,
the current text governs.

## 13. Related

- `docs/spec/wardline-01-15-conformance.md` §15.3.4 — the specification
  clause this pipeline satisfies
- `docs/adr/ADR-005-bootstrap-assurance-reference.md` — the decision
  record authorizing BAR and referencing this pipeline
- `src/wardline/manifest/schemas/compliance-ledger.schema.json` — the
  schema that enforces the ledger-representation half of the BAR
  contract
- `docs/spec/wardline-01-15-conformance.md` §15.6 — the default
  reviewer-independence rules for which this pipeline is a constrained
  substitution
