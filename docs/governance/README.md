# Wardline governance process specifications

This directory contains **normative governance-process specifications** for the
Wardline reference implementation. Documents in this directory are binding on
the project the same way the numbered specification chapters under `docs/spec/`
are binding, but they describe **processes and mechanisms** rather than the
language semantics the main spec defines.

## What belongs here

A document belongs in `docs/governance/` when **all** of the following are true:

1. It defines a process, pipeline, control, or mechanism that the reference
   implementation is bound to follow.
2. It is normative — it uses MUST, MUST NOT, SHOULD, and SHOULD NOT to state
   requirements, not just describe intent.
3. It is a specification — other documents (the main spec, ADRs, the compliance
   ledger, or tooling) reference it as authoritative.
4. It does not belong in a numbered Part I or Part II chapter of the main
   specification. Governance-process specs support the main spec but are not
   part of its chapter sequence.

## What does NOT belong here

- **Architecture decisions.** Go in `docs/adr/` as numbered ADRs.
- **Main specification content.** Goes in `docs/spec/` in the numbered chapter
  sequence.
- **Requirements.** Go in `docs/requirements/`.
- **Verification records and assessment outputs.** Go in `docs/verification/`.
- **Audit findings and external review reports.** Go in `docs/audits/`.
- **Explanatory material, guides, tutorials.** Not normative; do not belong in
  this directory.
- **Drafts under discussion.** Use `docs/adr/` for proposals until accepted.

## Current documents

| Document | Purpose | Binds |
|---|---|---|
| `bar-review-pipeline.md` | Normative specification for the BAR review pipeline referenced by §15.3.4 Bootstrap Assurance Reference | Reference-implementation BAR declarations |

## Relationship to `docs/spec/`

The main specification defines **what Wardline means** — the trust model, the
annotation vocabulary, the rule set, the conformance criteria. Documents in
`docs/governance/` define **how the reference implementation operates** the
governance mechanisms the main specification requires. A process spec here
cannot override the main spec; if there is a conflict, the main spec governs.

When the main specification references a governance-process document, the
reference is by path (e.g., `docs/governance/bar-review-pipeline.md §4`). Path
changes in this directory are breaking changes to the main specification and
require the same change-control treatment.
