# Plan Review: GO for Local S0

**Plan:** `docs/superpowers/plans/2026-08-09-s0-hardening-and-consumer-prep.md`
**Revision:** 3
**Reviewed:** 2026-08-09
**Reviewers:** Core/API reality, quality engineering, consumer systems, technical editor
**Verdict:** **GO for local S0 implementation after the clean-target preflight.**
**Published emission:** **NO-GO** for generic-3 or attest-3 until the published-release gate passes.

## Executive disposition

The original plan has been rescued in place so its ticket link remains canonical. The second-pass reviewers found no remaining document or design blocker after the rev 3 corrections. The plan now contains 21 ordered tasks with explicit ownership, test paths, commit boundaries, cross-repository receipts, and distinct local-versus-published readiness gates.

Execution is currently and correctly stopped by the clean-target preflight because the Legis target contains an unrelated untracked plan. That is an operator-owned workspace condition, not a defect in this document. Do not stash, delete, or absorb it.

## Load-bearing decisions

- Builtin marker grammar is registry-owned: call form, keyword set, and `ArgKind` are one source of truth.
- Literal `**{...}` extraction is shared by seeding and PY-WL-114; dynamic `**mapping` is reported as statically unverifiable, not falsely described as guaranteed `TypeError`.
- Builtin validation does not broaden into custom-pack validation. Level-bearing custom markers retain fail-closed unknown-key behavior; zero-level custom markers may retain foreign metadata.
- PY-WL-130 and the provider share one shape verdict. Resolver semantics move `sp1g` to `sp1h`; Wardline descriptor and attestation emission versions remain frozen in S0.
- P11a is closed by the unknown-marker FACT. P11b remains an explicit Phase 3 release gate for unknown `TOKEN_SET`/evidence tokens; a LEVEL typo is not accepted as proxy evidence.
- The corpus harness reconciles preview findings, validates the manifest totality, and gates every manifest kind. The waiver ceiling is the user-approved reviewed constant of five; current usage remains zero.
- Loomweave accepts exact `(schema, version)` pairs. Warpline accepts v2/v3 as an untrusted relay and never claims runtime HMAC verification. Wardline's key-holding verifier owns cryptographic verification.
- Task 21 is the first point at which the attest seam becomes `at_bar`; it requires the real Warpline commit and armed cross-repository byte receipt.
- Local archive installs permit coordinated S1 work. They do not authorize published emission. Published consumer releases, exact installed-package probes, tagged-source receipts, and release-owner authorization remain mandatory.

## Former blockers closed

| Area | Rev 3 disposition |
|---|---|
| Legacy `to_level=` exception | Removed; fixtures migrated; PY-WL-130 and provider agree |
| Missing/extra/bare/called grammar | Registry call forms plus required-key derivation cover the full false-green family |
| Literal/dynamic splats | Shared extractor, deterministic offence order, truthful diagnostics |
| Custom packs | Builtin-only validator; explicit level-bearing and zero-level compatibility tests |
| Warm summaries | Resolver epoch bump plus cold/warm equivalence tests |
| Dead preview sentinel | Preview skip removed; strict reconciliation and per-kind floors |
| Fingerprint collisions | Typed canonical JSON, full SHA-256, nested-code and delimiter adversaries |
| P11 overclaim | Split into S0 P11a and deferred Phase 3 P11b |
| Warpline authority overclaim | Runtime relay and key-holding verifier profiles separated throughout live docs |
| Premature seam truth-up | Moved to Task 21 after the real two-sided receipt |
| Local vs release readiness | Separate cumulative gates; S0 closes with `published_emission_ready=false` |

## Verification performed on the document

- Markdown structure: 21 tasks in strict numeric order; balanced fenced code blocks.
- `git diff --check`: clean.
- Live-source spot checks: resolver/version constants, summary/cache APIs, registry/boundary models, corpus harness, MCP/CLI coverage tests, and all named sibling-repository files.
- Loomweave project map: fresh at the reviewed Wardline head.
- Three specialist second passes plus a separate technical-editor pass: all GO.

No implementation tests were run because this custody change edits planning/review documents only. Each implementation task contains its own red/green and full-gate commands.

## Final handoff

Proceed with Task 1 only after committing this document and passing its initial clean/branch/Filigree preflight. Do not close the S0 ticket until Task 21's integrated Wardline commit and the four-repository local archive-install receipt exist. Do not publish generic-3 or attest-3 emission from S0.
