# PDR-0016: Tag and publish wardline v1.5.0

Date: 2026-08-09
Status: accepted
Author: Claude product-owner checkpoint
Owner sign-off: explicit, in-session — "lets tag and publish it, its been
running in ~/elspeth for long enough." This is the owner answer to the
publication escalation recorded in PDR-0014.
Related: PDR-0014 (the merge), tag `v1.5.0` at `23ce09c4`, Release workflow
run `31296246189`, PyPI `wardline 1.5.0`.

## Context

PDR-0014 merged release/1.5.0 to main with publication deliberately withheld
as an outward-facing owner decision. The owner authorized publication, citing
the sustained dogfood deployment: the 1.5.0 line has been running as the live
gate in the elspeth checkout (the primary external-shaped consumer) long
enough to trust it.

## Options considered

1. **Publish now** (chosen — owner call): the release content was
   suite-gated at merge (5815 green), a clean-archive build of `23ce09c4`
   produced `wardline-1.5.0` distributions locally before tagging, and the
   automated release path (tag-guard + trusted publisher) removes manual
   credential handling.
2. **Hold for 2.0.0.** Rejected by the owner: it would strand consumers on
   1.3.0 (the last published tag) for the duration of a multi-stage program.

## The call

Annotated tag `v1.5.0` created at `23ce09c4` and pushed. The Release workflow
(`31296246189`) built the distributions, verified the tag/version guard and
artifact hashes, and published to PyPI via the trusted-publisher environment
with digital attestations. Verified live: PyPI serves `wardline 1.5.0`
(wheel + sdist). No GitHub release object was created — matching the
repository's convention for v1.2.0/v1.3.0 (tags + PyPI only).

## Rationale

The dogfood evidence is the acceptance evidence: the same content has been
gating real work in elspeth. Publishing from the guarded, attested workflow
keeps the supply chain boring. The 2.0.0 program (PDR-0015) is unaffected —
`published_emission_ready=false` still governs generic-3/attest-3.

## Reversal trigger

A published version is not reversed. If a critical defect surfaces in 1.5.0,
the response is a forward-fix 1.5.1 from trunk; yanking the PyPI release is
reserved for install-breaking or security-critical distributions only, and is
itself an owner decision.
