# PDR-0015: Declaration-surface-v2 is Wardline 2; its residency is release/2.0.0

Date: 2026-08-09
Status: accepted
Author: Claude product-owner checkpoint
Owner sign-off: directed by the owner in-session ("create a new release branch
for 2.0.0 — this spec will be wardline 2"). Inward-facing branch/versioning
structure within the grant; any public 2.0.0 release remains owner-gated.
Related: PDR-0012 (the S0 bet), PDR-0013 (spec rev 3 / plan rev 3.1),
PDR-0014 (the enabling merge), `release/2.0.0` created from `main` at
`23ce09c4`, plan rev 3.1 `894b6d39` (residency retarget).

## Context

The declaration-surface-v2 program (S0 hardening through S4 dependency-taint)
is Wardline's next major capability arc: new declaration groups, restoration
states, and the staged generic-3/attest-3 consumer contracts. With 1.5.0
merged to trunk (PDR-0014), the program needed a named residency so its
staged, multi-repo work does not interleave with 1.5.x maintenance.

## Options considered

1. **Continue the program on release/1.5.0.** Rejected: conflates a shipped
   minor line with a major program whose emission changes are explicitly
   fenced; loomweave's consumer floor also tracks its own release/1.5.0,
   inviting branch-name confusion across repos.
2. **Execute on main directly.** Rejected: the program spans months of staged
   work with hard NO-GO emission gates; trunk should receive it in reviewed
   merges, not live as its worksite.
3. **Cut `release/2.0.0` from the merged main and declare it the wardline-2
   program residency.** Chosen — by the owner.

## The call

`release/2.0.0` was created from `main` (`23ce09c4`), pushed with upstream
tracking, and made the primary checkout. The S0 plan (rev 3.1) now names
wardline's fixed target branch as `release/2.0.0` in every wardline-side
preflight, commit, fence, and receipt line; loomweave deliberately remains
`release/1.5.0`, warpline and legis remain `main`. S0–S4 execute on this
branch; version-string bumps stay governed by the plan's global constraints
(none in S0).

## Rationale

The branch name states the product claim — this program IS the 2.0 release —
while the rollout fence keeps "resides on the 2.0 branch" strictly separated
from "2.0 is published": `published_emission_ready=false` survives S0
regardless of residency.

## Reversal trigger

If the P0 re-review returns NO-GO on spec rev 3, `release/2.0.0` carries no
engine changes until a passing revision exists (S0 execution stops per
PDR-0013). If the owner later descopes or renames the 2.0 program, the branch
is retired by a superseding PDR — never silently deleted.
