# Loom — Stable Entity Identity (SEI) conformance standard (design)

> **Promoted — this is now a pointer.** This suite-wide SEI conformance
> standard has been **promoted into the Loom federation hub** and is
> **authoritative at `~/loom/sei-standard.md` (as of 2026-06-05)**. That is the
> single canonical home for the standard; the member repos point there. This
> file always said its normative sections should be propagated out of the
> Wardline tree — that has now happened. It is retained here only as a pointer
> so old links resolve; do not edit it as the standard. For the federation
> axiom the standard serves, see `~/loom/doctrine.md` (§5, enrich-only).

---

## Wardline-specific consumer notes

These are Wardline's local notes as an SEI **consumer**; the normative
standard itself lives at `~/loom/sei-standard.md`.

- **Wardline is an SEI consumer, not the authority.** Clarion mints, persists,
  and resolves SEI; Wardline carries the SEI as the handle for `explain`/dossier
  reads and resolves `locator → SEI` via Clarion. This is **zero engine change**.
- **Graceful degrade.** When Clarion does not advertise the `sei` capability,
  Wardline degrades honestly ("identity unavailable") rather than guessing —
  consistent with the enrich-only axiom (`~/loom/doctrine.md` §5): a missing
  sibling capability reduces enrichment, never breaks the scan.
- **SEI must not leak into Wardline fact fingerprints.** The SEI is a *binding
  key*, not a *fingerprint input*. Wardline's warm/cold byte-identical-findings
  guarantee must survive whatever token scheme Clarion picks, so the SEI is kept
  out of `compute_finding_fingerprint`.
- **Content-axis hash-granularity** harmonisation (entity-body vs whole-file
  hash) is adjacent Wardline work, flagged so it is not silently inherited from
  the standard's content-axis wording.
