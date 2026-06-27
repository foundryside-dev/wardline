# Current State — Wardline

> The resume brief: the fastest path back to the running picture. Read this
> first next session. Refreshed 2026-06-28 at `/product-checkpoint`.

## The bet right now

**Close out the Wardline residency of the weft-seam-conformance program** (see
`roadmap.md` → Now; decisions `0002` rotation, `0003` doctor seam leg). Give every
Wardline-owned seam back its ability to say *"I don't know"*: every empty/stale seam
result carries a machine-readable `reason`, and every consumer read is
round-trip-verified — never by trusting a self-reported status field.

- *Metric it moves:* **G2-seam — cross-repo seam honesty** (`metrics.md`):
  `BASELINE (2026-06-15): 3 of 6 surfaces lie or can't self-report → TARGET: 0 of 6
  by 2026-07-31`.
- *Spec:* `PRD-0002-weft-seam-conformance.md` (`ready-for-planning`) +
  `~/weft/pm/2026-06-15-seam-health-map.md`.

## In flight (by tracker ID)

- **`wardline-c66f62894b`** (P1, task, open) — weft-seam-conformance program tracker.
  - **`c0563eee74`** (P2, ready) — warpline↔wardline change-impact contract. *PRD-0002 crit 3a.*
  - **`79ba05f464`** (P2, ready) — G6: SEI-oracle drift check required & fail-closed in CI. *crit 3b.*
  - **`23c8e4bef4`** (P4) / **`da883a2d07`** (P4) — secondary, non-gating.
- **`wardline-bf004e2aea`** (P1, task, open) — holistic-risk-review parent; children
  `80e457bc41` (P2) / `18499aaa2d` (P3) are code-landed, awaiting a separate ACCEPT pass.

## Landed this session

- **doctor.repo_binding seam producer leg** (commit `c661286f`, PDR-0003) — the
  producer half of lacuna's MCP-attachment harness: MCP `doctor` now emits a read-only
  `repo_binding` store-read check so a stale-but-running wardline reports "I can't read
  my store." Fork-1 split: unreadable→error, absent→ok (not-noisy anti-goal). Full
  suite 4472 passed; self-gate clean; round-trip-proven against the installed binary.
  Global `wardline` reinstalled **editable** (user-confirmed) so the change is live.

## Open questions / blocked-on-owner

1. **PRD-0001 ACCEPT is still pending — next session's first DECIDE act.** The Codex
   hardening bet paid off (both P1s closed, batch 0, G2 at target) but was never
   formally ACCEPTed. At ACCEPT, verify criterion 3's stronger form: a *byte-identical*
   active-finding set (full suite + dogfood self-scan), not the close notes' weaker
   "behavior-identical / no FN" claim. Then record an ACCEPT PDR.
2. **Lacuna-owner handoff (open follow-up, not blocked-on-owner).** Relay the confirmed
   doctor contract to the Lacuna owner so their (provisional) probe row is wired to
   match: probe reads `structuredContent.repo_binding.binding_ok` +
   `repo_binding.store.schema_version`; predicate `binding_ok==true AND schema_version
   not null`; assert on `repo_binding.*`, **not** doctor `ok`. (warpline ships its
   sibling tool independently; field shapes converge.)
3. **Seam bet "done" definition — settle before/at planning.** All *wardline-side*
   seams `at_bar`, vs. cross-repo *peers* confirmed via live round-trip probe? Tracked
   open on `c66f62894b`.
4. **North-star instrumentation still unmeasured.** Agent-fix success rate has no
   baseline corpus; this bet is judged on guardrails (G2-seam + G1/G3/G4) by design.
5. **Nothing blocked on owner / escalated.** The editable reinstall was owner-confirmed
   in-session; no push/publish/deprecation/pricing/data-deletion this session.

## What this checkpoint did

- Recorded **PDR-0003** (doctor.repo_binding seam + the Fork-1 absent→ok split,
  `accepted`); added a dated **G2-seam reading** noting the new honesty surface landed +
  round-trip-proven (6-set BASELINE/TARGET unchanged).
- Reconciled: one code commit this session (`c661286f`); commented the landing on the
  seam program tracker `c66f62894b`. Roadmap untouched (no horizon change).

## Where the next session starts

1. Confirm the grant still holds (re-confirmed 2026-06-27; next due ~2026-09-25).
2. **ACCEPT PRD-0001** with the byte-identical finding-set check (open question 1).
3. Continue the seam frontier: dispatch `c0563eee74` / `79ba05f464` (PRD-0002 crit 3) →
   `/axiom-planning`; relay the doctor contract to the Lacuna owner (open question 2).

## Provenance

Decisions: `0001` (bootstrap), `0002` (Now rotation), `0003` (doctor seam / Fork-1
split). Tactical truth is the tracker; intent lives here and in `roadmap.md`.
