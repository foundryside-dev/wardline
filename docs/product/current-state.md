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

- **PRD-0001 (Codex P1 close-out) formally ACCEPTED** (PDR-0004) — all 5 criteria met,
  evidence re-run at HEAD (c797 DoS bound O(N²)-pinned, d96b credential gate fail-closed,
  G1 held via the no-candidate-dropped soundness-lock family + suite 4472 + dogfood
  0-active). The Codex hardening bet is banked as paid off; its long-pending ACCEPT is
  closed. (Criterion-3 honesty note in PDR-0004: verified via soundness-lock tests, not a
  literal pre/post byte-diff.)
- **doctor.repo_binding seam producer leg** (commit `c661286f`, PDR-0003) — the
  producer half of lacuna's MCP-attachment harness: MCP `doctor` now emits a read-only
  `repo_binding` store-read check so a stale-but-running wardline reports "I can't read
  my store." Fork-1 split: unreadable→error, absent→ok (not-noisy anti-goal). Full
  suite 4472 passed; self-gate clean; round-trip-proven against the installed binary.
  Global `wardline` reinstalled **editable** (user-confirmed) so the change is live.

## Open questions / blocked-on-owner

1. **Lacuna-owner handoff (open follow-up, not blocked-on-owner).** Relay the confirmed
   doctor contract to the Lacuna owner so their (provisional) probe row is wired to
   match: probe reads `structuredContent.repo_binding.binding_ok` +
   `repo_binding.store.schema_version`; predicate `binding_ok==true AND schema_version
   not null`; assert on `repo_binding.*`, **not** doctor `ok`. (warpline ships its
   sibling tool independently; field shapes converge.)
2. **Seam bet "done" definition — settle before/at planning.** All *wardline-side*
   seams `at_bar`, vs. cross-repo *peers* confirmed via live round-trip probe? Tracked
   open on `c66f62894b`.
3. **North-star instrumentation still unmeasured.** Agent-fix success rate has no
   baseline corpus; this bet is judged on guardrails (G2-seam + G1/G3/G4) by design.
4. **Nothing blocked on owner / escalated.** The editable reinstall was owner-confirmed
   in-session; no push/publish/deprecation/pricing/data-deletion this session.

## What this session persisted

- **PDR-0004** — ACCEPT of PRD-0001 (Codex bet paid off; all 5 criteria met, evidence
  re-run at HEAD); PRD-0001 header → ACCEPTED; dated G2 reading added.
- **PDR-0003** — doctor.repo_binding seam + the Fork-1 absent→ok split; dated G2-seam
  reading (new honesty surface landed + round-trip-proven; 6-set BASELINE/TARGET
  unchanged). Tracker `c66f62894b` commented. Roadmap untouched (no horizon change).

## Where the next session starts

1. Confirm the grant still holds (re-confirmed 2026-06-27; next due ~2026-09-25).
2. Continue the seam frontier (the Now bet): dispatch `c0563eee74` / `79ba05f464`
   (PRD-0002 crit 3) → `/axiom-planning`; relay the doctor contract to the Lacuna owner
   (open question 1).

## Provenance

Decisions: `0001` (bootstrap), `0002` (Now rotation), `0003` (doctor seam / Fork-1
split), `0004` (ACCEPT PRD-0001). Tactical truth is the tracker; intent lives here and
in `roadmap.md`.
