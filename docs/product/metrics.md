# Metrics — Wardline

> The scoreboard the product is judged against. Every target is **falsifiable**:
> a number and a date against a `BASELINE → TARGET by <date>` placeholder. A
> directional word ("improve precision") is not a metric. Seeded on bootstrap
> 2026-06-22 — the human owner sets the real BASELINE/TARGET numbers; the
> placeholders mark *what* to measure and *which way is good*, not confirmed
> goals.

## North star

**Agent-fix success rate** — of the ERROR-severity findings Wardline surfaces in
an agent's edit-verify loop, the share the agent resolves *at the boundary* such
that a rescan confirms the finding cleared, within one fix-verify cycle and
without human help.

This is the thesis ("tools that work first time, every time") made measurable:
an analyzer the agent can actually act on, not just one that flags. It rises
only when findings are both *real* (precision) and *actionable* (explanation
points at the boundary, not the sink).

- `BASELINE → TARGET`: `BASELINE: TBD (instrument on a dogfood corpus) → TARGET:
  ≥ 0.90 by 2026-09-30`
- *Instrumentation gap:* requires a labeled corpus of findings + agent-fix
  outcomes. Not yet measured. **Open question for the human owner.**

## Guardrails (must-not-degrade)

### G1 — False-positive rate (precision)
An analyzer that cries wolf gets turned off. The unsuppressed ERROR/HIGH
population must stay true-positive-dominant.
- `BASELINE → TARGET`: `BASELINE: TBD → keep FP rate ≤ 0.05 of active findings,
  measured 2026-09-30`
- Proxy already in the repo: suppression/waiver growth vs. rule growth (a single
  rule accruing disproportionate waivers signals lattice mis-design).
- **Reading 2026-06-28 (PDR-0007/0008):** Part A's inert banner is calibrated +
  reliance-gated — it stays silent on the annotated corpus (anchored=43) and on
  bare scans, so **no G1 impact**. The pack-bridge (PDR-0008) validating-boundary
  seed has **UNMEASURED** FP quality on the real elspeth tree — its 25 boundaries
  are not yet calibrated. Reversal trigger: pack FP rate **> 0.05 of active
  findings** reopens the seed mapping (PDR-0008). Calibration is the tracked
  follow-on (`wardline-bd9d1e65cb`) before the pack is recommended as a gate of
  record.

### G2 — Soundness / surface integrity (no false green, no policy bypass)
Zero known fail-open taint holes (untrusted→trusted laundering) **and** zero
known agent-surface policy bypasses (MCP network/write-policy escapes, sibling
URL trust, fingerprint-suppression misapply).
- `BASELINE → TARGET`: `BASELINE: open codex-security-2026-06-20 batch (≈44
  open) → TARGET: 0 open in that batch by 2026-07-31; thereafter 0 known
  fail-open/bypass holes, held continuously`
- **Reading 2026-06-27:** `codex-security-2026-06-20` batch = **0 open**;
  `codex-security` overall = **0 open** — TARGET hit ahead of the 07-31 backstop
  (both P1s `c797baf28b` / `d96b94d4e9` closed with red/green regressions). The
  agent-surface axis of G2 is at target.
- Enforced by: the soundness oracle + the security regression suite. A new
  fail-open hole is a P0.
- **Reading 2026-06-28 (PDR-0004):** PRD-0001 (the P1 slice of G2) formally **ACCEPTED**
  — all 5 criteria met, evidence re-run at HEAD: c797 DoS bound pinned O(N²)
  (`test_lambda_candidate_merge_is_not_cubic...`), d96b credential gate fail-closed
  (`test_check_does_not_send_token_to_project_published_port`), G1 precision held via the
  no-candidate-dropped soundness-lock family + full suite 4472 + dogfood 0-active. G2
  agent-surface axis confirmed at target; the bet is banked as paid off.
- **Reading 2026-06-28 (PDR-0006):** closed a **cross-interpreter fingerprint-instability**
  soundness hole. `entity_source_fingerprint` hashed `ast.dump`, which changed in CPython
  3.13 (`show_empty=False` omits empty-list fields), so the cross-tool JOIN KEY
  (baseline/waiver/judged stores + Filigree wire) was interpreter-dependent — a
  silent-drop-on-join hazard. Fixed via a structural version-stable canonical dump (commit
  `b6704c00`); join key now byte-identical 3.12 == 3.13, proven by the CI matrix (both legs
  green) + full suite 3.12 4478 passed. **No scheme bump** (3.13 reference values unchanged).

#### G2-seam — cross-repo seam honesty (no confident-empty)
*Extension added 2026-06-27 for the weft-seam-conformance Now bet (PDR-0002 /
PRD-0002), framed by the hub seam-health-map (`~/weft/pm/2026-06-15-seam-health-
map.md`).* The outcome: **no Wardline-owned seam surface can return an answer
indistinguishable from a legitimate true-negative** — every one emits a
machine-readable `reason` for empty/partial/stale, and every consumer read is
round-trip-verifiable under the agreed identity scheme (never by trusting a
self-reported status field).
- **Closed surface set (6)** Wardline owns: (1) wardline→filigree emit, (2)
  wardline→legis attest, (3) SEI loomweave→wardline consumer read, (4) warpline
  worklist consumer read, (5) wardline delta-scope producer artifact, (6)
  SEI-oracle producer-source CI drift.
- `BASELINE → TARGET`: `BASELINE (2026-06-15 seam-health-map): of 6, 3 lie or
  cannot self-report — (1) hardwired failed:[], (2) attest key-absent fail-open
  with no amber/key_id, (3) SEI-wire-transport "gap" with no round-trip — and 0
  consumer round-trip probes exist → TARGET: 0 of 6 can return a
  true-negative-indistinguishable answer (all 6 emit a machine-readable reason
  and/or are round-trip/drift-verified) by 2026-07-31`
- Reversal trigger: a new Wardline seam surface that returns confident-empty with
  no reason is a P0, same class as a fail-open taint hole.
- **Reading 2026-06-28 (PDR-0003):** a NEW Wardline-owned seam-honesty surface landed
  — MCP `doctor.repo_binding` store-read check (lacuna consumer-read seam; commit
  `c661286f`). It is honest by construction: present-but-unreadable emits a
  machine-readable reason and `binding_ok=false`; the non-tautological signal is the
  baseline `schema_version` read from inside the store. **Round-trip-proven** against
  the freshly-spawned installed `wardline mcp` (binding_ok=true/schema_version=1 for a
  repo with a baseline). Outside the original 6-surface set, but it *satisfies* the
  reversal-trigger invariant for a new surface (it cannot return confident-empty
  without a reason). Net: the seam-honesty posture strengthened; the 6-set
  BASELINE→TARGET is unchanged.
- **Reading 2026-06-28 (PDR-0005):** PRD-0002 **crit-3 complete + CI-verified.** The
  producer-source byte-drift checks for the SEI-oracle (surface 6) and the warpline
  reverify-worklist (surface 4 consumer leg) now run **required & fail-closed** in a new
  weekly/dispatch `source-drift` CI job (byte-compare vs loomweave + warpline origin/main);
  `sei_drift`/`worklist_drift` joined `LIVE_ORACLE_MARKERS`. crit-3a (delta-scope producer
  artifact, surface 5) was already in-CI. Dispatched run 28301178826 green (2 passed). This
  closes the **producer-artifact axis**; the seam-health **probe** (criteria 1/2 — Layer-1
  `doctor --seams` self-check + Layer-2 consumer round-trip) remains the open work toward the
  0-of-6 target. Tickets `79ba05f464` + `c0563eee74` closed.

### G3 — Zero-config activation
`wardline scan .` runs and gates on an unconfigured repository with no required
human configuration — power arrives as activation, never as a form.
- `BASELINE → TARGET`: `BASELINE: holds at 1.0.6 (base package zero runtime
  deps; scanner via one extra) → TARGET: still holds, 0 required-config steps,
  re-checked each release`
- **Reading 2026-06-28 (PDR-0007/0008):** G3 (runs unconfigured) **still holds** —
  but the elspeth dogfood surfaced an important nuance: *"runs and gates" ≠
  "enforces."* wardline is annotation-driven, so on a codebase with no declared
  trust boundaries the gate is **inert** (passes green checking nothing) — the
  thesis "works first time" silently degrading to "checks nothing." This is **not a
  G3 breach** (no required config to *run*), but it is the gap between activation and
  *enforcement*. Part A (PDR-0007) makes the gap **honest** (always-on
  `resolution.inert` + a reliance-gated banner); the pack-bridge (PDR-0008) is the
  zero-*human*-config path to enforcement on a team's existing annotations. **Open
  strategic question (owner):** whether truly-unannotated apps warrant
  framework-boundary auto-inference — a revision of the "silent until opted in"
  anti-goal, escalated, not enacted.

### G4 — Weight discipline (anti-enterprise-creep)
The base package stays zero-runtime-dependency; capability stays behind opt-in
extras; no enterprise-process machinery (governance boards, formal V&V, corpus
gates) enters the tool.
- `BASELINE → TARGET`: `BASELINE: base = 0 runtime deps at 1.0.6 → TARGET: base
  stays 0 runtime deps; new deps only behind a named extra, re-checked each
  release`

## Notes

- All BASELINE values marked TBD need a measurement pass before they are real
  targets — flagged as open questions in `current-state.md`.
- A metric reading that crosses a guardrail is a reversal trigger for the bet
  that touches it; `/product-checkpoint` flags any such crossing.
