# Validation Report — Architect-Facing Synthesis (04 + 06)

**Validator:** analysis-validator (independent gate, fresh eyes)
**Date:** 2026-06-28
**Scope:** `04-final-report.md` and `06-architect-handover.md`, checked against their debt source
(`05-quality-assessment.md`) and evidence base (`02-subsystem-catalog.md`), with Filigree IDs
spot-checked against the live tracker via `mcp__filigree__issue_get`.
**Target under analysis:** `wardline` @ `e4668abc`.

---

## VERDICT: BLOCK (tightly scoped — fix two lines in 04/06, then re-validate)

The synthesis is structurally sound, internally consistent, and its load-bearing conclusions
(B+ grade, the six strengths, H1–H3 / M1–M5 / L1–L10, the layering-drift headline, the
god-function inventory) all trace cleanly to catalog entries and, where I re-checked, to live
source and the live tracker. **Ten of the eleven cited Filigree IDs plus the parent tracker are
accurate.** Everything below the two MUST-FIX items passed.

**Why BLOCK and not PASS-WITH-NOTES.** `06-architect-handover.md` carries a written verification
attestation — *"All Filigree IDs cited here were checked against the live tracker on 2026-06-28…
the P2/P3 items confirmed OPEN"* — that is **false**: `wardline-82f49ec3c3` is closed/done, and the
Tier-3 row routes a live residual to that closed ticket. Catching a false *"we verified this"*
claim before it propagates is the core mandate of this gate; a validation that found two
**must-fix-before-use** defects is, by definition and by this task's own framing ("must-fix items
if BLOCK"), not a PASS. A sidecar note does not repair the primary artifact — `04`/`06` themselves
must be corrected. The block is deliberately narrow: fix MUST-FIX-1 and MUST-FIX-2 in 04/06,
re-validate (a ~5-minute confirmation, not a re-review), and everything else is clear.

**Retry budget:** this is fix-attempt 0. Per protocol, if the same misstatement survives two
correction passes, escalate to the user rather than re-validating a third time.

---

## MUST-FIX (correctness-of-record; do before the handover is used)

### MUST-FIX-1 — `wardline-82f49ec3c3` is CLOSED/DONE, cited as OPEN in both 05 and 06
- **Live tracker (verified 2026-06-28):** `wardline-82f49ec3c3` — title *"Resolve return
  indirection in compute_return_callee (explain-surface completeness)"* — `status: done`,
  `closed_at: 2026-06-01`, type `feature`, P3. Closed as "T1.3 done… single-hop return-indirection;
  explain names the contributing callee… deeper/aliased chains stay None."
- **What the docs say:**
  - `05-quality-assessment.md` L4 (line 124): "`wardline-82f49ec3c3` (OPEN; roadmap "near-term") — by
    design, completeness gap."
  - `06-architect-handover.md` Tier 3 (line 65): "`wardline-82f49ec3c3` (OPEN, roadmap near-term)."
- **Why this is material (three ways):**
  1. **Factual misstatement of tracker state** — a closed issue is presented as open, the exact
     class of error this whole analysis is built to expose ("the code is ahead of its own tracker").
     The synthesis here commits the sin it indicts.
  2. **The catalog was more careful and the synthesis over-reached it.** Catalog S5 (line 346)
     says only: *"Watch-item `wardline-82f49ec3c3` tracks this territory; **no Filigree issue is
     currently attached** to these entities (`entity_issue_list` → `no_matches`), so these refs come
     from source comments, not live tickets."* The catalog never claimed OPEN. The synthesis
     hardened a cautious "tracks this territory" into a false "OPEN, roadmap near-term."
  3. **The routing is wrong.** The closed issue covered only the *single-hop* `compute_return_callee`
     case (and that landed). The Tier-3 action it is mapped to — "N-hop explain completeness without
     the optional store; avoid full re-scan for single-finding explain/attach" (source L4) — is the
     genuine *residual*, which the closed ticket does **not** track. That residual is effectively
     **untracked → it should be a NEW issue**, not routed to a done ticket.
- **Fix:** (a) mark `wardline-82f49ec3c3` as DONE/closed in 05 L4 and 06 Tier 3; (b) re-route the
  L4 N-hop / no-re-scan residual to a NEW issue (or confirm an existing open ticket actually owns
  it); (c) correct the handover's Validation footer (next item).

### MUST-FIX-2 — The handover's Validation footer makes a verification claim that is false for one ID
- `06-architect-handover.md` lines 101–102: *"All Filigree IDs cited here were checked against the
  live tracker on 2026-06-28 (`wardline-9ec283d168` confirmed CLOSED; the P2/P3 items confirmed OPEN
  in the ready queue)."*
- `wardline-82f49ec3c3` is a cited ID and is **not** open — so "all… checked… confirmed OPEN" is
  untrue as written. Either the check missed this ID or it was not performed exhaustively.
- **Fix:** correct the footer to reflect the actual state once MUST-FIX-1 lands (e.g., "10 cited
  IDs verified; `82f49ec3c3` found CLOSED and re-routed"). Do not ship an unqualified "all verified."

---

## NOTES (non-blocking; address opportunistically)

### NOTE-1 — "close or rescope" is mildly stale for `wardline-80e457bc41`
- 06 Tier 0 (line 42) and 05 L6 frame **both** `wardline-18499aaa2d` (WeftHttp) and
  `wardline-80e457bc41` (envelope) as "triage close-or-rescope."
- Live `wardline-80e457bc41` (P2, OPEN, updated 2026-06-20) was **already re-triaged 8 days before
  this analysis**: its per-tool-schema half is recorded done, and it is deliberately kept open with
  a concrete, current acceptance criterion for the *still-duplicated status-envelope projectors*
  (MCP `_filigree_emit_status`, CLI `_filigree_status`, scan-jobs `_filigree_status`). It is
  neither cleanly close-able (real residual remains) nor newly rescope-able (already rescoped).
- The catalog (S9 lines 577–578) is in fact *more precise* than the synthesis here. For
  `18499aaa2d` the "close-or-rescope" framing is apt (WeftHttp exists and is consumed); for
  `80e457bc41` the honest action is "verify the residual projector extraction, then close" — not
  "close or rescope."
- Priorities cited are correct: `18499aaa2d` P3, `80e457bc41` P2 (matches live).

### NOTE-2 — 04 §4's "cross-cutting five" ordering is thematic, not severity-ranked
- 04 §4 lists god-functions **first** (graded M1 / MEDIUM in 05) and the pytest-coupling **fifth**
  (graded H3 / HIGH in 05). 04 says "summarized here by blast radius," so this is grouping, not a
  contradiction — but a reader skimming §4 could infer a priority order that inverts 05's severities.
  The handover §2–§3 re-sorts correctly by leverage÷risk, so downstream routing is unaffected.
  Optional: add a one-line "(not severity-ordered; see 05 for severity)" to 04 §4.

### NOTE-3 — A few absolute phrasings slightly exceed the (test-guarded) evidence
- 04 strength #2: "the dogfood-#2 regression **can't recur**." The `GateDecision.__post_init__`
  invariant makes a *tripped-but-PASSED* verdict unrepresentable (S4 line 283), but the broader
  surface-parity property is still *test-guarded*, not type-guarded, for the population-choice (this
  is literally H2). "Cannot recur" is true for the specific representation, slightly strong for the
  property. Grounded; just absolute.
- 06 §1 / 04 §6: "no live security hole." Defensible as a synthesis of the catalog (M3 lineless-DEFECT,
  legis fail-open, the safe_paths TOCTOU are each called "correct today / narrow / legis's to close"),
  and the handover responsibly still recommends a STRIDE pass (§6). This is a *technical-accuracy*
  judgment outside my structural remit — flagged, not adjudicated (see Caveats).

---

## What I checked, and what passed

### 1. No unsupported claims (every strength + High/Medium finding traces to evidence)
PASS. Each item maps to a catalog entry with `file:line` evidence:
- **Strengths 1–6 (04 §3):** opt-in→NONE `modulate` (S2: `severity_model.py:47`, `_sink_helpers.py:849`);
  surface parity + `GateDecision.__post_init__` (S4 line 246/283, S10 line 618, `run.py:181`,
  `test_cli_mcp_parity.py`); fail-closed house style (S1/S4); 3-layer path confinement + O_NOFOLLOW +
  HMAC cache (S4 line 285, S11 line 678); determinism fingerprint 3.12/3.13 + golden oracle (S8 line 512);
  honest degradation `coverage_pct=None` / PDR-0023 / `mark_unseen` (S7 line 420, S5 line 339). All grounded.
- **H1** layering drift → S1 line 87, S3 line 228, S7 line 456, cross-cutting #1; **live-verified**
  (`lint-imports` evidence in close-note; `9ec283d168` closed 2026-06-20).
- **H2** split security invariants → S4 line 283/404, S6 line 393/404, S8 line 516, cross-cutting #4.
- **H3** pytest-coupled handshake → S10 line 630, cross-cutting #5.
- **M1** god-functions → S1 line 86, S3 line 230, S4 line 289, S10 line 632, S11 line 684, cross-cutting #2.
- **M2/M3/M4/M5** → S10 line 628/629, S6 line 401, S2 line 168 / S3 line 229 / S6 line 402 / S11 line 683, S11 line 683.
- **L1–L10** → S4 line 292 (L1), S11 line 685 (L2), S6 line 403 (L3), S5 line 345-346 (L4),
  S7 line 457 (L5), S9 line 577-578 (L6), S12 line 740-741 (L7), S12 line 742-744 (L8),
  S3 line 231 (L9), S8 line 517 / S12 (L10). All present.

### 2. Internal consistency (04 ↔ 05 ↔ 06 ↔ 02)
PASS (with NOTE-2). The three synthesis docs and the catalog **agree** on:
- **Headline layering status:** CLOSED (`9ec283d168`, 2026-06-20) + fix landed (no `core.attest`
  import in `scanner/`; `lint-imports` 1 kept / 0 broken) + stale `pyproject.toml:170-182` "BROKEN"
  comment + non-gating CI (`lint-imports || true`) + broad residual (158→102 deferred imports,
  real `run→…→attest→assure→run` cycles latent). Consistent in 04 §4.4, 05 H1, 06 §1, 02 cross-cutting #1.
- **God-function inventory:** `run_scan` ~374, `_analyze_inner` ~857, `variable_level.py` ~2,481,
  `server.py` 5,003, `install/doctor.py` ~947. Identical figures across 04 §4.1 / 05 M1 / 02.
- **The five cross-cutting themes**, the B+ scorecard rollup, 26 rules (15 stable / 11 preview),
  18 MCP tools, ~2:1 test:source. No numeric contradictions found.

### 3. Filigree ID fidelity (spot-checked live; 11 IDs + parent)
ONE ERROR (MUST-FIX-1); all others correct:

| ID | Cited as | Live status / priority | Verdict |
|----|----------|------------------------|---------|
| `wardline-9ec283d168` | CLOSED | closed, P2 | ✅ |
| `wardline-550ea44e53` | OPEN P2 | open, P2 | ✅ |
| `wardline-18499aaa2d` | OPEN (P3 in 05) | open, P3 | ✅ |
| `wardline-80e457bc41` | OPEN (P2 in 05) | open, P2 | ✅ (see NOTE-1) |
| `wardline-82f49ec3c3` | **OPEN, near-term** | **done, closed 2026-06-01** | ❌ **MISSTATED** |
| `wardline-d59f35c626` | OPEN P3 | open, P3 | ✅ |
| `wardline-535c9531cc` | OPEN P3 | open, P3 | ✅ |
| `wardline-9c3a76b257` | OPEN P3 (sub-#4 since-addressed) | open, P3 | ✅ |
| `wardline-a3eacc5d36` | OPEN P3 | open, P3 | ✅ |
| `wardline-88104b44f1` | OPEN P3 | open, P3 | ✅ |
| `wardline-bf004e2aea` (parent) | OPEN P1 | open, P1 | ✅ |

- **NEW-vs-tracked split honesty:** PASS in the forward direction — no genuinely-tracked issue is
  mislabeled "NEW." The split FAILS in the reverse direction once: `82f49ec3c3` is presented as
  "tracked + OPEN" when it is "tracked + CLOSED," which *hides a genuinely-untracked residual*
  (the L4 N-hop / no-re-scan work) behind a done ticket. Fixing MUST-FIX-1 repairs the split.
- The parent `wardline-bf004e2aea` exists, is OPEN/P1, and its own description corroborates the
  synthesis's framing (`80e457bc41`/`18499aaa2d`/`d59f35c626` listed as live residual children;
  `9ec283d168` listed as closed-during-triage). The recommendation to file NEW issues under it
  with label `arch-analysis-2026-06-28` is coherent.

### 4. Actionability (Tier 0–3 routing + "What NOT to do")
FAIL on one row (the blocking defect); otherwise coherent. Tier-0/1/2 routing is sound: each action maps to a real source finding
(H1/H2/H3/L6/L7/L9 → Tier 0; H1-broad/H2/H3/M4-M5 → Tier 1; M1/M2/M3/L2 → Tier 2) and to either an
honestly-NEW issue or a correctly-tracked one. The **Tier-3 row for `82f49ec3c3` is the one
incoherent mapping** (routes a residual to a closed ticket — MUST-FIX-1). The "What NOT to do"
section is consistent with the catalog and well-grounded:
- The **`fingerprint_v0.py` frozen-clone warning** is correct and important — S8 line 518 confirms
  it is an intentional byte-exact frozen clone of the live formula, guarded by a "do not edit"
  docstring + the byte-green identity oracle, and that re-syncing it "would silently mis-reconstruct
  every `old_fp` and orphan verdicts on migration" (`fingerprint_v0.py:1-13`). The handover's
  phrasing matches the evidence exactly.
- "Don't broaden scope" and "don't treat under-approximations as bugs (they fail closed)" both trace
  to 04 §5 and the catalog's documented fail-closed under-approximations (S3 line 233, S12 line 746).

### 5. Adversarial check (the weakest claim / over-reach)
The single strongest over-reach is **MUST-FIX-1**: the synthesis took the catalog's cautious
"watch-item… no live ticket attached" and asserted a hard "OPEN, roadmap near-term" for a ticket
that is in fact closed — then certified in its own footer that all IDs were verified open. Secondary,
softer over-reaches are catalogued in NOTE-1 (stale "close-or-rescope" for `80e457bc41`) and NOTE-3
(absolute "can't recur" / "no live security hole"). A zero-issue validation of this synthesis would
itself have been a defect; this is the place it over-reaches its evidence.

---

## SME Protocol Sections

### Confidence Assessment
**Overall confidence: High** on the structural verdict; **High** on the Filigree-fidelity finding
(direct live `issue_get` reads). I read all four documents in full (02 across paged reads covering
S1–S12 + cross-cutting), and independently re-queried the live tracker for all 11 cited IDs plus the
parent. Evidence-to-claim tracing was done against `file:line` citations in the catalog, which the
catalog in turn grounds in Loomweave graph edges + source reads. Confidence is **lower** only on
points explicitly outside structural validation (technical correctness of the B+ grade, the
"no live security hole" judgment, and raw LOC/file counts), which I did not independently recompute.

### Risk Assessment
- **Risk of shipping as-is (no fix):** Medium-low but real. A downstream planner who trusts the
  Tier-3 routing will open or reference a *closed* ticket for the N-hop/explain residual and may
  conclude that work is already tracked/scheduled when it is not — the residual would silently fall
  through. The false "all IDs verified" footer compounds this by inviting unearned trust in every
  other ID (which happen to be correct, but the reader can't know that).
- **Risk of the overall synthesis being wrong:** Low. The load-bearing conclusions are independently
  corroborated; the defect is isolated to one Tier-3 line and one footer sentence.
- **Risk introduced by my own validation:** Low. The one ID I flag was read directly from the live
  tracker; the verdict call (PASS-WITH-NOTES vs BLOCK) is a judgment I have surfaced explicitly so
  the coordinator can apply a stricter bar if desired.

### Information Gaps
- I did **not** exhaustively prove that every item labeled "NEW" has no pre-existing Filigree issue —
  I verified the 11 cited IDs and relied on the catalog agents' `entity_issue_list` (`no_matches`)
  checks for the NEW set. A residual chance exists that a NEW-labeled item duplicates an untracked-by-me
  open ticket.
- I did not re-run `lint-imports`, recount LOC/files, or re-execute the test suites; the layering
  "1 kept / 0 broken" status is taken from the catalog + the `9ec283d168` close-note (both consistent),
  not a fresh run in this session.
- Technical *accuracy* of the architectural judgments (grade, soundness of H2's "correct but fragile"
  framing, completeness of the security posture) is out of scope for structural validation.

### Caveats
- This is a **structural / contract / cross-document-consistency** validation, not a technical-accuracy
  audit. I validate that claims trace to evidence, that the three docs agree, and that tracker IDs are
  stated correctly — **not** whether the patterns, grades, or security conclusions are *right*.
- For technical adjudication of the items I flagged in NOTE-3 (security posture; "no live hole"),
  escalate to `ordis-security-architect:threat-analyst`; for the architecture grade and the
  refactor-risk framing, `axiom-system-architect:architecture-critic`. The handover already routes
  to both (§6), which is appropriate.
- Re-validation budget: MUST-FIX-1 and MUST-FIX-2 are mechanical corrections; one re-validation pass
  should suffice. Per protocol, escalate to the user if the same misstatement survives two fixes.

---

## Re-validation addendum (2026-06-28, fix-attempt 1)

**Trigger:** coordinator reported the two BLOCK must-fixes applied. I re-read only the changed
spots and independently re-checked each against the live tracker (I verified the artifacts, not the
report-of-fix).

- **MUST-FIX-1 — CLEARED.** `05` L4 (line 124) and `06` Tier 3 (line 65) now state
  `wardline-82f49ec3c3` is **CLOSED (2026-06-01, single-hop return-indirection only)** and route the
  broader N-hop-without-store residual to **untracked → NEW**; both also flag `ROADMAP.md`'s
  "near-term" listing as itself stale (a correct, additional tracker-drift catch). Matches the live
  tracker (`status: done`, `closed_at 2026-06-01`). The closed ticket is no longer presented as the
  owner of live work.
- **MUST-FIX-2 — CLEARED.** `06` Validation footer (lines 101–105) now splits **CLOSED/done**
  (`wardline-9ec283d168`, `wardline-82f49ec3c3`) from the **OPEN** set and no longer asserts "all
  confirmed OPEN." I re-verified every listed priority against live reads: `550ea44e53` P2,
  `80e457bc41` P2, `18499aaa2d` P3, `d59f35c626` P3, `535c9531cc` P3, `9c3a76b257` P3,
  `a3eacc5d36` P3, `88104b44f1` P3 — all correct. The attestation is now true as written.
- **NOTE-1 — ADDRESSED.** `06` Tier 0 (line 42) now records that `wardline-80e457bc41` was partially
  re-triaged 2026-06-20 but remains open.

**Remaining items:** only the two non-blocking observations NOTE-2 (04 §4's "cross-cutting five" is
thematic, not severity-ranked) and NOTE-3 (absolute phrasings "can't recur" / "no live security
hole" — technical-accuracy judgments outside structural scope). Neither blocks; both are optional.

### REVISED VERDICT: PASS-WITH-NOTES
The two blocking defects are resolved and confirmed against the live tracker. The false written
verification claim is gone; tracker fidelity is now 11/11 correct (10 OPEN/CLOSED states + the
parent). The synthesis is cleared for handover. NOTE-2 and NOTE-3 remain as optional polish.

---

## Cross-references
- Evidence base: `02-subsystem-catalog.md` (S1–S12 + cross-cutting; gated by `temp/validation-catalog.md`).
- Debt source: `05-quality-assessment.md` (H1–H3, M1–M5, L1–L10, tracker-fidelity meta-finding).
- Under review: `04-final-report.md`, `06-architect-handover.md`.
- Live tracker reads (2026-06-28): `mcp__filigree__issue_get` on the 11 cited IDs + `wardline-bf004e2aea`.
