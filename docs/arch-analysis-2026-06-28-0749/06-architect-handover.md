# 06 — Architect Handover

**Purpose:** hand this analysis to architecture/improvement planning. **Target:** `wardline` @ `e4668abc`.
**Read first:** `04-final-report.md` (synthesis) and `05-quality-assessment.md` (prioritized debt with
Filigree mapping). This document routes the debt to tracked work and sequences the next moves.

---

## 1. Current-state in one paragraph

A production-stable (1.0.6 shipped), deliberately-scoped Python taint analyzer with a coherent
**surfaces → orchestration → engine** architecture, a hard zero-dependency-base invariant, identical-by-
construction CLI/MCP/LSP surfaces, and serious test investment (~2:1 test:source, conformance + golden +
hypothesis). The debt is **concentrated and well-understood**, not diffuse: a few god-functions, porous
private-name seams, security invariants enforced across cooperating subsystems rather than locally, and —
most actionable — **drift between the code and its own tracker/docs** (the headline "violation" is already
fixed). There is no live security hole and no architectural emergency; the highest-leverage work is
*finishing and recording* partial completions before new construction.

## 2. The refactor safety net (use it)

Every god-function flagged for decomposition is backed by a conformance/oracle suite that pins behavior —
decomposition is therefore *low-risk if the suite stays green*:
- Gate/suppression/delta: `tests/conformance/test_warpline_delta_scope.py`, `tests/unit/core/test_run_affected.py`,
  `test_axis7_gate_population_not_narrowed`, `test_delta_trust_suppressions_cannot_forge_green`.
- Identity/fingerprint: `tests/golden/identity/test_identity_parity.py`,
  `tests/unit/scanner/rules/test_entity_fingerprint_stability.py`, `tests/conformance/qualnames*.json`.
- Surface parity: `tests/unit/core/test_cli_mcp_parity.py`, `tests/unit/mcp/test_server_doctor.py`.
- Federation wire: golden vectors + the armed `sei_drift`/`worklist_drift` CI + `*_e2e` live oracles.
Run `make ci` (`lint typecheck test-cov`, 90% gate) as the gate for any change.

## 3. Prioritized improvement roadmap (mapped to tracker)

Ordered by **leverage ÷ risk**. "NEW" = no current Filigree issue; recommend filing under the holistic
risk-review parent `wardline-bf004e2aea` with label `arch-analysis-2026-06-28`.

### Tier 0 — Tracker/doc reconciliation (highest leverage, near-zero risk) — do first
| Action | Source | Filigree |
|---|---|---|
| Fix the stale "BROKEN today" import-linter comment in `pyproject.toml:170-182` | H1 | NEW (or reopen-note on closed `wardline-9ec283d168`) |
| Flip CI `lint-imports \|\| true` → gating now that the contract passes | H1 | NEW (tiny) |
| Re-triage `wardline-18499aaa2d` (WeftHttp) + `wardline-80e457bc41` (envelope): close or rescope to the residual adapter shells (`80e457bc41` was partially re-triaged 2026-06-20 but remains open) | L6 | **`wardline-18499aaa2d`**, **`wardline-80e457bc41`** (both OPEN) |
| Trim `wardline-9c3a76b257` sub-item #4 (since-addressed: `analyzer.py:175-181`) | L7 | **`wardline-9c3a76b257`** (OPEN) |
| Fix stale "SP1 ships only…" docstrings in the taint provider | L9 | NEW (trivial) |

### Tier 1 — Structural integrity (real debt, bounded)
| Action | Source | Filigree |
|---|---|---|
| Track + drive down the **broad `core/` layering** residual (102 deferred imports; real `run→…→attest→assure→run` cycles) — the part the closed ticket explicitly left to "future layering work" | H1 | **NEW** (parent `wardline-bf004e2aea`) |
| Harden the 3 **split security invariants** (gate-population, THREAT-001 confinement, fingerprint determinism) toward type-/assertion-enforced + documented seam contracts | H2 | **NEW** |
| Remove the **pytest-coupled handshake bypass** (`protocol.py:43`) — inject test state instead of sniffing `sys.modules` | H3 | **NEW** (surgical) |
| Promote cross-subsystem `_private` dependencies to public seams (rules→`decorator_provider`, `grammar`→`variable_level`, S6→`sei_resolver._client`, `cli/doctor`→`install.doctor` privates) | M4, M5 | **NEW** (umbrella) |

### Tier 2 — Maintainability & surface hardening
| Action | Source | Filigree |
|---|---|---|
| Decompose the load-bearing god-functions (`run_scan`, `_analyze_inner`, `variable_level.py`) behind the conformance net | M1 | **NEW** (per-function) |
| Add `where`/paging/truncation to `decorator_coverage` (+ `scan_file_findings`, judge slice) | M2 | **`wardline-550ea44e53`** (P2), **`wardline-a3eacc5d36`** (P3), **`wardline-88104b44f1`** (P3) — all OPEN |
| Guard the lineless-DEFECT downgrade so only known-safe rule families can leave the gate population | M3 | **NEW** |
| Harden `install/pre_commit.py` to a YAML parser (match `block.py`/`mcp_json.py`) | L2 | **NEW** |

### Tier 3 — Completeness / preview (by-design gaps, lower priority)
| Action | Source | Filigree |
|---|---|---|
| N-hop explain completeness without the optional store; avoid full re-scan for single-finding explain/attach | L4 | **`wardline-82f49ec3c3` is CLOSED** (2026-06-01 — single-hop return-indirection only); the broader N-hop-without-store residual is **untracked → NEW**. `ROADMAP.md`'s "near-term" listing is stale |
| Pin `verify_attestation` missing-schema / non-dict-payload edge tests | L5 | **`wardline-d59f35c626`** (OPEN, P3) |
| Rust FN gaps (mid-chain `?`/`.await`; block/inner doc markers) | L7 | **`wardline-535c9531cc`** (P3), **`wardline-9c3a76b257`** (P3) |
| Rust preview surface gaps (`config` unused, `last_context` None ⇒ delta/SARIF degrade, `edges.py` unwired); finish/retire the `node_id` Python contract | L8, L10 | **NEW** (Rust-preview tracker) |

## 4. Suggested sequencing

1. **Tier 0 reconciliation sprint** (hours, not days) — converts silent partial completion into accurate
   state; closes/rescopes 4 tickets and removes a misleading comment + a needlessly-off CI gate.
2. **H3 + M4** — small, high-clarity coupling/correctness fixes that de-risk everything downstream.
3. **H1 broad-layering + H2 split-invariants** — the genuine structural work; do behind the conformance
   net, contracts-report-only-first, then enforcing (the same playbook the closed ticket used).
4. **M1 god-function decomposition** — opportunistic, one function per PR, suite-gated.

## 5. What NOT to do
- Don't "fix" `fingerprint_v0.py` to match the live formula — it is an intentional frozen clone; re-syncing
  it silently orphans every migrated verdict (`fingerprint_v0.py:1-13`).
- Don't broaden Wardline's scope (more languages, broad SAST, hosted service) — the L1–L2+L3 / Python-first
  / local-first boundary is a deliberate, defended product decision (`ROADMAP.md`,
  `project_product_thesis`).
- Don't treat the documented under-approximations as bugs — they fail *closed* (precision/recall debt).

## 5b. Filed issues (the "NEW" items are now tracked)

Filed 2026-06-28 under parent `wardline-bf004e2aea`, label `arch-analysis-2026-06-28`:

| Issue | Tier | Source finding | Pri |
|---|---|---|---|
| `wardline-7971cbcf9e` | 0 | H1 — fix stale pyproject "BROKEN" comment + make CI `lint-imports` gating | P2 |
| `wardline-a0eaa7dd12` | 1 | H1 broad — drive down `core/` layering residual (~102 deferred imports) | P2 |
| `wardline-8a1399a8b5` | 1 | H2 — harden 3 split security invariants | P2 |
| `wardline-5e4a4ee246` | 1 | H3 — remove pytest-coupled MCP handshake bypass | P2 |
| `wardline-3932db542c` | 1 | M4/M5 — promote cross-subsystem `_private` deps to public seams | P3 |
| `wardline-83c416811a` | 2 | M1 — decompose god-functions behind the conformance net | P3 |
| `wardline-da175547cf` | 2 | M3 — guard the lineless-DEFECT→FACT gate-population exit | P3 |
| `wardline-a8c1815e64` | 2 | L2 — harden `install/pre_commit.py` to a YAML parser | P3 |
| `wardline-e2487c053a` | 3 | L4 — N-hop explain completeness residual (+ stale ROADMAP entry) | P3 |
| `wardline-00beb310e0` | 3 | L8/L10 — Rust preview surface gaps | P3 |
| `wardline-f3ef15adb2` | low | L9/L3/L1 — doc/naming cleanups + TOCTOU note | P4 |

Tracked-but-existing items (re-triage / continue): `wardline-550ea44e53`, `wardline-a3eacc5d36`,
`wardline-88104b44f1` (M2 bounding); `wardline-18499aaa2d`, `wardline-80e457bc41` (L6 close/rescope);
`wardline-d59f35c626` (L5); `wardline-535c9531cc`, `wardline-9c3a76b257` (L7).

## 6. Cross-pack recommendations
- **Quality/architecture deep-dive:** `axiom-system-architect` (`/assess-architecture`, `/catalog-debt`,
  `/prioritize-improvements`) to turn §3 into a costed improvement backlog.
- **Threat modeling:** `ordis-security-architect` (`/threat-model`) — the split security invariants (H2),
  the lineless-DEFECT gate exit (M3), and the federation replica-drift surface (L6/legis fail-open) are
  worth a STRIDE pass even though no live hole was found.
- **Static-analyzer-specific:** `axiom-static-analysis-engineering` (false-positive-economics,
  rule/lattice design) — relevant to the 11 PREVIEW rules and the MIXED_RAW latent-disagreement invariant.

---

### Validation
This handover and `04-final-report.md` were gated by a second `analysis-validator` pass — see
`temp/validation-synthesis.md`. The catalog gate is `temp/validation-catalog.md` (PASS-WITH-NOTES).
Filigree IDs cited here were checked against the live tracker on 2026-06-28. **CLOSED/done:**
`wardline-9ec283d168` (layering), `wardline-82f49ec3c3` (single-hop return-indirection). **OPEN:**
`wardline-550ea44e53` (P2), `wardline-80e457bc41` (P2), `wardline-18499aaa2d` (P3),
`wardline-d59f35c626` (P3), `wardline-535c9531cc` (P3), `wardline-9c3a76b257` (P3),
`wardline-a3eacc5d36` (P3), `wardline-88104b44f1` (P3). Items marked **NEW** have no current issue.
