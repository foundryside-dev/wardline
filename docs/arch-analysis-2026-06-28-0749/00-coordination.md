# 00 — Coordination Plan

## Analysis Configuration
- **Target**: `wardline` — generic semantic-tainting static analyzer for Python (with a Rust preview frontend)
- **Scope**: `src/wardline/` (182 Python files, ~42.5K LOC) + supporting config; `tests/` (367 files) for evidence only
- **Deliverables**: **Option C — Architect-Ready** (discovery + catalog + diagrams + report + quality + handover)
- **Strategy**: **PARALLEL** subsystem exploration (≥5 loosely-coupled subsystems, 42K LOC) — justified below
- **Time constraint**: none stated
- **Complexity estimate**: **High** (taint dataflow engine, multi-surface product: CLI + MCP + federation clients + Rust frontend)
- **Commit analyzed**: `e4668abc` (branch `release/consolidation-2026-06-26`)
- **Date**: 2026-06-28

## Tooling leverage
- **Loomweave** index is FRESH at `e4668abc` (7729 entities, 20068 edges, 540 subsystem clusters, SEI populated). Used for entity/edge/subsystem queries instead of re-grepping.
- **Filigree** tracker live (25 ready issues) — used as the authoritative source of *known* debt/roadmap, cross-referenced against findings.

## Orchestration decision
PARALLEL is selected per the command's rule (≥5 independent subsystems AND 20K+ LOC). The product
decomposes into 11 cohesive subsystems with mostly one-directional coupling (CLI/MCP → core → scanner).
Each subsystem is handed to one `codebase-explorer` subagent producing a schema-conforming catalog entry;
entries are merged into `02-subsystem-catalog.md`. A validation subagent (`analysis-validator`) gates the
catalog before synthesis. Discovery, diagrams, report, quality, and handover are authored by the
orchestrator (holistic, cross-subsystem judgement).

### Subsystem decomposition (12) — VERIFIED EXHAUSTIVE
Canonical file→subsystem map: `temp/file-map.tsv`. **All 182 source files assigned exactly once**
(0 gaps / 0 ghosts / 0 duplicates, verified by `comm` diff against `find`). Decomposition refined from
11→12 on advisor feedback: the original "Identity, SEI & Federation" unit was oversized and split into
**S8 Identity & SEI** + **S9 Federation Clients** for review depth; six top-level package modules
(`__init__`, `_version`, `_live_oracle`, `lsp`, `weft_decorator_coverage`, `weft_dossier`) that the
brace-expansion lists had silently dropped are now explicitly assigned.

1. **S1 Scanner Engine** (8 files) — `scanner/{analyzer,pipeline,context,grammar,index,ast_primitives,flow_trace,diagnostics}.py`
2. **S2 Rule Lattice** (35) — `scanner/rules/*` + `decorators/*`
3. **S3 Taint Engine** (15) — `scanner/taint/*`
4. **S4 Core Orchestration & Config** (21) — `core/{run,scan_jobs,scan_file_workflow,config,config_schema,ruleset,descriptor,discovery,registry,errors,protocols,paths,optional_deps,frontends,taints,gitignore,safe_paths}.py` + package roots
5. **S5 Findings, Outputs & Emit** (10) — `core/{finding,finding_query,emit,sarif,filigree_emit,filigree_issue,source_excerpt,agent_summary,artifacts,explain}.py`
6. **S6 Gate Discipline & Remediation** (8) — `core/{baseline,waivers,suppression,triage,delta,delta_resolve,delta_scope,autofix}.py`
7. **S7 Trust Evidence & Judge** (10) — `core/{attest,attest_key,assure,dossier,judge,judge_run,judged,decorator_coverage}.py` + `weft_{decorator_coverage,dossier}.py`
8. **S8 Identity & SEI** (7) — `core/{identity,sei_resolution,fingerprint_v0,finding_identity,qualname,rekey,node_id}.py`
9. **S9 Federation Clients** (15) — `core/{http,federation_status,legis}.py` + `loomweave/*` + `filigree/*` + `_live_oracle.py`
10. **S10 MCP & LSP Server** (9) — `mcp/*` + `lsp.py`
11. **S11 CLI & Install/Activation** (29) — `cli/*` + `install/*`
12. **S12 Rust Frontend** (15) — `rust/*`

### Validation scope (advisor point 3 — recorded deviation)
The command says validate after EVERY major document. Plan:
- **`02-subsystem-catalog.md`** — MANDATORY parallel `analysis-validator` gate (12 parallel-authored entries, highest error risk).
- **`04-final-report.md` + `06-architect-handover.md`** — validation subagent gate (architect-facing; synthesis is not single-subsystem/<30min, so self-validation is not contract-permitted).
- **`01`, `03`, `05`** — orchestrator self-validation with documented evidence (all authored personally from primary sources + the validated catalog). This is the recorded deviation; it is narrower than a subagent gate per doc but every downstream doc draws on the subagent-validated catalog.

## Execution Log
- [07:49] Created workspace `docs/arch-analysis-2026-06-28-0749/`
- [07:50] User selected **Option C (Architect-Ready)**
- [07:51] Holistic orientation: layout, LOC, pyproject, import-linter contracts, Loomweave status
- [07:52] Wrote coordination plan + discovery findings
- [07:55] Advisor review → adopted all 4 points: exhaustive file map, Loomweave-grounded deps, broadened validation scope, Filigree-ID wiring for quality/handover
- [07:58] Built + verified exhaustive 182-file map (`temp/file-map.tsv`); split S8/S9; wrote `temp/catalog-spec.md`
- [08:10] Dispatched 12 `codebase-explorer` agents (PARALLEL); 11 succeeded first pass, S12 hit a transient rate-limit and was re-dispatched. All 12 entries written to `temp/catalog-S*.md`.
- [08:25] Cross-agent signal: S1/S3/S7 independently report the tracked layering violation already remediated. **Orchestrator verified directly:** `lint-imports` → "1 kept, 0 broken"; no `core.attest` import in `scanner/`. Assembled `02-subsystem-catalog.md` (12 entries + cross-cutting synthesis).
- [08:30] `analysis-validator` gate on catalog → **PASS-WITH-NOTES** (`temp/validation-catalog.md`); validator independently reproduced `lint-imports`. Applied the one HIGH correction (S3's stale "still broken" claim).
- [08:45] Confirmed via Filigree `issue_get`: `wardline-9ec283d168` CLOSED 2026-06-20 (narrow contract done; broad `core/` layering residual = ~102 deferred imports, untracked). Wrote `03-diagrams`, `04-final-report`, `05-quality-assessment` (Filigree-ID mapped), `06-architect-handover`.
- [09:00] Second `analysis-validator` gate on synthesis (`04`+`06`) → **BLOCK** on 2 must-fixes: `wardline-82f49ec3c3` mis-stated OPEN (actually CLOSED 2026-06-01 — propagated from stale `ROADMAP.md`) + a false footer attestation. Verified the ID CLOSED via `issue_get`; corrected `05` L4 + `06` Tier 3 + footer; addressed NOTE-1. Re-validation requested.
- [09:10] Synthesis re-validation → **PASS-WITH-NOTES** (BLOCK cleared; `temp/validation-synthesis.md`). Tracker fidelity 11/11; both must-fixes verified; only non-blocking NOTE-2 (report §4 thematic ordering) / NOTE-3 (absolute phrasings, routed to STRIDE) remain by choice.
- [09:20] User confirmed → **filed 11 Filigree issues** under `wardline-bf004e2aea`, label `arch-analysis-2026-06-28` (IDs in `06-architect-handover.md` §5b): 7971cbcf9e, a0eaa7dd12, 8a1399a8b5, 5e4a4ee246, 3932db542c, 83c416811a, da175547cf, a8c1815e64, e2487c053a, 00beb310e0, f3ef15adb2.
- **STATUS: COMPLETE.** All 6 deliverables written and durable; both validation gates PASS-WITH-NOTES; 11 untracked findings filed as tracked issues.
