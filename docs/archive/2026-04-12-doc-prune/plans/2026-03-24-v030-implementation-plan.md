# Wardline v0.3.0 "Analysis" — Implementation Plan

**Date:** 2026-03-24
**Status:** Draft
**Predecessor:** `docs/plans/2026-03-23-post-mvp-roadmap.md` (Track 2)
**Design specs:**
- WP 2.1: `docs/superpowers/specs/2026-03-24-l3-callgraph-taint-design.md`
- WP 2.3a: `docs/superpowers/specs/2026-03-24-governance-cli-design.md`
- WP 2.2: `docs/superpowers/specs/2026-03-23-mypy-tier-approach-spike.md`

## Release Structure

v0.3.0 is preceded by a v0.2.1 hotfix that ships prerequisites discovered during panel review.

```
v0.2.0 (current)
  │
  ├─ v0.2.1 — Prerequisites (XS, sequential)
  │    ├─ 0.6: Corpus verifier taint wiring + rules 006-009
  │    └─ 0.7: analysis_level_required corpus field
  │
  └─ v0.3.0 — Analysis
       ├─ 2.1:  L3 Call-Graph Taint (L)          ─┐
       ├─ 2.2:  NewType Migration (S)             │ parallelizable
       ├─ 2.3a: Governance CLI (M)                │
       ├─ 2.4:  SARIF Governance Metadata (XS)   ─┘
       │
       ├─ 2.3b: Extended Explain + L3 (S)         ← depends on 2.1
       └─ 2.5:  Self-hosting + corpus baselines   ← depends on 2.1
```

## Phase 0: v0.2.1 Prerequisites

Ship before any v0.3.0 work begins. Fixes discovered during panel review — the corpus verifier doesn't wire taint context and is missing rules 006-009.

### WP 0.6: Corpus Verifier Fix

- Wire `ScanContext` from specimen YAML `taint_state` into rule execution
- Add rules 006-009 to `_make_rules()` in `corpus_cmds.py`
- Re-validate all 184 existing specimen verdicts
- **Effort:** S
- **Depends on:** nothing
- **Spec:** Panel findings (Quality C-1, C-2)

### WP 0.7: `analysis_level_required` Corpus Field

- Add field to `corpus-specimen.schema.json` (must update before specimens, `additionalProperties: false`)
- Add `--analysis-level` flag to corpus verifier CLI
- Verifier skips specimens above configured level
- Default 1 for all existing specimens
- **Effort:** XS
- **Depends on:** 0.6

### v0.2.1 Exit Criteria

- All 184 existing specimens re-validated with taint context wired
- Rules 006-009 exercised by corpus verifier
- `analysis_level_required` field in schema and verifier
- Tests pass, self-hosting green

---

## Phase 1: Parallel Work Packages (no cross-dependencies)

These four WPs can be developed concurrently. Each has its own feature branch.

### WP 2.1: L3 Call-Graph Taint

The largest WP. Intra-module call-graph taint propagation with fixed-point iteration.

**Key deliverables:**
1. L1 provenance output (`assign_function_taints` returns `TaintSource` map)
2. Call graph extraction (`scanner/taint/callgraph.py`)
3. SCC decomposition + fixed-point propagation (`scanner/taint/callgraph_propagation.py`)
4. Engine integration (Pass 1.5, gated on `analysis_level >= 3`)
5. Mandatory taint provenance with resolved/unresolved counts
6. Exception taint-drift + level-stale governance findings
7. Exception migration CLI (`preview-drift`, `migrate`)
8. L3 corpus specimens (11+)
9. Property-based convergence tests (Hypothesis)
10. Qualname extraction to shared utility

**Critical design decisions (from panel):**
- Three-way provenance classification (decorator/module_default/fallback)
- Total trust order via `least_trusted()`, not `taint_join`
- Unresolved calls transparent with `L3-LOW-RESOLUTION` diagnostic
- Iterative Tarjan's SCC (not recursive)

**Effort:** L
**Depends on:** v0.2.1 (corpus prerequisites)
**Spec:** `2026-03-24-l3-callgraph-taint-design.md`

### WP 2.2: NewType Migration

Scope dramatically reduced by spike — no mypy plugin needed.

**Key deliverables:**
1. Change `Tier1-4` from `Annotated[Any, TierMarker(N)]` to `NewType("TierN", object)`
2. Add companion `_TIER_REGISTRY` mapping `Tier1 → TierMarker(1)` for runtime introspection
3. Keep `TierMarker` in `__all__` (backward compatible)
4. Create `ValidatedRecord` Protocol in `runtime/protocols.py`
5. mypy integration tests (verify tier mismatches caught natively)

**Effort:** S
**Depends on:** nothing
**Spec:** `2026-03-23-mypy-tier-approach-spike.md`

### WP 2.3a: Governance CLI

Full Lite governance surface — four CLI subsystems.

**Key deliverables:**
1. `wardline manifest coherence` — wire 8 existing checks to CLI with `--json` + `--gate`
2. `wardline fingerprint update/diff` — annotation fingerprints, policy/enforcement classification, coverage report
3. `wardline regime status/verify` — governance health dashboard + verification checks
4. Extended `wardline explain` — exception status, overlay resolution, fingerprint state, `--json`
5. `artefact_class` field on `FingerprintEntry` model
6. Frozen test fixture (`tests/fixtures/governance/`)

**Effort:** M
**Depends on:** nothing
**Spec:** `2026-03-24-governance-cli-design.md`

### WP 2.4: SARIF Governance Metadata

Four fields added to SARIF run-level properties.

**Key deliverables:**
1. `wardline.analysisLevel` — engine analysis depth (integer)
2. `wardline.manifestHash` — SHA-256 of manifest + overlays
3. `wardline.scanTimestamp` — ISO 8601 UTC
4. `wardline.commitRef` — git HEAD or null

**Effort:** XS
**Depends on:** nothing
**Filigree:** `wardline-3aa2cec7b7`

---

## Phase 2: L3-Dependent Work (after WP 2.1 merges)

### WP 2.3b: Extended Explain + L3 Provenance

Extends the `explain` command with L3-specific features.

**Key deliverables:**
1. Taint inference chain display ("taint is X because callers A, B are Y")
2. `taintInferenceSource` field per finding in SARIF
3. `--compare-levels 2,3` dual-run transition assurance
4. `--all --json` batch mode for bulk evidence generation

**Effort:** S
**Depends on:** 2.1 (L3 must be merged), 2.3a (base explain extensions)

### WP 2.5: Self-Hosting + Corpus Baselines at L3

**Key deliverables:**
1. Measure L3 self-hosting baselines (per-rule finding counts at analysis_level=3)
2. Parameterize `test_scan_finding_count_stable` by analysis level
3. Validate KFN specimens flip to TP at L3
4. L3 canary test (dedicated test for KFN→TP transition)
5. Performance benchmark: L3 self-hosting scan under 30s budget

**Effort:** S
**Depends on:** 2.1

---

## Dependency Graph

```
v0.2.1 Prerequisites
├── 0.6 Corpus verifier fix
└── 0.7 analysis_level_required ──→ depends on 0.6
         │
         ▼
v0.3.0 Phase 1 (parallel)
├── 2.1 L3 Call-Graph Taint ──────┬──→ 2.3b Extended Explain + L3
├── 2.2 NewType Migration         ├──→ 2.5  Self-Hosting Baselines
├── 2.3a Governance CLI           │
└── 2.4 SARIF Metadata            │
                                   │
v0.3.0 Phase 2 (sequential)       │
├── 2.3b ◄────────────────────────┘
└── 2.5  ◄────────────────────────┘
```

## v0.3.0 Exit Criteria

- [ ] L3 call-graph taint operational with three-way provenance
- [ ] Mandatory taint provenance on all functions
- [ ] Exception taint-drift and level-stale governance findings active
- [ ] Exception migration CLI functional (preview-drift, migrate)
- [ ] `Tier1-4` as NewType, `ValidatedRecord` Protocol defined
- [ ] `wardline manifest coherence` with `--gate` CI integration
- [ ] `wardline fingerprint update/diff` with coverage reporting
- [ ] `wardline regime status/verify` with governance health dashboard
- [ ] Extended `wardline explain` with exceptions, overlay, fingerprint, `--json`
- [ ] SARIF run-level: analysisLevel, manifestHash, scanTimestamp, commitRef
- [ ] 11+ L3 corpus specimens passing (including KFN→TP transitions)
- [ ] Self-hosting gate green at L1, L2, and L3 with per-level baselines
- [ ] Property-based convergence tests (Hypothesis) passing
- [ ] L3 self-hosting scan under 30s budget
- [ ] No open P0/P1 bugs

## Effort Summary

| WP | Effort | Parallelizable |
|----|--------|---------------|
| 0.6 + 0.7 (v0.2.1) | S | Sequential |
| 2.1 L3 Taint | L | Phase 1 |
| 2.2 NewType | S | Phase 1 |
| 2.3a Governance CLI | M | Phase 1 |
| 2.4 SARIF Metadata | XS | Phase 1 |
| 2.3b Explain + L3 | S | Phase 2 (after 2.1) |
| 2.5 Baselines | S | Phase 2 (after 2.1) |
| **Total** | **XL** | 4 parallel + 2 sequential |

## Risk Register

| # | Risk | Mitigation | WP |
|---|------|-----------|-----|
| 1 | Three-way provenance requires L1 API change | Additive return value — existing consumers unaffected | 2.1 |
| 2 | Iterative Tarjan's is subtle to implement correctly | Exhaustive unit tests with known graph topologies; consider `networkx` if hand-rolling proves buggy | 2.1 |
| 3 | L3 finding count shift breaks self-hosting CI | Phase 2 WP 2.5 re-measures baselines; interim: widen tolerance bands | 2.5 |
| 4 | Hypothesis not yet a project dependency | Budget setup task within WP 2.1; conftest strategies for random graph generation | 2.1 |
| 5 | NewType migration breaks `test_types.py` introspection tests | Known — `__value__` unwrapping path changes; update tests alongside migration | 2.2 |
| 6 | `module_tiers: UNKNOWN_RAW` edge case in anchored classification | Provenance-based classification handles this by design — add specific test | 2.1 |
