# Wardline Post-MVP Roadmap: v0.1.0 → v1.0

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the Wardline Python implementation from MVP (v0.1.0) through full spec compliance (v1.0), consolidating MVP gaps, post-MVP phases from the design doc, red-team hardening, and migration tooling into a single sequenced plan.

**Architecture:** Four release milestones (v0.2, v0.3, v0.4, v1.0) mapped to the design doc's Phase 2–4, plus a continuous hardening track. Each milestone has clear entry/exit criteria and produces a releasable artifact.

**Current State (v0.1.0, 2026-03-23):**
- 48/48 work packages delivered, 694 tests passing
- 5 MVP rules (PY-WL-001–005), Level 1 taint (syntax-only)
- Groups 1+2 decorators, manifest system, SARIF output, self-hosting gate
- 29 corpus specimens, CI pipeline configured
- 88 open red-team findings (0 P0, 2 P1 bugs, remainder P1-P3 hardening)

**Prerequisites:**
- v0.1.0 committed and tagged
- Red-team findings triaged (complete as of session 6)

---

## Release Map

| Release | Codename | Phase | Relative Size | Key Deliverable |
|---------|----------|-------|---------------|-----------------|
| **v0.1.1** | Hardening | — | XS | Red-team P0/P1 bug fixes, API surface cleanup |
| **v0.2.0** | Enforcement | Phase 2 | L | Tier-aware rules, overlay system, exception register, PY-WL-006–009, Level 2 taint |
| **v0.3.0** | Analysis | Phase 3 | M | Level 3 taint (call-graph), mypy plugin, full governance CLI |
| **v0.4.0** | Integration | Phase 4 | S | flake8 plugin, runtime enforcement hooks, SARIF aggregation |
| **v1.0.0** | Conformance | — | S | Full corpus (126+), spec conformance certification, stable schemas |

---

## Track 0: MVP Gap Closure (v0.1.1)

These items are within the MVP spec but were deferred or incomplete. Fix before starting Phase 2 work.

### 0.1 Engine → Discovery/Taint Wiring

**Problem:** `ScanEngine` runs rules on raw AST without invoking decorator discovery, taint assignment, or constructing `ScanContext`. Rules fire on syntax patterns only — no tier-aware severity grading. This is the largest MVP gap.

**Scope:**
- Wire `discover_annotations()` into `ScanEngine._scan_file()`
- Wire `assign_function_taints()` to build a per-file taint map
- Construct `ScanContext` with the taint map after pass 1
- Pass `ScanContext` to rules so they can look up severity from the matrix
- Update `RuleBase` to accept `ScanContext` and use `matrix.lookup()` for severity
- Update all 5 rules to use taint-aware severity instead of hardcoded `Severity.ERROR`
- Update self-hosting scan baseline (finding count will change)

**Design decision (from panel review):** Use `set_context(ctx: ScanContext)` method on RuleBase. Engine calls it before `visit(tree)`. Rules access `self._context` for taint lookup and severity grading. Preserves existing `visit_function` signature.

**Depends on:** Nothing (all infrastructure exists)
**Effort:** L (upgraded from M per panel review — single largest API-breaking change)
**Risk:** High integration surface — this touches engine, all 5 rules, all rule tests, scan command, and test baselines

### 0.2 Public API Surface

**Problem:** `decorators/__init__.py`, `runtime/__init__.py`, `core/__init__.py` are empty — no `__all__`, no re-exports. Users must know internal module structure.

**Scope:**
- Add `__all__` to `core/__init__.py` (TaintState, AuthorityTier, Severity, etc.)
- Add `__all__` to `runtime/__init__.py` (WardlineBase, AuthoritativeField, Tier1-4, FailFast)
- Add `__all__` to `decorators/__init__.py` (all Group 1+2 decorators, schema_default)
- Add `__all__` to `authority.py`, `audit.py`

**Depends on:** Nothing
**Effort:** XS

### 0.3 Red-Team P1 Bug Fixes

**Problem:** 2 open P1 bugs from red-team audit that affect correctness.

**Scope:**
- `--output` file write error handling in scan.py (OSError → exit 2, not exit 1)
- `max_unknown_raw_percent` formula denominator (findings/files mismatch — document or fix)

**Depends on:** Nothing
**Effort:** XS

### 0.4 Red-Team P1 Hardening Batch

**Problem:** ~29 P1 items covering error handling, type safety, test coverage gaps.

**Scope:** (selected high-value items)
- REGISTRY → MappingProxyType wrapping
- SEVERITY_MATRIX → MappingProxyType wrapping
- Schema version check: exact match instead of substring
- Baseline JSON error handling in coherence.py
- Specimen file error handling in corpus_cmds.py
- `_resolve_decorator` recursion depth limit
- `get_wardline_attrs` use `vars()` instead of `dir()`
- Loader file opened with `encoding="utf-8"`
- SARIF artifactLocation.uri: relative paths instead of absolute
- Async decorator support in `_base.py` (asyncio.iscoroutinefunction check)

**Depends on:** Nothing
**Effort:** M (batch parallelizable)

### 0.5 Red-Team P2/P3 Backlog

**Problem:** ~56 P2/P3 items — test coverage gaps, docstring fixes, minor hardening.

**Scope:** Triage into:
- **Fix now** (~15): Missing tests (async decorators, mixed stacking, pattern matching), dead imports, API cleanup
- **Defer to relevant phase** (~25): Items that naturally resolve during Phase 2/3 work
- **Close as wontfix** (~16): Design observations, acceptable tradeoffs, Python version notes

**Depends on:** 0.3, 0.4
**Effort:** S (after triage)

---

## Track 1: Phase 2 — Enforcement Broadening (v0.2.0)

The largest phase. Broadens the enforcement surface from 5 syntax-only rules to 9 tier-aware rules with full overlay and exception systems.

### 1.1 Groups 3–5 Decorators

**Scope:**
- Group 3: `@system_plugin` (plugin.py)
- Group 4: `@int_data` (provenance.py)
- Group 5: `@all_fields_mapped`, `@output_schema`, extend `schema_default` (schema.py)
- Registry entries for all new decorators
- Tests following existing factory pattern

**Depends on:** 0.2 (public API surface)
**Effort:** S
**Parallelizable with:** 1.2, 1.3

### 1.2 Groups 6–17 Decorators

**Scope:**
- Groups 6–17: boundaries, safety, secrets, operations, sensitivity, determinism, concurrency, access, lifecycle (10 modules, ~25 decorators)
- All one-liners using the factory
- Registry entries + tests

**Depends on:** 0.2
**Effort:** M
**Parallelizable with:** 1.1, 1.3

### 1.3 Overlay System

**Scope:**
- Full overlay merge with boundary-level narrow-only enforcement
- Overlay discovery with allowlist enforcement
- `schema_default()` overlay verification — closes the MVP conformance gap
- `PY-WL-001-UNVERIFIED-DEFAULT` → ERROR when no overlay declaration
- Update `wardline.conformanceGaps` to remove `PY-WL-001-SCHEMA-DEFAULT-UNVERIFIED`

**Depends on:** 0.1 (taint wiring)
**Effort:** M
**Critical:** Must ship with 1.7 (migration tooling) per design doc ordering constraint

### 1.4 Exception Register

**Scope:**
- `wardline.exceptions.json` loading and validation
- Exception matching against findings (suppress matched findings)
- `agent_originated` enforcement (WARNING for null provenance — already in coherence.py)
- `recurrence_count` tracking on (rule, location) tuples
- `governance_path` enum support
- `wardline exception add/expire/review` CLI commands

**Depends on:** 1.3 (overlay system)
**Effort:** M

### 1.5 Rules PY-WL-006 through PY-WL-009

**Scope:**
- PY-WL-006: Audit writes in broad handlers (requires audit context from decorators)
- PY-WL-007: Runtime type-checking internal data (requires tier context)
- PY-WL-008: Validation with no rejection path (structural analysis)
- PY-WL-009: Semantic without prior shape validation (annotation ordering)
- All require `ScanContext` with taint state (depends on 0.1)
- Corpus specimens for each new rule

**Depends on:** 0.1 (taint wiring), 1.1/1.2 (decorator groups for context)
**Effort:** L (PY-WL-008 is the hardest rule — see Risk Area 1)

### 1.6 Level 2 Taint — Variable-Level

**Scope:**
- `scanner/taint/variable_level.py` — per-variable taint tracking within function bodies
- Assignment propagation: `x = external_func()` → x is EXTERNAL_RAW
- `taint_join` at control flow merge points (if/else → same variable)
- Function return: effective taint = join of all return paths
- Update engine to use L2 when `analysis_level >= 2`

**Depends on:** 0.1 (taint wiring)
**Effort:** L
**Risk:** Highest technical risk in Phase 2 — see Risk Area 2

### 1.7 Migration Tooling

**Scope:**
- `wardline scan --preview-phase2` — reports impact of Phase 2 changes
- `wardline exception review --migrate-mvp` — re-evaluates MVP-era exceptions
- `schema_default()` triage: auto-resolve against overlay declarations

**Depends on:** 1.3 (overlay system), 1.4 (exception register)
**Effort:** S
**Critical:** MUST ship in same release as 1.3 (blocking ordering constraint from design doc)

### 1.8 Full Corpus — 126+ Specimens

**Scope:**
- 1 TP + 1 TN per non-SUPPRESS cell in 9×8 matrix
- Adversarial specimens: ≥1 FP + ≥1 FN per rule (≥10 adversarial total)
- Evasion-variant specimens (helper wrappers, conditional assignments)
- Precision/recall per cell, not just per rule
- Update `wardline corpus verify` output to report Wardline-Core conformance

**Depends on:** 1.5 (all 9 rules), 1.6 (Level 2 taint for scenario 3/4 specimens)
**Effort:** M

### Phase 2 Exit Criteria
- All 9 rules active with tier-aware severity
- Overlay system operational, `schema_default()` conformance gap closed
- Exception register functional with threat control enforcement
- Level 2 taint assignment operational
- 126+ corpus specimens passing
- Migration tooling shipped
- Self-hosting gate green with updated baselines
- `wardline.propertyBagVersion` incremented to `"0.2"`

---

## Track 2: Phase 3 — Analysis Deepening (v0.3.0)

Medium-sized phase. Deepens analysis with call-graph taint and adds the mypy plugin.

### 2.1 Level 3 Taint — Call-Graph Inference

**Scope:**
- `scanner/taint/callgraph.py` — build call graph from AST
- Function call → target resolution (name resolution within module)
- Worklist algorithm: compute effective taint from callers + annotations
- Iterate until fixed point (guaranteed: finite lattice, monotonic join)
- Cross-function tier-flow detection
- Evaluate `astroid` dependency vs stdlib `ast` + manual resolution

**Depends on:** 1.6 (Level 2 taint)
**Effort:** L
**Risk:** `astroid` version conflicts with pylint. Evaluate carefully.

### 2.2 mypy Plugin

**Scope:**
- `runtime/protocols.py` — `ValidatedRecord` Protocol, trust-typed interfaces
- Custom mypy plugin using `mypy.plugin` API
- Read `Annotated[str, TierMarker(1)]` metadata from type annotations
- Flag tier mismatches: Tier4 value flowing to Tier1 parameter
- Separate from scanner — runs at IDE/development time
- Extend `test_registry_sync.py` for Protocol structural conformance

**Depends on:** 0.2 (public API surface)
**Effort:** L
**Risk:** mypy plugin API stability — breaking changes between mypy versions

### 2.3 Full Governance CLI

**Scope:**
- `wardline manifest coherence` — run all coherence checks (5 remaining)
- `wardline fingerprint update/diff` — annotation hash tracking
- `wardline regime status/verify` — enforcement state reporting
- Extended `wardline explain` — per-rule match details, exception status, schema_default resolution

**Depends on:** 1.4 (exception register), 2.1 (Level 3 taint for explain)
**Effort:** M

### Phase 3 Exit Criteria
- Level 3 call-graph taint operational
- mypy plugin detects tier mismatches in IDE
- Full governance CLI suite functional
- Corpus upgraded with Level 3 specimens (scenarios 3/4 become TP)

---

## Track 3: Phase 4 — Integration (v0.4.0)

Smallest phase. Complements existing tools with IDE-level feedback and runtime hooks.

### 3.1 flake8 Plugin (Advisory)

**Scope:**
- `wardline-flake8` package implementing PY-WL-001 through PY-WL-005 as flake8 rules
- Per-file AST matching only — no manifest, no tier-graded severity
- Advisory: fires in IDE/CI for immediate feedback
- Uses flake8's stable plugin API (entry_points, ast_tree checker)
- Separate package: `pip install wardline-flake8`

**Depends on:** Nothing (reimplements rules in flake8's framework)
**Effort:** M

### 3.2 Runtime Enforcement Hooks

**Scope:**
- Runtime checking via `WardlineBase.__init_subclass__` extensions
- Enforcement hooks for production monitoring (optional, behind flag)
- `ValidatedRecord` Protocol runtime checking

**Depends on:** 2.2 (mypy plugin for Protocol definitions)
**Effort:** S

### 3.3 SARIF Aggregation

**Scope:**
- Multi-run SARIF comparison and trend analysis
- Finding count tracking over time
- Governance dashboard integration

**Depends on:** Nothing
**Effort:** S

### Phase 4 Exit Criteria
- flake8 plugin providing IDE/CI-time advisory feedback
- Runtime hooks available for production use
- SARIF aggregation functional

---

## Track 4: v1.0 Conformance Certification

### 4.1 Schema Stabilization + Package Split

**Scope:**
- Promote all schemas from `0.x` to `1.0`
- Freeze schema contracts
- Split `wardline-decorators` package (zero deps, `>=3.9` floor)
- Main `wardline` package depends on `wardline-decorators`

**Effort:** S

### 4.2 Full Spec Conformance Audit

**Scope:**
- Verify all normative requirements from Wardline Framework Specification v0.2.0
- Close all `wardline.conformanceGaps`
- Document any remaining deviations

**Effort:** S

### 4.3 Documentation & Adopter Guide

**Scope:**
- Adopter quickstart guide
- Tier assignment methodology guide
- Migration guide (existing projects)
- API reference documentation

**Effort:** M

### v1.0 Exit Criteria
- All normative spec requirements implemented or documented as out-of-scope
- Stable schemas (v1.0)
- `wardline-decorators` split and published
- Full corpus passing (126+ specimens)
- Adopter documentation complete
- No open P0/P1 bugs

---

## Dependency Graph

```
Track 0 (v0.1.1)
├── 0.1 Engine/Taint Wiring ──────┬──→ 1.3 Overlay System ──→ 1.7 Migration
├── 0.2 Public API ──┬──→ 1.1 Groups 3-5    │                  ↓
│                    └──→ 1.2 Groups 6-17    ├──→ 1.4 Exception Register
├── 0.3 P1 Bug Fixes              │          │
└── 0.4 P1 Hardening              │          ├──→ 1.5 Rules 006-009
                                   │          │
                                   └──→ 1.6 Level 2 Taint ──→ 1.8 Full Corpus
                                                    │
                                                    ↓
                                        2.1 Level 3 Taint ──→ 2.3 Governance CLI
                                        2.2 mypy Plugin
                                                    │
                                                    ↓
                                        3.1 flake8 Plugin
                                        3.2 Runtime Hooks
                                        3.3 SARIF Aggregation
                                                    │
                                                    ↓
                                        4.1-4.3 v1.0 Conformance
```

---

## Risk Register

| # | Risk | Mitigation | Phase |
|---|------|-----------|-------|
| 1 | PY-WL-008 structural analysis is hard — valid rejection path detection requires control flow analysis | Start with positive heuristic (raise, conditional return). Add exclusions iteratively. | 2 |
| 2 | Level 2 variable taint is the highest technical risk — control flow merge semantics are subtle | Extensive property-based testing. Start with straight-line code, add branches incrementally. | 2 |
| 3 | `astroid` version conflicts with pylint ecosystem | Evaluate stdlib ast + manual resolution first. Only add astroid if essential. | 3 |
| 4 | mypy plugin API stability — breaking changes between mypy versions | Pin mypy version range. Test against 2 most recent mypy releases. | 3 |
| 5 | flake8 performance at scale — slower than ruff for large codebases | Advisory-only (not blocking CI), IDE integration offsets latency | 4 |
| 6 | Migration tooling must ship WITH overlay system (blocking constraint) | Pin as explicit dependency in release planning. Single release for 1.3 + 1.7. | 2 |

---

## Effort Estimates

| Track | Items | Total Effort | Parallelizable |
|-------|-------|-------------|----------------|
| Track 0 (v0.1.1) | 5 items | M | Mostly parallel (0.1 is sequential) |
| Track 1 (v0.2.0) | 8 items | XL | 1.1/1.2 parallel, 1.5/1.6 parallel |
| Track 2 (v0.3.0) | 3 items | L | 2.1/2.2 parallel |
| Track 3 (v0.4.0) | 3 items | S | All parallel |
| Track 4 (v1.0.0) | 3 items | M | Mostly parallel |

**Total estimated effort:** ~3-4x the MVP implementation effort, with Phase 2 being the largest single phase.

---

## Red-Team Finding Disposition

| Priority | Total | Fixed | Closed (known limitation) | Downgraded | Remaining Open | Disposition |
|----------|-------|-------|---------------------------|------------|----------------|-------------|
| P0 | 17 | 4 | 8 | 5 → P1/P2 | 0 | All resolved |
| P1 | 31 | 1 | 0 | 0 | ~30 | Fix in 0.3/0.4, defer subsystem-specific items to relevant phase |
| P2 | 48 | 0 | 0 | 0 | ~48 | Triage: ~15 fix in 0.5, ~25 defer to phase, ~8 wontfix |
| P3 | 4 | 0 | 0 | 0 | ~4 | Backlog |

---

## Resolved Decisions

1. **Level 2 taint scope:** Full Level 2 in v0.2.0. If it slips, ship rules 006-009 with Level 1 and deliver Level 2 in a v0.2.1 follow-up. Do not scope down to "Level 2 lite" — the full variable-level tracking is the target.

2. **IDE-time linting:** Use flake8 plugin API (stable, proven ecosystem) rather than ruff (no public plugin API). Phase 4 deliverable is a `wardline-flake8` plugin package.

3. **Package split:** Defer to v1.0.0. Internal use only until v1.0 — no external adopters need decorators-without-scanner before then. The `[project.optional-dependencies]` groups keep the split path open.

4. **Schema migration:** No automated migration tooling. We're dogfooding our way to v1.0 — schema changes are applied directly to our own manifests as we go. The `--migrate-mvp` command (v0.2.0) handles the one transition that matters (MVP → overlay-verified `schema_default`).

---

## Panel Review Findings (2026-03-23)

Five-reviewer panel (solution architect, systems thinker, Python engineer, quality engineer, static analysis specialist) reviewed this roadmap against the codebase and filigree work packages.

### Critical — Applied

| # | Finding | Resolution |
|---|---------|------------|
| C1 | RuleBase interface change unspecified — WP 0.1 must decide how rules receive ScanContext | Added requirement: use `set_context()` method on RuleBase (preserves visit_function signature). Design decision added to WP 0.1. |
| C2 | WP 0.1 effort underestimated (rated M, touches engine + all rules + tests + baselines) | Upgraded to effort L. |
| C3 | Level 2 taint scope underspecified — only mentions simple assignment and if/else | Added assignment form enumeration requirement to WP 1.6 (10 Python assignment constructs). |
| C4 | Self-hosting baseline will erode — total count (50-200) too coarse for tier-aware severity changes | Added requirement: decompose to per-rule finding counts before WP 0.1 ships. |
| C5 | Integration tests only run on merge to main — PRs can break self-hosting undetected | Added requirement: move integration CI job to run on every PR. |

### Important — Applied

| # | Finding | Resolution |
|---|---------|------------|
| I1 | Missing dependency: 1.8 (corpus) → 1.3 (overlay). PY-WL-001 specimens change with overlay. | Added dependency edge. |
| I2 | Async decorator is a correctness bug (framework introspection fails), not hardening. | Reclassified to P1 bug, moved from WP 0.4 to WP 0.3. |
| I3 | PY-WL-003 fires on ALL `in` operators — unacceptable FP when taint wiring activates. | Added requirement: PY-WL-003 taint-gated to EXTERNAL_RAW/UNKNOWN_RAW only. |
| I4 | Exception register threat controls must be hard v0.2 exit criteria, not soft goals. | Made explicit in Phase 2 exit criteria. |
| I5 | Package split: `wardline-decorators` must include `wardline.core` subset (taints, tiers, registry). | Clarified in WP 4.1 description. |
| I6 | Corpus specimens need `analysis_level_required` field before L2 ships. | Added requirement to WP 1.8. |
| I7 | flake8 plugin will contradict scanner results (no taint context). | Documented as known limitation in WP 3.1. |
| I8 | mypy plugin: `Annotated[Any, ...]` opaque to mypy — consider NewType redesign. | Added design decision requirement to WP 2.2. |
| I9 | PY-WL-008 needs structural-conditional definition, not "any raise in body." | Refined WP 1.5 PY-WL-008 requirement. |
| I10 | No performance budget defined for L2/L3. | Added weekly performance benchmark job from v0.2. |

### Suggestions — Backlog

S1-S10 recorded as filigree tasks at P3 for future consideration.
