# Wardline v1.0 Pre-Release Conformance Review

**Date:** 2026-04-09
**Reviewer:** Independent automated review (6 parallel agents)
**Spec Version:** Wardline Framework Specification v0.2.0 + Python Binding v0.2.0
**Implementation:** wardline Python, branch `phase-4.4-test-quality-gates`
**Prior Assessment:** docs/requirements/spec-fitness/assessment-2026-03-29.md (101 PASS / 5 PARTIAL / 0 FAIL)

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Sections reviewed | 28 (16 framework + Python binding + Lite profile + subsections) |
| PASS | 22 |
| PARTIAL | 6 |
| FAIL | 0 |
| FAIL-level items within PARTIAL sections | 7 |

**Overall verdict: SHIP WITH CAVEATS**

The implementation is structurally sound. Core domain types, taint algebra, enforcement layers, governance model, and all 9 pattern rules are conformant. The 6 PARTIAL verdicts cluster around two themes: (1) missing SARIF properties required by §10.1, and (2) expected narrowings for a Python-only v1.0 binding. The 7 FAIL-level items are all SARIF property omissions that can be addressed without architectural changes.

**Test suite health:** 2,158 tests passing, 0 failures, mypy clean across 89 source files.

**Prior assessment accuracy:** HIGH. All 101 PASS claims independently verified. All 5 PARTIAL ratings confirmed. Two minor discrepancies found (specimen count 241 vs claimed 244; PY-010 text stale but conservative).

---

## Per-Section Detailed Review

### §1 -- What a Wardline Is

**MUST requirements:** 5 declaration components (tier assignment, taint tracking, transition semantics, annotation vocabulary, governance model)

**Verdict: PASS**

All 5 components implemented. Closed set enforced via frozen registries (`MappingProxyType`).

---

### §2 -- The Problem a Wardline Solves

**MUST requirements:** Taint tracking implemented for untrusted data flows.

**Verdict: PASS**

Three-phase taint propagation (variable-level, function-level, callgraph) with 8 canonical taint tokens.

---

### §3 -- Non-Goals

**Verdict: PASS** (no normative requirements)

---

### §4 -- Authority Tier Model

**MUST requirements:**
1. Four authority tiers (INTEGRAL > OPERATIONAL > BOUNDARY > EXTERNAL_RAW)
2. `TAINT_TO_TIER` mapping complete for all 8 taint states
3. Severity matrix: 9 rules x 8 taint states = 72 cells
4. Combined validation boundaries supported

**Implementation evidence:**
- `AuthorityTier` IntEnum at `core/tiers.py:8-13` with 4 values, lower = higher authority
- `TAINT_TO_TIER` at `core/tiers.py:26-35` — `MappingProxyType` with all 8 entries, runtime completeness check at lines 38-40
- 72-cell severity matrix at `core/matrix.py:94-125` with runtime totality verification (lines 136-143)
- Combined boundary support via `validates_external` decorator (T4→T2 direct)

**Verdict: PASS**

---

### §5.1 -- Trust Classification (Taint States)

**MUST requirements:**
1. 8 canonical taint tokens as a closed set
2. `taint_join()` is commutative, associative, idempotent
3. `MIXED_RAW` is the absorbing element
4. Cross-family joins produce `MIXED_RAW`

**Implementation evidence:**
- `TaintState` StrEnum at `core/taints.py:8-23` with 8 explicit uppercase string values
- `taint_join()` at `core/taints.py:44-62` — lookup-based, tested with 64 commutativity pairs, 512 associativity triples
- `MIXED_RAW` absorption verified at line 62 (all unlisted pairs fall through to MIXED_RAW)

**Verdict: PASS**

---

### §5.2 -- Transition Semantics

**MUST requirements:** 7 invariants including skip-promotion rejection (T4→T1, T3→T1 blocked unless T2→T1 restoration)

**Implementation evidence:**
- `reject_skip_promotions()` at `manifest/loader.py:336-353` — rejects `to_tier=1` unless `from_tier=2` or restoration
- 8+ loader tests covering T4→T1 rejection, T3→T1 rejection, T2→T1 acceptance

**Verdict: PASS**

---

### §5.3 -- Trusted Restoration

**MUST requirements:** Evidence-bounded restoration with 4 categories (structural, semantic, integrity, institutional provenance)

**Implementation evidence:**
- `max_restorable_tier()` at `core/evidence.py` — 6-row evidence matrix
- Overclaim detection at `function_level.py:302-313`
- 4 evidence categories in `decorators/restoration.py:30-65`

**Verdict: PASS**

---

### §5.4 -- Cross-Language Taint Propagation

**MUST requirements:**
1. Data crossing language boundary resets to UNKNOWN_RAW unless independently verified
2. Verification mechanism declared in manifest

**Implementation evidence:** No polyglot manifest infrastructure. Unannotated code defaults to UNKNOWN_RAW (conservative).

**Verdict: PARTIAL**
**Deviation:** Narrowing — Python-only binding, no polyglot support. Default UNKNOWN_RAW is the correct failure mode per spec's conservative design. Matches prior assessment WL-FIT-CORE-015.

---

### §5.5 -- Third-Party In-Process Dependency Taint

**MUST requirements:** Undeclared library calls default to UNKNOWN_RAW; unresolvable compound patterns fall back to UNKNOWN_RAW.

**Implementation evidence:**
- `variable_level.py:236-238` — undeclared functions fall back to UNKNOWN_RAW
- `function_level.py:368-369` — unannotated functions default to UNKNOWN_RAW

**Verdict: PASS**
**Deviation:** Compound patterns (chaining, generators, context managers) not explicitly tracked — all fall to UNKNOWN_RAW. Conformant (spec requires this fallback).

---

### §6 -- Annotation Vocabulary

**MUST requirements:**
1. Binding can express all 17 annotation groups
2. Version-tracked semantic equivalents for each pattern rule

**Implementation evidence:**
- All 17 groups present in `core/registry.py:51-220` with correct group numbers
- Group 1: 7 authority decorators matching spec exactly
- Group 17: Restoration boundary with 4 evidence categories
- Groups 2-16: All present with appropriate decorators

**Verdict: PARTIAL**
**Deviation:** Group 16 parameterised `trust_boundary(from_tier, to_tier)` with `to_tier=1 only when from_tier=2` constraint not implemented as standalone generic declaration. Standard transitions fully covered by Group 1 decorators. This is a **narrowing** — users cannot declare arbitrary custom tier transitions outside the standard 4-step chain.

---

### §7 -- Pattern Rules

**MUST requirements:**
1. All 8 framework rules implemented (9 binding-level after WL-001 split)
2. Severity matrix matches spec for all 72 cells
3. Sub-rule deviations documented with rationale
4. WL-007: rejection paths exclude `assert`, detect constant-False guards, support two-hop delegation
5. WL-008: semantic validation preceded by shape validation

**Implementation evidence:**
- All 9 rules: `py_wl_001.py` through `py_wl_009.py` + SCN-021, SUP-001
- Severity matrix: **exact match** across all 72 cells verified programmatically
- PY-WL-002 widens 3 cells vs parent WL-001 (permitted per §7.1 sub-rule provision, documented at `matrix.py:102-103`)
- Rejection path: `assert` not matched (exclusion by omission), `_is_constant_false()` at `rejection_path.py:74-82`, two-hop at `py_wl_008.py:75-112`
- Shape-before-semantic: `py_wl_009.py:279-281` excludes combined boundaries

**Verdict: PASS**
**Risk:** `assert` exclusion is by omission (not matched) rather than explicit documentation. Fragile if someone adds Assert matching later.

---

### §8.1 -- Static Analysis (Enforcement Layer 1)

**MUST requirements:**
1. Detect WL-001–WL-006 intraprocedurally
2. WL-007 structural verification with two-hop
3. WL-008 validation ordering
4. Trace explicit-flow taint (direct + two-hop intermediaries)
5. Deterministic SARIF v2.1.0 output

**Implementation evidence:**
- All rules implemented in `scanner/rules/`
- Two-hop: `expand_rejection_index()` at `engine.py:84-128`
- Three-phase taint: `variable_level.py`, `function_level.py`, `callgraph_propagation.py` (Tarjan SCC + fixed-point)
- SARIF determinism: sorted findings by `(file_path, line, col, rule_id)` at `sarif.py:321-324`, `sort_keys=True` at line 406

**Verdict: PASS**
**Deviation:** `join_fuse`/`join_product` distinction not implemented — conservative fallback to MIXED_RAW (explicitly permitted by spec).

---

### §8.2 -- Type System (Enforcement Layer 2)

**Verdict: N/A** (no MUST requirements for Python binding)

---

### §8.3 -- Runtime Structural (Enforcement Layer 3)

**Verdict: PASS** (conditional MUST for restoration boundary verification satisfied)

---

### §9.1 -- Exceptionability Classes

**MUST requirements:** 4 classes (UNCONDITIONAL/STANDARD/RELAXED/TRANSPARENT); UNCONDITIONAL cannot be overridden; STANDARD requires rationale/reviewer/expiry.

**Implementation evidence:**
- `Exceptionability` StrEnum at `core/severity.py:14-20`
- UNCONDITIONAL blocking at `exceptions.py:161-163`
- `ExceptionEntry` at `manifest/models.py:22-45` with required fields

**Verdict: PASS**

---

### §9.2 -- Governance Mechanisms

**Verdict: PASS**

Fingerprint baseline with canonical SHA-256 hashing, coverage reporting with Tier 1 tracking, artefact classification (policy vs enforcement), Assurance gating via `should_gate_on_profile()`.

---

### §9.2.1 -- Governance Audit Logging

**Verdict: PASS**

`GovernanceEvent` dataclass at `sarif.py:109-116`. Events emitted to SARIF under `wardline.governanceEvents`. Control law state reported.

---

### §9.3 -- Scope of Governance (Agent Authorship)

**Verdict: PASS**

`agent_originated` field on `ExceptionEntry`. `GOVERNANCE_UNKNOWN_PROVENANCE` finding emitted for null provenance.

---

### §9.3.1 -- Artefact Classification

**Verdict: PASS**

`_classify_artefact()` at `fingerprint.py:124-137` with policy groups 1-4, enforcement for all others.

---

### §9.3.2 -- Manifest Threat Model

**Verdict: PASS**

6 anomaly detection checks in `coherence.py`: tier downgrades, upgrade-without-evidence, permissive distribution, boundary widening, SUPPRESS activation, exception volume.

---

### §9.4 -- Governance Capacity

**Verdict: PASS**

Recurrence tracking (`recurrence_count >= 2` triggers `GOVERNANCE_RECURRING_EXCEPTION`), expedited ratio in SARIF, `GovernancePath` enum (STANDARD/EXPEDITED).

---

### §9.5 -- Enforcement Availability (Control Law)

**MUST requirements:** Three-state model (normal/alternate/direct), SARIF reporting, direct-law artefact exclusion, retrospective scan.

**Implementation evidence:**
- `compute_control_law()` at `sarif.py:118-151`
- `wardline.controlLaw` at `sarif.py:339`
- `check_direct_law_exclusion()` at `coherence.py:793-817`
- Retroactive scan properties at `sarif.py:284-285, 344-347`

**Verdict: PASS**
**Risk:** Control law does not check corpus staleness or precision/recall below floors (spec mentions these as alternate-law triggers). A scan may report "normal" when it should be "alternate" if corpus is stale.

---

### §10 -- Verification Properties

**MUST requirements:** 19 requirements covering corpus oracle, self-hosting gate, precision/recall measurement, deterministic SARIF, and mandatory SARIF properties.

**Verdict: PARTIAL**

**FAIL-level items:**

| # | Missing Property | Level | Spec Reference |
|---|-----------------|-------|----------------|
| 1 | `wardline.enclosingTier` | Result | §10.1 |
| 2 | `wardline.annotationGroups` | Result | §10.1 |
| 3 | `wardline.excepted` | Result | §10.1 |
| 4 | `wardline.dataSource` | Result | §10.1 |
| 5 | `wardline.deterministic` | Run | §10.1 |
| 6 | `wardline.deferredFixRatio` | Run | §10.1 |

**Additional deviation:** Corpus specimen `expected_match` is a boolean, not the structured `{line, text, function}` object the spec requires. Verification only confirms "did the rule fire" not "did it fire at the correct location with the correct text."

**What passes:** Corpus has 241 specimens (exceeds both Lite 20-30 and Assurance 126 floors), self-hosting gate works, per-cell precision/recall measured with floors (80%/90%), deterministic SARIF via verification mode, 8 taint_flow specimens, adversarial coverage meets minimums.

---

### §11 -- Language Evaluation Criteria

**Verdict: PASS** (no MUST requirements; 1 SHOULD for versioned evaluation not followed)

---

### §12 -- Residual Risks

**MUST requirements:**
1. Coverage metrics reported (annotation coverage + data paths traced)
2. Coverage below 100% visible
3. Evasion adaptation deliberate and adversarially informed

**Verdict: PARTIAL**
**Deviation:** "Percentage of data paths traced" not separately computed or reported. Only annotation coverage ratio reported via fingerprint baseline. Also, `coverageRatio` is absent when no fingerprint baseline exists, making the "MUST be visible" requirement conditional on an optional artifact.

---

### §13 -- Portability and Manifest Format

**MUST requirements:** 24 requirements covering overlay narrow-only invariant, schema validation, skip-promotion rejection, Norway problem, contract identity.

**Verdict: PARTIAL**

**What passes (22/24):** Narrow-only invariant enforced in `merge.py` (raises `ManifestWidenError`), UNCONDITIONAL protection, schema validation on every load, Norway problem fix (YAML 1.2 strict booleans), skip-promotion rejection, overlay scope verification, UNCONDITIONAL exceptions schema-invalid, ratification age computation, unknown TOML keys rejected.

**Deviations:**
- `validation_scope` not schema-required for boundaries claiming Tier 2 — spec says MUST
- Delegation authority not checked at merge time (schema prevents UNCONDITIONAL but doesn't verify delegation level matches)

---

### §14 -- Conformance

**MUST requirements:** 10 conformance criteria + Lite profile checklist + assessment procedure.

**Verdict: PARTIAL**

SARIF property gaps from §10 cascade to Criterion 8. `wardline.deterministic` missing breaks assessment procedure Step 4. Exception expiry allows null in schema (mitigated by governance finding).

---

### §A -- Python Language Binding

**MUST requirements:** 9 normative requirements in A.3 + exit codes.

**Implementation evidence:**
- All 9 A.3 requirements satisfied
- Exit codes: 0 (clean), 1 (ERROR findings), 2 (config error), 3 (direct law, `wardline regime` only)
- All verified with file:line references

**Verdict: PASS**
**Risk:** `wardline.taintState` falls back to `"UNKNOWN"` for governance/TOOL-ERROR findings — not a canonical token. Low risk (pseudo-rule findings only).

---

### §15 -- Document Scope

**Verdict: PASS** (no normative requirements)

---

## Risk Register

### Critical (blocks conformance claim)

| # | Risk | Section | Impact | Remediation |
|---|------|---------|--------|-------------|
| R1 | 4 missing result-level SARIF properties | §10.1 | Assessor following §15.6 procedure fails Step 4 | Add `enclosingTier`, `annotationGroups`, `excepted`, `dataSource` to `sarif.py:198-219` |
| R2 | 2 missing run-level SARIF properties | §10.1 | Same | Add `deterministic`, `deferredFixRatio` to `sarif.py:332-386` |
| R3 | Corpus `expected_match` is boolean | §10.1 | Verification only confirms rule fires, not location accuracy | Upgrade to structured `{line, text, function}` with SARIF snippet comparison |

### High (weakens conformance posture)

| # | Risk | Section | Impact | Remediation |
|---|------|---------|--------|-------------|
| R4 | Control law missing corpus staleness trigger | §9.5 | May report "normal" when corpus is stale | Add corpus age check to `compute_control_law()` |
| R5 | `validation_scope` not enforced on Tier 2 boundaries | §13.1.2 | Boundary can claim T2 without declaring validation contracts | Add schema `required` or loader check |
| R6 | `coverageRatio` absent without fingerprint baseline | §12 | MUST visibility requirement conditional on optional artifact | Compute coverage independently of baseline |
| R7 | "Data paths traced" coverage metric absent | §12 | Only annotation coverage reported | Implement path coverage metric |

### Medium (acceptable for v1.0 with documentation)

| # | Risk | Section | Impact | Remediation |
|---|------|---------|--------|-------------|
| R8 | Group 16 parameterised trust_boundary missing | §6 | Cannot declare custom tier transitions | Document as known narrowing |
| R9 | Cross-language taint propagation absent | §5.4 | Python-only limitation | Document; UNKNOWN_RAW default is safe |
| R10 | Retrospective scan absence detection unclear | §9.5 | May not detect missing retrospective after degraded window | Verify CLI enforcement path |
| R11 | `resolve.py` and `regime.py` lack dedicated unit tests | Cross-cutting | Governance-critical code covered only transitively | Add focused unit tests |
| R12 | `assert` exclusion in rejection paths by omission | §7 | Fragile if someone adds Assert matching | Add explicit exclusion with comment |
| R13 | Delegation authority not checked at overlay merge | §13.1 | Schema prevents UNCONDITIONAL but not level mismatch | Add runtime check in merge path |

### Low (acceptable)

| # | Risk | Section | Impact |
|---|------|---------|--------|
| R14 | Overlay hash sorting not verified as lexicographic | §10.1 | May produce non-deterministic overlay ordering |
| R15 | Cross-module taint limited to per-file + dependency_taint | §8.1 | Within spec bounds (full transitive is "quality target") |
| R16 | Incremental analysis doesn't trace transitive dependents | §8.1 | SHOULD-level, not MUST |
| R17 | SIEM export not implemented | §9.2.1 | SHOULD for Assurance profile only |
| R18 | `wardline.taintState` emits non-canonical "UNKNOWN" for pseudo-rules | §A | Governance/TOOL-ERROR findings only |

---

## Prior Assessment Audit

**Assessment accuracy: HIGH**

- 101/101 PASS claims independently verified — all evidence is real
- 5/5 PARTIAL ratings confirmed as legitimate
- 0 false PASSes detected

**Discrepancies found (minor):**
1. SCAN-006 claims 244 specimens; actual count is 241 Python files
2. PY-010 text is stale — says "28/29 enforced" but commit `411fe98` implemented entry #25 (29/29 now enforced; reality is better than claimed)

**Gaps not flagged by assessment:**
- Missing §10.1 SARIF properties (R1-R2) are not called out as individual requirements in the assessment's requirement numbering
- Corpus `expected_match` weakness (R3) is not flagged

---

## Test Suite Health

| Metric | Value |
|--------|-------|
| Total tests | 2,158 |
| Failures | 0 |
| Deselected (integration/network) | 166 |
| Duration | 4.53s |
| mypy errors | 0 (89 source files) |
| Rule test files | 12/12 rules covered |
| Core algebra tests | 512-triple associativity, 64-pair commutativity |
| SARIF tests | 70+ |
| Taint propagation tests | 120+ across 3 levels |

**Modules lacking dedicated unit tests:**
- `manifest/resolve.py` — governance scope enforcement (MEDIUM risk)
- `manifest/regime.py` — ratification age computation (MEDIUM risk)
- `scanner/rejection_path.py` — covered transitively via rule tests (LOW risk)

---

## Final Recommendation

### SHIP WITH CAVEATS

**Mandatory before release (R1-R3):**

1. **Add 6 missing SARIF properties** — `enclosingTier`, `annotationGroups`, `excepted`, `dataSource` (result-level) + `deterministic`, `deferredFixRatio` (run-level). These are straightforward additions to `sarif.py` with data already available in the `Finding` and `ScanContext` objects. Without these, an assessor following the §15.6 procedure will fail the implementation at Step 4.

2. **Upgrade corpus `expected_match`** — Change from boolean to structured `{line, text, function}` and add SARIF snippet text comparison in `corpus_cmds.py`. This strengthens verification property 1 from "rule fires" to "rule fires at the correct location."

**Recommended before release (R4-R7):**

3. Add corpus staleness and precision/recall floor checks to `compute_control_law()`
4. Enforce `validation_scope` on Tier 2 boundaries
5. Compute coverage ratio independently of fingerprint baseline
6. Implement or document "data paths traced" coverage metric

**Document as known narrowings (R8-R9):**

7. Group 16 parameterised trust boundary — covered by Group 1 decorators for standard transitions
8. Cross-language taint propagation — Python-only binding, UNKNOWN_RAW default is safe

**Architectural assessment:** The implementation is structurally sound and well-tested. The core domain model (taint algebra, tier model, severity matrix) is thoroughly verified with exhaustive property tests. The governance model is comprehensive. The gaps are concentrated in SARIF output completeness and corpus verification precision — both are additive fixes, not architectural issues.
