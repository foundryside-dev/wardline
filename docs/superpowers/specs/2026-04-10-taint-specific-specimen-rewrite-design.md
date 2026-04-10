# Taint-Specific Specimen Rewrite

> **Purpose:** Eliminate inflated specimen count by making each taint-matrix
> specimen's fragment unique and self-documenting, and collapsing taint-invariant
> rules to a single specimen per verdict.

**Branch:** `phase-4.4-test-quality-gates`
**Issue:** `wardline-01a36526c7`
**Prerequisite for:** Workstream B (corpus `expected_match` upgrade)

---

## 1. Problem Statement

139 of 259 corpus specimens (54%) are taint-state clones — identical Python
fragments with only the `taint_state` YAML metadata changed. This inflates the
specimen count without adding detection coverage. A reader seeing 8 taint
variants assumes taint matters for each, but the code is byte-for-byte identical.

## 2. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Taint-sensitive rules (001–007) | Rewrite fragments to be structurally minimal but unique | Each fragment uses distinct variable/function names hinting at taint provenance |
| Taint-invariant rules (008, 009) | Collapse to 1 TP + 1 TN per rule | Taint changes nothing — severity, exceptionability, and detection are all identical across all 8 taint states |
| Fragment naming | `{rule_pattern}_{taint_context}` function names | Self-documenting: the function name tells you the rule and trust level |
| Structural complexity | Minimal — same pattern shape, different names | Maintenance-friendly; realistic corpus enhancement deferred to future work |
| SCN-021, SUP-001 | No changes | Already unique — no taint clones exist |
| ADV-vs-rule duplicates | Out of scope | Cross-category duplication is a separate concern |

## 3. Taint Context Vocabulary

Each taint state maps to a consistent naming context used across all rules:

| Taint State | Tier | Context Noun | Example Variable | Example Function Suffix |
|-------------|------|-------------|-----------------|------------------------|
| INTEGRAL | 1 | system config | `sys_config` | `_system_config` |
| ASSURED | 1 | verified payload | `verified_payload` | `_verified_payload` |
| GUARDED | 2 | session data | `session_data` | `_session_data` |
| UNKNOWN_ASSURED | 2 | claimed_token | `claimed_token` | `_claimed_token` |
| UNKNOWN_GUARDED | 2 | cached_profile | `cached_profile` | `_cached_profile` |
| UNKNOWN_RAW | 3 | unknown_input | `unknown_input` | `_unknown_input` |
| EXTERNAL_RAW | 4 | request_param | `request_param` | `_request_param` |
| MIXED_RAW | 4 | mixed_source | `mixed_source` | `_mixed_source` |

## 4. Fragment Rewrites by Rule

### 4.1 PY-WL-001: Dict key access with fallback default

**Pattern:** `.get("key", "default")` — must have a second argument.

**TP fragments (8 specimens):** Currently all `def process(data): x = data.get("key", "default")`

| Taint | New Fragment |
|-------|-------------|
| INTEGRAL | `def dict_default_system_config(sys_config):\n    x = sys_config.get("key", "default")\n` |
| ASSURED | `def dict_default_verified_payload(verified_payload):\n    x = verified_payload.get("key", "default")\n` |
| GUARDED | `def dict_default_session_data(session_data):\n    x = session_data.get("key", "default")\n` |
| UNKNOWN_ASSURED | `def dict_default_claimed_token(claimed_token):\n    x = claimed_token.get("key", "default")\n` |
| UNKNOWN_GUARDED | `def dict_default_cached_profile(cached_profile):\n    x = cached_profile.get("key", "default")\n` |
| UNKNOWN_RAW | `def dict_default_unknown_input(unknown_input):\n    x = unknown_input.get("key", "default")\n` |
| EXTERNAL_RAW | `def dict_default_request_param(request_param):\n    x = request_param.get("key", "default")\n` |
| MIXED_RAW | `def dict_default_mixed_source(mixed_source):\n    x = mixed_source.get("key", "default")\n` |

**TN fragments (8 specimens):** Currently all `def process(data): x = data.get("key")`

| Taint | New Fragment |
|-------|-------------|
| INTEGRAL | `def no_default_system_config(sys_config):\n    x = sys_config.get("key")\n` |
| ASSURED | `def no_default_verified_payload(verified_payload):\n    x = verified_payload.get("key")\n` |
| GUARDED | `def no_default_session_data(session_data):\n    x = session_data.get("key")\n` |
| UNKNOWN_ASSURED | `def no_default_claimed_token(claimed_token):\n    x = claimed_token.get("key")\n` |
| UNKNOWN_GUARDED | `def no_default_cached_profile(cached_profile):\n    x = cached_profile.get("key")\n` |
| UNKNOWN_RAW | `def no_default_unknown_input(unknown_input):\n    x = unknown_input.get("key")\n` |
| EXTERNAL_RAW | `def no_default_request_param(request_param):\n    x = request_param.get("key")\n` |
| MIXED_RAW | `def no_default_mixed_source(mixed_source):\n    x = mixed_source.get("key")\n` |

**Note:** PY-WL-001 also has a KFN group (sha `fde5ab3dd8`, 9 specimens mixing
TP and KFN verdicts). These share the same fragment as the TP group. Apply the
same naming pattern — each specimen gets the fragment matching its taint state.
The KFN specimens at EXTERNAL_RAW, MIXED_RAW, UNKNOWN_RAW use the same function
name as their taint's TP counterpart since the fragment is structurally identical
(the difference is only in expected verdict).

**PY-WL-001 non-matrix duplicates:**
- `PY-WL-001-TN-02` (EXTERNAL_RAW) and `PY-WL-001-TN-04` (UNKNOWN_RAW) share
  fragment `def process(data): x = data["key"]`. Rewrite TN-04 to
  `def direct_key_unknown_input(unknown_input): x = unknown_input["key"]` and
  TN-02 to `def direct_key_request_param(request_param): x = request_param["key"]`.

### 4.2 PY-WL-002: Attribute access with fallback default

**Pattern:** `getattr(obj, "name", default)` — must have a third argument.

**TP fragments (8 specimens):** Currently all `def process(obj): x = getattr(obj, "name", None)`

Apply naming: `def getattr_default_{context}({var}): x = getattr({var}, "name", None)`

**TN fragments (9 specimens):** Currently all `def process(obj): x = getattr(obj, "name")`

Apply naming: `def getattr_no_default_{context}({var}): x = getattr({var}, "name")`

**Note:** TN group has 9 specimens (includes PY-WL-002-TN-01 at EXTERNAL_RAW
alongside PY-WL-002-TN-EXTERNAL_RAW — both are EXTERNAL_RAW with identical
fragment). Delete PY-WL-002-TN-01 as a true duplicate (same taint, same fragment,
same verdict). Keep PY-WL-002-TN-EXTERNAL_RAW for naming consistency.

### 4.3 PY-WL-003: Existence-checking as structural gate

**Pattern:** `if "key" in data` — membership test used as control flow.

**TP fragments (8 specimens):** Currently all `def process(data): if "key" in data: pass`

Apply naming: `def key_check_{context}({var}): if "key" in {var}: pass`

**TN fragments (8 specimens):** Currently all `def process(data): x = data["key"]`

Apply naming: `def direct_access_{context}({var}): x = {var}["key"]`

### 4.4 PY-WL-004: Broad exception handlers

**Pattern:** `except Exception` (or bare `except` or `except BaseException`).

**TP fragments (8 specimens):** Currently all `def process(): try: pass; except Exception: handle()`

Apply naming: `def broad_except_{context}(): try: pass; except Exception: handle()`

**TN fragments (8 specimens):** Currently all `def process(): try: pass; except ValueError: handle()`

Apply naming: `def specific_except_{context}(): try: pass; except ValueError: handle()`

**Non-matrix duplicates:**
- `PY-WL-004-TN-01` (EXTERNAL_RAW) and `PY-WL-004-TN-03` (UNKNOWN_RAW) share
  `def process(data): try: x = int(data); except ValueError: x = 0`. Rewrite
  with taint-specific naming.

### 4.5 PY-WL-005: Silent exception handling

**Pattern:** `except Exception: pass` (or `...` or bare return).

**TP fragments (8 specimens):** Currently all `def process(): try: pass; except Exception: pass`

Apply naming: `def silent_except_{context}(): try: pass; except Exception: pass`

**TN fragments (8 specimens):** Currently all `def process(): try: pass; except ValueError: pass`

Apply naming: `def silent_specific_{context}(): try: pass; except ValueError: pass`

### 4.6 PY-WL-006: Audit-critical writes in broad handlers

**Pattern:** `except Exception:` with audit write (logger/print) in handler.

**TP fragments (8 specimens):** Currently all `def process(): try: risky(); except Exception: logger.error("failed")`

Apply naming: `def audit_broad_{context}(): try: risky(); except Exception: logger.error("failed")`

**TN fragments (8 specimens):** Currently all `def process(): try: risky(); except ValueError: logger.error("failed")`

Apply naming: `def audit_specific_{context}(): try: risky(); except ValueError: logger.error("failed")`

### 4.7 PY-WL-007: Runtime type-checking on internal data

**Pattern:** `isinstance(data, type)` used as control flow.

**TP/TN-SUPPRESS group (8 specimens, mixed verdicts):** Currently all
`def process(data): if isinstance(data, dict): pass`. At EXTERNAL_RAW and
UNKNOWN_RAW this is TN (suppressed — type-checking external data is expected).
At other taint states it's TP.

Apply naming: `def isinstance_check_{context}({var}): if isinstance({var}, dict): pass`

**TN group A (6 specimens):** Currently all `def process(data): x = len(data)`

Apply naming: `def no_typecheck_{context}({var}): x = len({var})`

**TN group B (2 specimens):** `PY-WL-007-TN-EXTERNAL_RAW` and
`PY-WL-007-TN-UNKNOWN_RAW` share `def process(data): x = data["key"]`.

Apply naming: `def direct_access_{context}({var}): x = {var}["key"]`

### 4.8 PY-WL-008: Declared boundary without rejection path (COLLAPSE)

**Taint-invariant.** Collapse from 8 TP + 8 TN → 1 TP + 1 TN.

Keep: `PY-WL-008-TP-EXTERNAL_RAW` → rename to `PY-WL-008-TP-standard`
Keep: `PY-WL-008-TN-EXTERNAL_RAW` → rename to `PY-WL-008-TN-standard`

Delete the other 14 taint variants (7 TP + 7 TN). Keep taint_state as
EXTERNAL_RAW on the retained specimens (conservative default; the rule ignores
it). Move kept specimens from `EXTERNAL_RAW/` into a `standard/` subdirectory.

Existing unique adversarial specimens are untouched:
- `PY-WL-008-TN-AFP-has-rejection` (ASSURED)
- `PY-WL-008-TP-AFN-no-rejection` (ASSURED)

### 4.9 PY-WL-009: Semantic boundary without shape validation (COLLAPSE)

Same as PY-WL-008. Collapse 8 TP + 8 TN → 1 TP + 1 TN.

Keep: `PY-WL-009-TP-EXTERNAL_RAW` → rename to `PY-WL-009-TP-standard`
Keep: `PY-WL-009-TN-EXTERNAL_RAW` → rename to `PY-WL-009-TN-standard`

Delete the other 14 taint variants (7 TP + 7 TN). Same directory treatment as
PY-WL-008.

Existing unique adversarial specimens are untouched:
- `PY-WL-009-TN-AFP-shape-before-semantic` (ASSURED)
- `PY-WL-009-TP-AFN-noop-shape-check` (ASSURED)
- `PY-WL-009-TP-TF-shape-only` (ASSURED)

## 5. Directory Structure Changes

### Before (PY-WL-004 example)
```
PY-WL-004/
  ASSURED/positive/PY-WL-004-TP-ASSURED.yaml
  ASSURED/negative/PY-WL-004-TN-ASSURED.yaml
  EXTERNAL_RAW/positive/PY-WL-004-TP-EXTERNAL_RAW.yaml
  EXTERNAL_RAW/negative/PY-WL-004-TN-EXTERNAL_RAW.yaml
  ...8 taint dirs, each with positive/ and negative/
```

### After (unchanged)

The directory structure stays the same — specimens remain in their
`{TAINT_STATE}/{positive,negative}/` directories. Only the YAML content changes.

For PY-WL-008/009, the 7 deleted taint directories become empty and are removed.
The kept specimen stays in `EXTERNAL_RAW/` (the taint_state field value is
preserved for directory consistency, though the rule ignores it).

## 6. Manifest Regeneration

After all specimen edits, regenerate `corpus/corpus_manifest.json` using the
existing generation script. The sha256 values will change for all rewritten
specimens since fragment content changed.

## 7. Acceptance Criteria

1. **Zero duplicate sha256 values** within any rule (except ADV cross-references,
   which are out of scope)
2. **`corpus verify` passes** with zero failures
3. **Specimen count drops** from 259 to 230 (28 deleted from PY-WL-008/009 + 1 PY-WL-002-TN-01 duplicate)
4. **Every taint-matrix function name** follows the `{rule_pattern}_{taint_context}`
   convention
5. **No functional change** to scanner behavior — only corpus metadata changes

## 8. Relationship to Workstream B

This work should be completed BEFORE Workstream B (structured `expected_match`
upgrade). When Workstream B computes `expected_match.line`, `.text`, `.function`
for each specimen, every fragment will produce unique values — making the
structured verification genuinely meaningful rather than verifying the same
match point 8 times.

## 9. Out of Scope

- Adversarial specimen duplicates (ADV-* sharing fragments with rule specimens)
- Realistic/enhanced fragments (different code patterns per taint level)
- PY-WL-001 KFN-get-default and schema-default duplicates (semantic, not taint-matrix)
- SCN-021 and SUP-001 (no taint clones)
