# Workstream A: SARIF Completeness

> **Purpose:** Spec and implementation plan for closing all SARIF property gaps
> identified in the 2026-04-09 conformance review (R1, R2, R14, R18).
> Give this to an implementation agent. It is self-contained.

**Branch:** `phase-4.4-test-quality-gates`
**Conformance review:** `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`
**Spec authority:** `docs/spec/wardline-01-11-verification-properties.md`

---

## 1. Problem Statement

The external conformance review (2026-04-09) identified 4 SARIF-related
findings that block a v1.0 conformance claim. An assessor following the
§15.6 procedure will fail the implementation at Step 4 because the SARIF
output is missing mandatory properties defined in §11.1.

| Finding | Severity | Description |
|---------|----------|-------------|
| R1 | CRITICAL | 4 missing result-level properties (`enclosingTier`, `annotationGroups`, `excepted`, `dataSource`) |
| R2 | CRITICAL | 2 missing run-level properties (`deterministic`, `deferredFixRatio`) |
| R14 | LOW | Overlay hash lexicographic ordering not test-verified |
| R18 | LOW | `taintState` emits non-canonical `"UNKNOWN"` for pseudo-rule findings |

**Out of scope:** R3 (corpus `expected_match` structure) is a separate
workstream — it touches corpus infrastructure, not SARIF emission.

---

## 2. Normative Requirements (from §11.1)

### 2.1 Result-Level Properties (per finding)

Every SARIF `result` MUST carry these in its `properties` bag:

| Property | Type | Spec Text |
|----------|------|-----------|
| `wardline.enclosingTier` | `int` (1-4) | "the authority tier (1, 2, 3, 4) of the enclosing scope" |
| `wardline.annotationGroups` | `list[int]` | "which of the 17 annotation groups are declared on the enclosing function. Bindings MUST use the Part I group numbers, not binding-specific annotation names" |
| `wardline.excepted` | `bool` | "boolean indicating whether an active exception covers this finding. Excepted findings are still emitted — they are visible, not suppressed" |
| `wardline.dataSource` | `str \| null` | "the named data source from the wardline manifest, if applicable" |

Already present (no changes needed): `wardline.rule`, `wardline.taintState`,
`wardline.severity`, `wardline.exceptionability`, `wardline.analysisLevel`,
`wardline.qualname`, `wardline.sourceSnippet`, `wardline.exceptionId`,
`wardline.exceptionExpires`, `wardline.retroactiveScan`.

**SHOULD-level (not in this workstream):** `wardline.exceptionRecurrence` —
integer count of exception renewals. Present only on findings with active
exceptions. Deferred to post-v1.0 because it requires wiring recurrence_count
from the matched ExceptionEntry onto each Finding at match time.

### 2.2 Run-Level Properties (per scan run)

Every SARIF `run` MUST carry these in its `properties` bag:

| Property | Type | Spec Text |
|----------|------|-----------|
| `wardline.deterministic` | `bool` | "boolean self-report that the tool believes its output is deterministic. A declaration of intent, not verification evidence" |
| `wardline.deferredFixRatio` | `float` | "the proportion of active exceptions that represent deferred architectural fixes rather than genuine domain variance (§14.1.3)" |

### 2.3 Correctness Constraints

1. `enclosingTier` MUST be derived from `TAINT_TO_TIER[finding.taint_state]`.
   When `taint_state is None` (pseudo-rule findings), emit `null` — pseudo-rules
   operate outside the tier model, and emitting a fabricated tier value would be
   misleading. The spec says "the authority tier of the enclosing scope" — a
   governance finding at `<governance>:1` has no enclosing scope with a tier.

2. `annotationGroups` MUST use Part I group numbers (1-17), NOT decorator names.
   The `WardlineAnnotation.group` field already stores these. The array MUST be
   sorted ascending and deduplicated.

3. `excepted` is `finding.exception_id is not None`. This MUST be emitted on
   every result, not conditionally.

4. `dataSource` comes from `dependency_taint` declarations in the manifest.
   When a finding's taint provenance does not trace to a declared dependency,
   emit `null`. For v1.0, since the taint provenance system does not currently
   carry dependency attribution through to findings, this field will be `null`
   on all findings. The field MUST be present (as `null`) to satisfy the
   property bag contract — the spec says "if applicable", meaning the field
   is always emitted but its value can be null.

5. `deterministic` is always `true` for wardline. The scanner's output is
   deterministic by design (sorted findings, `sort_keys=True` JSON,
   verification mode strips volatile data). Determinism holds within a
   fixed CPython version — AST node positions may differ across CPython
   releases (e.g., `col_offset` changes between 3.12 and 3.13).

6. `deferredFixRatio` is computed as:
   ```
   count(exceptions with elimination_path) / count(all active exceptions)
   ```
   Special cases:
   - Zero active exceptions → emit `0.0`
   - Active exceptions exist but NONE have `elimination_path` → emit `null`
     (means "not yet classified", distinct from "zero deferred fixes").
     **Note:** This differs from `coverageRatio`, which is *omitted* (key absent)
     when null. `deferredFixRatio` is always *present* — `null` is a meaningful
     signal ("unclassified"), distinct from absent ("feature not applicable").
     The `coverageRatio` conditional-omission pattern at `sarif.py:342-343` must
     NOT be followed here.
   - At least one exception has `elimination_path` → emit the computed ratio.

   The `elimination_path` field does not yet exist on `ExceptionEntry` —
   it must be added (see §14.1.3 in the spec). After adding the field,
   `deferredFixRatio` will be `null` for the current exception register
   (78+ exceptions, zero classified) — which is the correct signal.

7. `taintState` MUST emit `null` (not `"UNKNOWN"`) for findings where
   `taint_state is None`. The 8 canonical tokens are a closed set; `"UNKNOWN"`
   is not among them.

8. `overlayHashes` ordering MUST be verified by test as lexicographic by
   forward-slash-normalized relative path.

9. **Verification mode:** All 6 new properties are deterministic and MUST
   NOT be stripped in verification mode. `enclosingTier` is derived from
   taint (deterministic), `annotationGroups` from annotations (deterministic),
   `excepted` from exception_id (deterministic), `dataSource` is always null
   (deterministic), `deterministic` is always true, `deferredFixRatio` is
   computed from static data. No `verification_mode` guards needed.

---

## 3. Current State Audit

### 3.1 Finding Creation Sites

There are **two code paths** that create findings. Both must be updated for
`annotation_groups` and `data_source`:

**Path A: `_emit_matrix_finding()` in `base.py:183-207`**

Used by 7 rule files (11 call sites total):

| Rule file | Call count |
|-----------|-----------|
| `py_wl_004.py` | 3 |
| `py_wl_005.py` | 1 |
| `py_wl_006.py` | 2 |
| `py_wl_007.py` | 2 |
| `py_wl_008.py` | 1 |
| `py_wl_009.py` | 1 |
| `base.py` (definition) | 1 |

**Path B: Direct `Finding()` construction**

Used by 7 rule files (10 call sites total):

| Rule file | Call count | Notes |
|-----------|-----------|-------|
| `py_wl_001.py` | 3 | Multiple detection patterns |
| `py_wl_002.py` | 1 | |
| `py_wl_003.py` | 1 | |
| `scn_021.py` | 1 | Contradictory decorator pairs + fix `taint_state=None` → `_get_function_taint()` |
| `scn_022.py` | 2 | Field-completeness |
| `sup_001.py` | 1 | Contract violation + fix `taint_state=None` → `_get_function_taint()` |

**Path C: `make_governance_finding()` in `context.py:180-213`**

Factory for governance pseudo-rule findings. Sets `taint_state=None`,
`analysis_level=0`. These have no enclosing function scope, so
`annotation_groups=()` and `data_source=None` are correct defaults.

### 3.2 SARIF Emission (`sarif.py`)

- `_make_result()` at lines 195-237: Builds per-finding properties bag.
  Missing: `enclosingTier`, `annotationGroups`, `excepted`, `dataSource`.
- `to_dict()` at lines 332-386: Builds run-level properties bag.
  Missing: `deterministic`, `deferredFixRatio`.
- `taintState` fallback at line 203: Emits `"UNKNOWN"` instead of `null`.

### 3.3 `ExceptionEntry` (`models.py:22-46`)

Does NOT have `elimination_path` or `elimination_cost` fields.
The spec (§14.1.3) defines these as optional but recommended. They are
required for computing `deferredFixRatio`.

### 3.4 Self-Hosting Exception Register

`wardline.exceptions.json` contains 78+ exceptions. None currently have
`elimination_path` because the field doesn't exist on the dataclass.
After adding the field, `deferredFixRatio` will be `null` (not `0.0`)
because 78 exceptions with zero classification means "unclassified,"
not "zero deferred fixes." The ratio becomes a real number only after
at least one exception has `elimination_path` set.

---

## 4. Implementation Plan

### 4.1 Execution Order and Dependencies

```
R18 (taintState null)     ─── no deps ───────────────────── smallest change
  │
R14 (overlay hash test)   ─── no deps ───────────────────── test-only
  │
R1  (4 result properties) ─── depends on Finding changes ── largest change
  │
R2  (2 run properties)    ─── depends on ExceptionEntry ─── schema change
```

All four are independent except that R1 and R2 both touch `sarif.py`, so
they should not be developed in parallel. R18 → R14 → R1 → R2 is the
optimal order: smallest-to-largest, building confidence incrementally.

### 4.2 Fix R18: Emit `null` for `taintState` on pseudo-rule findings

**Risk:** LOW. Single-line change, well-tested code path.

**Changes:**

1. **`src/wardline/scanner/sarif.py:200-204`** — Change the `taintState`
   fallback from `"UNKNOWN"` to `None`:

   ```python
   # BEFORE
   "wardline.taintState": (
       str(finding.taint_state)
       if finding.taint_state is not None
       else "UNKNOWN"
   ),

   # AFTER
   "wardline.taintState": (
       str(finding.taint_state)
       if finding.taint_state is not None
       else None
   ),
   ```

2. **`tests/unit/scanner/test_sarif.py`** — Update these specific tests:

   - Search for `"UNKNOWN"` and change assertions to expect `None`.
   - **`test_mandatory_properties_never_omitted` (line 119-133):** This
     test asserts `props[key] is not None` for ALL mandatory properties
     including `wardline.taintState`. After R18, taintState IS None for
     pseudo-rule findings. Fix by splitting the assertion: check key
     *presence* for all mandatory properties, but only check `is not None`
     for properties that are never null. Exclude ALL nullable mandatory
     properties: `taintState`, `enclosingTier`, and `dataSource`.

3. **Add negative regression test** to prevent reintroduction of `"UNKNOWN"`:

   ```python
   def test_no_unknown_string_in_serialized_sarif(self) -> None:
       """No non-canonical 'UNKNOWN' token in serialized SARIF output."""
       report = SarifReport(findings=[_make_finding(taint_state=None)])
       json_str = report.to_json_string()
       # "UNKNOWN" should not appear as a taintState value.
       # It may appear in message text — check the properties specifically.
       sarif = json.loads(json_str)
       for result in sarif["runs"][0]["results"]:
           ts = result["properties"]["wardline.taintState"]
           assert ts is None or ts in {
               "INTEGRAL", "ASSURED", "GUARDED", "EXTERNAL_RAW",
               "UNKNOWN_RAW", "UNKNOWN_GUARDED", "UNKNOWN_ASSURED", "MIXED_RAW",
           }, f"Non-canonical taintState: {ts!r}"
   ```

**Tests:**
- Existing test updated to expect `None`
- Mandatory properties test updated to handle nullable taintState
- Negative regression test prevents reintroduction of `"UNKNOWN"`

**Commit:** `fix(R18): emit null for taintState on pseudo-rule findings`

---

### 4.3 Fix R14: Verify overlay hash lexicographic ordering

**Risk:** LOW. Test-only change, no production code modification.

**Changes:**

1. **New test** in `tests/unit/cli/test_scan_helpers.py`, inside the existing
   `TestComputeOverlayHashes` class (which already tests this function).
   The existing test `test_sorted_by_normalized_path` verifies basic sort
   order but does NOT verify that path-order differs from hash-order.
   `_compute_overlay_hashes` is a module-level function at
   `src/wardline/cli/scan.py:121-146` and is already imported in that file:

   ```python
   import hashlib
   from wardline.cli.scan import _compute_overlay_hashes

   def test_overlay_hashes_sorted_lexicographically_by_path(
       self, tmp_path: Path
   ) -> None:
       """Overlay hashes must be ordered by POSIX-normalized relative path."""
       overlays_dir = tmp_path / "overlays"
       (overlays_dir / "a").mkdir(parents=True)
       (overlays_dir / "b").mkdir(parents=True)

       # Content deliberately chosen so hash-alphabetical order differs
       # from path-alphabetical order.
       files = {
           overlays_dir / "a" / "z.yaml": "overlay_for: a/z\n",
           overlays_dir / "b" / "a.yaml": "overlay_for: b/a\n",
           overlays_dir / "a" / "a.yaml": "overlay_for: a/a\n",
       }
       for path, content in files.items():
           path.write_text(content)

       # Pass in NON-sorted order to verify the function sorts internally.
       hashes = _compute_overlay_hashes(
           [overlays_dir / "b" / "a.yaml",
            overlays_dir / "a" / "z.yaml",
            overlays_dir / "a" / "a.yaml"],
           project_root=tmp_path,
       )

       # Compute expected hashes in path-sorted order.
       def sha(content: str) -> str:
           return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

       expected = (
           sha("overlay_for: a/a\n"),   # overlays/a/a.yaml
           sha("overlay_for: a/z\n"),   # overlays/a/z.yaml
           sha("overlay_for: b/a\n"),   # overlays/b/a.yaml
       )
       assert hashes == expected
   ```

**Commit:** `test(R14): verify overlay hash lexicographic ordering invariant`

---

### 4.4 Fix R1: Add 4 missing result-level SARIF properties

**Risk:** MEDIUM. Touches the `Finding` dataclass (frozen, used everywhere)
and the base class `_emit_matrix_finding`. Changes propagate to all rule
files that construct `Finding` directly.

#### Step 1: Extend the `Finding` dataclass

**`src/wardline/scanner/context.py:22-47`** — Add two new fields with defaults
so all existing `Finding()` construction sites remain valid:

```python
@dataclass(frozen=True, kw_only=True)
class Finding:
    # ... existing fields ...
    retroactive_scan: bool = False
    # R1: §11.1 result-level properties
    annotation_groups: tuple[int, ...] = ()
    data_source: str | None = None  # Always None in v1.0 — requires taint provenance threading to populate
```

**Why defaults:** `Finding` is `kw_only=True` and `frozen=True`. Adding
fields with defaults means zero existing call sites break. The `()` default
for `annotation_groups` is semantically correct (no annotations discovered).

**Path C requires no changes.** `make_governance_finding()` at
`context.py:180-213` will inherit the new defaults (`annotation_groups=()`,
`data_source=None`), which are correct for governance findings — they have
no enclosing function scope and no data source.

#### Step 2: Add annotation group lookup to `RuleBase`

**`src/wardline/scanner/rules/base.py`** — Add a helper method:

```python
def _get_annotation_groups(self) -> tuple[int, ...]:
    """Get sorted, deduplicated annotation group numbers for the current function.

    Returns the Part I group numbers (1-17) of all wardline annotations
    declared on the function. Used to populate the §11.1 SARIF
    property ``wardline.annotationGroups``.

    The result is sorted at creation time for convenience, but
    ``_make_result()`` also sorts at emission time as a defensive
    safeguard.
    """
    if not self._current_qualname or self._context is None:
        return ()
    annotations_map = self._context.annotations_map
    if annotations_map is None:
        return ()
    annotations = annotations_map.get(self._current_qualname, ())
    return tuple(sorted({a.group for a in annotations}))
```

**Why no `qualname` parameter:** All rules (including SCN-021 and SUP-001)
emit findings against `self._current_qualname`, which is set by
`_dispatch()` before `visit_function()` runs. No rule needs to look up
annotation groups for a different function than the one being visited.

#### Step 3: Update `_emit_matrix_finding` (Path A)

**`src/wardline/scanner/rules/base.py:183-207`** — Pass annotation_groups
to the Finding constructor:

```python
def _emit_matrix_finding(self, node: ast.AST, message: str) -> None:
    taint = self._get_function_taint(self._current_qualname)
    cell = matrix.lookup(self.RULE_ID, taint)
    self.findings.append(
        Finding(
            rule_id=self.RULE_ID,
            file_path=self._file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            end_line=getattr(node, "end_lineno", None),
            end_col=getattr(node, "end_col_offset", None),
            message=message,
            severity=cell.severity,
            exceptionability=cell.exceptionability,
            taint_state=taint,
            analysis_level=1,
            source_snippet=None,
            qualname=self._current_qualname,
            annotation_groups=self._get_annotation_groups(),
        )
    )
```

This single change covers **all 7 rule files** that use `_emit_matrix_finding`
(py_wl_004, py_wl_005, py_wl_006, py_wl_007, py_wl_008, py_wl_009, and the
definition in base.py). No changes to those rule files needed.

#### Step 4: Update direct `Finding()` construction sites (Path B)

Each of the 7 rule files that construct `Finding()` directly must pass
`annotation_groups`. The pattern is the same in each case — add
`annotation_groups=self._get_annotation_groups()` to the keyword arguments.

**Files to modify (with direct Finding construction):**

| File | Approximate line(s) | Notes |
|------|---------------------|-------|
| `py_wl_001.py` | 3 sites | Check each — qualname may differ |
| `py_wl_002.py` | 1 site | |
| `py_wl_003.py` | 1 site | |
| `scn_021.py` | 1 site | Uses project_annotations_map, not per-file |
| `scn_022.py` | 2 sites | |
| `sup_001.py` | 1 site | |

**No special cases needed.** All Path B rules emit findings against the
current function (`self._current_qualname` / `self._file_path`), so the
standard `self._get_annotation_groups()` call works for all of them:

- **SCN-021:** Uses per-file `annotations_map` (keyed by `qualname` string,
  verified at `scn_021.py:223-224`). The `_get_annotation_groups()` helper
  reads the same map. Standard call works.
- **SUP-001:** Uses `project_annotations_map` for cross-file constraint
  *lookups* (`sup_001.py:380-401`), but its `_emit()` method
  (`sup_001.py:924-941`) emits findings against `self._current_qualname`
  — the function being visited, not the remote function. Standard call works.
- **SCN-022:** Standard call works.

**Also fix taint_state=None in SCN-021 and SUP-001.** Both rules currently
hardcode `taint_state=None` on their findings (`scn_021.py:253`,
`sup_001.py:936`), but they fire on decorated functions that *do* have
tiers. This means `enclosingTier` would be `null` — a factual error in
the SARIF output that partially undermines the R1 conformance fix.

Both rules inherit `_get_function_taint()` from `RuleBase`. The fix is
small: replace `taint_state=None` with
`taint_state=self._get_function_taint(self._current_qualname)` at both
sites. This gives correct `enclosingTier` values for these findings.

**Note:** SCN-021 has a fallback path (`scn_021.py:226-232`) where
`annotations_map` has no entry for the qualname, so it parses decorator
names directly from the AST. In this case, `_get_annotation_groups()` will
return `()` even though decorators are present. This is a known limitation
— fixing it would require mapping AST decorator nodes to group numbers
at the rule level. Acceptable for v1.0.

#### Step 5: Add SARIF emission for the 4 properties

**`src/wardline/scanner/sarif.py:195-237`** (`_make_result`) — Add a helper
function and 4 properties:

Add a top-level import (no circular import risk — `sarif.py` already
imports from `wardline.core.severity`, and `wardline.core.tiers` only
imports from `wardline.core.taints`):

```python
# At the top of sarif.py, alongside existing imports:
from wardline.core.tiers import TAINT_TO_TIER

# Then the helper function:
def _taint_to_tier_value(taint_state: TaintState | None) -> int | None:
    """Map taint state to authority tier integer (1-4).

    Returns None for pseudo-rule findings (taint_state is None) —
    governance findings operate outside the tier model.
    """
    if taint_state is None:
        return None
    return TAINT_TO_TIER[taint_state].value
```

In `_make_result()`, add to the **mandatory** properties dict (lines
198-208), NOT through the `_clean_none` call on line 210.

**CRITICAL:** The `_clean_none()` helper at `sarif.py:161-163` strips all
`None`-valued keys. The new properties `enclosingTier` and `dataSource`
will be `null` for pseudo-rule findings and all v1.0 findings respectively.
If they are accidentally placed in the `_clean_none` block, they will be
silently dropped with no TypeError — only a missing-key test would catch it.

```python
# Add these to the mandatory properties dict at lines 198-208,
# BEFORE the _clean_none block at line 210.
"wardline.enclosingTier": _taint_to_tier_value(finding.taint_state),
"wardline.annotationGroups": sorted(set(finding.annotation_groups)),
"wardline.excepted": finding.exception_id is not None,
"wardline.dataSource": finding.data_source,
```

**Import:** Add `TaintState` to the `TYPE_CHECKING` imports at the top
(needed for the type annotation on `_taint_to_tier_value`).

**Note on double-sort/dedup:** `_get_annotation_groups()` returns a sorted,
deduplicated tuple, and `_make_result()` calls `sorted(set(...))` again.
The emission-time `sorted(set(...))` is a defensive safeguard — if someone
constructs a `Finding` directly with unsorted or duplicated groups, the SARIF
output is still correct. `sorted()` alone does NOT deduplicate: `sorted((3,1,3,1))`
gives `[1,1,3,3]`. The `set()` wrapper is required.

#### Step 6: Tests for R1

Add to `tests/unit/scanner/test_sarif.py`.

**REQUIRED imports** — the existing test file does NOT import `_make_result`
or `TaintState`. Add these to the import block:

```python
from wardline.core.taints import TaintState
from wardline.scanner.sarif import _make_result  # module-private, imported for direct testing
```

Then add the tests:

```python
@pytest.mark.parametrize("taint,expected_tier", [
    (TaintState.INTEGRAL, 1),
    (TaintState.ASSURED, 2),
    (TaintState.GUARDED, 3),
    (TaintState.UNKNOWN_ASSURED, 3),
    (TaintState.UNKNOWN_GUARDED, 3),
    (TaintState.EXTERNAL_RAW, 4),
    (TaintState.UNKNOWN_RAW, 4),
    (TaintState.MIXED_RAW, 4),
    (None, None),
])
def test_enclosing_tier_from_taint_state(self, taint, expected_tier) -> None:
    """enclosingTier derived from TAINT_TO_TIER for all 8 states + None."""
    finding = _make_finding(taint_state=taint)
    result = _make_result(finding, base_path=None)
    assert result["properties"]["wardline.enclosingTier"] == expected_tier

def test_annotation_groups_in_result(self) -> None:
    """Annotation groups appear sorted in result properties."""
    finding = _make_finding(annotation_groups=(5, 1, 12))
    result = _make_result(finding, base_path=None)
    assert result["properties"]["wardline.annotationGroups"] == [1, 5, 12]

def test_annotation_groups_empty(self) -> None:
    """No annotations → empty list."""
    finding = _make_finding(annotation_groups=())
    result = _make_result(finding, base_path=None)
    assert result["properties"]["wardline.annotationGroups"] == []

def test_annotation_groups_deduplicated(self) -> None:
    """Duplicate group numbers are deduplicated."""
    finding = _make_finding(annotation_groups=(3, 1, 3, 1))
    result = _make_result(finding, base_path=None)
    assert result["properties"]["wardline.annotationGroups"] == [1, 3]

def test_excepted_true_when_exception_id_set(self) -> None:
    """Finding with exception_id → excepted True."""
    finding = _make_finding(exception_id="EXC-001")
    result = _make_result(finding, base_path=None)
    assert result["properties"]["wardline.excepted"] is True

def test_excepted_false_when_no_exception(self) -> None:
    """Finding without exception_id → excepted False."""
    finding = _make_finding(exception_id=None)
    result = _make_result(finding, base_path=None)
    assert result["properties"]["wardline.excepted"] is False

def test_data_source_null_by_default(self) -> None:
    """Data source is null when not set."""
    finding = _make_finding()
    result = _make_result(finding, base_path=None)
    assert result["properties"]["wardline.dataSource"] is None

def test_data_source_string_when_set(self) -> None:
    """Data source appears as string when set."""
    finding = _make_finding(data_source="partner-api")
    result = _make_result(finding, base_path=None)
    assert result["properties"]["wardline.dataSource"] == "partner-api"

def test_nullable_mandatory_properties_present_as_keys(self) -> None:
    """Nullable mandatory properties must be present as KEYS even when null.

    This catches the _clean_none trap: if these are accidentally routed
    through _clean_none(), the keys disappear silently.
    """
    finding = _make_finding(taint_state=None, data_source=None)
    result = _make_result(finding, base_path=None)
    props = result["properties"]
    # These keys MUST exist even though their values are None/null.
    assert "wardline.enclosingTier" in props
    assert "wardline.dataSource" in props
    assert "wardline.taintState" in props
    # Verify they are actually null, not just present.
    assert props["wardline.enclosingTier"] is None
    assert props["wardline.dataSource"] is None
    assert props["wardline.taintState"] is None
```

Also add a **property bag completeness test** that asserts the full set
of mandatory result-level properties in a single test. This prevents
future property omissions:

```python
MANDATORY_RESULT_PROPERTIES = {
    "wardline.rule", "wardline.taintState", "wardline.severity",
    "wardline.exceptionability", "wardline.analysisLevel",
    "wardline.enclosingTier", "wardline.annotationGroups",
    "wardline.excepted", "wardline.dataSource",
}

def test_all_mandatory_result_properties_present(self) -> None:
    """All 9 mandatory result-level properties present (§11.1)."""
    finding = _make_finding(taint_state=TaintState.INTEGRAL)
    result = _make_result(finding, base_path=None)
    props = set(result["properties"].keys())
    missing = MANDATORY_RESULT_PROPERTIES - props
    assert not missing, f"Missing mandatory properties: {missing}"
```

**REQUIRED: Update the `_make_finding()` test helper** at
`tests/unit/scanner/test_sarif.py:16-48`. The existing helper does NOT
accept `exception_id`, `annotation_groups`, or `data_source`. The tests
above will fail with `TypeError` unless these are added. Add to the
helper signature and pass through to `Finding(...)`:

```python
exception_id: str | None = None,
annotation_groups: tuple[int, ...] = (),
data_source: str | None = None,
```

**Commit:** `fix(R1): add 4 missing result-level SARIF properties (§11.1)`

---

### 4.5 Fix R2: Add 2 missing run-level SARIF properties

**Risk:** MEDIUM. Requires `ExceptionEntry` schema change and YAML loader
update, plus computing the ratio in the scan CLI.

#### Step 1: Add `elimination_path` and `elimination_cost` to `ExceptionEntry`

**`src/wardline/manifest/models.py:22-46`** — Add after `migrated_by`:

```python
elimination_path: str | None = None
elimination_cost: str | None = None
```

These are optional fields with `None` default, so all existing exception
loading continues to work. The spec (§14.1.3) defines them as "optional
but recommended."

#### Step 2: Update the exception JSON schema

**`src/wardline/manifest/schemas/exceptions.schema.json`** — Add
`elimination_path` and `elimination_cost` as optional string properties
(type `"string"` or `["string", "null"]`).

#### Step 3: Update the exception loader

**`src/wardline/manifest/exceptions.py:60-81`** — The loader uses explicit
field construction (NOT `**kwargs`). Add the two new fields after
`migrated_by` at line 80:

```python
            migrated_by=raw.get("migrated_by"),
            elimination_path=raw.get("elimination_path"),
            elimination_cost=raw.get("elimination_cost"),
```

#### Step 4: Add fields to `SarifReport`

**`src/wardline/scanner/sarif.py:255-287`** — Add:

```python
deterministic: bool = True
deferred_fix_ratio: float | None = None
```

#### Step 5: Emit in `to_dict()`

**`src/wardline/scanner/sarif.py:332-386`** — Add to the run properties dict,
after `wardline.expeditedExceptionRatio`:

```python
"wardline.deterministic": self.deterministic,
"wardline.deferredFixRatio": (
    round(self.deferred_fix_ratio, 4)
    if self.deferred_fix_ratio is not None
    else None
),
```

#### Step 6: Compute `deferredFixRatio` in the scan CLI

**`src/wardline/cli/scan.py`** — Where exceptions are loaded and the
`SarifReport` is constructed, compute the ratio:

```python
active_exceptions = [...]  # however they're currently collected
has_any_classified = any(e.elimination_path for e in active_exceptions)
if not active_exceptions:
    deferred_fix_ratio = 0.0    # no exceptions at all → 0.0
elif not has_any_classified:
    deferred_fix_ratio = None   # unclassified → null (not "zero deferred")
else:
    deferred_count = sum(1 for e in active_exceptions if e.elimination_path)
    deferred_fix_ratio = deferred_count / len(active_exceptions)

# Pass to SarifReport
report = SarifReport(
    ...,
    deferred_fix_ratio=deferred_fix_ratio,
)
```

Search for ALL `SarifReport(` construction sites across the codebase
(`grep -rn 'SarifReport(' src/`). Each site must pass `deferred_fix_ratio`
explicitly. The default `None` on `SarifReport` means "unclassified" — if
a construction site has zero exceptions but doesn't pass `0.0`, it will
incorrectly emit `null`. Every site must compute or pass the correct value.

#### Step 7: Tests for R2

```python
def test_deterministic_always_true(self) -> None:
    """wardline.deterministic is always True."""
    report = SarifReport(findings=[])
    props = report.to_dict()["runs"][0]["properties"]
    assert props["wardline.deterministic"] is True

def test_deferred_fix_ratio_default_null(self) -> None:
    """Default deferred fix ratio is null (unclassified)."""
    report = SarifReport(findings=[])
    props = report.to_dict()["runs"][0]["properties"]
    assert props["wardline.deferredFixRatio"] is None

def test_deferred_fix_ratio_zero_when_no_exceptions(self) -> None:
    """Zero active exceptions → 0.0 (not null)."""
    report = SarifReport(findings=[], deferred_fix_ratio=0.0)
    props = report.to_dict()["runs"][0]["properties"]
    assert props["wardline.deferredFixRatio"] == 0.0

def test_deferred_fix_ratio_computed(self) -> None:
    """Deferred fix ratio reflects the value passed in."""
    report = SarifReport(findings=[], deferred_fix_ratio=0.3333)
    props = report.to_dict()["runs"][0]["properties"]
    assert props["wardline.deferredFixRatio"] == 0.3333

def test_deferred_fix_ratio_rounded(self) -> None:
    """Deferred fix ratio is rounded to 4 decimal places."""
    report = SarifReport(findings=[], deferred_fix_ratio=1/3)
    props = report.to_dict()["runs"][0]["properties"]
    assert props["wardline.deferredFixRatio"] == 0.3333
```

**Commit:** `fix(R2): add 2 missing run-level SARIF properties (§11.1)`

---

## 5. Property Bag Version

The current `wardline.propertyBagVersion` is `"0.4"` (`sarif.py:354`).
Adding 6 new properties to the bag is a schema-additive change —
consumers that ignore unknown properties are unaffected, but consumers
that validate against a known schema need the version bump.

**Decision:** Bump to `"0.5"` in the R1 commit (when result-level
properties are added), since that's the commit where the property bag
shape actually changes. Do NOT bump in R18 (changing a value from
`"UNKNOWN"` to `null` is a bug fix, not a schema change).

**Tests that must be updated in the R1 commit:**
- `tests/unit/scanner/test_sarif.py:364` — asserts `"0.4"`, change to `"0.5"`
- `tests/integration/test_scan_cmd.py:945` — asserts `"0.4"`, change to `"0.5"`

Add a comment in `sarif.py` documenting what each version means:
```python
# Property bag versions:
# "0.4" — initial stable schema (17 run-level, 5 result-level mandatory)
# "0.5" — R1+R2: 19 run-level, 9 result-level mandatory (§11.1 complete)
```

---

## 6. Verification Criteria

### 6.1 Per-Fix Verification

After each fix, run:

```bash
uv run pytest tests/unit/scanner/test_sarif.py -v
uv run pytest                     # full suite
uv run ruff check src/
uv run mypy src/
```

### 6.2 Post-Workstream Verification

After all 4 fixes:

1. **Self-hosting scan produces valid SARIF:**
   ```bash
   uv run wardline scan src/ --output /tmp/wardline-sarif.json
   ```
   Verify the output JSON contains all 6 new properties.

2. **Property presence check (manual or scripted):**
   ```python
   import json
   with open("/tmp/wardline-sarif.json") as f:
       sarif = json.load(f)
   run = sarif["runs"][0]
   # Run-level
   assert "wardline.deterministic" in run["properties"]
   assert "wardline.deferredFixRatio" in run["properties"]
   assert run["properties"]["wardline.propertyBagVersion"] == "0.5"
   # Result-level (spot check first result)
   if run["results"]:
       props = run["results"][0]["properties"]
       assert "wardline.enclosingTier" in props
       assert "wardline.annotationGroups" in props
       assert "wardline.excepted" in props
       assert "wardline.dataSource" in props
   ```

3. **No taintState "UNKNOWN" in output:**
   ```bash
   grep -c '"UNKNOWN"' /tmp/wardline-sarif.json
   # Should be 0 (or only in message text, not in taintState values)
   ```

4. **Test count delta:** Expect ~18 new tests (12 for R1 including
   parametrized tier test, dedup, key-presence, and completeness;
   4-5 for R2; 1 for R14; 2 updated/added for R18).

---

## 7. Risk Analysis

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| `Finding` field addition breaks downstream | LOW | LOW | Fields have defaults; `kw_only=True` means no positional arg shifts |
| `_emit_matrix_finding` change missed by a rule | MEDIUM | LOW | All 7 users go through the single base class method |
| Direct `Finding()` site missed | MEDIUM | MEDIUM | Use `grep -rn 'Finding(' src/wardline/scanner/rules/` to verify all sites |
| `ExceptionEntry` schema change breaks existing `.exceptions.json` | LOW | LOW | New fields are optional with `None` default |
| `deferredFixRatio` null for current exceptions | NONE | CERTAIN | Expected — null means "unclassified." Becomes a real ratio when at least one exception has `elimination_path`. |
| `annotation_groups` empty for functions with no annotations | NONE | CERTAIN | Correct behavior — unannotated functions have no groups |
| SCN-021 fallback path produces empty `annotationGroups` | LOW | RARE | Only triggers when `annotations_map` misses the qualname; returns `()` instead of actual groups. Known limitation. |

---

## 8. Files Reference

### Must Modify

| File | Changes |
|------|---------|
| `src/wardline/scanner/sarif.py` | R18 null fix, R1 result properties, R2 run properties, version bump |
| `src/wardline/scanner/context.py` | R1 Finding fields |
| `src/wardline/scanner/rules/base.py` | R1 annotation_groups helper + _emit_matrix_finding |
| `src/wardline/scanner/rules/py_wl_001.py` | R1 annotation_groups on 3 Finding sites |
| `src/wardline/scanner/rules/py_wl_002.py` | R1 annotation_groups on 1 Finding site |
| `src/wardline/scanner/rules/py_wl_003.py` | R1 annotation_groups on 1 Finding site |
| `src/wardline/scanner/rules/scn_021.py` | R1 annotation_groups + fix taint_state on 1 Finding site |
| `src/wardline/scanner/rules/scn_022.py` | R1 annotation_groups on 2 Finding sites |
| `src/wardline/scanner/rules/sup_001.py` | R1 annotation_groups + fix taint_state on 1 Finding site |
| `src/wardline/manifest/models.py` | R2 ExceptionEntry fields |
| `src/wardline/manifest/exceptions.py` | R2 loader update (explicit field construction at lines 60-81) |
| `src/wardline/manifest/schemas/exceptions.schema.json` | R2 JSON schema update |
| `src/wardline/cli/scan.py` | R2 deferredFixRatio computation |
| `tests/unit/scanner/test_sarif.py` | R18 fix, R1 tests, R2 tests |
| `tests/unit/cli/test_scan_helpers.py` | R14 test (add to existing `TestComputeOverlayHashes` class) |

### Must Not Modify

| File | Reason |
|------|--------|
| `src/wardline/core/tiers.py` | Read-only — `TAINT_TO_TIER` is used, not changed |
| `src/wardline/core/taints.py` | Read-only — taint tokens unchanged |
| `src/wardline/core/matrix.py` | No matrix changes |
| Rule files using `_emit_matrix_finding` only | Changes flow through base class |

---

## 9. Commit Strategy

4 commits, one per fix, each with all tests passing:

1. `fix(R18): emit null for taintState on pseudo-rule findings`
2. `test(R14): verify overlay hash lexicographic ordering invariant`
3. `fix(R1): add 4 missing result-level SARIF properties (§11.1)`
4. `fix(R2): add 2 missing run-level SARIF properties (§11.1)`

---

## 10. Code Conventions

- `from __future__ import annotations` in every file
- `MappingProxyType` for deep immutability of registries
- Explicit `ValueError` over `assert` (survives `python -O`)
- Ruff line length: 140. Target: Python 3.12+
- mypy strict mode with `warn_return_any`
- Zero runtime dependencies in core; scanner extras: pyyaml, jsonschema, click
- Frozen dataclasses for all data models

---

## 11. Status Protocol

Report status **after each commit** (R18, R14, R1, R2), not only at
workstream end. Use: **DONE**, **DONE_WITH_CONCERNS**, **NEEDS_CONTEXT**,
or **BLOCKED** with a brief explanation. Include the test count and
whether lint/mypy pass.
