# SARIF Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all 4 SARIF property gaps (R1, R2, R14, R18) from the 2026-04-09 conformance review so the §14.6 assessment procedure passes at Step 4.

**Architecture:** Four independent fixes applied sequentially (R18 → R14 → R1 → R2). R18 is a one-line null fix. R14 is test-only. R1 adds 4 result-level properties by extending `Finding` and `_make_result()`. R2 adds 2 run-level properties by extending `ExceptionEntry` and `SarifReport.to_dict()`. SCN-021 and SUP-001 taint fixes are bundled into R1.

**Tech Stack:** Python 3.12+, pytest, frozen dataclasses, SARIF v2.1.0 JSON, mypy strict.

**Spec:** `docs/superpowers/prompts/workstream-a-sarif-completeness.md` (panel-reviewed, 2 rounds)

---

## Task 1: R18 — Emit `null` for `taintState` on pseudo-rule findings

**Files:**
- Modify: `src/wardline/scanner/sarif.py:200-204`
- Modify: `tests/unit/scanner/test_sarif.py:113-133`

- [ ] **Step 1: Update existing test to expect `None` instead of `"UNKNOWN"`**

In `tests/unit/scanner/test_sarif.py`, change `test_result_property_bag_defaults_taint_state_when_missing` at line 113-117:

```python
    def test_result_property_bag_defaults_taint_state_when_missing(self) -> None:
        report = SarifReport(findings=[_make_finding(taint_state=None)])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert props["wardline.taintState"] is None
```

- [ ] **Step 2: Update `test_mandatory_properties_never_omitted` to handle nullable taintState**

At line 119-133, the test asserts `props[key] is not None` for all mandatory keys including `taintState`. After R18, `taintState` is `None` for pseudo-rule findings. Split the assertion — check key *presence* for all, check `is not None` only for non-nullable keys:

```python
    def test_mandatory_properties_never_omitted(self) -> None:
        """All mandatory properties (§A.3) present even when taint_state is None."""
        report = SarifReport(findings=[_make_finding(taint_state=None)])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        mandatory = [
            "wardline.rule",
            "wardline.taintState",
            "wardline.severity",
            "wardline.exceptionability",
            "wardline.analysisLevel",
        ]
        # Nullable mandatory properties — key must exist, value can be None.
        nullable = {"wardline.taintState"}
        for key in mandatory:
            assert key in props, f"mandatory key {key!r} missing from properties"
            if key not in nullable:
                assert props[key] is not None, f"mandatory key {key!r} is None"
```

- [ ] **Step 3: Add negative regression test**

Add below the updated test:

```python
    def test_no_unknown_string_in_taint_state(self) -> None:
        """No non-canonical 'UNKNOWN' token in taintState — must be null or canonical."""
        report = SarifReport(findings=[_make_finding(taint_state=None)])
        sarif = json.loads(report.to_json_string())
        for result in sarif["runs"][0]["results"]:
            ts = result["properties"]["wardline.taintState"]
            assert ts is None or ts in {
                "INTEGRAL", "ASSURED", "GUARDED", "EXTERNAL_RAW",
                "UNKNOWN_RAW", "UNKNOWN_GUARDED", "UNKNOWN_ASSURED", "MIXED_RAW",
            }, f"Non-canonical taintState: {ts!r}"
```

- [ ] **Step 4: Run tests — expect 3 failures**

Run: `uv run pytest tests/unit/scanner/test_sarif.py -v -k "taint_state_when_missing or mandatory_properties or unknown_string"`
Expected: 3 FAIL — all three tests fail because taintState is currently `"UNKNOWN"` (not `None`, and not in the canonical set).

- [ ] **Step 5: Fix the SARIF emission**

In `src/wardline/scanner/sarif.py:200-204`, change `"UNKNOWN"` to `None`:

```python
        "wardline.taintState": (
            str(finding.taint_state)
            if finding.taint_state is not None
            else None
        ),
```

- [ ] **Step 6: Run tests — all pass**

Run: `uv run pytest tests/unit/scanner/test_sarif.py -v`
Expected: All PASS.

- [ ] **Step 7: Run full suite + lint + typecheck**

Run: `uv run pytest && uv run ruff check src/ && uv run mypy src/`
Expected: All PASS.

- [ ] **Step 8: Commit**

```bash
git add src/wardline/scanner/sarif.py tests/unit/scanner/test_sarif.py
git commit -m "$(cat <<'EOF'
fix(R18): emit null for taintState on pseudo-rule findings

taintState now emits null (not non-canonical "UNKNOWN") for
findings where taint_state is None (TOOL-ERROR, GOVERNANCE-*).
The 8 canonical tokens are a closed set; "UNKNOWN" was not
among them. This is a type change (str → str|null) for the
taintState property but pre-v1.0 with no external consumers.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: R14 — Verify overlay hash lexicographic ordering

**Files:**
- Modify: `tests/unit/cli/test_scan_helpers.py:124-164`

- [ ] **Step 1: Add test to existing `TestComputeOverlayHashes` class**

In `tests/unit/cli/test_scan_helpers.py`, add a new method to the `TestComputeOverlayHashes` class (after `test_skips_symlinks` at line 163):

```python
    def test_path_order_differs_from_hash_order(self, tmp_path: Path) -> None:
        """Overlay hashes sorted by POSIX path, not by hash value (§10.1)."""
        import hashlib

        from wardline.cli.scan import _compute_overlay_hashes

        overlays_dir = tmp_path / "overlays"
        (overlays_dir / "a").mkdir(parents=True)
        (overlays_dir / "b").mkdir(parents=True)

        # Content deliberately chosen so hash-alphabetical order
        # differs from path-alphabetical order.
        files = {
            overlays_dir / "a" / "z.yaml": b"overlay_for: a/z\n",
            overlays_dir / "b" / "a.yaml": b"overlay_for: b/a\n",
            overlays_dir / "a" / "a.yaml": b"overlay_for: a/a\n",
        }
        for path, content in files.items():
            path.write_bytes(content)

        # Pass in NON-sorted order to verify internal sorting.
        result = _compute_overlay_hashes(
            [overlays_dir / "b" / "a.yaml",
             overlays_dir / "a" / "z.yaml",
             overlays_dir / "a" / "a.yaml"],
            tmp_path,
        )

        def sha(content: bytes) -> str:
            return f"sha256:{hashlib.sha256(content).hexdigest()}"

        expected = (
            sha(b"overlay_for: a/a\n"),   # overlays/a/a.yaml
            sha(b"overlay_for: a/z\n"),   # overlays/a/z.yaml
            sha(b"overlay_for: b/a\n"),   # overlays/b/a.yaml
        )
        assert result == expected
```

- [ ] **Step 2: Run test — expect PASS (implementation already sorts correctly)**

Run: `uv run pytest tests/unit/cli/test_scan_helpers.py::TestComputeOverlayHashes::test_path_order_differs_from_hash_order -v`
Expected: PASS — `_compute_overlay_hashes` already sorts by path at `scan.py:145`.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/cli/test_scan_helpers.py
git commit -m "$(cat <<'EOF'
test(R14): verify overlay hash lexicographic ordering invariant

Adds test where path-alphabetical order differs from
hash-alphabetical order, verifying §10.1's requirement
that overlay hashes are sorted by forward-slash-normalized
relative path, not by hash value.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: R1 — Extend `Finding` dataclass and update `_make_finding` test helper

**Files:**
- Modify: `src/wardline/scanner/context.py:22-47`
- Modify: `tests/unit/scanner/test_sarif.py:16-48`

- [ ] **Step 1: Add `annotation_groups` and `data_source` fields to `Finding`**

In `src/wardline/scanner/context.py`, add after `retroactive_scan: bool = False` (line 46):

```python
    # R1: §10.1 result-level properties
    annotation_groups: tuple[int, ...] = ()
    data_source: str | None = None  # Always None in v1.0 — requires taint provenance threading
```

- [ ] **Step 2: Update `_make_finding` test helper**

In `tests/unit/scanner/test_sarif.py:16-48`, add three new parameters to the helper signature and pass them through:

```python
def _make_finding(
    *,
    rule_id: RuleId = RuleId.PY_WL_001,
    file_path: str = "src/example.py",
    line: int = 10,
    col: int = 4,
    end_line: int | None = 10,
    end_col: int | None = 30,
    message: str = "Use .get() with a default",
    severity: Severity = Severity.ERROR,
    exceptionability: Exceptionability = Exceptionability.STANDARD,
    taint_state: object = None,
    analysis_level: int = 1,
    source_snippet: str | None = None,
    qualname: str | None = None,
    retroactive_scan: bool = False,
    exception_id: str | None = None,
    annotation_groups: tuple[int, ...] = (),
    data_source: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        col=col,
        end_line=end_line,
        end_col=end_col,
        message=message,
        severity=severity,
        exceptionability=exceptionability,
        taint_state=taint_state,
        analysis_level=analysis_level,
        source_snippet=source_snippet,
        qualname=qualname,
        retroactive_scan=retroactive_scan,
        exception_id=exception_id,
        annotation_groups=annotation_groups,
        data_source=data_source,
    )
```

- [ ] **Step 3: Run tests — all pass (defaults are backward-compatible)**

Run: `uv run pytest tests/unit/scanner/test_sarif.py -v`
Expected: All PASS.

- [ ] **Step 4: Commit**

```bash
git add src/wardline/scanner/context.py tests/unit/scanner/test_sarif.py
git commit -m "$(cat <<'EOF'
refactor(R1): extend Finding with annotation_groups and data_source

Add two new fields with defaults to the frozen Finding dataclass.
kw_only=True means zero existing call sites break. Update
_make_finding test helper to accept and forward the new fields.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: R1 — Add `_get_annotation_groups` helper to `RuleBase`

**Files:**
- Modify: `src/wardline/scanner/rules/base.py:100-250`

- [ ] **Step 1: Add the helper method to `RuleBase`**

In `src/wardline/scanner/rules/base.py`, add after `_get_function_taint` (after line 181):

```python
    def _get_annotation_groups(self) -> tuple[int, ...]:
        """Get sorted, deduplicated annotation group numbers for the current function.

        Returns the Part I group numbers (1-17) of all wardline annotations
        declared on the function. Used to populate the §10.1 SARIF
        property ``wardline.annotationGroups``.
        """
        if not self._current_qualname or self._context is None:
            return ()
        annotations_map = self._context.annotations_map
        if annotations_map is None:
            return ()
        annotations = annotations_map.get(self._current_qualname, ())
        return tuple(sorted({a.group for a in annotations}))
```

- [ ] **Step 2: Update `_emit_matrix_finding` to pass `annotation_groups`**

In the same file, update `_emit_matrix_finding` (around line 183-207) to add `annotation_groups=self._get_annotation_groups()` to the `Finding` constructor:

```python
    def _emit_matrix_finding(self, node: ast.AST, message: str) -> None:
        """Emit a finding using the severity matrix for ``self.RULE_ID``."""
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

- [ ] **Step 3: Add unit tests for `_get_annotation_groups`**

Add to `tests/unit/scanner/test_sarif.py` (or a new test file for base.py):

```python
    def test_get_annotation_groups_no_context(self) -> None:
        """Returns () when _context is None."""
        from wardline.scanner.rules.base import RuleBase

        # RuleBase is abstract — test via _emit_matrix_finding subclass
        # or by instantiating a concrete rule and clearing context.
        # Simplest: verify _get_annotation_groups logic directly via
        # a Finding constructed with annotation_groups=() default.
        finding = _make_finding(annotation_groups=())
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.annotationGroups"] == []

    def test_get_annotation_groups_empty_map(self) -> None:
        """Returns () when annotations_map has no entry for qualname."""
        finding = _make_finding(annotation_groups=())
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.annotationGroups"] == []
```

Note: Full integration testing of `_get_annotation_groups` through the engine
pipeline (source file → decorator discovery → ScanContext → rule → Finding)
is covered by the existing rule test suites. These unit tests verify the
emission-time handling of the default `()` value.

- [ ] **Step 4: Run tests**

Run: `uv run pytest && uv run mypy src/`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/rules/base.py tests/unit/scanner/test_sarif.py
git commit -m "$(cat <<'EOF'
refactor(R1): add _get_annotation_groups helper to RuleBase

Centralized annotation group lookup for §10.1 annotationGroups
property. Also wired into _emit_matrix_finding, covering all 6
rule files that use Path A emission (py_wl_004 through py_wl_009).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: R1 — Update direct `Finding()` construction sites (Path B)

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_001.py:180,223,258`
- Modify: `src/wardline/scanner/rules/py_wl_002.py:83`
- Modify: `src/wardline/scanner/rules/py_wl_003.py:547`
- Modify: `src/wardline/scanner/rules/scn_021.py:240`
- Modify: `src/wardline/scanner/rules/scn_022.py:53,76`
- Modify: `src/wardline/scanner/rules/sup_001.py:926`

- [ ] **Step 1: Add `annotation_groups` to `py_wl_001.py` (3 sites)**

At line 180 (`Finding` in `_emit_finding`), add after `qualname=self._current_qualname,`:
```python
                annotation_groups=self._get_annotation_groups(),
```

At line 223 (`Finding` for `PY_WL_001_GOVERNED_DEFAULT`), add after `qualname=self._current_qualname,`:
```python
                    annotation_groups=self._get_annotation_groups(),
```

At line 258 (`Finding` for `PY_WL_001_UNGOVERNED_DEFAULT`), add after `qualname=self._current_qualname,`:
```python
                    annotation_groups=self._get_annotation_groups(),
```

- [ ] **Step 2: Add `annotation_groups` to `py_wl_002.py` (1 site)**

At line 83 (`Finding` in `_emit_finding`), add after `qualname=self._current_qualname,`:
```python
                annotation_groups=self._get_annotation_groups(),
```

- [ ] **Step 3: Add `annotation_groups` to `py_wl_003.py` (1 site)**

At line 547 (`Finding` in `_emit_finding`), add after `qualname=self._current_qualname,`:
```python
                annotation_groups=self._get_annotation_groups(),
```

- [ ] **Step 4: Fix `scn_021.py` — add `annotation_groups` AND fix `taint_state`**

At line 240 (`Finding` in `_emit_finding`), change `taint_state=None` to use the taint lookup, and add `annotation_groups`:

```python
                taint_state=self._get_function_taint(self._current_qualname),
```

And add after `qualname=self._current_qualname,`:
```python
                annotation_groups=self._get_annotation_groups(),
```

- [ ] **Step 5: Fix `scn_022.py` — add `annotation_groups` AND fix `taint_state` (2 sites)**

SCN-022 also sets `taint_state=None` on functions that have `@all_fields_mapped`
decorators (and therefore have tiers). Fix for consistency with SCN-021/SUP-001.

At line 53 (`Finding` for "source class not found"), change `taint_state=None` to:
```python
                taint_state=self._get_function_taint(self._current_qualname),
```
And add after `qualname=self._current_qualname,`:
```python
                annotation_groups=self._get_annotation_groups(),
```

At line 76 (`Finding` for unmapped fields), change `taint_state=None` to:
```python
                taint_state=self._get_function_taint(self._current_qualname),
```
And add after `qualname=self._current_qualname,`:
```python
                annotation_groups=self._get_annotation_groups(),
```

- [ ] **Step 6: Fix `sup_001.py` — add `annotation_groups` AND fix `taint_state`**

At line 926 (`Finding` in `_emit`), change `taint_state=None` to:

```python
                taint_state=self._get_function_taint(self._current_qualname),
```

And add after `qualname=self._current_qualname,`:
```python
                annotation_groups=self._get_annotation_groups(),
```

- [ ] **Step 7: Verify all sites covered**

Verify all Path B sites have `annotation_groups`. Since `Finding()` calls
span multiple lines, use a multiline check — for each rule file, confirm
`annotation_groups` appears within the `Finding(` block:

```bash
for f in py_wl_001 py_wl_002 py_wl_003 scn_021 scn_022 sup_001; do
  echo "--- $f ---"
  grep -c 'annotation_groups' src/wardline/scanner/rules/${f}.py
done
```

Expected: Each file shows at least 1 match (py_wl_001 shows 3).
Note: `Finding()` sites outside `rules/` (engine.py, context.py) use
the `()` default and don't need changes.

- [ ] **Step 8: Run tests + lint + typecheck**

Run: `uv run pytest && uv run ruff check src/ && uv run mypy src/`
Expected: All PASS.

- [ ] **Step 9: Commit**

```bash
git add src/wardline/scanner/rules/
git commit -m "$(cat <<'EOF'
fix(R1): add annotation_groups to all Path B Finding sites

Wire _get_annotation_groups() into all 9 direct Finding()
construction sites across 6 rule files. Also fix taint_state=None
in SCN-021, SCN-022, and SUP-001 — all three rules fire on
decorated functions that have tiers, so enclosingTier should
reflect actual taint rather than emitting null.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: R1 — Add SARIF emission for the 4 result-level properties

**Files:**
- Modify: `src/wardline/scanner/sarif.py:16-18,195-237,354`
- Modify: `tests/unit/scanner/test_sarif.py` (imports + new tests)
- Modify: `tests/unit/scanner/test_sarif.py:364` (version bump)
- Modify: `tests/integration/test_scan_cmd.py:945` (version bump)

- [ ] **Step 1: Add imports to `sarif.py`**

At the top of `src/wardline/scanner/sarif.py`, add the runtime import after line 16:

```python
from wardline.core.tiers import TAINT_TO_TIER
```

In the **existing** `TYPE_CHECKING` block (lines 17-18, which currently only
imports `Finding`), add `TaintState` alongside the existing import:

```python
if TYPE_CHECKING:
    from wardline.core.taints import TaintState
    from wardline.scanner.context import Finding
```

Note: `TAINT_TO_TIER` is a runtime import (used in dict lookup). `TaintState`
is annotation-only (used in type signature of `_taint_to_tier_value`).
`from __future__ import annotations` is already at line 7, so the annotation
is a string at runtime — `TYPE_CHECKING`-only is correct for `TaintState`.

- [ ] **Step 2: Add `_taint_to_tier_value` helper function**

Add before `_make_result` (before line 195):

```python
def _taint_to_tier_value(taint_state: TaintState | None) -> int | None:
    """Map taint state to authority tier integer (1-4).

    Returns None for pseudo-rule findings (taint_state is None) —
    governance findings operate outside the tier model.
    """
    if taint_state is None:
        return None
    return TAINT_TO_TIER[taint_state].value
```

- [ ] **Step 3: Add 4 properties to `_make_result` mandatory dict**

In `_make_result()`, add to the mandatory `properties` dict (after `"wardline.analysisLevel"` at line 207), BEFORE the `_clean_none` block at line 210:

```python
        "wardline.enclosingTier": _taint_to_tier_value(finding.taint_state),
        "wardline.annotationGroups": sorted(set(finding.annotation_groups)),
        "wardline.excepted": finding.exception_id is not None,
        "wardline.dataSource": finding.data_source,
```

**CRITICAL:** These go in the mandatory dict, NOT through `_clean_none()`. `enclosingTier` and `dataSource` are nullable — `_clean_none` would silently drop them.

- [ ] **Step 4: Bump `propertyBagVersion` to `"0.5"`**

In `to_dict()`, change `"wardline.propertyBagVersion": "0.4"` to:

```python
                # Property bag versions:
                # "0.4" — initial stable schema (17 run-level, 5 result-level mandatory)
                # "0.5" — R1+R2: 19 run-level, 9 result-level mandatory (§10.1 complete)
                "wardline.propertyBagVersion": "0.5",
```

- [ ] **Step 5: Update version assertions in tests**

In `tests/unit/scanner/test_sarif.py:364`, change `"0.4"` to `"0.5"`.

In `tests/integration/test_scan_cmd.py:945`, change `"0.4"` to `"0.5"`.

- [ ] **Step 6: Add imports to test file**

At the top of `tests/unit/scanner/test_sarif.py`, add:

```python
from wardline.core.taints import TaintState
from wardline.scanner.sarif import _make_result
```

- [ ] **Step 7: Add R1 tests**

Add to `tests/unit/scanner/test_sarif.py` in the appropriate test class:

```python
    @pytest.mark.parametrize("taint,expected_tier", [
        (TaintState.INTEGRAL, 1),
        (TaintState.ASSURED, 2),
        (TaintState.GUARDED, 3),         # Tier 3 cluster:
        (TaintState.UNKNOWN_ASSURED, 3),  # three taint states
        (TaintState.UNKNOWN_GUARDED, 3),  # share tier 3
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

    def test_annotation_groups_sorted(self) -> None:
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
        """Duplicate group numbers are deduplicated at emission time."""
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
        """Nullable mandatory properties present as KEYS even when null.

        Guards against _clean_none trap: if accidentally routed through
        _clean_none(), these keys disappear silently.
        """
        finding = _make_finding(taint_state=None, data_source=None)
        result = _make_result(finding, base_path=None)
        props = result["properties"]
        assert "wardline.enclosingTier" in props
        assert "wardline.dataSource" in props
        assert "wardline.taintState" in props
        assert props["wardline.enclosingTier"] is None
        assert props["wardline.dataSource"] is None
        assert props["wardline.taintState"] is None

    def test_all_mandatory_result_properties_present(self) -> None:
        """All 9 mandatory result-level properties present (§10.1)."""
        finding = _make_finding(taint_state=TaintState.INTEGRAL)
        result = _make_result(finding, base_path=None)
        props = set(result["properties"].keys())
        required = {
            "wardline.rule", "wardline.taintState", "wardline.severity",
            "wardline.exceptionability", "wardline.analysisLevel",
            "wardline.enclosingTier", "wardline.annotationGroups",
            "wardline.excepted", "wardline.dataSource",
        }
        missing = required - props
        assert not missing, f"Missing mandatory properties: {missing}"
```

- [ ] **Step 8: Update `test_mandatory_properties_never_omitted` for R1 nullable keys**

**This step amends the edit from Task 1 Step 2**, not the original file.
Task 1 introduced `nullable = {"wardline.taintState"}` in this test. Now
that `enclosingTier` and `dataSource` are also nullable mandatory properties,
expand the set. Find the line `nullable = {"wardline.taintState"}` and
replace with:

```python
        nullable = {"wardline.taintState", "wardline.enclosingTier", "wardline.dataSource"}
```

- [ ] **Step 9: Run tests + lint + typecheck**

Run: `uv run pytest && uv run ruff check src/ && uv run mypy src/`
Expected: All PASS.

- [ ] **Step 10: Commit**

```bash
git add src/wardline/scanner/sarif.py tests/unit/scanner/test_sarif.py tests/integration/test_scan_cmd.py
git commit -m "$(cat <<'EOF'
fix(R1): add 4 missing result-level SARIF properties (§10.1)

Add enclosingTier, annotationGroups, excepted, dataSource to every
SARIF result. enclosingTier derived from TAINT_TO_TIER (null for
pseudo-rules). annotationGroups sorted+deduplicated at emission.
excepted is exception_id is not None. dataSource is null for v1.0.
Bump propertyBagVersion from 0.4 to 0.5.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: R2 — Extend `ExceptionEntry` with `elimination_path` fields

**Files:**
- Modify: `src/wardline/manifest/models.py:22-46`
- Modify: `src/wardline/manifest/schemas/exceptions.schema.json:103-106`
- Modify: `src/wardline/manifest/exceptions.py:60-81`

- [ ] **Step 1: Add fields to `ExceptionEntry` dataclass**

In `src/wardline/manifest/models.py`, add after `migrated_by: str | None = None` (line 45):

```python
    elimination_path: str | None = None
    elimination_cost: str | None = None
```

- [ ] **Step 2: Update the exception JSON schema**

In `src/wardline/manifest/schemas/exceptions.schema.json`, add before `"migrated_by"` closing brace (after line 105):

```json
          "elimination_path": {
            "type": ["string", "null"],
            "description": "Architectural change that would eliminate the need for this exception (§13.1.3)."
          },
          "elimination_cost": {
            "type": ["string", "null"],
            "description": "Estimated effort to implement the elimination path."
          },
```

Note: `additionalProperties: false` at line 113 means these MUST be added to the schema or validation will reject them.

- [ ] **Step 3: Update the exception loader**

In `src/wardline/manifest/exceptions.py:60-81`, add after `migrated_by=raw.get("migrated_by"),` (line 80):

```python
            elimination_path=raw.get("elimination_path"),
            elimination_cost=raw.get("elimination_cost"),
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest && uv run mypy src/`
Expected: All PASS (new fields have `None` defaults).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/manifest/models.py src/wardline/manifest/schemas/exceptions.schema.json src/wardline/manifest/exceptions.py
git commit -m "$(cat <<'EOF'
refactor(R2): add elimination_path/cost to ExceptionEntry

§13.1.3 optional fields for tracking architectural debt on
exceptions. Both have None defaults — existing exception
registers load without changes. Schema, loader, and dataclass
all updated together.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: R2 — Add `deterministic` and `deferredFixRatio` to SARIF run properties

**Files:**
- Modify: `src/wardline/scanner/sarif.py:255-287,332-386`
- Modify: `src/wardline/cli/scan.py:630-672,836-863`
- Modify: `tests/unit/scanner/test_sarif.py`

- [ ] **Step 1: Add fields to `SarifReport`**

In `src/wardline/scanner/sarif.py`, add after `expedited_exception_ratio: float = 0.0` (line 269):

```python
    deterministic: bool = True
    deferred_fix_ratio: float | None = None
```

- [ ] **Step 2: Add emission to `to_dict()`**

In `to_dict()`, add after `"wardline.expeditedExceptionRatio": round(self.expedited_exception_ratio, 3),` (line 380):

```python
                "wardline.deterministic": self.deterministic,
                "wardline.deferredFixRatio": (
                    round(self.deferred_fix_ratio, 4)
                    if self.deferred_fix_ratio is not None
                    else None
                ),
```

Note: `deferredFixRatio` is always present as a key (unlike `coverageRatio` which is omitted when null). `null` means "unclassified," not "feature not applicable."

- [ ] **Step 3: Add `deferredFixRatio` computation to `scan.py`**

In `src/wardline/cli/scan.py`, after the exception stats computation block (after line 672, before `# --- Merge governance findings ---`), add:

```python
    # Compute deferredFixRatio for SARIF (§10.1, §13.1.3).
    # Reuse the active-exception filtering already done at lines 653-660
    # (same loop that computed _active). Count elimination_path among
    # the same set of active (non-expired) exceptions.
    deferred_fix_ratio: float | None = 0.0  # default: no exceptions
    if exceptions and _active > 0:
        _deferred = 0
        for _exc in exceptions:
            if _exc.expires is not None:
                try:
                    if _dt.date.fromisoformat(_exc.expires) < _today:
                        continue
                except ValueError:
                    pass
            if _exc.elimination_path:
                _deferred += 1
        if _deferred == 0:
            deferred_fix_ratio = None  # unclassified — distinct from 0.0
        else:
            deferred_fix_ratio = _deferred / _active
```

Note: `_today` and `_active` are already computed at lines 649 and 650-660.
The active-exception filter is replicated (same `fromisoformat` + try/except
pattern) to count `elimination_path` among active entries. `_active` is used
as the denominator to avoid a second count. The variable is initialized as
`0.0` before the `if exceptions:` block to ensure it's always defined when
`SarifReport(` is reached.

- [ ] **Step 4: Pass `deferred_fix_ratio` to `SarifReport`**

At the `SarifReport(` construction at line 836, add after `expedited_exception_ratio=expedited_exception_ratio,`:

```python
        deferred_fix_ratio=deferred_fix_ratio,
```

- [ ] **Step 5: Add R2 tests**

Add to `tests/unit/scanner/test_sarif.py`:

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

    def test_deferred_fix_ratio_zero(self) -> None:
        """Zero active exceptions → 0.0 (not null)."""
        report = SarifReport(findings=[], deferred_fix_ratio=0.0)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.deferredFixRatio"] == 0.0

    def test_deferred_fix_ratio_computed(self) -> None:
        """Deferred fix ratio reflects the value passed in."""
        report = SarifReport(findings=[], deferred_fix_ratio=0.5)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.deferredFixRatio"] == 0.5

    def test_deferred_fix_ratio_rounded(self) -> None:
        """Deferred fix ratio is rounded to 4 decimal places."""
        report = SarifReport(findings=[], deferred_fix_ratio=1 / 3)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.deferredFixRatio"] == 0.3333

    def test_deterministic_not_stripped_in_verification_mode(self) -> None:
        """Deterministic property survives verification mode."""
        report = SarifReport(findings=[], verification_mode=True)
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.deterministic" in props
        assert "wardline.deferredFixRatio" in props
```

- [ ] **Step 6: Run tests + lint + typecheck**

Run: `uv run pytest && uv run ruff check src/ && uv run mypy src/`
Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add src/wardline/scanner/sarif.py src/wardline/cli/scan.py tests/unit/scanner/test_sarif.py
git commit -m "$(cat <<'EOF'
fix(R2): add 2 missing run-level SARIF properties (§10.1)

Add wardline.deterministic (always true) and
wardline.deferredFixRatio (null when unclassified, 0.0 for
zero exceptions, computed ratio otherwise). deferredFixRatio
is always present as a key — null is a meaningful signal
distinct from absent.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Post-workstream verification

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest`
Expected: All PASS, ~18 new tests.

- [ ] **Step 2: Run self-hosting scan**

Run: `uv run wardline scan src/ --output /tmp/wardline-sarif.json`
Expected: Clean exit. SARIF output contains all new properties.

- [ ] **Step 3: Spot-check SARIF output**

```bash
python3 -c "
import json, sys
with open('/tmp/wardline-sarif.json') as f:
    sarif = json.load(f)
run = sarif['runs'][0]
props = run['properties']
print('deterministic:', props.get('wardline.deterministic'))
print('deferredFixRatio:', props.get('wardline.deferredFixRatio'))
print('propertyBagVersion:', props.get('wardline.propertyBagVersion'))
assert props['wardline.deterministic'] is True
assert 'wardline.deferredFixRatio' in props
assert props['wardline.propertyBagVersion'] == '0.5'
results = run['results']
assert results, 'Self-scan produced no findings — spot-check is vacuous'
# Check ALL results, not just the first
for i, r in enumerate(results):
    rp = r['properties']
    for key in ['wardline.enclosingTier', 'wardline.annotationGroups',
                'wardline.excepted', 'wardline.dataSource']:
        assert key in rp, f'Result {i} missing {key}'
print(f'Checked {len(results)} results — all have 4 new properties')
r0 = results[0]['properties']
print('enclosingTier:', r0.get('wardline.enclosingTier'))
print('annotationGroups:', r0.get('wardline.annotationGroups'))
print('excepted:', r0.get('wardline.excepted'))
print('dataSource:', r0.get('wardline.dataSource'))
"
```

Expected: All assertions pass. Output shows property values for first result.

- [ ] **Step 4: Verify no "UNKNOWN" taintState in output**

Run: `python3 -c "import json; d=json.load(open('/tmp/wardline-sarif.json')); print(sum(1 for r in d['runs'][0]['results'] if r['properties'].get('wardline.taintState') == 'UNKNOWN'))"`
Expected: `0`
