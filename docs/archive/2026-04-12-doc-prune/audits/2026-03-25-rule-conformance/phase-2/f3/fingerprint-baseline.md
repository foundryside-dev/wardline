# Fingerprint Baseline Assessment

**Agent:** Fingerprint Baseline Agent
**Date:** 2026-03-25
**Scope:** Annotation fingerprint baseline implementation vs spec (SS9.2, SS13.1.4)

## Files Assessed

- `src/wardline/scanner/fingerprint.py` -- core fingerprint computation and batch walk
- `src/wardline/cli/fingerprint_cmd.py` -- CLI `update` and `diff` commands
- `src/wardline/manifest/models.py` -- `FingerprintEntry` and `CoverageReport` dataclasses
- `src/wardline/manifest/schemas/fingerprint.schema.json` -- JSON Schema for baseline file
- `src/wardline/scanner/sarif.py` -- SARIF output (checked for coverage ratio)

## 1. Hash Scope

**Spec requirement (SS9.2):** Hash computed over the annotation surface only (decorators, tier assignments, group memberships), NOT the function body.

**Finding: PASS.**

`compute_annotation_fingerprint()` (fingerprint.py:86-112) hashes `qualname`, sorted decorator names, and sorted decorator attributes. It deliberately excludes file_path (documented: "a function moved between files with unchanged annotations produces the same hash"). The function body (`ast.dump`) is used only in the separate `compute_ast_fingerprint()` function for exception staleness, not for the annotation fingerprint. The two fingerprint functions are distinct and serve different purposes.

Evidence:
```python
payload = f"{version}|{qualname}|{sorted_decorators}|{sorted_attrs}"
```

No function body content enters the annotation hash.

## 2. Canonicalisation

**Spec requirement (SS9.2):** Hash MUST be computed over a canonical serialisation -- deterministic ordering regardless of annotation syntax order.

**Finding: PASS.**

Decorator names are sorted before hashing (line 108: `sorted(decorator_names)`). Decorator attributes are sorted by key (line 110: `sorted(attrs.items())`). This ensures that `@validates_shape` followed by `@validates_semantic` produces the same hash as the reverse ordering. The canonical form is: Python version, qualname, comma-joined sorted decorator names, comma-joined sorted key=value attrs.

The `FingerprintEntry.decorators` field is also stored as a sorted tuple (line 343: `tuple(sorted(decorator_names))`), ensuring the persisted record is canonical.

## 3. Change Detection

**Spec requirement (SS9.2):** Three categories: annotation added, annotation modified, annotation removed.

**Finding: PASS.**

The `diff` command (fingerprint_cmd.py:300-323) implements all three categories:

- **ADDED** (lines 305-307): in current but not in baseline, keyed by `qualified_name`
- **REMOVED** (lines 309-312): in baseline but not in current
- **MODIFIED** (lines 314-323): in both but hash differs; also flags Python version mismatch as a reason

Output classifies changes into `[policy]` and `[enforcement]` sections per SS9.3.1 (lines 359-377).

The `--gate` flag (lines 388-400) exits non-zero when tier 1 annotations are removed, implementing the SS9.2 requirement that "Annotation removal in Tier 1 modules MUST be flagged as a priority review item."

## 4. Coverage Reporting

**Spec requirement (SS9.2):** Baseline MUST report annotation coverage: count and ratio of annotated functions to total functions.

**Finding: PASS.**

`batch_compute_fingerprints()` returns a `CoverageReport` with:
- `annotated` / `total` / `ratio` -- global coverage
- `tier1_annotated` / `tier1_total` -- tier 1 specific counts

The coverage is written into the baseline JSON under `coverage` (fingerprint_cmd.py:163-169) and reported in both human-readable and JSON output.

The JSON schema (`fingerprint.schema.json`) validates the coverage section with required fields: `annotated`, `total`, `ratio`, `tier1_annotated`, `tier1_total`.

## 5. Tier 1 Unannotated Function Enumeration

**Spec requirement (SS9.2):** Specific enumeration of unannotated functions in Tier 1 modules.

**Finding: PASS.**

`batch_compute_fingerprints()` (fingerprint.py:356-361) iterates all function qualnames in tier 1 files and appends unannotated ones to `tier1_unannotated` as `"{file_path}:{qualname}"` strings.

The `CoverageReport` model stores these as `tier1_unannotated: tuple[str, ...]` (models.py:72).

The baseline JSON includes `tier1_unannotated` in the coverage section (fingerprint_cmd.py:169). The schema permits this field as an array of strings (fingerprint.schema.json:50-53), though it is not in the `required` list -- this is acceptable since the field may be empty or absent for projects without tier 1 modules.

## 6. Record Format vs SS13.1.4 Schema

**Spec requirement (SS13.1.4):** Records must include: qualified_name, module, decorators, annotation_hash, tier_context, boundary_transition, last_changed.

**Finding: PASS with minor divergences.**

Implementation record fields:
| Spec field | Implementation field | Status |
|---|---|---|
| `qualified_name` | `qualified_name` | Present |
| `module` | `module` | Present |
| `decorators` | `decorators` | Present (sorted array) |
| `annotation_hash` | `annotation_hash` | Present (16-char SHA-256 prefix) |
| `tier_context` | `tier_context` | Present as integer (1-4); spec example uses taint state string ("SHAPE_VALIDATED") |
| `boundary_transition` | `boundary_transition` | Present as string ("shape_validation"); spec example uses object `{"from_tier": 3, "to_tier": 2}` |
| `last_changed` | `last_changed` | Present (date string) |
| `artefact_class` | `artefact_class` | Present (implementation adds this beyond SS13.1.4 minimal, per SS9.3.1 requirement) |

**Divergences noted:**

1. **`tier_context` representation:** Implementation uses integer (1-4). Spec SS13.1.4 example shows taint state string (`"SHAPE_VALIDATED"`). This is a reasonable binding-level decision -- integers are unambiguous and the schema validates the range. MINOR.

2. **`boundary_transition` representation:** Implementation uses a flat string (`"shape_validation"`, `"semantic_validation"`, etc.). Spec SS13.1.4 example shows a structured object `{"from_tier": 3, "to_tier": 2}`. The flat string is less informative but still identifies the transition type. MINOR -- the from/to tier information can be derived from the transition type.

3. **Top-level structure:** Spec example uses `version` + `functions` + `summary`. Implementation uses `$id` + `python_version` + `generated_at` + `coverage` + `fingerprints`. The implementation structure is richer (includes Python version for hash reproducibility, generation timestamp) but uses different field names. The spec notes that the SS13.1.4 example is "minimal record structure" -- the implementation exceeds it.

4. **`wardline.coverageRatio` in SARIF:** Not present in `sarif.py`. The coverage ratio is reported in the fingerprint baseline JSON and CLI output but is not surfaced in SARIF run properties. SS9.2 does not explicitly require it in SARIF -- coverage is a fingerprint baseline concern, not a scan finding concern. NO GAP.

## 7. Implementation Completeness

**Finding: Fully implemented, not stubbed.**

| Capability | Status |
|---|---|
| `compute_annotation_fingerprint()` | Implemented, canonical hash |
| `compute_single_annotation_fingerprint()` | Implemented, full FingerprintEntry construction |
| `batch_compute_fingerprints()` | Implemented, directory walk with coverage counting |
| `wardline fingerprint update` | Implemented, writes JSON baseline with schema validation |
| `wardline fingerprint diff` | Implemented, three-category change detection |
| `--gate` flag for CI | Implemented, exits 1 on tier 1 removals |
| Schema validation on load | Implemented via jsonschema against fingerprint.schema.json |
| Backward compatibility normalization | Implemented (entries->fingerprints rename, missing field defaults) |
| Policy/enforcement classification | Implemented via `_classify_artefact()` |
| Boundary transition resolution | Implemented via `_resolve_boundary_transition()` |
| Python version mismatch detection | Implemented, flags all entries as MODIFIED with reason |

Test coverage exists across three test files:
- `tests/unit/scanner/test_fingerprint.py`
- `tests/unit/scanner/test_annotation_fingerprint.py`
- `tests/unit/cli/test_fingerprint_cmd.py`

## Summary

| Criterion | Result |
|---|---|
| Hash scope (annotation surface only, not body) | PASS |
| Canonicalisation (deterministic ordering) | PASS |
| Change detection (added/modified/removed) | PASS |
| Coverage reporting (ratio + counts) | PASS |
| Tier 1 unannotated enumeration | PASS |
| Record format (SS13.1.4 alignment) | PASS (minor representation divergences) |
| Implementation completeness | PASS (fully working, no stubs) |

The two minor divergences (tier_context as integer vs taint-state string, boundary_transition as flat string vs structured object) are binding-level representation decisions that do not compromise the governance function. The spec SS13.1.4 explicitly states the example is a "minimal record structure" and the implementation exceeds it. The SS13.1.5 note that "implementations MAY derive manifest schemas from the field specifications" pending published normative schemas provides latitude for these differences.

## Verdict: PASS

The fingerprint baseline implementation satisfies all seven assessment criteria. Hash computation is scoped to the annotation surface only, canonicalised via sorted decorator names and attributes, and excludes the function body. Change detection covers all three spec categories. Coverage reporting includes global ratios and specific tier 1 unannotated function enumeration. The record format aligns with SS13.1.4 with minor binding-level representation choices. The implementation is complete with no stubs, backed by schema validation and test coverage.
