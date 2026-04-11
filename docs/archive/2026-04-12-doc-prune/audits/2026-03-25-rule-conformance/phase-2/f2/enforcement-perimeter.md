# Enforcement Perimeter Assessment

**Auditor:** Enforcement Perimeter Agent
**Date:** 2026-03-25
**Scope:** Scanner respect for enforcement perimeter defined in wardline.toml and manifest files
**Spec references:** wardline-01-13 (S13.2), wardline-01-05 (S5.1)

---

## 1. Include/Exclude Enforcement

### Spec requirement (S13.2)
wardline.toml declares `include` and `exclude` glob patterns. Excluded files must not be scanned.

### Implementation

The scanner uses **path-prefix exclusion**, not glob-pattern exclusion. The `ScannerConfig.from_toml()` method (models.py:261-268) reads `target_paths` and `exclude_paths` as directory paths, resolves them relative to the config file's directory, and passes them to `ScanEngine`.

The engine's `_is_excluded()` method (engine.py:144-153) checks whether a resolved path is a child of any exclude path using `Path.relative_to()`. This is prefix matching, not glob matching.

The engine's `_scan_tree()` (engine.py:114-142) prunes excluded directories from `os.walk` in-place (line 128-131) and skips excluded files (line 139-140). The same exclusion logic is mirrored in `_iter_python_files()` (engine.py:281-302) for the project-index build pass.

**The actual wardline.toml in this project** uses:
```toml
target_paths = ["src/wardline"]
exclude_paths = [".venv", "__pycache__"]
```

### Finding: CONCERN -- include/exclude uses paths, not globs

The spec (S13.2) defines `include` as an array of glob patterns (default `["**/*.py"]`) and `exclude` as an array of glob patterns (default `["**/test_*", "**/tests/**", "**/.venv/**"]`). The implementation uses `target_paths` and `exclude_paths` as directory paths with prefix matching, not glob evaluation. The `_KNOWN_KEYS` set (models.py:200-210) does not contain `include`, `exclude`, `root`, or `follow_symlinks` -- none of the S13.2 `[scanner]` keys are recognized.

The implementation's key vocabulary (`target_paths`, `exclude_paths`) is a flat-namespace alternative to the spec's `[scanner]` section structure. This is a schema divergence, not a logic bug -- the exclusion *works* for directory-level filtering -- but it cannot express file-level patterns like `**/test_*` or `**/*.py`.

**Evidence:** `_KNOWN_KEYS` at models.py:200-210 lists `target_paths` and `exclude_paths` but not `include`, `exclude`, `root`, or `follow_symlinks`.

---

## 2. Perimeter Boundary Taint

### Spec requirement (S5.1)
Data crossing the enforcement perimeter boundary -- from unannotated code or third-party libraries -- must be treated as UNKNOWN_RAW.

### Implementation

The taint assignment in `function_level.py` (lines 41-49, 55-88) follows a strict three-level precedence:

1. **Decorator taint** (highest): If a function has a wardline decorator mapped in `DECORATOR_TAINT_MAP`, use it.
2. **Module tiers**: If the manifest declares a `module_tiers` entry matching the file path, use that default taint.
3. **UNKNOWN_RAW fallback**: If neither applies, the function gets `TaintState.UNKNOWN_RAW`.

This correctly implements S5.1: any function without a wardline annotation and without a module-tier declaration defaults to UNKNOWN_RAW. The precedence is a security invariant documented in the module docstring (function_level.py:12-14).

The `resolve_module_default()` function (function_level.py:94-138) uses proper path-prefix matching with `PurePath.relative_to()` and most-specific-match-wins logic.

### Finding: PASS

UNKNOWN_RAW is correctly used as the fallback taint for unclassified data. The precedence order (decorator > module_default > UNKNOWN_RAW) is correct and documented.

---

## 3. Overlay Scoping

### Spec requirement (S13.1.2)
Each overlay must reside within the directory it claims to govern. The enforcement tool verifies that `overlay_for` is a prefix of the overlay file's actual path.

### Implementation

The `resolve_boundaries()` function (resolve.py:26-71) performs this check:

1. Computes `overlay_dir` as the overlay file's parent directory relative to the project root (line 47).
2. Calls `relative_path_within_scope(overlay_dir, overlay.overlay_for.rstrip("/"))` (line 48-51).
3. Raises `GovernanceError` if the check fails (line 52-55).

The `relative_path_within_scope()` function (scope.py:26-41) uses `Path.relative_to()` for prefix matching, which correctly prevents sibling-directory confusion (e.g., `src/apiary` does not match `src/api`).

Each boundary is tagged with the overlay's absolute scope path (resolve.py:65-69), and rules use `path_within_scope()` to verify that a file falls within the boundary's governing overlay scope before applying boundary-related suppression. This is used consistently across:
- py_wl_001.py (line 280, 307)
- py_wl_003.py (line 97)
- py_wl_008.py (line 134)
- py_wl_009.py (line 253, 268)

### Finding: PASS

Overlay scoping is correctly implemented with path-prefix checks at both resolution time (overlay location validation) and rule execution time (boundary applicability). The `GovernanceError` for out-of-scope overlays is a hard error, not a warning.

---

## 4. Symlink Handling

### Spec requirement (S13.2)
`follow_symlinks` defaults to `false`.

### Implementation

All `os.walk()` calls in the scanner use `followlinks=False`:
- engine.py:118 (`_scan_tree`)
- engine.py:285 (`_iter_python_files`)
- fingerprint.py:292
- discovery.py:163

The `follow_symlinks` configuration key is **not implemented**. The scanner hardcodes `followlinks=False` in all walk calls. There is no mechanism to set it to `true` via wardline.toml -- the key is not in `_KNOWN_KEYS` and would trigger the unknown-key rejection.

Additionally, `_compute_manifest_hash()` in scan.py:64 explicitly skips symlinked overlay files (`if overlay_file.is_symlink(): continue`).

### Finding: CONCERN -- follow_symlinks not configurable

The default behavior (do not follow symlinks) is correct per spec. However, the spec defines `follow_symlinks` as a configurable boolean in `[scanner]`. The implementation hardcodes `false` with no mechanism to override. This is safe-by-default but does not implement the full spec surface.

---

## 5. Missing wardline.toml Behavior

### Spec requirement (S13.2)
"A missing `wardline.toml` is not an error -- the tool runs with defaults (all groups enabled, all rules enabled, advisory mode)."

### Implementation

The `_load_config()` function (scan.py:614-641) returns `None` when `config_arg is None` (line 623-624). The scan command then runs with no config:
- `target_paths` defaults to `(scan_path,)` (scan.py:306)
- `exclude_paths` defaults to `()` (scan.py:308-310)
- All rules are active (no disabled_rules filtering)
- `analysis_level` defaults to 1 (scan.py:347)

### Finding: CONCERN -- missing wardline.toml only when --config not passed

The implementation handles missing wardline.toml gracefully **only when the --config flag is not specified**. If `--config wardline.toml` is passed and the file does not exist, the tool exits with code 2 (scan.py:628-629). This is correct behavior for an explicitly requested config file.

However, there is **no auto-discovery** of wardline.toml. Unlike wardline.yaml (which has `discover_manifest()` that walks up the directory tree), wardline.toml is only loaded when explicitly passed via `--config`. If the user does not pass `--config`, the scanner always runs with defaults regardless of whether a wardline.toml exists in the project. This means a wardline.toml sitting at the project root is silently ignored unless the user explicitly references it.

---

## 6. Unknown Key Rejection

### Spec requirement (S13.2)
"Unknown keys MUST produce a structured error (exit code 2)."

### Implementation

`ScannerConfig.from_toml()` (models.py:250-255) computes the set difference between the TOML keys and `_KNOWN_KEYS`, and raises `ScannerConfigError` for any unknown keys. The CLI (`_load_config` in scan.py:634-638) catches `ScannerConfigError` and returns `_CONFIG_ERROR`, which triggers `sys.exit(EXIT_CONFIG_ERROR)` (exit code 2) at scan.py:241.

**One subtlety:** The parser does `wardline_section = data.get("wardline", data)` (models.py:248). If the TOML file uses a `[wardline]` section, it validates keys under that section. If the file has no `[wardline]` section, it validates top-level keys. This means unknown top-level sections (e.g., `[scanner]`, `[rules]`, `[regime]` as the spec defines) would be rejected as unknown keys -- because the implementation expects a flat `[wardline]` namespace, not the S13.2 section structure.

### Finding: PASS (with caveat)

Unknown key rejection works correctly and produces exit code 2. The caveat is that the key namespace differs from the spec's section structure (see finding 1).

---

## Summary

| Check | Result | Notes |
|-------|--------|-------|
| Include/exclude enforcement | CONCERN | Path-prefix exclusion, not glob patterns per S13.2 |
| Perimeter boundary taint (UNKNOWN_RAW) | PASS | Correct fallback to UNKNOWN_RAW |
| Overlay scoping | PASS | Path-prefix validation with GovernanceError on violation |
| Symlink handling | CONCERN | Correct default (false), but not configurable per S13.2 |
| Missing wardline.toml | CONCERN | No auto-discovery; silently ignored unless --config passed |
| Unknown key rejection | PASS | Exit code 2 on unknown keys (different key namespace than spec) |

---

## Verdict: CONCERN

The enforcement perimeter is **functionally sound** for its implemented scope: excluded paths are truly not scanned, the UNKNOWN_RAW fallback is correct, overlay scoping is properly validated, and symlinks are not followed. No security-relevant gaps were found in the implemented behavior.

However, the wardline.toml schema diverges from the S13.2 specification in three ways:

1. **Glob patterns not implemented.** The spec defines `include`/`exclude` as glob arrays; the implementation uses `target_paths`/`exclude_paths` as directory path arrays. File-level patterns (e.g., `**/test_*`) cannot be expressed.
2. **`follow_symlinks` not configurable.** Hardcoded to `false`. Safe default, but the spec says it should be a setting.
3. **No wardline.toml auto-discovery.** The spec implies wardline.toml is a standard project file; the implementation requires explicit `--config` to load it.

These are specification-implementation gaps, not active security vulnerabilities. The scanner errs on the side of caution (no symlinks, UNKNOWN_RAW fallback). The gaps affect configurability and spec conformance, not enforcement correctness.
