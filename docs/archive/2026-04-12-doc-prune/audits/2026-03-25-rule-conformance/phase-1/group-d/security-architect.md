# Security Architect Audit: SCN-021 (Contradictory Decorator Combination Detection)

**Auditor role:** Security Architect
**Date:** 2026-03-25
**Rule:** SCN-021 — Group D: Decorator Surface Integrity
**Files reviewed:**
- `/home/john/wardline/src/wardline/scanner/rules/scn_021.py`
- `/home/john/wardline/src/wardline/scanner/discovery.py`
- `/home/john/wardline/src/wardline/scanner/context.py`
- `/home/john/wardline/src/wardline/scanner/engine.py`
- `/home/john/wardline/src/wardline/core/registry.py`
- `/home/john/wardline/docs/wardline/wardline-02-A-python-binding.md` (section A.4.3)
- `/home/john/wardline/docs/wardline/wardline-01-13-residual-risks.md` (section 12, risks 9 and 12)
- `/home/john/wardline/tests/unit/scanner/test_scn_021.py`

---

## 1. Defence Against Adversarial Annotation Injection (Risk 9)

### 1a. Can an agent add `@fail_open` to an `@audit_critical` function?

**Yes, SCN-021 catches this.** Combination #5 (`fail_open` + `audit_critical`) is in the table at line 39 as a CONTRADICTORY ERROR with rationale "Audit-critical paths must not have fallback paths." Combination #19 (line 73, reversed order) is also present as a deliberate alias.

However, the reversed entry creates a **duplicate finding bug**: the lookup at line 132 uses `spec.left in names and spec.right in names`, which is order-independent. Both entry #5 (`fail_open`, `audit_critical`) and entry #19 (`audit_critical`, `fail_open`) will match the same decorator pair, producing two identical-severity findings for one violation. This is noise, not a security gap, but it degrades signal quality.

### 1b. Can an agent add `@external_boundary` to an `@int_data` function?

**Yes.** Combination #6 (`external_boundary` + `int_data`) is in the table at line 40 as CONTRADICTORY ERROR.

### 1c. Assessment

SCN-021 addresses the specific threat of contradictory annotation injection. It does NOT address the more dangerous variant of risk 9: semantically dishonest but structurally non-contradictory annotations (e.g., applying `@int_data` to a function that actually reads external data). This is explicitly acknowledged as out-of-scope in the spec (A.7.4), and SCN-021 is not claimed to address it. The rule correctly covers its declared threat surface.

---

## 2. Evasion via Decorator Aliasing

**Pattern:** `from wardline import fail_open as x; @x`

**Detected.** The discovery module (`discovery.py`, `_process_from_import`, line 167) maps `local_name = alias.asname or imported_name` against the registry. So `from wardline import fail_open as x` produces a name table entry `"x" -> "fail_open"`. When SCN-021's `_decorator_names` (line 140) uses the `annotations_map` from the context, it receives canonical names, not local aliases. The test at line 100-115 (`test_context_annotations_drive_detection_for_alias_imports`) confirms this works.

**Verdict: RESISTANT to aliased imports.**

---

## 3. Evasion via Variable Indirection

**Pattern:** `x = fail_open; @x`

**Not detected.** The discovery module only processes import statements (`ast.Import` and `ast.ImportFrom`). A variable assignment like `x = fail_open` is an `ast.Assign` node, which is not tracked by the import table builder. The decorator `@x` would resolve as an `ast.Name` with `id="x"`, which would not appear in the import table and would not match any registry entry.

Additionally, the fallback path in SCN-021's `_decorator_names` (lines 145-149) uses `_decorator_name`, which extracts the terminal name from `ast.Name` or `ast.Attribute` nodes. For `@x`, this returns `"x"`, which would not match any combination spec entry (all entries use canonical names like `"fail_open"`).

**Verdict: EVASION POSSIBLE.** This is a Level 1 limitation documented in `discovery.py` line 15-18: "Import table construction only scans top-level statements." Variable indirection is a strictly harder problem than import aliasing and requires data-flow analysis (Level 2+). The risk is mitigated by the fact that this pattern is unusual in production code and would be flagged during code review as suspicious.

---

## 4. Evasion via Dynamic Import

**Pattern:** `importlib.import_module("wardline").fail_open`

**Not detected for enforcement purposes.** The discovery module has a `_detect_dynamic_imports` function (line 197-245) that scans for `importlib.import_module("wardline...")` and `__import__("wardline...")` patterns, but it only emits a `logger.warning` -- it does not add entries to the import table or the annotations map. Decorators obtained through dynamic imports are invisible to SCN-021.

**Verdict: EVASION POSSIBLE.** The warning-only approach is defensible for Level 1 analysis: dynamic imports cannot be statically resolved to specific decorator names. The warning provides audit trail visibility but no enforcement. A dedicated scanner rule (not SCN-021) could flag dynamic wardline imports as a finding, converting the warning to a governance-visible SARIF entry. Currently this gap exists only in log output.

---

## 5. UNCONDITIONAL Exceptionability for All 29 Combinations

SCN-021 emits all findings with `Exceptionability.UNCONDITIONAL` (line 169). This means no governance exception can waive any of these findings.

### Assessment of the 26 contradictory combinations (ERROR severity)

**Appropriate.** Every contradictory combination represents a logical impossibility -- a function cannot simultaneously fail-open and fail-closed, or be both an external boundary and an internal data source. There is no legitimate business reason to override these. UNCONDITIONAL is the correct exceptionability.

### Assessment of the 3 suspicious combinations (#27-29, WARNING severity)

| # | Combination | Concern |
|---|---|---|
| 27 | `@fail_open` + `@deterministic` | Fail-open fallback defaults *may* produce non-deterministic output |
| 28 | `@compensatable` + `@deterministic` | Compensation state changes *may* affect determinism |
| 29 | `@time_dependent` + `@idempotent` | Time-dependent operations *may not* be idempotent |

These use hedging language ("may", "may not"). The combinations are not logically impossible -- they are architectural code smells that deserve scrutiny but may have legitimate explanations:

- A `@fail_open` + `@deterministic` function where the fallback default is itself a deterministic constant.
- A `@compensatable` + `@deterministic` function where compensation is externally managed and does not affect the function's own determinism.
- A `@time_dependent` + `@idempotent` function where time-dependence is in logging/timestamps only, not in the return value.

**CONCERN:** UNCONDITIONAL exceptionability for suspicious (WARNING) combinations may be overly rigid. These are "probably wrong" signals, not "logically impossible" signals. If a legitimate use case exists, the only recourse is to remove one of the decorators (weakening the annotation surface) or to split the function. Both responses reduce annotation fidelity. STANDARD exceptionability with mandatory rationale would preserve the warning while allowing governance override for documented exceptions.

However, the practical impact is limited: WARNING severity means these findings do not block CI in most configurations. The UNCONDITIONAL flag prevents them from being silenced in the exception register, which ensures they remain visible. This is a conservative choice that errs toward noise over silence.

---

## 6. SCN-021 as a Gatekeeper: Downstream Impact of Missed Contradictions

If SCN-021 fails to detect a contradictory combination, the downstream rules (PY-WL-004 through PY-WL-009) will operate on a function whose annotation surface contains a logical impossibility. The impact depends on the specific missed combination:

| Missed combination | Downstream impact |
|---|---|
| `@fail_open` + `@fail_closed` | PY-WL-004/005 body-pattern rules will evaluate under conflicting failure mode assumptions. The scanner picks one decorator's severity context; the other is silently ignored. |
| `@fail_open` + `@audit_critical` | PY-WL-006 (audit path integrity) will see audit_critical and enforce strict requirements, while the function's actual fail_open behaviour permits degraded paths. The rule fires correctly but the function's behaviour contradicts its annotations. |
| `@external_boundary` + `@int_data` | Taint assignment will see both T4 source and T1 source declarations. The `assign_function_taints` logic must resolve the conflict; if it picks `int_data`, the function's external data escapes tier enforcement entirely. |
| `@validates_shape` + `@validates_semantic` | Body evaluation context (A.4.3 table) differs between shape (EXTERNAL_RAW) and semantic (SHAPE_VALIDATED). The scanner applies one; the wrong choice causes false negatives or false positives on PY-WL-003. |

**Assessment:** SCN-021 is a critical gatekeeper. Its failure mode is not "no findings" but "wrong findings from downstream rules," which is harder to detect and more dangerous than missing findings entirely. The downstream rules implicitly trust the annotation surface to be non-contradictory.

---

## 7. Governance Implications of Contradictory Annotations in Production

Contradictory annotations that survive to production create three governance failures:

1. **Audit evidence corruption.** SARIF findings from downstream rules are unreliable when the annotation surface is contradictory. An assessor reviewing SARIF output cannot distinguish "no findings because the code is correct" from "no findings because the scanner evaluated under the wrong assumption."

2. **Baseline integrity erosion.** The annotation fingerprint baseline (section 9.2) tracks annotation changes but does not validate annotation coherence. A contradictory pair of annotations, once ratified into the baseline, becomes the accepted state. Subsequent scans that fail to detect the contradiction will produce a clean bill of health.

3. **Agent generation feedback loop.** Per risk 12 (evasion surface trajectory), agents use existing annotations as context for generating new code. Contradictory annotations in the training context will produce contradictory annotations in generated code, compounding the problem across the codebase.

---

## 8. Additional Finding: Registry Gap for `data_flow` and `restoration_boundary`

The SCN-021 combination table references two decorator names that do NOT appear in the canonical registry (`src/wardline/core/registry.py`):

- `data_flow` (combination #25, line 90-94)
- `restoration_boundary` (combinations #16 and #17, lines 56-66)

When the discovery module processes a source file, it resolves decorator names against the registry. If `data_flow` and `restoration_boundary` are not in the registry, they will never appear in the `annotations_map`. SCN-021's primary path (lines 140-144) consults the `annotations_map` first; if it contains entries, it uses canonical names from annotations and does NOT fall back to AST-level name extraction.

The fallback path (lines 145-149) extracts names directly from decorator AST nodes, which would match `data_flow` and `restoration_boundary` as raw names. So detection depends on whether the annotations_map is populated for the function in question:

- If the function has OTHER wardline decorators that ARE in the registry, the annotations_map will be non-empty, the primary path will be used, and `data_flow`/`restoration_boundary` will be MISSING from the canonical name set. Combinations #16, #17, and #25 will not fire.
- If the function has NO registry-recognized decorators, the annotations_map will be empty, the fallback path will be used, and raw names will match. These combinations will fire.

**This is a conditional detection gap.** The most dangerous case -- a function with `@tier1_read` (in registry) + `@restoration_boundary` (not in registry) -- will NOT be detected because the primary path will see only `tier1_read` in the canonical names.

---

## 9. Additional Finding: Duplicate Finding for Entry #5/#19

As noted in section 1a, entries #5 and #19 are the same decorator pair (`fail_open` + `audit_critical`) with reversed left/right. Since the set membership check `spec.left in names and spec.right in names` is commutative, both entries match the same function, producing two findings with different messages but the same severity for the same violation. The spec acknowledges #19 as "Alias of #5 -- caught regardless of decorator ordering," but the implementation emits two findings rather than one.

This is a quality issue, not a security gap. It adds noise to SARIF output and may confuse automated finding triage.

---

## Verdict: CONCERN

**SCN-021 correctly addresses its declared threat surface** -- contradictory decorator combinations are detected for standard import patterns, including aliased imports and qualified access. The 26 contradictory combinations are well-reasoned and UNCONDITIONAL exceptionability is appropriate for them.

**Three concerns prevent a PASS verdict:**

1. **Registry gap for `data_flow` and `restoration_boundary` (section 8).** Three combination entries (#16, #17, #25) reference decorators not in the canonical registry. Detection is conditional on whether other registry-known decorators are present. The highest-risk case (`@tier1_read` + `@restoration_boundary`) is the one that fails. This is a functional defect, not a design limitation.

2. **UNCONDITIONAL exceptionability for suspicious combinations #27-29 (section 5).** The "suspicious" category describes combinations that are probably wrong but not logically impossible. UNCONDITIONAL prevents governance override for legitimate edge cases. This forces developers to weaken annotations rather than document exceptions, which reduces annotation fidelity. Recommend STANDARD exceptionability for the 3 WARNING-severity entries.

3. **Dynamic import and variable indirection evasion (sections 3-4).** These are documented Level 1 limitations, not implementation defects. However, the dynamic import detector emits only a log warning, not a SARIF finding. An adversarial agent that uses `importlib.import_module` to obtain decorators evades SCN-021 with no governance-visible trace. Recommend promoting the dynamic import warning to a scanner finding (separate rule or SCN-021 sub-finding).

**The duplicate finding issue (section 9) is a quality defect, not a security concern.**
