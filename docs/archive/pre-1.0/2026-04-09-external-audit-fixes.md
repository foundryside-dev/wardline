# External Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all four findings from the external Python Binding audit (SCAN-014, PY-008, PY-011, PY-010) plus write ADR-003 for the SCAN-014 decision.

**Architecture:** Five independent tasks — spec amendment + binding spec fix (SCAN-014 via Option C), SARIF property emission (PY-008), exit code realignment (PY-011), SCN-021 entry #25 (PY-010), and ADR-003. Tasks 1-4 have no shared dependencies. Task 5 (ADR) can run in parallel.

**Tech Stack:** Python 3.12+, pytest, AST analysis, SARIF JSON, Click CLI, Markdown specs.

**Decision context:** A 6-person expert panel (Solution Architect, Systems Thinker, Python Engineer, Quality Engineer, Security Architect, ADR Reviewer) reviewed SCAN-014 and converged on Option C: amend §7.1 to formalize that split sub-rules can have their own matrix rows, rather than amending §7.3's "MUST NOT widen" invariant or simply complying. This preserves both the §7.3 monotonicity guarantee AND the falsy-substitution safety signal.

---

## Task 1: SCAN-014 — Formalize split-rule matrix independence (Option C)

**Problem:** PY-WL-002 has 3 cells that differ from the framework WL-001 matrix (WARNING where WL-001 says SUPPRESS). The current spec §7.1 says split sub-rules "inherit WL-001's severity matrix entries" with no provision for deviation. The binding spec (Part II-A line 273) documents the deviation but incorrectly calls it "narrowing."

**Option C approach:**
1. Amend §7.1 in the framework spec to state that when a binding splits a framework rule, sub-rules inherit the framework matrix as the default but MAY establish their own matrix rows when the language-specific semantics that motivated the split create risks absent from the framework pattern.
2. Fix the binding spec's "narrowing" factual error to correctly identify the deviation as a widening relative to WL-001, now authorized under the amended §7.1.
3. The implementation (`matrix.py`) and test oracles stay as they are — the 3 cells are correct per the binding spec's documented matrix.

**Files:**
- Modify: `docs/spec/wardline-01-08-pattern-rules.md:19` (§7.1 WL-001 split paragraph)
- Modify: `docs/spec/wardline-01-08-pattern-rules.md:88` (§7.3 binding-level deviations paragraph)
- Modify: `docs/spec/wardline-02-A-python-binding.md:273` (fix "narrowing" → correct terminology)
- Verify: `src/wardline/core/matrix.py:103` (no code change needed — values are correct)
- Verify: `tests/unit/core/test_matrix.py:41-45` (no change needed — oracle matches binding spec)

- [ ] **Step 1: Amend §7.1 — split sub-rule matrix independence**

In `docs/spec/wardline-01-08-pattern-rules.md`, find the WL-001 description at line 19. The current text ends with:

```
When a binding splits WL-001, the sub-rules inherit WL-001's severity matrix entries and share its exceptionability class; the binding documents the mapping between its sub-rules and this framework rule.
```

Replace that final sentence with:

```
When a binding splits WL-001, the sub-rules inherit WL-001's severity matrix entries as their default. Where the language-specific semantics that motivated the split create risks absent from the framework-level pattern, a sub-rule MAY establish its own matrix row that deviates from the inherited default. Such deviations MUST be documented in the binding's matrix with explicit rationale identifying the language-specific semantic risk. The §7.3 narrowing constraint applies to each sub-rule relative to its own documented matrix row, not relative to the parent framework rule's row. The binding documents the mapping between its sub-rules and this framework rule.
```

- [ ] **Step 2: Amend §7.3 — clarify scope for split rules**

In `docs/spec/wardline-01-08-pattern-rules.md`, find the "Binding-level matrix deviations" paragraph at line 88. After the existing text, add a new sentence:

```
When a binding splits a framework rule into sub-rules under §7.1, each sub-rule's documented matrix row is the baseline for §7.3 conformance — the narrowing constraint applies relative to the sub-rule's own matrix, not relative to the parent framework rule.
```

- [ ] **Step 3: Fix the Python binding spec — correct "narrowing" factual error**

In `docs/spec/wardline-02-A-python-binding.md`, replace the paragraph at line 273. Current text:

```
**PY-WL-002 (attribute access with fallback default).** PY-WL-002 derives from WL-001 but covers `getattr(obj, name, default)` and `obj.attr or default`. The `obj.attr or default` form has a falsy-substitution risk absent from dict-key access: it silently replaces *present but falsy* attribute values (0, `""`, `False`, `None`) with the default, not just missing attributes. For this reason, PY-WL-002 uses WARNING/RELAXED (not SUPPRESS/TRANSPARENT) at EXTERNAL_RAW, UNKNOWN_RAW, UNKNOWN_GUARDED, and MIXED_RAW — the pattern is expected at T4 boundaries but the falsy-substitution risk warrants visibility. This deviation *narrows* relative to the framework's WL-001 SUPPRESS at those cells (it uses WARNING where the framework uses SUPPRESS), which is permitted by §7.3.
```

Replace with:

```
**PY-WL-002 (attribute access with fallback default).** PY-WL-002 derives from WL-001 but covers `getattr(obj, name, default)` and `obj.attr or default`. The `obj.attr or default` form has a falsy-substitution risk absent from dict-key access: it silently replaces *present but falsy* attribute values (0, `""`, `False`, `None`) with the default, not just missing attributes. This language-specific semantic risk — absent from the framework-level WL-001 pattern — justifies PY-WL-002 establishing its own matrix row under §7.1's split-rule provision. PY-WL-002 uses WARNING/RELAXED (not SUPPRESS/TRANSPARENT) at EXTERNAL_RAW, UNKNOWN_RAW, and MIXED_RAW because the falsy-substitution risk warrants visibility even at T4 boundaries where dict-key fallback defaults are expected and safe. This is a widening relative to the framework's WL-001 SUPPRESS at those cells, authorized by §7.1 for split sub-rules where language-specific semantics create risks absent from the framework pattern. See ADR-003 for the decision record.
```

- [ ] **Step 4: Verify implementation and tests are already correct**

Run: `uv run pytest tests/unit/core/test_matrix.py -v`
Expected: All PASS — no code changes needed. The matrix values and test oracle already match the binding spec's documented matrix.

- [ ] **Step 5: Add a conformance-layer test (Quality Engineer recommendation)**

In `tests/unit/core/test_matrix.py`, add a new test that explicitly documents which cells deviate from the framework matrix and why:

```python
# Split-rule deviations: PY-WL-002 establishes its own matrix row per §7.1.
# These cells intentionally differ from WL-001's framework matrix.
# See ADR-003 for rationale.
SPLIT_RULE_DEVIATIONS: list[tuple[RuleId, TaintState, Severity, Exceptionability, str]] = [
    (RuleId.PY_WL_002, TaintState.EXTERNAL_RAW, W, R, "falsy-substitution risk (ADR-003)"),
    (RuleId.PY_WL_002, TaintState.UNKNOWN_RAW, W, R, "falsy-substitution risk (ADR-003)"),
    (RuleId.PY_WL_002, TaintState.MIXED_RAW, W, St, "falsy-substitution risk (ADR-003)"),
]


@pytest.mark.parametrize(
    "rule, taint, expected_sev, expected_exc, rationale",
    SPLIT_RULE_DEVIATIONS,
    ids=[f"{r.name}-{t.name}" for r, t, _, _, _ in SPLIT_RULE_DEVIATIONS],
)
def test_split_rule_deviation_is_documented(
    rule: RuleId,
    taint: TaintState,
    expected_sev: Severity,
    expected_exc: Exceptionability,
    rationale: str,
) -> None:
    """Split-rule deviations from framework matrix are intentional and documented."""
    from wardline.core.matrix import SEVERITY_MATRIX

    cell = SEVERITY_MATRIX[(rule, taint)]
    assert cell.severity == expected_sev, f"Deviation {rule}×{taint}: {rationale}"
    assert cell.exceptionability == expected_exc, f"Deviation {rule}×{taint}: {rationale}"
```

- [ ] **Step 6: Run full test suite**

Run: `uv run pytest`
Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/wardline-01-08-pattern-rules.md docs/spec/wardline-02-A-python-binding.md tests/unit/core/test_matrix.py
git commit -m "fix(SCAN-014): formalize split-rule matrix independence in §7.1

Amend §7.1: split sub-rules MAY establish own matrix rows when
language-specific semantics create risks absent from framework pattern.
Amend §7.3: narrowing constraint scoped to sub-rule's own matrix row.
Fix binding spec: correct 'narrowing' to 'widening' with §7.1 authorization.
Add conformance-layer test documenting intentional deviations.
See ADR-003."
```

---

## Task 2: PY-008 — Always emit `wardline.manifestHash` in SARIF output

**Problem:** `wardline.manifestHash` is conditionally omitted when `manifest_hash` is None. Spec says it's a mandatory run-level property — it must always be present, emitting JSON `null` when no hash is available.

**Files:**
- Modify: `src/wardline/scanner/sarif.py:352-354`
- Modify: `tests/unit/scanner/test_sarif.py:549-552` (test asserts wrong behavior)

- [ ] **Step 1: Update the test to expect the correct behavior**

In `tests/unit/scanner/test_sarif.py`, change `test_manifest_hash_none_when_not_set` from:
```python
    def test_manifest_hash_none_when_not_set(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.manifestHash" not in props
```
to:
```python
    def test_manifest_hash_none_when_not_set(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.manifestHash" in props
        assert props["wardline.manifestHash"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/scanner/test_sarif.py::TestSarifReport::test_manifest_hash_none_when_not_set -v`
Expected: FAIL — key not present.

- [ ] **Step 3: Fix the SARIF emission**

In `src/wardline/scanner/sarif.py`, change lines 352-354 from:
```python
                **({"wardline.manifestHash": self.manifest_hash}
                   if self.manifest_hash is not None
                   else {}),
```
to:
```python
                "wardline.manifestHash": self.manifest_hash,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/scanner/test_sarif.py -v`
Expected: All PASS, including both the "hash present" and "hash None" tests.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/sarif.py tests/unit/scanner/test_sarif.py
git commit -m "fix(PY-008): always emit wardline.manifestHash in SARIF properties

Mandatory run-level property must be present even when value is null.
Previously omitted the key entirely when manifest_hash was None."
```

---

## Task 3: PY-011 — Fix exit code 3 semantics

**Problem:** Spec says exit code 3 means "direct law — regime cannot produce meaningful enforcement output; `wardline regime` only." Implementation uses exit code 3 as `EXIT_TOOL_ERROR` in `wardline scan`. Meanwhile `wardline regime` has no exit code 3 at all.

**Fix approach:**
1. In `wardline scan`: TOOL_ERROR findings should exit 1 (they're findings, not a separate exit class). Remove `EXIT_TOOL_ERROR` from scan.
2. In `wardline regime`: Add exit code 3 for direct-law state (manifest validation failed, regime cannot produce meaningful output).

**Files:**
- Modify: `src/wardline/cli/scan.py:48, 726-731, 914-922`
- Modify: `src/wardline/cli/regime_cmd.py` (add exit 3 for direct law)
- Modify: `tests/integration/test_cli.py:115-174` (update exit code test)
- Modify: `tests/integration/test_scan_cmd.py:948, 973` (update exit code assertions)
- Check: `tests/integration/test_self_hosting_scan.py` (references to exit 3)

- [ ] **Step 1: Write a failing test for regime exit code 3 on direct law**

In `tests/integration/test_cli.py` (or the appropriate regime test file), add a test that invokes `wardline regime verify` (or `regime status`) when the manifest is invalid/missing, and expects exit code 3.

```python
def test_regime_exit_3_direct_law(self, tmp_path: Path) -> None:
    """Direct law (no valid manifest) exits 3 from regime."""
    runner = CliRunner()
    # No wardline.yaml in tmp_path → direct law
    result = runner.invoke(cli, [
        "regime", "status",
        "--path", str(tmp_path),
    ])
    assert result.exit_code == 3, (
        f"Expected exit 3 (direct law), got {result.exit_code}.\n"
        f"stdout: {result.output}\n"
    )
```

- [ ] **Step 2: Update existing scan exit code test to expect exit 1 instead of 3**

In `tests/integration/test_cli.py`, rename `test_exit_3_tool_error` to `test_tool_error_exits_1` and change the assertion from `exit_code == 3` to `exit_code == 1` (TOOL_ERROR is still a finding, so it exits 1).

In `tests/integration/test_scan_cmd.py:973`, change `assert result.exit_code == 3` to `assert result.exit_code == 1`.

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/integration/test_cli.py -v -k "exit"`
Expected: Both the new regime test and the updated scan test should FAIL.

- [ ] **Step 4: Fix scan.py — remove EXIT_TOOL_ERROR from scan exit logic**

In `src/wardline/cli/scan.py`:
1. Remove or deprecate `EXIT_TOOL_ERROR = 3` (line 48). If regime_cmd imports it, move the constant there instead.
2. At line 921-922, replace `if has_tool_error: sys.exit(EXIT_TOOL_ERROR)` — TOOL_ERROR findings have severity WARNING, but they indicate infrastructure failure. They should exit 1 (findings present):
```python
    if has_tool_error or exceeded_pct or bd.gate_blocking > 0 or has_governance_findings:
        sys.exit(EXIT_FINDINGS)
    else:
        sys.exit(EXIT_CLEAN)
```
3. Apply the same change at lines 726-731 (preview exit logic).

- [ ] **Step 5: Fix regime_cmd.py — add exit code 3 for direct law**

In `src/wardline/cli/regime_cmd.py`:
1. Add `EXIT_DIRECT_LAW = 3` constant.
2. In the regime status/verify command, when manifest loading fails (direct law state), exit with code 3 instead of the current error handling.

Find the manifest loading section and add:
```python
if control_law == "direct":
    # Direct law — no meaningful enforcement output possible
    sys.exit(EXIT_DIRECT_LAW)
```

- [ ] **Step 6: Update test_self_hosting_scan.py references**

In `tests/integration/test_self_hosting_scan.py`, update comments and assertions that reference "exit code 3" for scan crashes. Scanner crashes now exit 1 (findings present), not 3. Update:
- Line 4: comment about "no TOOL-ERROR exit code 3"
- Lines 96-98: `assert exit_code != 3` → update comment/assertion as appropriate

In `tests/integration/test_l3_performance.py:58-59`, update assertion: exit code 3 no longer means scan crash.

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest`
Expected: All PASS.

- [ ] **Step 8: Commit**

```bash
git add src/wardline/cli/scan.py src/wardline/cli/regime_cmd.py tests/
git commit -m "fix(PY-011): exit code 3 is direct law (regime only), not tool error

Spec §A.10: exit 3 means 'regime cannot produce meaningful enforcement
output.' TOOL_ERROR findings in scan now exit 1 (findings present).
regime status/verify exits 3 when control law is direct."
```

---

## Task 4: PY-010 — Implement SCN-021 entry #25 (data_flow + external_boundary)

**Problem:** Spec entry #25 (`@data_flow` + `@external_boundary`) is the only unimplemented contradictory decorator pair. The `@data_flow` decorator now exists (Group 16), so this can be implemented.

**Files:**
- Modify: `src/wardline/scanner/rules/scn_021.py` (add entry #25 to `_COMBINATIONS`)
- Modify: `tests/unit/scanner/test_scn_021.py` (add test for the new pair)

- [ ] **Step 1: Read the current SCN-021 implementation to understand the pattern**

Read: `src/wardline/scanner/rules/scn_021.py` — find `_COMBINATIONS` and the entry #25 comment.

- [ ] **Step 2: Write a failing test for entry #25**

In `tests/unit/scanner/test_scn_021.py`, add a test case for `@data_flow` + `@external_boundary`:

```python
def test_data_flow_plus_external_boundary(self) -> None:
    """Entry #25: @data_flow + @external_boundary is contradictory."""
    code = textwrap.dedent("""\
        from wardline.decorators import data_flow, external_boundary

        @data_flow(produces="feed_data")
        @external_boundary
        def process_feed(raw):
            return raw
    """)
    findings = self._run_scn021(code)
    assert len(findings) >= 1
    assert any("data_flow" in f.message and "external_boundary" in f.message for f in findings)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/unit/scanner/test_scn_021.py -v -k "data_flow_plus_external_boundary"`
Expected: FAIL — pair not detected.

- [ ] **Step 4: Add entry #25 to _COMBINATIONS**

In `src/wardline/scanner/rules/scn_021.py`, add the entry to `_COMBINATIONS`. Follow the existing pattern — each entry is a tuple of `(decorator_a, decorator_b, kind, reason, spec_entry)`. Remove any comment about L2+ deferral.

```python
    ("data_flow", "external_boundary", "contradictory",
     "@data_flow declares internal data production; @external_boundary declares external intake — contradictory flow direction",
     25),
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/scanner/test_scn_021.py -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/rules/scn_021.py tests/unit/scanner/test_scn_021.py
git commit -m "fix(PY-010): implement SCN-021 entry #25 (data_flow + external_boundary)

Last missing contradictory decorator pair. @data_flow decorator now
exists (Group 16), so parameterised analysis deferral no longer needed."
```

---

## Task 5: ADR-003 — Split-rule severity matrix independence

**Problem:** The decision to formalize split-rule matrix independence in §7.1 needs an ADR. This captures the panel review, the alternatives considered, and the rationale.

**Files:**
- Create: `docs/adr/ADR-003-split-rule-matrix-independence.md`

- [ ] **Step 1: Write ADR-003**

Create `docs/adr/ADR-003-split-rule-matrix-independence.md` following the project's existing ADR format (see ADR-001, ADR-002):

```markdown
# ADR-003: Split-rule severity matrix independence

**Status**: Accepted
**Date**: 2026-04-09
**Deciders**: Project Lead, 6-person expert panel review
**Context**: External audit SCAN-014 found PY-WL-002 widens 3 matrix cells relative to WL-001

## Summary

When a language binding splits a framework rule into sub-rules (e.g., WL-001 →
PY-WL-001 + PY-WL-002), sub-rules inherit the framework matrix as their default
but MAY establish their own matrix rows when the language-specific semantics that
motivated the split create risks absent from the framework-level pattern.

The §7.3 "MUST NOT widen" invariant remains absolute — it applies to each
sub-rule relative to its own documented matrix row, not relative to the parent
framework rule.

## Context

PY-WL-002 (attribute access with fallback default) is a Python-specific split of
framework rule WL-001. It covers two detection patterns:

1. `getattr(obj, name, default)` — 3-arg form (attribute absence → default)
2. `obj.attr or default` — or-expression (falsy value → default)

The or-expression form has a **falsy-substitution risk** absent from dict-key
access (PY-WL-001): it silently replaces present-but-falsy values (0, "", False,
None) with the fabricated default. This is not a theoretical concern — it enables
silent data corruption at trust boundaries where security-relevant fields hold
legitimate falsy values.

The Python binding spec documented PY-WL-002 using WARNING (not SUPPRESS) at
EXTERNAL_RAW, UNKNOWN_RAW, and MIXED_RAW for this reason. However:

1. The binding spec incorrectly called this deviation "narrowing" — it is
   widening (WARNING > SUPPRESS in severity).
2. Framework §7.1 stated split sub-rules "inherit WL-001's severity matrix
   entries" with no provision for deviation.
3. Framework §7.3 states bindings "MUST NOT assign higher severity" than the
   framework matrix.
4. An external audit correctly flagged this as FAIL (SCAN-014).

## Decision

Amend §7.1 to formalize that split sub-rules can establish their own matrix rows
when language-specific semantics justify it. This is Option C from the panel
review — it preserves both the §7.3 monotonicity guarantee and the
falsy-substitution safety signal.

## Alternatives Considered

### Option A: Comply with §7.3 as written

Change PY-WL-002 to SUPPRESS at the 3 cells. Simple and conformant, but loses a
real safety signal. The Security Architect's STRIDE analysis showed that
compensating controls (WL-007, WL-008) cannot catch falsy-substitution because
the corruption occurs before the boundary validator sees the data.

Rejected because it sacrifices a genuine safety signal to satisfy a constraint
that was not designed for the split-rule case.

### Option B: Amend §7.3 with exception clause

Add "unless the target language introduces a semantic risk" to §7.3's "MUST NOT
widen" constraint. The Systems Thinker identified this as an Eroding Goals
archetype — it weakens a clean invariant with a subjective gate that future
binding authors would exploit.

Rejected because it destroys the monotonicity guarantee that makes §7.3 useful
for cross-language policy and CI pipeline thresholds.

### Option C (chosen): Amend §7.1 for split-rule independence

Fix the problem at the abstraction layer where it actually lives — the
rule-splitting mechanism. §7.3 stays absolute. Split sub-rules get their own
documented matrix rows. The narrowing constraint applies relative to each
sub-rule's own matrix, not the parent rule.

## Consequences

### Positive

- PY-WL-002 retains falsy-substitution visibility at T4 boundaries
- §7.3's "MUST NOT widen" invariant remains absolute and simple
- Future bindings that split rules have a governed mechanism for the same case
- The binding spec's deviation is correctly characterized and authorized

### Negative

- Split-rule governance is slightly more complex — reviewers must check both the
  split rationale and each sub-rule's matrix
- Creates a second class of matrix baseline (framework-inherited vs
  binding-documented) that conformance testing must distinguish

### Process gaps identified

- Test oracle in `test_matrix.py` was authored from the implementation, not the
  spec — oracle provenance must be independently verified
- Binding spec contained a factual error ("narrowing" for a widening) that
  persisted through self-assessment — cross-layer conformance testing should
  compare framework cells to binding cells explicitly

## Panel Input

Six-person panel reviewed this decision on 2026-04-09:

| Role | Recommendation | Key Insight |
|------|---------------|-------------|
| Solution Architect | Option A | Monotonicity guarantee has real cross-language value |
| Systems Thinker | Option B with tight governance | Eroding Goals archetype — leverage is in amendment specificity |
| Python Engineer | Option A + new rule (PY-WL-002B) | Detection split already exists in code |
| Quality Engineer | Option A (default) | Oracle contamination is the root process failure |
| Security Architect | Keep current (misread §7.3) | Compensating controls can't catch pre-boundary corruption |
| ADR Reviewer | **Option C** | Fix at §7.1 where the semantic gap lives, not §7.3 |
```

- [ ] **Step 2: Commit**

```bash
git add docs/adr/ADR-003-split-rule-matrix-independence.md
git commit -m "docs: ADR-003 split-rule severity matrix independence

Captures SCAN-014 decision: §7.1 amended to allow split sub-rules
their own matrix rows. 6-person panel review documented.
§7.3 monotonicity invariant preserved."
```

---

## Verification

- [ ] **Final step: Run full test suite and self-hosting scan**

```bash
uv run pytest
uv run wardline scan src/
```

All tests pass. Self-hosting scan produces no regressions. All four audit findings resolved. ADR-003 captured.
