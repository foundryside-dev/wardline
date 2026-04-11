# Control Law Computation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded `control_law="normal"` in SARIF output with actual computation from governance state, per spec §9.5.

**Architecture:** A pure function `compute_control_law()` takes governance signals already available at the scan.py call site and returns the control law state plus a list of degradation reasons. The function lives in `sarif.py` alongside the `SarifReport` dataclass it feeds. A new `control_law_degradations` field on `SarifReport` emits `wardline.controlLawDegradations` in SARIF output when non-empty.

**Tech Stack:** Pure Python, no new dependencies. Consumes `ManifestMetrics` from `regime.py`.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/wardline/scanner/sarif.py` | Modify | Add `compute_control_law()`, add `control_law_degradations` field, emit in SARIF |
| `src/wardline/cli/scan.py` | Modify | Call `compute_control_law()` with available signals, pass results to `SarifReport` |
| `tests/unit/scanner/test_sarif.py` | Modify | Tests for `compute_control_law()` and `controlLawDegradations` emission |

## Spec Reference (§9.5)

Three states:
- **normal** — all rules active, manifest ratification current, no conformance gaps
- **alternate** — tool runs but degraded; `wardline.controlLawDegradations` lists reasons
- **direct** — tool cannot run (out of scope: if we're running, we're not in direct law)

Degradation conditions we can detect now:
1. `ratification_overdue` — manifest metadata from `ManifestMetrics`
2. `conformance_gaps` non-empty — known spec gaps from `wardline.conformance.json`
3. Rules disabled — `loaded_rule_ids` is a subset of canonical rule IDs
4. Stale exceptions — `stale_exception_count > 0`

Conditions we CANNOT detect yet (not blocking — the function is designed to grow):
- Corpus staleness (no age tracking infrastructure)
- Per-rule precision/recall floors (no measurement infrastructure)

---

### Task 1: Add `compute_control_law()` function with tests

**Files:**
- Modify: `src/wardline/scanner/sarif.py` (add function after `_PSEUDO_RULE_IDS`)
- Modify: `tests/unit/scanner/test_sarif.py` (add test class)

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/scanner/test_sarif.py`:

```python
from wardline.scanner.sarif import compute_control_law


class TestComputeControlLaw:
    """Tests for §9.5 control law computation."""

    def test_normal_when_no_degradation(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=False,
            conformance_gaps=(),
            rules_disabled=(),
            stale_exception_count=0,
        )
        assert law == "normal"
        assert degradations == ()

    def test_alternate_when_ratification_overdue(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=True,
            conformance_gaps=(),
            rules_disabled=(),
            stale_exception_count=0,
        )
        assert law == "alternate"
        assert "ratification_overdue" in degradations

    def test_alternate_when_conformance_gaps(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=False,
            conformance_gaps=("SARIF-run-level-incomplete",),
            rules_disabled=(),
            stale_exception_count=0,
        )
        assert law == "alternate"
        assert "conformance_gaps_present" in degradations

    def test_alternate_when_rules_disabled(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=False,
            conformance_gaps=(),
            rules_disabled=("PY-WL-006", "PY-WL-007"),
            stale_exception_count=0,
        )
        assert law == "alternate"
        assert "rules_disabled" in degradations

    def test_alternate_when_stale_exceptions(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=False,
            conformance_gaps=(),
            rules_disabled=(),
            stale_exception_count=3,
        )
        assert law == "alternate"
        assert "stale_exceptions_present" in degradations

    def test_multiple_degradations_all_reported(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=True,
            conformance_gaps=("gap-1",),
            rules_disabled=("PY-WL-006",),
            stale_exception_count=1,
        )
        assert law == "alternate"
        assert len(degradations) == 4

    def test_degradations_are_sorted(self) -> None:
        """Deterministic output for verification mode."""
        law, degradations = compute_control_law(
            ratification_overdue=True,
            conformance_gaps=("gap-1",),
            rules_disabled=(),
            stale_exception_count=0,
        )
        assert degradations == tuple(sorted(degradations))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_sarif.py -k "TestComputeControlLaw" -v`
Expected: FAIL — `cannot import name 'compute_control_law'`

- [ ] **Step 3: Implement `compute_control_law()`**

Add to `src/wardline/scanner/sarif.py` after the `_PSEUDO_RULE_IDS` definition (around line 92):

```python
def compute_control_law(
    *,
    ratification_overdue: bool = False,
    conformance_gaps: tuple[str, ...] = (),
    rules_disabled: tuple[str, ...] = (),
    stale_exception_count: int = 0,
) -> tuple[str, tuple[str, ...]]:
    """Compute the enforcement control law state per spec §9.5.

    Returns (law, degradations) where law is "normal" or "alternate"
    and degradations is a sorted tuple of degradation condition names.
    Direct law is not computable by the tool itself — if we are running,
    we are not in direct law.
    """
    degradations: list[str] = []
    if ratification_overdue:
        degradations.append("ratification_overdue")
    if conformance_gaps:
        degradations.append("conformance_gaps_present")
    if rules_disabled:
        degradations.append("rules_disabled")
    if stale_exception_count > 0:
        degradations.append("stale_exceptions_present")

    degradations.sort()
    law = "alternate" if degradations else "normal"
    return law, tuple(degradations)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/scanner/test_sarif.py -k "TestComputeControlLaw" -v`
Expected: 7 passed

- [ ] **Step 5: Commit**

```
git add src/wardline/scanner/sarif.py tests/unit/scanner/test_sarif.py
git commit -m "feat: add compute_control_law() for §9.5 enforcement state"
```

---

### Task 2: Add `control_law_degradations` to `SarifReport` and SARIF output

**Files:**
- Modify: `src/wardline/scanner/sarif.py:223` (add field to dataclass)
- Modify: `src/wardline/scanner/sarif.py:285` (emit in SARIF properties)
- Modify: `tests/unit/scanner/test_sarif.py` (add emission tests)

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/scanner/test_sarif.py` in the existing `TestRunLevelProperties` class (or wherever the control_law tests live):

```python
def test_control_law_degradations_omitted_when_normal(self) -> None:
    report = SarifReport(findings=[], control_law="normal")
    props = report.to_dict()["runs"][0]["properties"]
    assert "wardline.controlLawDegradations" not in props

def test_control_law_degradations_emitted_when_alternate(self) -> None:
    report = SarifReport(
        findings=[],
        control_law="alternate",
        control_law_degradations=("ratification_overdue", "stale_exceptions_present"),
    )
    props = report.to_dict()["runs"][0]["properties"]
    assert props["wardline.controlLawDegradations"] == [
        "ratification_overdue", "stale_exceptions_present"
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_sarif.py -k "control_law_degradations" -v`
Expected: FAIL — `unexpected keyword argument 'control_law_degradations'`

- [ ] **Step 3: Add field and SARIF emission**

In `src/wardline/scanner/sarif.py`, add the field to `SarifReport` after `control_law` (line 223):

```python
    control_law: str = "normal"
    control_law_degradations: tuple[str, ...] = ()
```

In the `run["properties"]` dict (around line 285), add conditional emission after the `controlLaw` line:

```python
                "wardline.controlLaw": self.control_law,
                **({"wardline.controlLawDegradations": list(self.control_law_degradations)}
                   if self.control_law_degradations else {}),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/scanner/test_sarif.py -k "control_law" -v`
Expected: All control_law tests pass (existing + new)

- [ ] **Step 5: Commit**

```
git add src/wardline/scanner/sarif.py tests/unit/scanner/test_sarif.py
git commit -m "feat: emit wardline.controlLawDegradations in SARIF output"
```

---

### Task 3: Wire `compute_control_law()` into `scan.py`

**Files:**
- Modify: `src/wardline/cli/scan.py:706-761` (compute and pass control law to SarifReport)

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/cli/` or `tests/integration/` — a test that runs a scan and checks the SARIF output has a computed control_law. Since scan.py is CLI-level, an integration-style test is appropriate. However, this is most easily verified by checking the self-hosting scan output. We'll verify manually after wiring.

Instead, write a unit test for the wiring logic. Add to `tests/unit/scanner/test_sarif.py`:

```python
def test_compute_and_report_integration(self) -> None:
    """Verify compute_control_law output feeds SarifReport correctly."""
    law, degradations = compute_control_law(
        ratification_overdue=True,
        stale_exception_count=2,
    )
    report = SarifReport(
        findings=[],
        control_law=law,
        control_law_degradations=degradations,
    )
    props = report.to_dict()["runs"][0]["properties"]
    assert props["wardline.controlLaw"] == "alternate"
    assert "ratification_overdue" in props["wardline.controlLawDegradations"]
    assert "stale_exceptions_present" in props["wardline.controlLawDegradations"]
```

- [ ] **Step 2: Run test to verify it passes** (should pass already from Tasks 1+2)

Run: `uv run pytest tests/unit/scanner/test_sarif.py -k "compute_and_report" -v`
Expected: PASS

- [ ] **Step 3: Wire into scan.py**

In `src/wardline/cli/scan.py`, after the `conformance_gaps` computation (~line 717) and before the `SarifReport` construction (~line 739):

```python
    from wardline.scanner.sarif import compute_control_law
    from wardline.manifest.regime import collect_manifest_metrics

    # --- Compute control law (§9.5) ---
    manifest_metrics = collect_manifest_metrics(manifest_path)
    canonical_rule_ids = frozenset(r for r in RuleId if r not in _PSEUDO_RULE_IDS)
    disabled_rules = tuple(sorted(
        r.value for r in canonical_rule_ids - loaded_rule_ids
    ))
    control_law, control_law_degradations = compute_control_law(
        ratification_overdue=manifest_metrics.ratification_overdue,
        conformance_gaps=conformance_gaps,
        rules_disabled=disabled_rules,
        stale_exception_count=stale_exception_count,
    )
```

Then update the `SarifReport(...)` constructor call to pass the computed values instead of relying on the default:

```python
    sarif_report = SarifReport(
        ...
        control_law=control_law,
        control_law_degradations=control_law_degradations,
        ...
    )
```

Remove the existing hardcoded default — it's now computed.

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest -q`
Expected: All pass (no regressions)

- [ ] **Step 5: Verify self-hosting scan output**

Run: `uv run wardline scan src/ 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); p=d['runs'][0]['properties']; print('controlLaw:', p.get('wardline.controlLaw')); print('degradations:', p.get('wardline.controlLawDegradations', 'none'))"`

Expected: `controlLaw: normal` (if no degradations in self-hosting) or `controlLaw: alternate` with specific degradation reasons listed.

- [ ] **Step 6: Commit**

```
git add src/wardline/cli/scan.py
git commit -m "feat: wire control law computation into scan command (§9.5)"
```

---

### Task 4: Close the filigree issue

- [ ] **Step 1: Close the issue**

```
filigree close wardline-41760265a8 --reason "control_law computed from ratification_overdue, conformance_gaps, rules_disabled, stale_exception_count. Emits wardline.controlLaw and wardline.controlLawDegradations in SARIF. Direct law out of scope (if tool runs, not direct)."
```

- [ ] **Step 2: Run full test suite one final time**

Run: `uv run pytest -q`
Expected: All pass
