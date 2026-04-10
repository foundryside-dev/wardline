# Taint-Specific Specimen Rewrite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate 139 duplicate corpus specimens by making each taint-matrix fragment unique, collapsing taint-invariant rules, and resolving ADV duplicates.

**Architecture:** Update `scripts/generate_corpus.py` to produce per-taint fragments (the root cause of duplication), re-run it to regenerate matrix specimens, then manually fix edge-case specimens not created by the script. Delete stale files and validate.

**Tech Stack:** Python 3.12, PyYAML, hashlib, pytest

**Spec:** `docs/superpowers/specs/2026-04-10-taint-specific-specimen-rewrite-design.md`

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `scripts/generate_corpus.py` | Modify | Add per-taint fragment generation, collapse 008/009, fix ADV duplicates |
| `tests/unit/corpus/test_corpus_oracle.py` | Modify | Add sha256 uniqueness test + taint-invariance test (new `TestCorpusIntegrity` class, NOT under `@pytest.mark.integration`) |
| `tests/unit/corpus/test_corpus_skeleton.py` | Modify | Update `test_rule_directory_exists` for PY-WL-008/009 collapsed directories |
| `corpus/specimens/PY-WL-*/` | Regenerated | Matrix specimens get unique fragments |
| `corpus/specimens/adversarial/` | Modify+Delete | 6 ADV specimens deleted, 3 renamed |
| `corpus/corpus_manifest.json` | Regenerated | Updated specimen index |
| `docs/requirements/spec-fitness/corpus-reduction-2026-04-10.md` | Create | Conformance evidence for 259→224 reduction |

---

### Task 1: Write SHA256 Uniqueness Test (TDD — Currently Fails)

**Files:**
- Modify: `tests/unit/corpus/test_corpus_oracle.py`

This test asserts acceptance criterion #1: zero duplicate sha256 values within any rule. It will FAIL on the current corpus (139 duplicates exist) and PASS after the rewrite.

**Important:** `TestCorpusOracle` is marked `@pytest.mark.integration` and bare `uv run pytest` skips integration tests. These new tests only read JSON/matrix data (no subprocess calls), so they must go in a **separate unmarked class** to run by default.

- [ ] **Step 1: Write the failing test**

Add a new class **after** `TestCorpusOracle` at the bottom of `tests/unit/corpus/test_corpus_oracle.py`. Add `from collections import defaultdict` to the module-level imports.

```python
class TestCorpusIntegrity:
    """Corpus structural invariants — runs by default (no integration marker)."""

    def test_no_duplicate_sha256_within_rule(self) -> None:
        """Every specimen within a rule must have a unique fragment (sha256)."""
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))

        by_rule_sha: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for s in data["specimens"]:
            by_rule_sha[s["rule"]][s["sha256"]].append(s["specimen_id"])

        duplicates: list[str] = []
        for rule, sha_groups in sorted(by_rule_sha.items()):
            for sha, ids in sha_groups.items():
                if len(ids) > 1:
                    duplicates.append(f"{rule} sha={sha[:10]}: {ids}")

        assert not duplicates, (
            f"{len(duplicates)} duplicate sha256 groups:\n"
            + "\n".join(duplicates[:10])
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/corpus/test_corpus_oracle.py::TestCorpusIntegrity::test_no_duplicate_sha256_within_rule -v`

Expected: FAIL with "duplicate sha256 groups" listing the clone groups.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/corpus/test_corpus_oracle.py
git commit -m "test(corpus): add sha256 uniqueness test — currently failing (139 duplicates)"
```

---

### Task 2: Write Taint-Invariance Test for PY-WL-008/009

**Files:**
- Modify: `tests/unit/corpus/test_corpus_oracle.py`

This test proves acceptance criterion #7: PY-WL-008 and PY-WL-009 produce identical severity, exceptionability, and detection results across all 8 taint states. This should PASS immediately (it's a regression test proving the assumption behind collapsing these rules).

- [ ] **Step 1: Write the test**

Add to the new `TestCorpusIntegrity` class (created in Task 1). Add the required imports at the **module level** of `tests/unit/corpus/test_corpus_oracle.py`:

```python
from wardline.core.matrix import SEVERITY_MATRIX
from wardline.core.severity import RuleId
from wardline.core.taints import TaintState
```

Then add the test method to `TestCorpusIntegrity`:

```python
def test_taint_invariant_rules_produce_identical_outputs(self) -> None:
    """PY-WL-008 and PY-WL-009 must produce identical severity/exceptionability for all taint states."""
    taint_invariant_rules = [RuleId.PY_WL_008, RuleId.PY_WL_009]
    all_taints = list(TaintState)

    for rule in taint_invariant_rules:
        cells = [SEVERITY_MATRIX[(rule, t)] for t in all_taints]
        severities = {c.severity for c in cells}
        exceptionabilities = {c.exceptionability for c in cells}
        assert len(severities) == 1, (
            f"{rule}: expected uniform severity, got {severities}"
        )
        assert len(exceptionabilities) == 1, (
            f"{rule}: expected uniform exceptionability, got {exceptionabilities}"
        )
```

**Note:** Acceptance criterion #7 also requires verifying "identical detection results." The severity matrix check proves the rule's output is uniform, but does not exercise the scanner. This is sufficient because detection logic for these rules does not branch on taint (verified by SA-Dev review of the rule implementations). If scanner-level verification is desired later, a parametrized integration test running the scanner on a single fragment with all 8 taint states can be added.

- [ ] **Step 2: Run test to verify it passes**

Run: `uv run pytest tests/unit/corpus/test_corpus_oracle.py::TestCorpusIntegrity::test_taint_invariant_rules_produce_identical_outputs -v`

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/unit/corpus/test_corpus_oracle.py
git commit -m "test(corpus): add taint-invariance regression test for PY-WL-008/009"
```

---

### Task 3: Update generate_corpus.py — Per-Taint Fragment Generation

**Files:**
- Modify: `scripts/generate_corpus.py`

Replace the static `TP_FRAGMENTS` and `TN_FRAGMENTS` dicts with a taint-context lookup table and per-taint template functions. This is the core fix.

- [ ] **Step 1: Add the taint context vocabulary**

Add after line 31 (`RULES = ...`) in `scripts/generate_corpus.py`:

```python
# Taint context vocabulary — authoritative reference from spec §3
# Maps taint name → (function_suffix, variable_name)
TAINT_CONTEXT: dict[str, tuple[str, str]] = {
    "INTEGRAL": ("system_config", "sys_config"),
    "ASSURED": ("verified_payload", "verified_payload"),
    "GUARDED": ("session_data", "session_data"),
    "UNKNOWN_ASSURED": ("claimed_token", "claimed_token"),
    "UNKNOWN_GUARDED": ("cached_profile", "cached_profile"),
    "UNKNOWN_RAW": ("unknown_input", "unknown_input"),
    "EXTERNAL_RAW": ("request_param", "request_param"),
    "MIXED_RAW": ("mixed_source", "mixed_source"),
}

# Rules where taint does not affect severity/exceptionability/detection.
# These get a single specimen per verdict instead of 8.
TAINT_INVARIANT_RULES = {"PY-WL-008", "PY-WL-009"}
# For taint-invariant rules, use this as the single representative taint state.
TAINT_INVARIANT_REPRESENTATIVE = "EXTERNAL_RAW"
```

- [ ] **Step 2: Replace static fragment dicts with template functions**

Find and replace the `TP_FRAGMENTS: dict[str, str] = {` block (use content matching,
not line numbers — Step 1's insertion shifts line numbers) with:

```python
def _tp_fragment(rule: str, taint_name: str) -> str:
    """Generate a TP fragment with taint-specific function/variable names."""
    suffix, var = TAINT_CONTEXT[taint_name]
    templates: dict[str, str] = {
        "PY-WL-001": f'def dict_default_{suffix}({var}):\n    x = {var}.get("key", "default")\n',
        "PY-WL-002": f'def getattr_default_{suffix}({var}):\n    x = getattr({var}, "name", None)\n',
        "PY-WL-003": f'def key_check_{suffix}({var}):\n    if "key" in {var}:\n        pass\n',
        "PY-WL-004": f"def broad_except_{suffix}():\n    try:\n        pass\n    except Exception:\n        handle()\n",
        "PY-WL-005": f"def silent_except_{suffix}():\n    try:\n        pass\n    except Exception:\n        pass\n",
        "PY-WL-006": f'def audit_broad_{suffix}():\n    try:\n        risky()\n    except Exception:\n        logger.error("failed")\n',
        "PY-WL-007": f"def isinstance_check_{suffix}({var}):\n    if isinstance({var}, dict):\n        pass\n",
        "PY-WL-008": "def process(data):\n    result = validate(data)\n    return data\n",
        "PY-WL-009": 'def process(data):\n    if data["status"] == "active":\n        pass\n',
    }
    return templates[rule]
```

Find and replace the `TN_FRAGMENTS: dict[str, str] = {` block with:

```python
def _tn_fragment(rule: str, taint_name: str) -> str:
    """Generate a TN fragment with taint-specific function/variable names."""
    suffix, var = TAINT_CONTEXT[taint_name]
    templates: dict[str, str] = {
        "PY-WL-001": f'def no_default_{suffix}({var}):\n    x = {var}.get("key")\n',
        "PY-WL-002": f'def getattr_no_default_{suffix}({var}):\n    x = getattr({var}, "name")\n',
        "PY-WL-003": f'def direct_access_{suffix}({var}):\n    x = {var}["key"]\n',
        "PY-WL-004": f"def specific_except_{suffix}():\n    try:\n        pass\n    except ValueError:\n        handle()\n",
        "PY-WL-005": f"def silent_specific_{suffix}():\n    try:\n        pass\n    except ValueError:\n        pass\n",
        "PY-WL-006": f'def audit_specific_{suffix}():\n    try:\n        risky()\n    except ValueError:\n        logger.error("failed")\n',
        "PY-WL-007": f"def no_typecheck_{suffix}({var}):\n    x = len({var})\n",
        "PY-WL-008": 'def process(data):\n    result = validate(data)\n    if not result:\n        raise ValueError("invalid")\n',
        "PY-WL-009": 'from wardline.decorators import validates_semantic\n\n@validates_semantic\ndef validate_order(data):\n    if not isinstance(data, dict):\n        raise TypeError("expected dict")\n    if data["amount"] > 1000:\n        raise ValueError("amount exceeds limit")\n    return data\n',
    }
    return templates[rule]
```

- [ ] **Step 3: Update generate_matrix_specimens() to use the new functions and handle taint-invariant rules**

Replace the `generate_matrix_specimens()` function body. The key changes:
1. Use `_tp_fragment(rule_str, taint_name)` instead of `TP_FRAGMENTS[rule_str]`
2. Use `_tn_fragment(rule_str, taint_name)` instead of `TN_FRAGMENTS[rule_str]`
3. Skip non-representative taint states for taint-invariant rules
4. Use `kfn_` prefix for KFN specimens to avoid sha256 collision with TP counterparts

```python
def generate_matrix_specimens() -> dict[str, dict]:
    """Generate TP+TN for every non-SUPPRESS cell."""
    manifest: dict[str, dict] = {}
    tp_count = 0
    tn_count = 0
    kfn_count = 0

    for rule in RULES:
        rule_str = str(rule)
        for taint in TAINT_ORDER:
            cell = SEVERITY_MATRIX[(rule, taint)]
            taint_name = taint.name

            # Skip SUPPRESS cells
            if cell.severity == Severity.SUPPRESS:
                continue

            # For taint-invariant rules, only generate the representative taint state
            if rule_str in TAINT_INVARIANT_RULES and taint_name != TAINT_INVARIANT_REPRESENTATIVE:
                continue

            # PY-WL-003 is taint-gated: only fires at 3 taint states
            tp_will_fire = True
            if rule_str == "PY-WL-003" and taint_name not in PY_WL_003_ACTIVE_TAINTS:
                tp_will_fire = False

            # --- TP specimen ---
            tp_frag = _tp_fragment(rule_str, taint_name)
            tp_hash = _sha256(tp_frag)

            if rule_str in TAINT_INVARIANT_RULES:
                tp_id = f"{rule_str}-TP-standard"
            else:
                tp_id = f"{rule_str}-TP-{taint_name}"

            if tp_will_fire:
                verdict = "true_positive"
                exp_sev = cell.severity.name
                exp_exc = cell.exceptionability.name
                exp_rules = [rule_str]
                tp_count += 1
            else:
                verdict = "known_false_negative"
                exp_sev = None
                exp_exc = None
                exp_rules = []
                kfn_count += 1

            tp_data = {
                "specimen_id": tp_id,
                "description": f"{rule_str} {verdict} at {taint_name}",
                "rule": rule_str,
                "fragment": tp_frag,
                "taint_state": taint_name,
                "expected_rules": exp_rules,
                "expected_severity": exp_sev,
                "expected_exceptionability": exp_exc,
                "expected_match": tp_will_fire,
                "sha256": tp_hash,
                "verdict": verdict,
            }
            tp_path = os.path.join(
                BASE, rule_str, taint_name, "positive", f"{tp_id}.yaml"
            )
            _write_specimen(tp_path, tp_data)
            manifest[tp_id] = {
                "path": os.path.relpath(tp_path, "corpus"),
                "sha256": tp_hash,
            }

            # --- TN specimen ---
            tn_frag = _tn_fragment(rule_str, taint_name)
            tn_hash = _sha256(tn_frag)

            if rule_str in TAINT_INVARIANT_RULES:
                tn_id = f"{rule_str}-TN-standard"
            else:
                tn_id = f"{rule_str}-TN-{taint_name}"

            tn_data = {
                "specimen_id": tn_id,
                "description": f"{rule_str} true negative at {taint_name}",
                "rule": rule_str,
                "fragment": tn_frag,
                "taint_state": taint_name,
                "expected_rules": [],
                "expected_severity": None,
                "expected_exceptionability": None,
                "expected_match": False,
                "sha256": tn_hash,
                "verdict": "true_negative",
            }
            tn_path = os.path.join(
                BASE, rule_str, taint_name, "negative", f"{tn_id}.yaml"
            )
            _write_specimen(tn_path, tn_data)
            manifest[tn_id] = {
                "path": os.path.relpath(tn_path, "corpus"),
                "sha256": tn_hash,
            }
            tn_count += 1

    print(f"Matrix specimens: {tp_count} TP, {kfn_count} KFN, {tn_count} TN")
    return manifest
```

- [ ] **Step 4: Run the script to verify it produces correct output**

Run: `uv run python scripts/generate_corpus.py`

Verify:
- No errors
- Output shows specimen counts
- Spot-check a few generated files have taint-specific function names

```bash
# Check PY-WL-001 INTEGRAL TP has the right fragment
grep "dict_default_system_config" corpus/specimens/PY-WL-001/INTEGRAL/positive/PY-WL-001-TP-INTEGRAL.yaml
# Check PY-WL-008 only has EXTERNAL_RAW specimens
ls corpus/specimens/PY-WL-008/EXTERNAL_RAW/positive/
```

- [ ] **Step 5: Commit**

```bash
git add scripts/generate_corpus.py
git commit -m "refactor(corpus): update generate_corpus.py for per-taint fragments and 008/009 collapse"
```

---

### Task 4: Update generate_corpus.py — Fix ADV Specimens

**Files:**
- Modify: `scripts/generate_corpus.py`

In the `generate_adversarial_specimens()` function, make 3 changes:
1. Delete 6 same-verdict ADV duplicates (remove from the specimens list)
2. Add `adv_` prefix to 3 conflicting-verdict ADV fragments
3. Keep all other ADV specimens unchanged

- [ ] **Step 1: Remove 6 same-verdict duplicate ADV specimens**

In the `specimens` list inside `generate_adversarial_specimens()`, delete these 6 dict entries entirely:
- `ADV-005-long-function` (duplicate of PY-WL-005-TP-long-function)
- `ADV-006-decorator-stack` (duplicate of PY-WL-001-TP-decorator-stack)
- `ADV-008-async-except` (duplicate of PY-WL-004-TP-async-except)
- `ADV-009-async-silent` (duplicate of PY-WL-005-TP-async-silent)
- `ADV-010-async-getattr` (duplicate of PY-WL-002-TP-async-getattr)
- `ADV-011-class-method` (duplicate of PY-WL-001-TP-class-method)

- [ ] **Step 2: Rename 3 conflicting-verdict ADV fragments with `adv_` prefix**

Update the fragment field for these 3 specimens:

ADV-007-async-get:
```python
"fragment": 'async def adv_async_get(data):\n    x = data.get("key", "default")\n',
```

ADV-012-setdefault:
```python
"fragment": 'def adv_setdefault(data):\n    x = data.setdefault("key", [])\n',
```

ADV-013-defaultdict:
```python
"fragment": "from collections import defaultdict\ndef adv_defaultdict():\n    d = defaultdict(list)\n",
```

- [ ] **Step 3: Run the script**

Run: `uv run python scripts/generate_corpus.py`

Verify the 3 renamed ADV specimens have `adv_` prefixed function names:
```bash
grep "adv_async_get" corpus/specimens/adversarial/ADV-007-async-get.yaml
grep "adv_setdefault" corpus/specimens/adversarial/ADV-012-setdefault.yaml
grep "adv_defaultdict" corpus/specimens/adversarial/ADV-013-defaultdict.yaml
```

- [ ] **Step 4: Commit**

```bash
git add scripts/generate_corpus.py
git commit -m "refactor(corpus): remove 6 ADV duplicates and rename 3 conflicting-verdict ADV fragments"
```

---

### Task 5: Delete Stale Files

**Files:**
- Delete: 14 PY-WL-008 taint-variant YAMLs + PY files
- Delete: 14 PY-WL-009 taint-variant YAMLs + PY files
- Delete: 6 ADV YAML + PY files
- Delete: PY-WL-002-TN-01
- Delete: empty directories

The generation script created new files but didn't remove old ones. This task deletes the stale specimens.

- [ ] **Step 1: Delete PY-WL-008 stale taint variants**

Delete all PY-WL-008 specimens EXCEPT the EXTERNAL_RAW directory and the ASSURED adversarial specimens (AFP/AFN). The adversarial specimens live in the ASSURED directory, so that directory must be preserved — only the taint-matrix clones within it get deleted.

```bash
# Delete taint-matrix clones in ASSURED (keep AFP/AFN)
rm corpus/specimens/PY-WL-008/ASSURED/negative/PY-WL-008-TN-ASSURED.yaml
rm corpus/specimens/PY-WL-008/ASSURED/positive/PY-WL-008-TP-ASSURED.yaml
# Remove .py companions if they exist
rm -f corpus/specimens/PY-WL-008/ASSURED/negative/PY-WL-008-TN-ASSURED.py
rm -f corpus/specimens/PY-WL-008/ASSURED/positive/PY-WL-008-TP-ASSURED.py

# Delete entire non-ASSURED, non-EXTERNAL_RAW taint directories
rm -r corpus/specimens/PY-WL-008/GUARDED
rm -r corpus/specimens/PY-WL-008/INTEGRAL
rm -r corpus/specimens/PY-WL-008/MIXED_RAW
rm -r corpus/specimens/PY-WL-008/UNKNOWN_ASSURED
rm -r corpus/specimens/PY-WL-008/UNKNOWN_GUARDED
rm -r corpus/specimens/PY-WL-008/UNKNOWN_RAW
```

- [ ] **Step 2: Delete PY-WL-009 stale taint variants**

Same pattern. Delete taint-matrix clones but keep ASSURED adversarial specimens (AFP/AFN/TF) and EXTERNAL_RAW.

```bash
# Delete taint-matrix clones in ASSURED (keep AFP/AFN/TF)
rm corpus/specimens/PY-WL-009/ASSURED/negative/PY-WL-009-TN-ASSURED.yaml
rm corpus/specimens/PY-WL-009/ASSURED/positive/PY-WL-009-TP-ASSURED.yaml
rm -f corpus/specimens/PY-WL-009/ASSURED/negative/PY-WL-009-TN-ASSURED.py
rm -f corpus/specimens/PY-WL-009/ASSURED/positive/PY-WL-009-TP-ASSURED.py

# Delete entire non-ASSURED, non-EXTERNAL_RAW taint directories
rm -r corpus/specimens/PY-WL-009/GUARDED
rm -r corpus/specimens/PY-WL-009/INTEGRAL
rm -r corpus/specimens/PY-WL-009/MIXED_RAW
rm -r corpus/specimens/PY-WL-009/UNKNOWN_ASSURED
rm -r corpus/specimens/PY-WL-009/UNKNOWN_GUARDED
rm -r corpus/specimens/PY-WL-009/UNKNOWN_RAW
```

- [ ] **Step 3: Delete 6 stale ADV specimen files (YAML + PY)**

```bash
rm corpus/specimens/adversarial/ADV-005-long-function.yaml corpus/specimens/adversarial/ADV-005-long-function.py
rm corpus/specimens/adversarial/ADV-006-decorator-stack.yaml corpus/specimens/adversarial/ADV-006-decorator-stack.py
rm corpus/specimens/adversarial/ADV-008-async-except.yaml corpus/specimens/adversarial/ADV-008-async-except.py
rm corpus/specimens/adversarial/ADV-009-async-silent.yaml corpus/specimens/adversarial/ADV-009-async-silent.py
rm corpus/specimens/adversarial/ADV-010-async-getattr.yaml corpus/specimens/adversarial/ADV-010-async-getattr.py
rm corpus/specimens/adversarial/ADV-011-class-method.yaml corpus/specimens/adversarial/ADV-011-class-method.py
```

- [ ] **Step 4: Delete PY-WL-002-TN-01 (true duplicate of TN-EXTERNAL_RAW)**

```bash
rm corpus/specimens/PY-WL-002/EXTERNAL_RAW/negative/PY-WL-002-TN-01.yaml
rm -f corpus/specimens/PY-WL-002/EXTERNAL_RAW/negative/PY-WL-002-TN-01.py
```

- [ ] **Step 5: Delete old EXTERNAL_RAW-named files for PY-WL-008/009**

Task 3 generated new `*-standard` files but the old `*-EXTERNAL_RAW` files still
exist alongside them. Both would appear in the manifest causing duplicate sha256.

```bash
rm corpus/specimens/PY-WL-008/EXTERNAL_RAW/positive/PY-WL-008-TP-EXTERNAL_RAW.yaml
rm -f corpus/specimens/PY-WL-008/EXTERNAL_RAW/positive/PY-WL-008-TP-EXTERNAL_RAW.py
rm corpus/specimens/PY-WL-008/EXTERNAL_RAW/negative/PY-WL-008-TN-EXTERNAL_RAW.yaml
rm -f corpus/specimens/PY-WL-008/EXTERNAL_RAW/negative/PY-WL-008-TN-EXTERNAL_RAW.py
rm corpus/specimens/PY-WL-009/EXTERNAL_RAW/positive/PY-WL-009-TP-EXTERNAL_RAW.yaml
rm -f corpus/specimens/PY-WL-009/EXTERNAL_RAW/positive/PY-WL-009-TP-EXTERNAL_RAW.py
rm corpus/specimens/PY-WL-009/EXTERNAL_RAW/negative/PY-WL-009-TN-EXTERNAL_RAW.yaml
rm -f corpus/specimens/PY-WL-009/EXTERNAL_RAW/negative/PY-WL-009-TN-EXTERNAL_RAW.py
```

- [ ] **Step 6: Delete orphaned PY-WL-001-KFN-01.py**

This `.py` file has no YAML companion and would be a stale artifact.

```bash
rm -f corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-KFN-01.py
```

- [ ] **Step 7: Update test_corpus_skeleton.py for PY-WL-008/009 directory changes**

`tests/unit/corpus/test_corpus_skeleton.py` has a parametrized `test_rule_directory_exists`
that asserts `UNKNOWN_RAW/positive` and `UNKNOWN_RAW/negative` exist for ALL 9 rules.
Since PY-WL-008/009 no longer have UNKNOWN_RAW directories, update the test to skip
the UNKNOWN_RAW assertion for taint-invariant rules.

Read the test file and modify the parametrized assertion to either:
- Exclude PY-WL-008/009 from the UNKNOWN_RAW check, or
- Make the UNKNOWN_RAW assertion conditional on the rule not being in
  `{"PY-WL-008", "PY-WL-009"}`

The exact edit depends on the test's current structure — read
`tests/unit/corpus/test_corpus_skeleton.py` and apply the minimal change.

- [ ] **Step 8: Commit**

```bash
git add -A corpus/specimens/ tests/unit/corpus/test_corpus_skeleton.py
git commit -m "fix(corpus): delete 35 stale/duplicate specimen files and update skeleton test"
```

---

### Task 6: Update Manually-Created Specimens

**Files:**
- Modify: ~15 manually-created specimen YAML files not generated by the script

The generation script only creates matrix specimens (TP/TN at non-SUPPRESS cells) and adversarial specimens. Several specimens were created manually and still have the old generic `def process(data)` fragment. These need taint-specific naming.

- [ ] **Step 1: Update PY-WL-001 KFN specimens**

These KFN specimens exist at SUPPRESS taint states (EXTERNAL_RAW, MIXED_RAW, UNKNOWN_RAW) and use the TP fragment. They need `kfn_` prefixed function names.

For each of these files, update the `fragment` field and recompute the `sha256`:

**`corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-KFN-EXTERNAL_RAW.yaml`:**
```yaml
fragment: "def kfn_dict_default_request_param(request_param):\n    x = request_param.get(\"key\"\
  , \"default\")\n"
```

**`corpus/specimens/PY-WL-001/MIXED_RAW/negative/PY-WL-001-KFN-MIXED_RAW.yaml`:**
```yaml
fragment: "def kfn_dict_default_mixed_source(mixed_source):\n    x = mixed_source.get(\"key\"\
  , \"default\")\n"
```

**`corpus/specimens/PY-WL-001/UNKNOWN_RAW/negative/PY-WL-001-KFN-UNKNOWN_RAW.yaml`:**
```yaml
fragment: "def kfn_dict_default_unknown_input(unknown_input):\n    x = unknown_input.get(\"key\"\
  , \"default\")\n"
```

**`corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-KFN-get-default.yaml`:**
```yaml
fragment: "def kfn_dict_default_get_default(request_param):\n    x = request_param.get(\"key\"\
  , \"default\")\n"
```

For each file, recompute sha256 after editing the fragment. Use this helper command
which reads the fragment from the YAML and prints the correct sha256:

```bash
uv run python -c "
import yaml, hashlib, sys
with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)
print(hashlib.sha256(data['fragment'].encode()).hexdigest())
" <path-to-yaml-file>
```

Then update the `sha256` field in the YAML to match the printed value.

**Verification after all Task 6 edits:** Run the helper on every edited file and
confirm the YAML `sha256` field matches. A mismatch means the fragment text in
the YAML wasn't saved correctly (common cause: YAML quoting/escaping differences).

- [ ] **Step 2: Update PY-WL-001 non-matrix duplicates**

**`corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-TN-02.yaml`:**
```yaml
fragment: "def direct_key_request_param(request_param):\n    x = request_param[\"key\"]\n"
```

**`corpus/specimens/PY-WL-001/UNKNOWN_RAW/negative/PY-WL-001-TN-04.yaml`:**
```yaml
fragment: "def direct_key_unknown_input(unknown_input):\n    x = unknown_input[\"key\"]\n"
```

Recompute sha256 for each.

- [ ] **Step 3: Update PY-WL-004 non-matrix duplicates**

**`corpus/specimens/PY-WL-004/EXTERNAL_RAW/negative/PY-WL-004-TN-01.yaml`:**
```yaml
fragment: |
  def specific_convert_request_param(request_param):
      try:
          x = int(request_param)
      except ValueError:
          x = 0
```

**`corpus/specimens/PY-WL-004/UNKNOWN_RAW/negative/PY-WL-004-TN-03.yaml`:**
```yaml
fragment: |
  def specific_convert_unknown_input(unknown_input):
      try:
          x = int(unknown_input)
      except ValueError:
          x = 0
```

Recompute sha256 for each.

- [ ] **Step 4: Update PY-WL-007 TN-SUPPRESS specimens**

These are manually-created specimens for SUPPRESS taint states. They use the TP fragment (isinstance check) but have verdict=true_negative (because type-checking external data is expected).

**`corpus/specimens/PY-WL-007/EXTERNAL_RAW/negative/PY-WL-007-TN-SUPPRESS-EXTERNAL_RAW.yaml`:**
```yaml
fragment: "def isinstance_check_request_param(request_param):\n    if isinstance(request_param,\
  \ dict):\n        pass\n"
```

**`corpus/specimens/PY-WL-007/UNKNOWN_RAW/negative/PY-WL-007-TN-SUPPRESS-UNKNOWN_RAW.yaml`:**
```yaml
fragment: "def isinstance_check_unknown_input(unknown_input):\n    if isinstance(unknown_input,\
  \ dict):\n        pass\n"
```

Recompute sha256 for each.

- [ ] **Step 5: Update PY-WL-007 TN group B specimens**

These are the 2 TN specimens at EXTERNAL_RAW/UNKNOWN_RAW that use `data["key"]`:

**`corpus/specimens/PY-WL-007/EXTERNAL_RAW/negative/PY-WL-007-TN-EXTERNAL_RAW.yaml`:**
```yaml
fragment: "def direct_access_request_param(request_param):\n    x = request_param[\"key\"]\n"
```

**`corpus/specimens/PY-WL-007/UNKNOWN_RAW/negative/PY-WL-007-TN-UNKNOWN_RAW.yaml`:**
```yaml
fragment: "def direct_access_unknown_input(unknown_input):\n    x = unknown_input[\"key\"]\n"
```

Recompute sha256 for each.

- [ ] **Step 6: Update PY-WL-001 schema-default duplicate pair**

These two specimens share a fragment but test different scenarios (governed vs ungoverned suppression). Differentiate by renaming the functions:

**`corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-KFN-schema-default-ungoverned.yaml`:**
```yaml
fragment: |
  from wardline import schema_default

  def ungoverned_schema_default(data):
      return schema_default(data.get("key", ""))
```

**`corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-TN-schema-default-governed.yaml`:**
```yaml
fragment: |
  from wardline import schema_default

  def governed_schema_default(data):
      return schema_default(data.get("key", ""))
```

Recompute sha256 for each.

- [ ] **Step 7: Commit**

```bash
git add corpus/specimens/
git commit -m "fix(corpus): update manually-created specimens with taint-specific fragments"
```

---

### Task 7: Regenerate Manifest and Run Validation

**Files:**
- Regenerated: `corpus/corpus_manifest.json`

- [ ] **Step 1: Regenerate the manifest**

```bash
uv run python scripts/generate_corpus.py
```

This re-scans disk and rebuilds `corpus/corpus_manifest.json` from all YAML files.

- [ ] **Step 2: Verify specimen count**

```bash
python3 -c "import json; d=json.load(open('corpus/corpus_manifest.json')); print(f'Count: {d[\"specimen_count\"]}')"
```

Expected: `Count: 224`

- [ ] **Step 3: Verify zero duplicate sha256 within rules**

```bash
python3 -c "
import json
from collections import defaultdict
d = json.load(open('corpus/corpus_manifest.json'))
by_rule = defaultdict(lambda: defaultdict(list))
for s in d['specimens']:
    by_rule[s['rule']][s['sha256']].append(s['specimen_id'])
dupes = [(r,ids) for r,shas in by_rule.items() for sha,ids in shas.items() if len(ids)>1]
print(f'Duplicates: {len(dupes)}')
for r,ids in dupes: print(f'  {r}: {ids}')
"
```

Expected: `Duplicates: 0`

- [ ] **Step 4: Run corpus verify**

```bash
uv run wardline corpus verify --json
```

Expected: exit code 0, all specimens pass.

- [ ] **Step 5: Run full test suite**

```bash
uv run pytest
```

Expected: all tests pass, including the new sha256 uniqueness test from Task 1.

- [ ] **Step 6: Commit**

```bash
git add corpus/corpus_manifest.json
git commit -m "fix(corpus): regenerate manifest — 224 specimens, zero sha256 duplicates"
```

---

### Task 8: Write Conformance Evidence Document

**Files:**
- Create: `docs/requirements/spec-fitness/corpus-reduction-2026-04-10.md`

- [ ] **Step 1: Write the conformance evidence document**

```markdown
# Corpus Specimen Reduction: 259 → 224

**Date:** 2026-04-10
**Issue:** wardline-01a36526c7
**Design spec:** `docs/superpowers/specs/2026-04-10-taint-specific-specimen-rewrite-design.md`

## Summary

35 corpus specimens were removed as part of a quality improvement to eliminate
fragment duplication. No detection coverage was lost.

## Specimens Removed

### PY-WL-008/009 taint-variant collapse (28 specimens)

PY-WL-008 and PY-WL-009 are **taint-invariant rules**: they produce identical
severity (ERROR), exceptionability (UNCONDITIONAL), and detection results
regardless of taint state. A parametrized test in
`tests/unit/corpus/test_corpus_oracle.py::test_taint_invariant_rules_produce_identical_outputs`
mechanically verifies this property.

The 8 taint variants per verdict were collapsed to 1 representative (EXTERNAL_RAW).
Adversarial specimens (AFP, AFN, TF) were preserved.

### PY-WL-002-TN-01 (1 specimen)

True duplicate of PY-WL-002-TN-EXTERNAL_RAW (kept): same taint state
(EXTERNAL_RAW), same fragment (`def process(obj): x = getattr(obj, "name")`),
same verdict (true_negative). Removed as redundant.

### ADV same-verdict duplicates (6 specimens)

Each ADV specimen below had an identical fragment, taint state, and verdict
as the listed rule-specific specimen. The rule specimen was kept.

| Deleted Specimen | Kept Specimen | Rule | Taint | Verdict |
|-----------------|---------------|------|-------|---------|
| ADV-005-long-function | PY-WL-005-TP-long-function | PY-WL-005 | EXTERNAL_RAW | TP |
| ADV-006-decorator-stack | PY-WL-001-TP-decorator-stack | PY-WL-001 | ASSURED | TP |
| ADV-008-async-except | PY-WL-004-TP-async-except | PY-WL-004 | UNKNOWN_RAW | TP |
| ADV-009-async-silent | PY-WL-005-TP-async-silent | PY-WL-005 | MIXED_RAW | TP |
| ADV-010-async-getattr | PY-WL-002-TP-async-getattr | PY-WL-002 | ASSURED | TP |
| ADV-011-class-method | PY-WL-001-TP-class-method | PY-WL-001 | GUARDED | TP |

## PY-WL-001 SUPPRESS Taint States

PY-WL-001 suppresses findings at EXTERNAL_RAW, MIXED_RAW, and UNKNOWN_RAW
(Tier 3-4 taint states). This is a deliberate design choice: at these trust
levels, dict-default patterns are expected and flagging them would produce
excessive noise. KFN specimens at these taint states document the known
suppression gap. The suppression policy is defined in the severity matrix
and verified by existing matrix tests.

## Coverage Assurance

- All remaining specimens use unique code fragments per rule (verified by
  `test_no_duplicate_sha256_within_rule`)
- `wardline corpus verify` passes with zero failures
- Full test suite (`uv run pytest`) passes
- Scanner detection logic unchanged — only corpus metadata was modified
```

- [ ] **Step 2: Commit**

```bash
git add docs/requirements/spec-fitness/corpus-reduction-2026-04-10.md
git commit -m "docs(conformance): add evidence for corpus 259→224 specimen reduction"
```

---

## Execution Order and Dependencies

```
Task 1 (sha256 test)  ──────────────────────────────────────────────┐
Task 2 (invariance test)  ──────────────────────────────────────────┤
Task 3 (update generate script — fragments)  ───┐                  │
Task 4 (update generate script — ADV)  ─────────┤                  │
                                                 ├─ Task 5 (delete stale files)
                                                 │
                                                 ├─ Task 6 (manual specimen edits)
                                                 │
                                                 └─ Task 7 (regenerate + validate) ─── Task 8 (conformance doc)
```

Tasks 1–2 can run in parallel with Tasks 3–4.
Tasks 3–4 must complete before Task 5.
Tasks 5–6 can run in parallel.
Task 7 depends on all prior tasks.
Task 8 depends on Task 7 passing.
