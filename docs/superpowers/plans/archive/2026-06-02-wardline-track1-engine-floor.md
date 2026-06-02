# Wardline Track 1 — Engine-Quality Floor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Track 1's engine-quality floor — stand up an FP-measurement substrate (T1.4), resolve the star-import false-negative (T1.2), complete the return-indirection explain surface (T1.3), and verify-and-close the taint-combination hardening epic (T1.1) — with every DoD gate green.

**Architecture:** Wardline is a zero-dep static taint analyzer. T1.4 adds a *test-only* labeled corpus under `tests/corpus/` plus a manifest-driven FP-rate harness (no engine change). T1.2 is a surgical change to `build_import_alias_map` (and the matching diagnostic suppression) that materializes the *statically-known* `wardline.decorators` exports for `from wardline.decorators import *` — never executing the target, keeping fail-closed for every other star import. T1.3 extends `compute_return_callee` with single-hop indirection (explain-surface only; taint *values* pinned unchanged). T1.1 is verify-and-close: the 2026-05-31 audit found the engine sound (0 live FP/FN) and PR #12/#13 landed the hardening — confirm each finding's regression test exists, then close the epic.

**Tech Stack:** Python 3.11+ stdlib `ast`, `uv`/`pytest` (random order via `pytest-randomly`), `ruff`, `mypy --strict`, `make ci`.

---

## Authoritative references (read before starting)

- Track spec: `docs/superpowers/specs/2026-06-02-wardline-track1-engine-floor-design.md`
- Program spec: `docs/superpowers/specs/2026-06-02-wardline-first-class-body-of-work-design.md` §2 Track 1
- Progress tracker (update on completion): `docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md`
- Audit (T1.1 source of truth): `docs/audits/2026-05-31-taint-combination-audit.md`
- Lattice decision: `docs/decisions/2026-05-31-wardline-taint-lattice-retain.md`
- Taint algebra concept: `docs/concepts/taint-algebra.md`

## Invariants (hold on EVERY task — a violation is a stop-the-line failure)

1. **Fail-closed / no false-green.** Every state the engine cannot prove stays an observable `WLN-ENGINE-*` FACT. A silent skip is a bug.
2. **Over-taint is safe; under-taint is a defect.** No fix may make a real untrusted flow disappear.
3. **Two operators stay distinct** — `least_trusted` (rank-meet) ≠ `taint_join` (provenance-clash → `MIXED_RAW`). Never collapse them.
4. **Byte-identical warm/cold** — cold scan ≡ warm-cache scan, byte-for-byte (`tests/unit/scanner/taint/test_project_resolver.py`).
5. **Determinism** — tests pass under `pytest-randomly`; order-dependence is a real failure.
6. **Zero-dep base** — no new runtime dependency in the base package; new test deps are dev-only.
7. **RED-first** — every soundness/completeness fix (T1.2, T1.3) starts with a regression test that FAILS on the current engine; capture the red output before implementing.

## DoD gates (all green together at close-out)

| Gate | Bar | How verified |
|---|---|---|
| Soundness | T1.1–T1.3 holes closed; each closed hole has a RED-first regression test | the per-task tests + the audit-finding regression tests |
| FP-rate | ≤5% active DEFECT findings labeled FALSE_POSITIVE on the corpus | `tests/corpus/test_fp_rate.py` |
| Coverage | 90% global; **95% on `src/wardline/scanner/taint/`** | `make test-cov` + the taint-subtree check (Task 7) |
| Determinism | warm/cold byte-identical test green | `test_project_resolver.py` warm/cold test |
| Dogfood | `wardline scan src/wardline --fail-on ERROR` finding-clean or fully baselined | `make scan-self` |
| Waiver discipline | every waiver has a reason; waiver count ≤ rule count | `tests/corpus/test_waiver_discipline.py` |

---

## File Structure

**New (test-only):**
- `tests/corpus/__init__.py` — marks the corpus package.
- `tests/corpus/fixtures/` — annotated `.py` fixture modules (one per FP-prone shape).
- `tests/corpus/MANIFEST.yaml` — ground-truth expectations: per fixture, the DEFECT findings the engine SHOULD produce, each tagged `TRUE_POSITIVE` / `FALSE_POSITIVE` with a note.
- `tests/corpus/harness.py` — loads the manifest, runs `run_scan` over `tests/corpus/fixtures/`, reconciles findings ↔ manifest, computes FP rate.
- `tests/corpus/test_fp_rate.py` — asserts FP rate ≤5% and that every active DEFECT is accounted for.
- `tests/corpus/test_waiver_discipline.py` — every waiver has a reason; waiver count ≤ rule count.

**Modified (engine — taint subtree, must keep 95% coverage):**
- `src/wardline/scanner/ast_primitives.py` — `build_import_alias_map` gains optional `star_exports` param (T1.2).
- `src/wardline/scanner/taint/decorator_provider.py` — add `vocabulary_star_exports()` helper (T1.2).
- `src/wardline/scanner/diagnostics.py` — `diagnose_unknown_imports` gains `resolvable_star_modules` param; suppress FACT for resolved star (T1.2).
- `src/wardline/scanner/analyzer.py` — pass `star_exports` into both call sites (T1.2).
- `src/wardline/scanner/taint/variable_level.py` — `compute_return_callee` single-hop indirection (T1.3).

**Modified (tests):**
- `tests/unit/scanner/taint/test_decorator_provider.py` or `test_provider_seedcontext.py` — star-import unit tests (T1.2).
- `tests/unit/scanner/test_diagnostics.py` — resolved-star suppression + unresolved-star FACT preserved (T1.2).
- `tests/unit/scanner/taint/test_variable_level.py` — return-indirection callee tests + `compute_return_taint` values-unchanged pin (T1.3).
- `tests/unit/core/test_explain.py` — explain names the indirect callee end-to-end (T1.3).

---

## Task 0: Branch + green baseline

**Files:** none (git + verification only).

- [ ] **Step 1: Create the working branch off current HEAD**

The Track 1 spec + tracker live on the current branch (`docs/loom-entity-dossier-spec`), not yet on `main`, so branch off HEAD so the spec travels with the work. (Merge target is decided with the user at close-out.)

```bash
git checkout -b feat/track1-engine-floor
```

- [ ] **Step 2: Confirm a green starting point**

Run and record output. Everything must pass BEFORE any change, so a later red is attributable to this work.

```bash
uv run pytest -q
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy
make scan-self
```

Expected: full suite passes; ruff/mypy clean; `scan-self` exits 0 (dogfood clean).

- [ ] **Step 3: Record the coverage baseline (esp. taint subtree)**

```bash
uv run pytest --cov=wardline --cov=src/wardline/scanner/taint --cov-report=term-missing -q | tail -30
```

Expected: global ≥90%. Note the `src/wardline/scanner/taint/` line — it must end ≥95% after Tasks 2 & 3.

- [ ] **Step 4: Commit the branch point (no-op marker optional)**

No commit needed; baseline is recorded. Proceed.

---

## Task 1 (T1.4): Labeled corpus scaffold + harness

**Files:**
- Create: `tests/corpus/__init__.py`
- Create: `tests/corpus/harness.py`
- Create: `tests/corpus/MANIFEST.yaml` (seeded empty, grown in Task 1b)

**Design:** The harness runs the real engine (`run_scan`) over `tests/corpus/fixtures/`, collects **active DEFECT findings** (kind `DEFECT`, `suppressed == "active"`), and reconciles them against `MANIFEST.yaml`. Matching key = `(relative_path, rule_id, qualname)`. Rules:
- Every active DEFECT must match exactly one manifest entry (no *unaccounted* findings — that is how clean-shape regressions are caught).
- Every manifest entry must match ≥1 finding (no *stale* expectations).
- FP rate = (active DEFECTs whose matched entry is `FALSE_POSITIVE`) / (total active DEFECTs). Asserted ≤ 0.05.

Line numbers are deliberately NOT part of the key (line edits must not break the corpus).

- [ ] **Step 1: Write the harness**

`tests/corpus/harness.py`:

```python
"""Labeled-corpus harness (T1.4): run the engine over tests/corpus/fixtures and
reconcile active DEFECT findings against MANIFEST.yaml ground truth."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from wardline.core.finding import Kind
from wardline.core.run import run_scan

CORPUS_ROOT = Path(__file__).parent / "fixtures"
MANIFEST_PATH = Path(__file__).parent / "MANIFEST.yaml"

TRUE_POSITIVE = "TRUE_POSITIVE"
FALSE_POSITIVE = "FALSE_POSITIVE"
_LABELS = frozenset({TRUE_POSITIVE, FALSE_POSITIVE})


@dataclass(frozen=True)
class Expectation:
    path: str
    rule_id: str
    qualname: str
    label: str
    note: str


@dataclass(frozen=True)
class Reconciliation:
    active_defects: int
    false_positives: int
    unaccounted: list[tuple[str, str, str]]  # (path, rule_id, qualname) findings with no manifest entry
    stale: list[Expectation]  # manifest entries that matched no finding

    @property
    def fp_rate(self) -> float:
        return 0.0 if self.active_defects == 0 else self.false_positives / self.active_defects


def load_manifest() -> list[Expectation]:
    raw = yaml.safe_load(MANIFEST_PATH.read_text()) or {}
    out: list[Expectation] = []
    for path, entries in (raw.get("fixtures") or {}).items():
        for e in entries or []:
            label = e["label"]
            if label not in _LABELS:
                raise ValueError(f"{path}: bad label {label!r} (want one of {sorted(_LABELS)})")
            out.append(
                Expectation(
                    path=path,
                    rule_id=e["rule_id"],
                    qualname=e["qualname"],
                    label=label,
                    note=e.get("note", ""),
                )
            )
    return out


def reconcile() -> Reconciliation:
    result = run_scan(CORPUS_ROOT)
    expectations = load_manifest()
    by_key: dict[tuple[str, str, str], Expectation] = {
        (e.path, e.rule_id, e.qualname): e for e in expectations
    }
    matched_keys: set[tuple[str, str, str]] = set()
    active_defects = 0
    false_positives = 0
    unaccounted: list[tuple[str, str, str]] = []
    for f in result.findings:
        if f.kind is not Kind.DEFECT or f.suppressed != "active":
            continue
        active_defects += 1
        key = (f.location.path, f.rule_id, f.qualname or "")
        exp = by_key.get(key)
        if exp is None:
            unaccounted.append(key)
            continue
        matched_keys.add(key)
        if exp.label == FALSE_POSITIVE:
            false_positives += 1
    stale = [e for e in expectations if (e.path, e.rule_id, e.qualname) not in matched_keys]
    return Reconciliation(
        active_defects=active_defects,
        false_positives=false_positives,
        unaccounted=unaccounted,
        stale=stale,
    )
```

> NOTE for the implementer: confirm `Finding` field names against `src/wardline/core/finding.py` — the plan assumes `f.kind` (enum `Kind`), `f.suppressed` (str, `"active"` when not suppressed), `f.rule_id`, `f.qualname`, `f.location.path`. If a name differs, adapt the harness and record the correction in the task notes. Confirm `run_scan` accepts a positional root `Path` (it does — `core/run.py`). `pyyaml` is already a `scanner`-extra dep (used by config); it is available in the dev env.

- [ ] **Step 2: Create the package marker + empty manifest**

`tests/corpus/__init__.py`:

```python
"""T1.4 labeled FP corpus — see docs/superpowers/plans/2026-06-02-wardline-track1-engine-floor.md."""
```

`tests/corpus/MANIFEST.yaml`:

```yaml
# Ground-truth expectations for the labeled FP corpus (T1.4).
# Key = (path relative to tests/corpus/fixtures, rule_id, qualname).
# label: TRUE_POSITIVE (engine correctly fires) | FALSE_POSITIVE (engine wrongly fires).
# FP rate = FALSE_POSITIVE / total active DEFECTs, must stay <= 5%.
fixtures: {}
```

- [ ] **Step 3: Smoke-test the harness on the empty corpus**

`tests/corpus/test_fp_rate.py` (initial — asserts the harness runs):

```python
from tests.corpus.harness import reconcile


def test_harness_runs_on_empty_corpus():
    rec = reconcile()
    assert rec.active_defects == 0
    assert rec.fp_rate == 0.0
```

Run: `uv run pytest tests/corpus/test_fp_rate.py -q`
Expected: PASS (no fixtures yet → zero findings).

- [ ] **Step 4: Commit**

```bash
git add tests/corpus/__init__.py tests/corpus/harness.py tests/corpus/MANIFEST.yaml tests/corpus/test_fp_rate.py
git commit -m "test(corpus): T1.4 labeled-corpus harness + manifest scaffold"
```

---

## Task 1b (T1.4): Populate the corpus with the FP-prone shapes

**Files:**
- Create: `tests/corpus/fixtures/*.py` (the annotated shapes)
- Modify: `tests/corpus/MANIFEST.yaml`
- Modify: `tests/corpus/test_fp_rate.py`

**Required shapes (track spec §3 — each MUST appear):** control-flow-join merges (if/try/match), validators (`@trust_boundary` with AND without a rejection path), broad/silent except in trusted tiers, aliased-stdlib sinks, match-arm assignments, return indirection.

**Sizing rule (anti-brittleness):** target **≥ 20 TRUE_POSITIVE** active DEFECTs so a single mislabel cannot trivially breach 5%. Clean shapes (validator-with-rejection, narrow except) produce NO finding and are guarded by the "no unaccounted findings" rule, not listed in the manifest.

- [ ] **Step 1: Author the fixtures (one file per theme)**

Create the files below. They use the real decorators (`from wardline.decorators import external_boundary, trust_boundary, trusted`) and the real `wardline.core.taints.TaintState` levels via string args. Each fixture is designed so the engine's CORRECT behavior is known.

`tests/corpus/fixtures/cf_joins.py` (control-flow joins — each should fire PY-WL-101 because a branch can return raw):

```python
"""Control-flow-join shapes. A @trusted producer whose SOME branch returns raw
must fire PY-WL-101 (weakest-link). Clean counterparts return validated data."""
from wardline.decorators import trusted, trust_boundary


def read_raw(p):  # untrusted source surrogate (undecorated → UNKNOWN_RAW seed)
    return p


@trust_boundary(to_level="ASSURED")
def validate(p):
    if not p:
        raise ValueError("reject")
    return p


@trusted(level="ASSURED")
def if_branch_leaks(flag, p):  # TP: else branch returns raw
    if flag:
        return validate(read_raw(p))
    return read_raw(p)


@trusted(level="ASSURED")
def try_branch_leaks(p):  # TP: except branch returns raw
    try:
        return validate(read_raw(p))
    except ValueError:
        return read_raw(p)


@trusted(level="ASSURED")
def if_branch_clean(flag, p):  # CLEAN: both branches validated → no finding
    if flag:
        return validate(read_raw(p))
    return validate(read_raw(p))
```

`tests/corpus/fixtures/match_arms.py` (match-arm assignment + merge):

```python
"""Match-arm assignment shapes (the L2 _handle_match path)."""
from wardline.decorators import trusted, trust_boundary


def read_raw(p):
    return p


@trust_boundary(to_level="ASSURED")
def validate(p):
    if not p:
        raise ValueError("reject")
    return p


@trusted(level="ASSURED")
def match_arm_leaks(cmd, p):  # TP: one arm binds raw, returned
    match cmd:
        case "a":
            v = validate(read_raw(p))
        case _:
            v = read_raw(p)
    return v


@trusted(level="ASSURED")
def match_arm_clean(cmd, p):  # CLEAN: every arm validated
    match cmd:
        case "a":
            v = validate(read_raw(p))
        case _:
            v = validate(read_raw(p))
    return v
```

`tests/corpus/fixtures/validators.py` (PY-WL-102 — boundary with/without rejection):

```python
"""Trust-boundary validators. Without a rejection path → PY-WL-102 (TP).
With a rejection path → clean (no finding)."""
from wardline.decorators import trust_boundary


@trust_boundary(to_level="ASSURED")
def no_rejection(p):  # TP: cannot say "no" → PY-WL-102
    return p


@trust_boundary(to_level="ASSURED")
def has_rejection(p):  # CLEAN: has a raise path
    if not p:
        raise ValueError("reject")
    return p
```

`tests/corpus/fixtures/exceptions.py` (PY-WL-103 broad / PY-WL-104 silent in trusted tier):

```python
"""Broad and silent exception handlers in trusted-tier functions."""
from wardline.decorators import trusted


def work():
    return 1


@trusted(level="INTEGRAL")
def broad_handler():  # TP: PY-WL-103 broad except in trusted tier
    try:
        return work()
    except Exception:
        return None


@trusted(level="INTEGRAL")
def silent_handler():  # TP: PY-WL-104 silently swallowed
    try:
        return work()
    except ValueError:
        pass
    return None


@trusted(level="INTEGRAL")
def narrow_logged():  # CLEAN: narrow + handled
    try:
        return work()
    except ValueError as e:
        raise RuntimeError("wrapped") from e
```

`tests/corpus/fixtures/aliased_stdlib.py` (aliased-stdlib sink + return indirection):

```python
"""Aliased-stdlib source and a single-hop indirection return (feeds T1.3 too)."""
import pickle as _pkl
from wardline.decorators import trusted


@trusted(level="ASSURED")
def aliased_sink(blob):  # TP: pickle.loads is a curated EXTERNAL_RAW source
    return _pkl.loads(blob)


@trusted(level="ASSURED")
def indirect_return(blob):  # TP: raw flows through a local var (indirection)
    data = _pkl.loads(blob)
    return data
```

> NOTE: confirm `pickle.loads` is in `src/wardline/scanner/taint/stdlib_taint.yaml` as an `EXTERNAL_RAW`-returning entry. If the curated table uses a different sink, swap to one that is present (e.g. `json.loads`, `os.environ.get`) and keep the alias shape. The fixture's job is the *aliased* call resolving through `alias_map`.

- [ ] **Step 2: Discover the engine's actual findings, then write the manifest**

Run the analyzer over the fixtures to see exactly what fires (rule_id + qualname):

```bash
uv run wardline scan tests/corpus/fixtures --format jsonl | python -c "import sys,json; [print(json.loads(l)['rule_id'], json.loads(l).get('qualname'), json.loads(l)['kind'], json.loads(l)['suppressed']) for l in sys.stdin if l.strip()]"
```

For each active DEFECT, add a manifest entry. Every entry that reflects CORRECT engine behavior is `TRUE_POSITIVE`. (The audit established 0 live FP, so expect zero `FALSE_POSITIVE` today; the label exists for regression capture.) Populate `MANIFEST.yaml`, e.g.:

```yaml
fixtures:
  cf_joins.py:
    - {rule_id: PY-WL-101, qualname: "cf_joins.if_branch_leaks", label: TRUE_POSITIVE, note: "else branch returns raw"}
    - {rule_id: PY-WL-101, qualname: "cf_joins.try_branch_leaks", label: TRUE_POSITIVE, note: "except branch returns raw"}
  # ... one entry per active DEFECT the scan above reported ...
```

> The implementer fills every reported `(path, rule_id, qualname)` active DEFECT. If the scan reports a finding on a shape the fixture intended to be CLEAN, that is a real FP — do NOT paper over it: label it `FALSE_POSITIVE`, and (if it pushes the rate >5% or contradicts the audit) STOP and surface it, because it means the engine regressed.

- [ ] **Step 3: Assert the FP-rate gate**

Replace `tests/corpus/test_fp_rate.py` body:

```python
from tests.corpus.harness import reconcile


def test_fp_rate_within_budget():
    rec = reconcile()
    assert rec.active_defects >= 20, f"corpus too small to be a meaningful gate: {rec.active_defects} active DEFECTs"
    assert not rec.unaccounted, f"unaccounted findings (engine fired with no manifest entry): {rec.unaccounted}"
    assert not rec.stale, f"stale manifest entries (no finding matched): {[(e.path, e.rule_id, e.qualname) for e in rec.stale]}"
    assert rec.fp_rate <= 0.05, f"FP rate {rec.fp_rate:.1%} exceeds 5% budget"
```

Run: `uv run pytest tests/corpus/test_fp_rate.py -q`
Expected: PASS — ≥20 active DEFECTs, 0 unaccounted, 0 stale, FP rate 0% (≤5%).

- [ ] **Step 4: Confirm the corpus does NOT leak into the dogfood scan**

```bash
make scan-self   # scans src/wardline only
```

Expected: exit 0. (CI scans `src/`, not `tests/` — confirm no corpus path appears in output.)

- [ ] **Step 5: Commit**

```bash
git add tests/corpus/
git commit -m "test(corpus): T1.4 FP-prone fixtures + manifest + FP-rate <=5% gate"
```

---

## Task 1c (T1.4): Waiver discipline

**Files:**
- Create: `tests/corpus/test_waiver_discipline.py`

**Design:** `core/waivers.py` already raises `ConfigError` on a reasonless waiver at parse time. This task asserts that invariant at the repo level AND adds the ratio gate (waiver count ≤ enabled-rule count). The repo currently has **0 waivers** (`.wardline/waivers.yaml` empty/absent) and **4 rules**, so the ratio holds with margin.

- [ ] **Step 1: Write the waiver-discipline tests**

```python
"""T1.4 waiver discipline: every waiver carries a reason; waiver count does not
outgrow rule count."""
from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.errors import ConfigError
from wardline.core.waivers import load_waivers
from wardline.scanner.rules import build_default_registry  # adjust import to the real registry builder

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_reasonless_waiver_rejected(tmp_path):
    cfg = tmp_path / "wardline.yaml"
    cfg.write_text("waivers:\n  - fingerprint: 'abc123'\n")  # no reason
    with pytest.raises(ConfigError):
        load_waivers(cfg)


def test_repo_waivers_all_have_reasons():
    cfg = REPO_ROOT / "wardline.yaml"
    if not cfg.exists():
        pytest.skip("no project config — no waivers to check")
    waivers = load_waivers(cfg)  # raises if any reason missing; pass == clean
    for w in waivers:
        assert w.reason and w.reason.strip()


def test_waiver_count_not_outgrowing_rule_count():
    cfg = REPO_ROOT / "wardline.yaml"
    waivers = load_waivers(cfg) if cfg.exists() else []
    # Rule count: the curated builtin rules currently enabled (4 today).
    rule_count = 4
    assert len(waivers) <= rule_count, (
        f"waiver count {len(waivers)} exceeds rule count {rule_count} — "
        "suppression is outgrowing the rule set (FP economics breach)"
    )
```

> NOTE: confirm `load_waivers` signature and the `Waiver.reason` attribute against `src/wardline/core/waivers.py` (the grep showed `Waiver(fingerprint=, reason=, expires=)` and `load_waivers`-style parsing — verify the exact public function name; adapt the import). For `rule_count`, prefer reading the real enabled-rule count from the default registry if cheaply available; the literal `4` is the documented current floor and is acceptable if the registry API is awkward — leave a comment pointing at the rule table in CLAUDE.md.

- [ ] **Step 2: Run**

Run: `uv run pytest tests/corpus/test_waiver_discipline.py -q`
Expected: PASS (reasonless rejected; repo waivers clean/empty; 0 ≤ 4).

- [ ] **Step 3: Commit**

```bash
git add tests/corpus/test_waiver_discipline.py
git commit -m "test(corpus): T1.4 waiver discipline — reason required, count <= rules"
```

- [ ] **Step 4: Close T1.4 in Filigree**

```bash
filigree close wardline-41f4a42a43 --actor claude
```

---

## Task 2 (T1.2): Star-import FN resolution — RED first

**Issue:** `wardline-2b427a9579`. **The reconciliation:** the older issue concluded "won't-fix" because *full* `import *` resolution requires executing the target module. The track spec (newer, authoritative) asks for the **tractable** case: `from wardline.decorators import *` brings in names Wardline *already knows a priori* (the `REGISTRY`). We materialize ONLY that statically-known export set — no source-reading of another module, no execution. Every other star import stays unresolved and keeps emitting the honest `WLN-ENGINE-UNKNOWN-IMPORT` FACT (fail-closed preserved).

**Files:**
- Test: `tests/unit/scanner/taint/test_decorator_provider.py` (or a new `test_star_import.py` in the same dir)
- Test: `tests/unit/scanner/test_diagnostics.py`
- Modify: `src/wardline/scanner/taint/decorator_provider.py`
- Modify: `src/wardline/scanner/ast_primitives.py`
- Modify: `src/wardline/scanner/diagnostics.py`
- Modify: `src/wardline/scanner/analyzer.py`

- [ ] **Step 1: Write the failing end-to-end test (RED)**

Add to `tests/unit/scanner/taint/test_decorator_provider.py` (uses the analyzer over an in-memory fixture; mirror the file's existing scan-helper style):

```python
def test_star_imported_trust_boundary_is_seeded(tmp_path):
    """from wardline.decorators import * must resolve @trust_boundary so PY-WL-102
    fires on a no-rejection validator reached via star-import (was a silent FN)."""
    pkg = tmp_path / "proj"
    pkg.mkdir()
    (pkg / "m.py").write_text(
        "from wardline.decorators import *\n"
        "\n"
        "@trust_boundary(to_level='ASSURED')\n"
        "def v(p):\n"
        "    return p\n"
    )
    from wardline.core.run import run_scan

    result = run_scan(pkg)
    rule_ids = {f.rule_id for f in result.findings if f.suppressed == "active"}
    assert "PY-WL-102" in rule_ids, "star-imported @trust_boundary was not seeded"
```

Run: `uv run pytest tests/unit/scanner/taint/test_decorator_provider.py::test_star_imported_trust_boundary_is_seeded -v`
Expected: **FAIL** — today the star import is dropped, `v` is undecorated, no PY-WL-102. Capture this red output.

- [ ] **Step 2: Add `vocabulary_star_exports()` to `decorator_provider.py`**

After the module constants (near `_VOCAB_PREFIX`):

```python
def vocabulary_star_exports() -> dict[str, dict[str, str]]:
    """Statically-known star-export map for the trust-decorator module.

    ``from wardline.decorators import *`` brings the REGISTRY decorator names into
    the importing module's namespace. Wardline knows these names a priori (they are
    the keys of :data:`REGISTRY`), so it can materialise them WITHOUT importing or
    executing the target module — the static-analyzer boundary is preserved. Returned
    as ``{source_module_fqn: {local_name: target_fqn}}`` for
    :func:`build_import_alias_map`. Only this one module resolves; every other star
    import stays unresolved (honest ``WLN-ENGINE-UNKNOWN-IMPORT`` FACT).
    """
    return {_VOCAB_PREFIX: {name: f"{_VOCAB_PREFIX}.{name}" for name in REGISTRY}}
```

- [ ] **Step 3: Teach `build_import_alias_map` to materialize known star exports**

In `src/wardline/scanner/ast_primitives.py`, change the signature and the `*`-handling branch:

```python
def build_import_alias_map(
    tree: ast.Module,
    module_path: str = "",
    *,
    is_package: bool = False,
    star_exports: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, str]:
```

Add `from collections.abc import Mapping` to the imports. Update the docstring's "Star imports ... are ignored" line to: "Absolute star imports (``from X import *``) are resolved ONLY when ``X`` is in ``star_exports`` (a statically-known export set, never read from the target's source); all others are ignored and surface as a FACT." Then in the `ImportFrom` loop, before the per-alias loop, handle the star case:

```python
        if isinstance(node, ast.ImportFrom):
            if node.module is None and (node.level or 0) == 0:
                continue
            # Absolute star import of a statically-known module: materialise its
            # known exports (no execution, no target-source read). Relative star
            # imports and unknown modules stay unresolved (honest FACT).
            if (node.level or 0) == 0 and node.module is not None and any(a.name == "*" for a in node.names):
                for local_name, fqn in (star_exports or {}).get(node.module, {}).items():
                    alias_map[local_name] = fqn
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                ...  # unchanged
```

> The existing `if alias.name == "*": continue` inside the per-alias loop stays as the fall-through for relative/unknown star imports.

- [ ] **Step 4: Pass `star_exports` from the analyzer**

In `src/wardline/scanner/analyzer.py`, import the helper and pass it at the `build_import_alias_map` call (line ~118):

```python
from wardline.scanner.taint.decorator_provider import vocabulary_star_exports
...
alias_map = build_import_alias_map(
    tree, module_path=module, star_exports=vocabulary_star_exports()
)
```

> Check for an import cycle: `analyzer.py` already imports from `decorator_provider` indirectly? It imports `provider`. `decorator_provider` imports `core.registry`/`core.taints`/`provider` — no analyzer import, so adding this import is acyclic. Verify `mypy` is clean.

- [ ] **Step 5: Run the RED test → GREEN**

Run: `uv run pytest tests/unit/scanner/taint/test_decorator_provider.py::test_star_imported_trust_boundary_is_seeded -v`
Expected: **PASS**.

- [ ] **Step 6: Suppress the UNKNOWN-IMPORT FACT for the resolved star (and keep it for unresolved)**

Add the RED test first in `tests/unit/scanner/test_diagnostics.py`:

```python
def test_resolved_star_module_emits_no_unknown_import_fact():
    import ast as _ast
    from wardline.scanner.diagnostics import diagnose_unknown_imports

    tree = _ast.parse("from wardline.decorators import *\n")
    diags = diagnose_unknown_imports(
        tree=tree,
        module_path="proj.m",
        project_modules=frozenset(),
        stdlib_keys=frozenset(),
        resolvable_star_modules=frozenset({"wardline.decorators"}),
    )
    assert diags == []  # resolved → no FACT


def test_unresolved_star_module_still_emits_fact():
    import ast as _ast
    from wardline.scanner.diagnostics import diagnose_unknown_imports

    tree = _ast.parse("from somethirdparty.plugins import *\n")
    diags = diagnose_unknown_imports(
        tree=tree,
        module_path="proj.m",
        project_modules=frozenset(),
        stdlib_keys=frozenset(),
        resolvable_star_modules=frozenset({"wardline.decorators"}),
    )
    assert any("somethirdparty.plugins" in d[2] for d in diags)  # honest FACT preserved
```

Run both → the first FAILS (unexpected kwarg / FACT still emitted). Then modify `diagnose_unknown_imports`:

```python
def diagnose_unknown_imports(
    *,
    tree: ast.Module,
    module_path: str,
    project_modules: frozenset[str],
    stdlib_keys: frozenset[tuple[str, str]],
    resolvable_star_modules: frozenset[str] = frozenset(),
) -> list[tuple[str, str, str]]:
```

In the star-import branch, before recording the FACT, skip resolved modules:

```python
        # Star-import branch.
        if any(alias.name == "*" for alias in node.names):
            if mod in resolvable_star_modules:
                continue  # statically materialised (see vocabulary_star_exports) → not a gap
            if not any(key[0] == mod for key in stdlib_keys):
                ...  # unchanged FACT emission
            continue
```

Thread the param through `build_unknown_import_findings` (it calls `diagnose_unknown_imports`): add `resolvable_star_modules: frozenset[str] = frozenset()` to its signature and pass it down; in `analyzer.py`, pass `frozenset(vocabulary_star_exports())` (the keyset) at the `build_unknown_import_findings` call (line ~275).

Run: `uv run pytest tests/unit/scanner/test_diagnostics.py -q`
Expected: both PASS.

- [ ] **Step 7: Full regression + dogfood + byte-identical**

```bash
uv run pytest -q
make scan-self
```

Expected: full suite passes (incl. the warm/cold byte-identical test — `star_exports` is a deterministic constant, so cold ≡ warm holds); dogfood clean. Wardline's own source uses *explicit* imports, so `scan-self` is unaffected.

- [ ] **Step 8: mypy + ruff**

```bash
uv run mypy && uv run ruff check src tests && uv run ruff format src tests
```

- [ ] **Step 9: Commit + close**

```bash
git add src/wardline/scanner/ast_primitives.py src/wardline/scanner/taint/decorator_provider.py src/wardline/scanner/diagnostics.py src/wardline/scanner/analyzer.py tests/unit/scanner/
git commit -m "feat(taint): resolve from wardline.decorators import * statically (T1.2)

Materialise the REGISTRY decorator names for the known vocabulary module without
executing the target; every other star import stays unresolved + emits the honest
WLN-ENGINE-UNKNOWN-IMPORT FACT. Closes the star-import seeding FN.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
filigree close wardline-2b427a9579 --actor claude
```

---

## Task 3 (T1.3): Return-indirection in `compute_return_callee` — RED first

**Issue:** `wardline-82f49ec3c3` (epic child). **Scope:** explain-surface provenance ONLY. `compute_return_callee` returns `None` when the worst (least-trusted) return path is an indirect `return some_var` rather than a direct call. Resolve a SINGLE hop: name the callee of the assignment that gave that var its worst-taint value. **Hard invariant:** `compute_return_taint` *values are unchanged* — pin it with a test.

**Files:**
- Test: `tests/unit/scanner/taint/test_variable_level.py`
- Test: `tests/unit/core/test_explain.py`
- Modify: `src/wardline/scanner/taint/variable_level.py`

- [ ] **Step 1: Write the failing unit test (RED)**

Add to `tests/unit/scanner/taint/test_variable_level.py` (follow the file's existing AST-building / `compute_return_callee` test helpers — locate an existing `compute_return_callee` test and mirror its setup of `function_taint`, `taint_map`, `var_taints`):

```python
def test_compute_return_callee_resolves_single_hop_indirection():
    """`x = read_raw(p); return x` should name `read_raw` as the contributing callee
    (was None — indirection deferred)."""
    import ast
    from wardline.core.taints import TaintState
    from wardline.scanner.taint.variable_level import compute_return_callee

    src = "def f(p):\n    x = read_raw(p)\n    return x\n"
    func = ast.parse(src).body[0]
    taint_map = {"read_raw": TaintState.EXTERNAL_RAW}
    var_taints = {"x": TaintState.EXTERNAL_RAW}
    callee = compute_return_callee(func, TaintState.UNKNOWN_RAW, taint_map, var_taints)
    assert callee == "read_raw"
```

Run: `uv run pytest tests/unit/scanner/taint/test_variable_level.py::test_compute_return_callee_resolves_single_hop_indirection -v`
Expected: **FAIL** — returns `None` today. Capture red.

- [ ] **Step 2: Add the values-unchanged pin (must already pass — guards the invariant)**

```python
def test_compute_return_taint_value_unchanged_for_indirection():
    """T1.3 touches callee provenance only; the taint VALUE must be identical."""
    import ast
    from wardline.core.taints import TaintState
    from wardline.scanner.taint.variable_level import compute_return_taint

    src = "def f(p):\n    x = read_raw(p)\n    return x\n"
    func = ast.parse(src).body[0]
    taint_map = {"read_raw": TaintState.EXTERNAL_RAW}
    var_taints = {"x": TaintState.EXTERNAL_RAW}
    assert compute_return_taint(func, TaintState.UNKNOWN_RAW, taint_map, var_taints) == TaintState.EXTERNAL_RAW
```

Run it → **PASS** now (and must stay green after Step 3).

- [ ] **Step 3: Implement single-hop indirection in `compute_return_callee`**

In `src/wardline/scanner/taint/variable_level.py`, extend the return-path collection to carry the return *value node*, then add an indirection fallback. Change `_collect_return_paths` to record a 3-tuple `(taint, callee, value_node)`:

```python
def _collect_return_paths(
    nodes: list[ast.AST],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    out: list[tuple[TaintState, str | None, ast.expr]],
) -> None:
    ...
        if isinstance(node, ast.Return) and node.value is not None:
            taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
            out.append((taint, _return_callee(node.value), node.value))
        _collect_return_paths(list(ast.iter_child_nodes(node)), function_taint, taint_map, var_taints, out)
```

Update `compute_return_taint`'s unpacking (VALUES must not change — it still joins taints only):

```python
    returns: list[tuple[TaintState, str | None, ast.expr]] = []
    _collect_return_paths(list(func_node.body), function_taint, taint_map, var_taints, returns)
    if not returns:
        return None
    result = returns[0][0]
    for taint, _callee, _node in returns[1:]:
        result = least_trusted(result, taint)
    return result
```

Rewrite `compute_return_callee`'s tail: try the direct-call match first (unchanged behavior), then a single-hop indirection fallback:

```python
    returns: list[tuple[TaintState, str | None, ast.expr]] = []
    _collect_return_paths(list(func_node.body), function_taint, taint_map, var_taints, returns)
    if not returns:
        return None
    worst = returns[0][0]
    for taint, _callee, _node in returns[1:]:
        worst = least_trusted(worst, taint)
    # 1) direct-call path whose taint is the worst (unchanged precedence)
    for taint, callee, _node in returns:
        if taint == worst and callee is not None:
            return callee
    # 2) single-hop indirection: a worst-taint `return <Name>` whose Name was
    #    assigned its value by a direct call. Provenance only — never changes a
    #    fire/no-fire decision.
    for taint, callee, node in returns:
        if taint == worst and callee is None and isinstance(node, ast.Name):
            indirect = _assignment_callee(
                list(func_node.body), node.id, worst, function_taint, taint_map, var_taints
            )
            if indirect is not None:
                return indirect
    return None
```

Add the helper near `_return_callee`:

```python
def _assignment_callee(
    nodes: list[ast.AST],
    name: str,
    worst: TaintState,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> str | None:
    """Single-hop: the callee of the last (source-order) direct-call assignment to
    ``name`` whose RHS resolves to ``worst`` taint. Scope-respecting (does not descend
    into nested def/class/lambda — their assignments bind a different scope). Returns
    None when ``name`` is not set by a direct call to the worst taint (deeper / aliased
    chains remain None — honest, deferred to the N-hop Clarion path)."""
    result: str | None = None
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Assign):
            callee = _return_callee(node.value)
            if callee is not None and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets
            ):
                if _resolve_expr(node.value, function_taint, taint_map, var_taints) == worst:
                    result = callee
        nested = _assignment_callee(
            list(ast.iter_child_nodes(node)), name, worst, function_taint, taint_map, var_taints
        )
        if nested is not None:
            result = nested
    return result
```

- [ ] **Step 4: Run the unit tests → GREEN**

Run: `uv run pytest tests/unit/scanner/taint/test_variable_level.py -q`
Expected: the indirection test PASSES; the values-unchanged pin PASSES; all existing `test_variable_level.py` tests still PASS.

- [ ] **Step 5: End-to-end explain test (RED → GREEN)**

Add to `tests/unit/core/test_explain.py` (mirror the file's existing `explain_finding` fixture-scan helpers):

```python
def test_explain_names_indirect_callee(tmp_path):
    """PY-WL-101 on an indirect raw return now names the contributing callee."""
    pkg = tmp_path / "proj"
    pkg.mkdir()
    (pkg / "m.py").write_text(
        "from wardline.decorators import trusted\n"
        "def read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\n"
        "def producer(p):\n    x = read_raw(p)\n    return x\n"
    )
    from wardline.core.explain import explain_finding
    from wardline.core.run import run_scan

    scan = run_scan(pkg)
    sink = next(f for f in scan.findings if f.rule_id == "PY-WL-101" and f.suppressed == "active")
    exp = explain_finding(pkg, fingerprint=sink.fingerprint)
    assert exp is not None
    assert exp.immediate_tainted_callee == "read_raw"
```

Run it before Step 3 would FAIL (callee None); after Step 3 it PASSES. (If executing strictly RED-first, write this test in this step and confirm it now passes with the Step-3 implementation.)

- [ ] **Step 6: Full regression + byte-identical + dogfood + lint/type**

```bash
uv run pytest -q
make scan-self
uv run mypy && uv run ruff check src tests && uv run ruff format src tests
```

Expected: all green. The byte-identical warm/cold test must still pass (this is a pure read-side computation over the same AST; cache stores taint *values*, which are unchanged).

- [ ] **Step 7: Commit + set acceptance + close the child**

```bash
git add src/wardline/scanner/taint/variable_level.py tests/unit/scanner/taint/test_variable_level.py tests/unit/core/test_explain.py
git commit -m "feat(taint): single-hop return-indirection in compute_return_callee (T1.3)

explain_finding now names the contributing callee for an indirect raw return
(return <var> assigned by a direct call). compute_return_taint values pinned
unchanged — provenance-only completeness, no fire/no-fire change.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
filigree update-issue wardline-82f49ec3c3 --field acceptance_criteria="explain_finding names the single-hop indirect contributing callee; compute_return_taint values unchanged (pinned by test); RED-first regression test present." --actor claude || true
filigree close wardline-82f49ec3c3 --actor claude
```

> If `filigree close` rejects from `building` without going through review, call `filigree transitions wardline-82f49ec3c3` and walk the workflow (e.g. `--advance`), or set the acceptance field then close.

---

## Task 4 (T1.1): Verify-and-close the hardening epic

**Issue:** `wardline-2b138b3662` (epic). 9/10 children already closed; the audit (`docs/audits/2026-05-31-taint-combination-audit.md`) found 0 live FP / 0 live FN and PR #12/#13 are merged. The remaining child was T1.3 (closed in Task 3). This task is **verification, not new engine work** — confirm every audit finding's regression test exists in-tree; add only genuinely-missing coverage.

**Files:** test-only additions if a gap is found.

- [ ] **Step 1: Confirm each audit finding (F1–F6) has its enforcing test/marker**

For each, locate the in-tree artifact:

```bash
# F5 — both ungated parsers reject the unreachable trio (the soundness guard):
uv run pytest -k "F5 or unreachable or reachable_set or INTEGRAL_round_trip or trio" -q
# F2 — dead unresolved-clamp removed:
grep -n "unreachable: line-172 floor\|unresolved" src/wardline/scanner/taint/propagation.py | head
# F3 — taint_join RETAIN marker + its 8 unit tests:
grep -n "documented-but-unused\|RETAIN\|no production call site" src/wardline/core/taints.py
uv run pytest tests/unit/core/test_taints.py -q
# F6 — stale comment fixed:
grep -n "least_trusted (wardline-4d9f840c24)\|control-flow merges" tests/unit/scanner/taint/test_variable_level.py
# operator-distinctness guard (least_trusted != taint_join):
uv run pytest -k "mixed_raw or MIXED or discrimination or join" -q
```

Expected: the F5 guard tests pass; the markers/comments are present; `test_taints.py` (taint_join's pinned semantics) passes; operator-distinctness tests pass. Record which test enforces each finding in the task notes / a comment on the epic.

- [ ] **Step 2: If (and only if) a finding has NO enforcing test, add a RED-first regression test**

The audit verdict is that all behavior-changing migrations already carry regression-guard comments + the F5 guard tests. If Step 1 surfaces a finding with no test, add one (RED on a hypothetical regression, GREEN on current engine). Do NOT add tests for findings explicitly dispositioned "no code change / by-design" (F1 latent, F4 by-design) beyond a comment assertion — those are documented limits, not holes.

- [ ] **Step 3: Re-run the soundness-relevant suite**

```bash
uv run pytest tests/unit/scanner/taint tests/unit/core/test_taints.py -q
```

Expected: all green.

- [ ] **Step 4: Record verification + close the epic**

```bash
filigree add-comment wardline-2b138b3662 --actor claude --text "T1.1 verify-and-close: audit findings F1-F6 each confirmed enforced/dispositioned in-tree (F5 parser guards + INTEGRAL round-trip test; F2 clamp removed; F3 taint_join RETAIN marker + 8 unit tests; F6 comment fixed; operator-distinctness MIXED_RAW tests green). Last open child wardline-82f49ec3c3 (T1.3 return-indirection) closed. Engine sound per 2026-05-31 audit (0 live FP/FN); no new holes. Closing."
filigree close wardline-2b138b3662 --actor claude
```

> If the epic refuses to close while children are open, list children with `filigree show wardline-2b138b3662` and confirm all are terminal first.

---

## Task 5: Close-out — all DoD gates green together + review panel + tracker

**Files:**
- Modify: `docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md`
- Modify: `CHANGELOG.md` (if present — add an `[Unreleased]` entry)

- [ ] **Step 1: Run the full CI gate**

```bash
make ci
```

Expected: ruff check + ruff format --check + mypy strict + full pytest + 90% coverage floor — all green.

- [ ] **Step 2: Enforce the 95% taint-subtree coverage gate**

```bash
uv run pytest --cov=src/wardline/scanner/taint --cov-report=term-missing -q | grep -E "scanner/taint|TOTAL"
```

Expected: the `src/wardline/scanner/taint/` total ≥95%. If T1.2/T1.3 added uncovered branches (e.g. `_assignment_callee` nested-scope skip, the relative-star fall-through), add targeted unit tests until ≥95%.

- [ ] **Step 3: Confirm warm/cold byte-identical + dogfood**

```bash
uv run pytest tests/unit/scanner/taint/test_project_resolver.py -k "warm or cold or identical" -q
make scan-self
```

Expected: byte-identical test green; `scan-self` exit 0.

- [ ] **Step 4: Default code-review panel on the engine diff**

Per repo norms (soundness work warrants the default code-review panel). Dispatch the panel (SA, ST, PE, QE, SAE, SecArch) over the T1.2 + T1.3 engine diff (`git diff main...feat/track1-engine-floor -- src/`). Fix convergent must-fixes before close; file genuine tech debt as Filigree issues. Re-run `make ci` after any fix.

- [ ] **Step 5: Update the progress tracker**

In `docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md`:
- Track 1 table: set T1.1, T1.2, T1.3, T1.4 status cells to ☑.
- Track 1 heading: change `◐ spec'd, ready to dispatch` → `☑ done` (or `◐` with remaining items if the panel deferred anything).
- The **Current position** line: replace with the Track 1 completion summary + next action (Track 2 = next to spec).

- [ ] **Step 6: Commit the tracker + changelog**

```bash
git add docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md CHANGELOG.md
git commit -m "docs: Track 1 engine-floor complete — tracker + changelog (T1.1-T1.4)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 7: Final verification statement**

Re-run `make ci` once more on the final tree and confirm: full suite green, coverage 90%/95%, byte-identical green, dogfood clean, FP-rate ≤5%, waiver discipline green. Report the evidence (actual command output), not assertions.

- [ ] **Step 8: Hand off the branch**

Surface to the user: branch `feat/track1-engine-floor`, all four units done, all gates green. Ask the merge target (the local `main` is ahead of `origin/main`; the docs branch carries the spec) before merging or opening a PR — do not merge unprompted.

---

## Self-review (run before declaring the plan done)

- **Spec coverage:** T1.1 → Task 4. T1.2 → Task 2. T1.3 → Task 3. T1.4 (corpus + FP-rate + waiver) → Tasks 1/1b/1c. All DoD gates → Task 5. Sequencing (corpus thin-slice first, then T1.2→T1.3, then close-out) honored. ✅
- **Out-of-scope guard:** no Track 2 grammar work, no SEI/dossier/legis, no new rules (T1.5 deferred). ✅
- **Invariants embedded:** RED-first (Tasks 2, 3), values-unchanged pin (Task 3 Step 2), byte-identical re-checked each engine task, fail-closed preserved (T1.2 unresolved star still FACTs), operator-distinctness re-verified (Task 4). ✅
- **Implementer NOTEs** flag the three field-name/signature assumptions to verify against source (`Finding` fields, `load_waivers` API, `pickle.loads` in stdlib_taint) — these are verification points, not placeholders. ✅
