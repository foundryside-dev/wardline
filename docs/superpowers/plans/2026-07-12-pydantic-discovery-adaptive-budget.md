# Adaptive Pydantic Discovery Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Wardline's statement-only, mid-round Pydantic discovery limit with a deterministic structural budget that admits or rejects complete rounds and lets Elspeth's healthy four-round model graph converge.

**Architecture:** Add a focused `pydantic_discovery` module that owns immutable budget arithmetic and project-wide fixed-point orchestration. `WardlineAnalyzer` delegates model discovery to that module, then translates its outcome into the existing fail-closed engine finding without changing model-classification semantics or exposing an operator-controlled budget.

**Tech Stack:** Python 3.12+, frozen dataclasses, `ast`, pytest, pytest monkeypatch, Ruff, mypy, Wardline CLI, Loomweave.

---

## Execution Preconditions

- Execute in a dedicated worktree created with `superpowers:using-git-worktrees`.
- Read `AGENTS.md`, the approved design at
  `docs/superpowers/specs/2026-07-12-pydantic-discovery-adaptive-budget-design.md`, and the
  current loop in `src/wardline/scanner/analyzer.py:647-706` before editing.
- Use `superpowers:test-driven-development` for every production change.
- Keep the change independent of `weft.toml`, CLI options, environment variables, packs,
  and Elspeth's custom trust decorators.
- Do not modify the pre-existing unrelated format drift in
  `tests/unit/install/test_doctor_filigree_auth.py` as part of this work.

## File Map

- Create `src/wardline/scanner/taint/pydantic_discovery.py` — pure budget policy,
  whole-round fixed-point orchestration, and immutable outcome values.
- Create `tests/unit/scanner/taint/test_pydantic_discovery.py` — arithmetic,
  whole-round admission, convergence, ceiling, repeated-state, and determinism tests.
- Modify `src/wardline/scanner/analyzer.py:42-48,647-706` — delegate to the new module
  and render the fail-closed diagnostic from its outcome.
- Modify `tests/unit/scanner/rules/test_fastapi_route_body_source.py:1035-1050` — pin the
  end-to-end engine finding and its actionable arithmetic.
- Verify, but do not modify, `tests/unit/core/test_run.py:742-773` — the discovery-limit
  finding must remain active under `--new-since`.

### Task 1: Add the immutable adaptive-budget policy

**Files:**
- Create: `src/wardline/scanner/taint/pydantic_discovery.py`
- Create: `tests/unit/scanner/taint/test_pydantic_discovery.py`

- [ ] **Step 1: Write failing arithmetic tests**

Create `tests/unit/scanner/taint/test_pydantic_discovery.py` with the Elspeth arithmetic,
minimum, ceiling, and whole-round admission contract:

```python
from __future__ import annotations

import pytest

from wardline.scanner.taint.pydantic_discovery import PydanticDiscoveryBudget


def test_elspeth_budget_admits_all_four_complete_rounds() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=593, statement_count=11_493)

    assert budget.work_budget == 773_504
    assert budget.absolute_cap_applied is False
    costs = tuple(budget.round_cost(count) for count in (0, 206, 259, 263))
    assert costs == (12_086, 134_244, 165_673, 168_045)
    assert sum(costs) == 480_048
    assert budget.admits_round(completed_work=sum(costs[:-1]), known_model_count=263)


def test_tiny_project_receives_minimum_budget() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=1, statement_count=0)

    assert budget.work_budget == 4_096
    assert budget.absolute_cap_applied is False


def test_large_project_is_capped_at_absolute_budget() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=100_000, statement_count=0)

    assert budget.work_budget == 5_000_000
    assert budget.absolute_cap_applied is True


def test_round_admission_uses_required_total() -> None:
    budget = PydanticDiscoveryBudget(
        file_count=80,
        statement_count=160,
        work_budget=15_360,
        absolute_cap_applied=False,
    )

    assert budget.round_cost(known_model_count=17) == 1_600
    assert budget.required_total(completed_work=14_960, known_model_count=17) == 16_560
    assert budget.admits_round(completed_work=14_960, known_model_count=17) is False


@pytest.mark.parametrize(("file_count", "statement_count"), [(-1, 0), (0, -1)])
def test_structural_counts_must_be_non_negative(file_count: int, statement_count: int) -> None:
    with pytest.raises(ValueError, match="must be non-negative"):
        PydanticDiscoveryBudget.from_counts(
            file_count=file_count,
            statement_count=statement_count,
        )
```

- [ ] **Step 2: Run the new test to verify RED**

Run:

```bash
uv run pytest -q tests/unit/scanner/taint/test_pydantic_discovery.py
```

Expected: collection fails with `ModuleNotFoundError` for
`wardline.scanner.taint.pydantic_discovery`.

- [ ] **Step 3: Implement the pure budget value**

Create `src/wardline/scanner/taint/pydantic_discovery.py` with this initial content:

```python
"""Bounded project-wide discovery of Pydantic model identities."""

from __future__ import annotations

from dataclasses import dataclass

_MIN_WORK_BUDGET = 4_096
_WORK_PER_STRUCTURAL_UNIT = 64
_ABSOLUTE_WORK_CAP = 5_000_000


@dataclass(frozen=True, slots=True)
class PydanticDiscoveryBudget:
    file_count: int
    statement_count: int
    work_budget: int
    absolute_cap_applied: bool

    @classmethod
    def from_counts(cls, *, file_count: int, statement_count: int) -> PydanticDiscoveryBudget:
        if file_count < 0 or statement_count < 0:
            raise ValueError("Pydantic discovery counts must be non-negative")
        scaled = (file_count + statement_count) * _WORK_PER_STRUCTURAL_UNIT
        return cls(
            file_count=file_count,
            statement_count=statement_count,
            work_budget=min(_ABSOLUTE_WORK_CAP, max(_MIN_WORK_BUDGET, scaled)),
            absolute_cap_applied=scaled > _ABSOLUTE_WORK_CAP,
        )

    def round_cost(self, known_model_count: int) -> int:
        if known_model_count < 0:
            raise ValueError("known_model_count must be non-negative")
        return self.statement_count + self.file_count * (known_model_count + 1)

    def required_total(self, *, completed_work: int, known_model_count: int) -> int:
        if completed_work < 0:
            raise ValueError("completed_work must be non-negative")
        return completed_work + self.round_cost(known_model_count)

    def admits_round(self, *, completed_work: int, known_model_count: int) -> bool:
        return self.required_total(
            completed_work=completed_work,
            known_model_count=known_model_count,
        ) <= self.work_budget
```

- [ ] **Step 4: Run arithmetic tests to verify GREEN**

Run:

```bash
uv run pytest -q tests/unit/scanner/taint/test_pydantic_discovery.py
uv run ruff check src/wardline/scanner/taint/pydantic_discovery.py tests/unit/scanner/taint/test_pydantic_discovery.py
uv run ruff format --check src/wardline/scanner/taint/pydantic_discovery.py tests/unit/scanner/taint/test_pydantic_discovery.py
uv run mypy src/wardline/scanner/taint/pydantic_discovery.py tests/unit/scanner/taint/test_pydantic_discovery.py
```

Expected: four tests pass; Ruff, formatting, and mypy are clean.

- [ ] **Step 5: Commit the budget policy**

```bash
git add src/wardline/scanner/taint/pydantic_discovery.py \
  tests/unit/scanner/taint/test_pydantic_discovery.py
git commit -m "feat(analyzer): add adaptive Pydantic budget"
```

### Task 2: Move fixed-point discovery behind whole-round admission

**Files:**
- Modify: `src/wardline/scanner/taint/pydantic_discovery.py`
- Modify: `tests/unit/scanner/taint/test_pydantic_discovery.py`

- [ ] **Step 1: Add parsed-module fixtures and failing whole-round tests**

Extend the test file with a structural fixture and two tests:

```python
import ast
from dataclasses import dataclass

from wardline.scanner.taint import pydantic_discovery
from wardline.scanner.taint.pydantic_discovery import discover_project_pydantic_models


@dataclass(frozen=True, slots=True)
class _ParsedModule:
    relpath: str
    module: str
    tree: ast.Module
    alias_map: dict[str, str]
    class_qualnames: frozenset[str]


def _parsed(module: str, source: str) -> _ParsedModule:
    tree = ast.parse(source)
    classes = frozenset(
        f"{module}.{statement.name}"
        for statement in tree.body
        if isinstance(statement, ast.ClassDef)
    )
    return _ParsedModule(
        relpath=f"{module}.py",
        module=module,
        tree=tree,
        alias_map={},
        class_qualnames=classes,
    )


def _model_chain(length: int) -> list[_ParsedModule]:
    modules = [_parsed("m0", "from pydantic import BaseModel\nclass Model0(BaseModel): pass\n")]
    modules.extend(
        _parsed(
            f"m{index}",
            f"from m{index - 1} import Model{index - 1}\n"
            f"class Model{index}(Model{index - 1}): pass\n",
        )
        for index in range(1, length)
    )
    return modules


def test_model_chain_rejects_round_before_any_partial_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    modules = _model_chain(80)
    real_discover = pydantic_discovery.discover_pydantic_models
    calls = 0

    def counted_discover(
        tree: ast.Module,
        *,
        module: str,
        aliases: dict[str, str],
        known_models: frozenset[str],
        is_package: bool = False,
    ) -> frozenset[str]:
        nonlocal calls
        calls += 1
        return real_discover(
            tree,
            module=module,
            aliases=aliases,
            known_models=known_models,
            is_package=is_package,
        )

    monkeypatch.setattr(pydantic_discovery, "discover_pydantic_models", counted_discover)

    result = discover_project_pydantic_models(modules)

    assert result.degraded_reason == "work_budget_exceeded"
    assert result.round_number == 18
    assert result.work_completed == 14_960
    assert result.next_round_cost == 1_600
    assert result.required_total == 16_560
    assert result.known_model_count == 17
    assert calls == 17 * len(modules)
    assert calls % len(modules) == 0
    assert result.models == frozenset(
        class_name for module in modules for class_name in module.class_qualnames
    )


def test_small_transitive_chain_converges_without_degradation() -> None:
    result = discover_project_pydantic_models(_model_chain(3))

    assert result.degraded_reason is None
    assert result.models == frozenset({"m0.Model0", "m1.Model1", "m2.Model2"})
    assert result.model_counts_by_round == (1, 2, 3, 3)
    assert result.round_number == 4


def test_repeated_state_retains_conservative_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _parsed("m", "class A: pass\nclass B: pass\n")
    states = [frozenset({"m.A"}), frozenset({"m.B"}), frozenset({"m.A"})]

    def alternating_discovery(
        tree: ast.Module,
        *,
        module: str,
        aliases: dict[str, str],
        known_models: frozenset[str],
        is_package: bool = False,
    ) -> frozenset[str]:
        del tree, module, aliases, known_models, is_package
        return states.pop(0)

    monkeypatch.setattr(pydantic_discovery, "discover_pydantic_models", alternating_discovery)

    result = discover_project_pydantic_models([module])

    assert result.degraded_reason == "repeated_state"
    assert result.models == frozenset({"m.A", "m.B"})
    assert result.model_counts_by_round == (1, 1, 1)


def test_round_limit_retains_conservative_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _parsed("m", "value = 1\n")

    def never_stable(
        tree: ast.Module,
        *,
        module: str,
        aliases: dict[str, str],
        known_models: frozenset[str],
        is_package: bool = False,
    ) -> frozenset[str]:
        del tree, module, aliases, known_models, is_package
        return frozenset({"m.Dynamic"})

    monkeypatch.setattr(pydantic_discovery, "discover_pydantic_models", never_stable)

    result = discover_project_pydantic_models([module])

    assert result.degraded_reason == "round_limit_exceeded"
    assert result.models == frozenset()
    assert result.model_counts_by_round == (1,)
```

- [ ] **Step 2: Run focused tests to verify RED**

Run:

```bash
uv run pytest -q \
  tests/unit/scanner/taint/test_pydantic_discovery.py::test_model_chain_rejects_round_before_any_partial_calls \
  tests/unit/scanner/taint/test_pydantic_discovery.py::test_small_transitive_chain_converges_without_degradation \
  tests/unit/scanner/taint/test_pydantic_discovery.py::test_repeated_state_retains_conservative_fallback \
  tests/unit/scanner/taint/test_pydantic_discovery.py::test_round_limit_retains_conservative_fallback
```

Expected: import or attribute failure because `discover_project_pydantic_models` and its
outcome do not exist.

- [ ] **Step 3: Implement the fixed-point outcome and whole-round loop**

Extend `pydantic_discovery.py` after `PydanticDiscoveryBudget`:

```python
import ast
from collections.abc import Sequence
from typing import Literal, Protocol

from wardline.scanner.taint.fastapi_sources import discover_pydantic_models


class ParsedPydanticModule(Protocol):
    relpath: str
    module: str
    tree: ast.Module
    alias_map: dict[str, str]
    class_qualnames: frozenset[str]


type PydanticDiscoveryReason = Literal[
    "work_budget_exceeded",
    "repeated_state",
    "round_limit_exceeded",
]


@dataclass(frozen=True, slots=True)
class PydanticDiscoveryResult:
    models: frozenset[str]
    degraded_reason: PydanticDiscoveryReason | None
    round_number: int
    work_completed: int
    budget: PydanticDiscoveryBudget
    next_round_cost: int | None
    required_total: int | None
    known_model_count: int
    model_counts_by_round: tuple[int, ...]


def discover_project_pydantic_models(
    files: Sequence[ParsedPydanticModule],
) -> PydanticDiscoveryResult:
    all_classes = frozenset(name for parsed in files for name in parsed.class_qualnames)
    statement_count = sum(len(parsed.tree.body) for parsed in files)
    budget = PydanticDiscoveryBudget.from_counts(
        file_count=len(files),
        statement_count=statement_count,
    )
    models = frozenset[str]()
    states = {models}
    counts: list[int] = []
    completed_work = 0
    max_rounds = sum(
        isinstance(statement, ast.ClassDef)
        for parsed in files
        for statement in parsed.tree.body
    ) + 1

    for round_index in range(max_rounds):
        round_number = round_index + 1
        known_model_count = len(models)
        next_round_cost = budget.round_cost(known_model_count)
        required_total = completed_work + next_round_cost
        if required_total > budget.work_budget:
            return PydanticDiscoveryResult(
                models=all_classes,
                degraded_reason="work_budget_exceeded",
                round_number=round_number,
                work_completed=completed_work,
                budget=budget,
                next_round_cost=next_round_cost,
                required_total=required_total,
                known_model_count=known_model_count,
                model_counts_by_round=tuple(counts),
            )

        next_models: set[str] = set()
        for parsed in files:
            discovered = discover_pydantic_models(
                parsed.tree,
                module=parsed.module,
                aliases=parsed.alias_map,
                known_models=models,
                is_package=parsed.relpath.rsplit("/", 1)[-1] == "__init__.py",
            )
            next_models.update(
                name for name in discovered if name.rpartition(".")[0] == parsed.module
            )
        completed_work = required_total
        next_state = frozenset(next_models)
        counts.append(len(next_state))
        if next_state == models:
            return PydanticDiscoveryResult(
                models=models,
                degraded_reason=None,
                round_number=round_number,
                work_completed=completed_work,
                budget=budget,
                next_round_cost=None,
                required_total=None,
                known_model_count=len(models),
                model_counts_by_round=tuple(counts),
            )
        if next_state in states:
            return PydanticDiscoveryResult(
                models=all_classes,
                degraded_reason="repeated_state",
                round_number=round_number,
                work_completed=completed_work,
                budget=budget,
                next_round_cost=None,
                required_total=None,
                known_model_count=len(models),
                model_counts_by_round=tuple(counts),
            )
        states.add(next_state)
        models = next_state

    return PydanticDiscoveryResult(
        models=all_classes,
        degraded_reason="round_limit_exceeded",
        round_number=max_rounds,
        work_completed=completed_work,
        budget=budget,
        next_round_cost=None,
        required_total=None,
        known_model_count=len(models),
        model_counts_by_round=tuple(counts),
    )
```

Place all imports at the top of the module and keep Ruff's import ordering. The
`model_counts_by_round` field is internal evidence for deterministic convergence; it is not
serialized into scan output.

- [ ] **Step 4: Run fixed-point tests to verify GREEN**

Run:

```bash
uv run pytest -q tests/unit/scanner/taint/test_pydantic_discovery.py
uv run ruff check src/wardline/scanner/taint/pydantic_discovery.py tests/unit/scanner/taint/test_pydantic_discovery.py
uv run ruff format --check src/wardline/scanner/taint/pydantic_discovery.py tests/unit/scanner/taint/test_pydantic_discovery.py
uv run mypy src/wardline/scanner/taint/pydantic_discovery.py tests/unit/scanner/taint/test_pydantic_discovery.py
```

Expected: all budget and fixed-point tests pass; the spy call count is exactly 1,360, proving
17 complete 80-file rounds and no calls from rejected round 18.

- [ ] **Step 5: Commit whole-round discovery**

```bash
git add src/wardline/scanner/taint/pydantic_discovery.py \
  tests/unit/scanner/taint/test_pydantic_discovery.py
git commit -m "refactor(analyzer): preflight Pydantic discovery rounds"
```

### Task 3: Integrate the outcome and enrich the fail-closed diagnostic

**Files:**
- Modify: `src/wardline/scanner/analyzer.py:42-48,647-706`
- Modify: `tests/unit/scanner/rules/test_fastapi_route_body_source.py:1035-1050`
- Verify: `tests/unit/core/test_run.py:742-773`

- [ ] **Step 1: Strengthen the end-to-end limit regression before production integration**

Replace `test_large_model_chain_degrades_loudly_with_bounded_work` with an assertion over
the actual finding. Add these imports beside the existing analyzer imports:

```python
from wardline.scanner.taint.pydantic_discovery import (
    PydanticDiscoveryBudget,
    PydanticDiscoveryReason,
    PydanticDiscoveryResult,
)
```

Then add the budget-rejection regression:

```python
def test_large_model_chain_degrades_before_starting_partial_round(tmp_path: Path) -> None:
    files = {
        "m0.py": "from pydantic import BaseModel\nclass Model0(BaseModel): pass\n",
        **{
            f"m{index}.py": (
                f"from m{index - 1} import Model{index - 1}\n"
                f"class Model{index}(Model{index - 1}): pass\n"
            )
            for index in range(1, 80)
        },
    }
    paths: list[Path] = []
    for name, source in files.items():
        path = tmp_path / name
        path.write_text(source, encoding="utf-8")
        paths.append(path)

    findings = WardlineAnalyzer().analyze(paths, WardlineConfig(), root=tmp_path)
    finding = next(
        item for item in findings if item.rule_id == "WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT"
    )

    assert finding.severity.value == "ERROR"
    assert finding.kind is Kind.DEFECT
    assert finding.properties == {
        "reason": "work_budget_exceeded",
        "round": 18,
        "work": 14_960,
        "budget": 15_360,
        "next_round_cost": 1_600,
        "required_total": 16_560,
        "file_count": 80,
        "statement_count": 160,
        "known_model_count": 17,
        "absolute_cap_applied": False,
    }
    assert "required=16560" in finding.message


@pytest.mark.parametrize("reason", ["repeated_state", "round_limit_exceeded"])
def test_non_budget_model_limit_reasons_keep_structural_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: PydanticDiscoveryReason,
) -> None:
    source = tmp_path / "m.py"
    source.write_text("class Local: pass\n", encoding="utf-8")
    budget = PydanticDiscoveryBudget.from_counts(file_count=1, statement_count=1)
    outcome = PydanticDiscoveryResult(
        models=frozenset({"m.Local"}),
        degraded_reason=reason,
        round_number=2,
        work_completed=2,
        budget=budget,
        next_round_cost=None,
        required_total=None,
        known_model_count=1,
        model_counts_by_round=(1,),
    )
    monkeypatch.setattr(
        "wardline.scanner.analyzer.discover_project_pydantic_models",
        lambda _files: outcome,
    )

    findings = WardlineAnalyzer().analyze([source], WardlineConfig(), root=tmp_path)
    finding = next(
        item for item in findings if item.rule_id == "WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT"
    )

    assert finding.properties == {
        "reason": reason,
        "round": 2,
        "work": 2,
        "budget": 4_096,
        "file_count": 1,
        "statement_count": 1,
        "known_model_count": 1,
        "absolute_cap_applied": False,
    }
    assert "next_round_cost" not in finding.properties
    assert "required_total" not in finding.properties


def test_absolute_cap_rejection_is_explicit_in_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "m.py"
    source.write_text("class Local: pass\n", encoding="utf-8")
    budget = PydanticDiscoveryBudget(
        file_count=100_000,
        statement_count=0,
        work_budget=5_000_000,
        absolute_cap_applied=True,
    )
    outcome = PydanticDiscoveryResult(
        models=frozenset({"m.Local"}),
        degraded_reason="work_budget_exceeded",
        round_number=3,
        work_completed=4_900_000,
        budget=budget,
        next_round_cost=200_000,
        required_total=5_100_000,
        known_model_count=1,
        model_counts_by_round=(1, 1),
    )
    monkeypatch.setattr(
        "wardline.scanner.analyzer.discover_project_pydantic_models",
        lambda _files: outcome,
    )

    findings = WardlineAnalyzer().analyze([source], WardlineConfig(), root=tmp_path)
    finding = next(
        item for item in findings if item.rule_id == "WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT"
    )

    assert finding.properties["budget"] == 5_000_000
    assert finding.properties["required_total"] == 5_100_000
    assert finding.properties["absolute_cap_applied"] is True
```

- [ ] **Step 2: Run the regression to verify RED**

Run:

```bash
uv run pytest -q \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py::test_large_model_chain_degrades_before_starting_partial_round \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py::test_non_budget_model_limit_reasons_keep_structural_context \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py::test_absolute_cap_rejection_is_explicit_in_diagnostic
```

Expected: FAIL because the analyzer still uses the old budget and omits the new diagnostic
properties.

- [ ] **Step 3: Delegate analyzer discovery to the new module**

Add this import in `src/wardline/scanner/analyzer.py`:

```python
from wardline.scanner.taint.pydantic_discovery import discover_project_pydantic_models
```

Remove `discover_pydantic_models` from the `fastapi_sources` import list. Replace the old
`pydantic_models`, `model_states`, `model_work`, budget, and round loop with:

```python
        model_result = discover_project_pydantic_models(file_meta)
        pydantic_models = model_result.models
        if model_result.degraded_reason is not None:
            properties: dict[str, object] = {
                "reason": model_result.degraded_reason,
                "round": model_result.round_number,
                "work": model_result.work_completed,
                "budget": model_result.budget.work_budget,
                "file_count": model_result.budget.file_count,
                "statement_count": model_result.budget.statement_count,
                "known_model_count": model_result.known_model_count,
                "absolute_cap_applied": model_result.budget.absolute_cap_applied,
            }
            detail = (
                f"work={model_result.work_completed}/{model_result.budget.work_budget}"
            )
            if model_result.next_round_cost is not None and model_result.required_total is not None:
                properties["next_round_cost"] = model_result.next_round_cost
                properties["required_total"] = model_result.required_total
                detail = (
                    f"work={model_result.work_completed}; "
                    f"next_round={model_result.next_round_cost}; "
                    f"required={model_result.required_total}; "
                    f"budget={model_result.budget.work_budget}"
                )
            func_skip_findings.append(
                Finding(
                    rule_id="WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT",
                    message=(
                        "Pydantic model discovery degraded to conservative class seeding "
                        f"({model_result.degraded_reason}; round={model_result.round_number}; "
                        f"{detail})"
                    ),
                    severity=Severity.ERROR,
                    kind=Kind.DEFECT,
                    location=Location(path=ENGINE_PATH, line_start=1),
                    fingerprint=_fp(
                        "WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT",
                        model_result.degraded_reason,
                    ),
                    properties=properties,
                )
            )
```

Do not alter the fingerprint inputs, severity, kind, `ENGINE_PATH`, or conservative
all-class result returned by the helper.

- [ ] **Step 4: Run end-to-end and compatibility tests**

Run:

```bash
uv run pytest -q \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py::test_large_model_chain_degrades_before_starting_partial_round \
  tests/unit/core/test_run.py::test_new_since_keeps_pydantic_discovery_limit_active \
  tests/unit/core/test_filigree_emit.py
uv run ruff check src/wardline/scanner/analyzer.py \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py
uv run ruff format --check src/wardline/scanner/analyzer.py \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py
uv run mypy src/wardline/scanner/analyzer.py \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py
git diff --check
```

Expected: the limit remains an active ERROR defect, downstream Filigree incomplete-analysis
handling remains green, and all new arithmetic is present.

- [ ] **Step 5: Commit analyzer integration**

```bash
git add src/wardline/scanner/analyzer.py \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py
git commit -m "fix(analyzer): admit complete Pydantic discovery rounds"
```

### Task 4: Pin Elspeth-scale convergence and file-order determinism

**Files:**
- Modify: `tests/unit/scanner/taint/test_pydantic_discovery.py`

- [ ] **Step 1: Add the exact in-memory Elspeth-shaped fixture**

Append this fixture builder and regression:

```python
def _elspeth_shaped_modules() -> list[_ParsedModule]:
    modules = [
        _parsed(
            f"m{index}",
            "from pydantic import BaseModel\n"
            f"class Model{index}(BaseModel): pass\n",
        )
        for index in range(206)
    ]
    modules.extend(
        _parsed(
            f"m{index}",
            f"from m{index - 206} import Model{index - 206}\n"
            f"class Model{index}(Model{index - 206}): pass\n",
        )
        for index in range(206, 259)
    )
    modules.extend(
        _parsed(
            f"m{index}",
            f"from m{206 + index - 259} import Model{206 + index - 259}\n"
            f"class Model{index}(Model{206 + index - 259}): pass\n",
        )
        for index in range(259, 263)
    )
    modules.extend(_parsed(f"m{index}", "") for index in range(263, 593))

    padding = 11_493 - sum(len(module.tree.body) for module in modules)
    assert padding >= 0
    for index in range(padding):
        modules[index % len(modules)].tree.body.append(ast.Pass())
    assert len(modules) == 593
    assert sum(len(module.tree.body) for module in modules) == 11_493
    return modules


def test_elspeth_shaped_graph_converges_deterministically() -> None:
    modules = _elspeth_shaped_modules()

    forward = discover_project_pydantic_models(modules)
    reverse = discover_project_pydantic_models(list(reversed(modules)))

    assert forward.degraded_reason is None
    assert forward.models == reverse.models
    assert len(forward.models) == 263
    assert forward.model_counts_by_round == (206, 259, 263, 263)
    assert forward.round_number == 4
    assert forward.work_completed == 480_048
    assert forward.budget.work_budget == 773_504
    assert reverse.model_counts_by_round == forward.model_counts_by_round
    assert reverse.work_completed == forward.work_completed
```

- [ ] **Step 2: Mutation-prove the scale regression**

Temporarily change `_WORK_PER_STRUCTURAL_UNIT` from `64` back to `32` and run:

```bash
uv run pytest -q \
  tests/unit/scanner/taint/test_pydantic_discovery.py::test_elspeth_shaped_graph_converges_deterministically
```

Expected: FAIL because round four is rejected with `work_budget_exceeded`.

Restore `64` immediately and confirm `git diff` contains only the intended test addition.

- [ ] **Step 3: Run the complete precision and scale suites**

Run:

```bash
uv run pytest -q \
  tests/unit/scanner/taint/test_pydantic_discovery.py \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py \
  tests/unit/scanner/rules/test_fastapi_request_source.py \
  tests/unit/scanner/taint/test_engine_precision.py
uv run ruff check tests/unit/scanner/taint/test_pydantic_discovery.py
uv run ruff format --check tests/unit/scanner/taint/test_pydantic_discovery.py
uv run mypy tests/unit/scanner/taint/test_pydantic_discovery.py
git diff --check
```

Expected: all focused tests and static checks pass; the scale test fails under the old
multiplier mutation and passes after restoration.

- [ ] **Step 4: Commit the scale oracle**

```bash
git add tests/unit/scanner/taint/test_pydantic_discovery.py
git commit -m "test(analyzer): pin Elspeth Pydantic convergence"
```

### Task 5: Complete repository and downstream verification

**Files:**
- Verify only: entire Wardline repository
- Verify only: `/home/john/elspeth`

- [ ] **Step 1: Run the full Wardline test and static-analysis gates**

Run from the Wardline worktree:

```bash
uv run pytest -q
uv run ruff check src tests
uv run mypy
git diff --check
```

Expected: all commands exit 0. Record the exact pytest passed/skipped/deselected counts.

- [ ] **Step 2: Check formatting without absorbing unrelated drift**

Run the changed-file format gate:

```bash
uv run ruff format --check \
  src/wardline/scanner/taint/pydantic_discovery.py \
  src/wardline/scanner/analyzer.py \
  tests/unit/scanner/taint/test_pydantic_discovery.py \
  tests/unit/scanner/rules/test_fastapi_route_body_source.py
```

Expected: all changed files are formatted.

Also run the repository-wide visibility check:

```bash
uv run ruff format --check
```

Expected at the pre-implementation baseline: the only failure is the unrelated existing
`tests/unit/install/test_doctor_filigree_auth.py`. Do not modify that file in this feature;
record whether the baseline exception is unchanged.

- [ ] **Step 3: Run Wardline's local-only trust-boundary gate**

```bash
uv run wardline scan . --fail-on ERROR --local-only
```

Expected: exit 0 with no active ERROR+ findings. Record the existing inert-boundary warning
separately; do not treat it as proof of meaningful self-taint coverage.

- [ ] **Step 4: Smoke-test the worktree executable without replacing the global tool**

```bash
uv run wardline --version
uv run wardline --help >/dev/null
```

Expected: Wardline reports `1.3.1` and help exits 0. Do not replace the global uv tool from
an isolated feature worktree; install the canonical checkout only after integration.

- [ ] **Step 5: Re-run the exact Elspeth local-only scan**

```bash
uv run wardline scan /home/john/elspeth \
  --config /home/john/elspeth/weft.toml \
  --local-only \
  --format jsonl \
  --fail-on ERROR \
  --output /tmp/wardline-elspeth-adaptive-budget.jsonl

if jq -e 'select(.rule_id == "WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT")' \
  /tmp/wardline-elspeth-adaptive-budget.jsonl >/dev/null; then
  echo "unexpected Pydantic discovery-limit finding" >&2
  exit 1
fi
```

Expected: the scan itself exits 0 if no separate active defect exists, and the shell check
exits 0 because no Pydantic discovery-limit finding remains. Verify the scan summary shows
593 files; report any unrelated finding rather than changing Elspeth.

- [ ] **Step 6: Refresh Loomweave and verify final repository state**

```bash
loomweave analyze /home/john/wardline
git status --short
git log -5 --oneline
```

Expected: Loomweave completes at the final HEAD; the feature worktree is clean; the log
shows the four ticket-isolated commits from Tasks 1-4.

No additional commit is expected in this task. If verification forces a code or test fix,
return to the task that owns the failed requirement, add a RED regression, make the minimal
fix, and rerun its review before repeating Task 5.

## Review and Closeout Checkpoints

After each implementation commit:

1. Run an independent specification review against the approved design.
2. Run an independent code-quality review for correctness, fail-closed behaviour,
   determinism, and denial-of-service bounds.
3. Address blockers in the owning task and repeat both reviews.

Before claiming completion:

- verify every design acceptance criterion against current code and executable evidence;
- confirm no repository-authored setting can raise the budget;
- confirm genuine exhaustion remains a gating ERROR defect;
- confirm Elspeth reaches `206 -> 259 -> 263 -> 263` without degradation;
- preserve unrelated worktree changes in sibling repositories;
- record exact commit anchors and verification results in Filigree if an implementation
  ticket is created for this plan.
