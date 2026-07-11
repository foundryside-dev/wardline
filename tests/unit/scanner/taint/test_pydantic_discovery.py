from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, dataclass

import pytest

from wardline.scanner.taint import pydantic_discovery as discovery
from wardline.scanner.taint.fastapi_sources import discover_pydantic_models

PydanticDiscoveryBudget = discovery.PydanticDiscoveryBudget


@dataclass(frozen=True, slots=True)
class _ParsedModule:
    relpath: str
    module: str
    tree: ast.Module
    alias_map: dict[str, str]
    class_qualnames: frozenset[str]


def _parsed(source: str, *, module: str) -> _ParsedModule:
    tree = ast.parse(source)
    return _ParsedModule(
        relpath=f"{module.replace('.', '/')}.py",
        module=module,
        tree=tree,
        alias_map={},
        class_qualnames=frozenset(
            f"{module}.{statement.name}" for statement in tree.body if isinstance(statement, ast.ClassDef)
        ),
    )


def _model_chain(length: int) -> tuple[_ParsedModule, ...]:
    modules = [
        _parsed(
            "import pydantic\n\nclass Model0(pydantic.BaseModel):\n    pass\n",
            module="m0",
        )
    ]
    modules.extend(
        _parsed(
            f"from m{index - 1} import Model{index - 1}\n\nclass Model{index}(Model{index - 1}):\n    pass\n",
            module=f"m{index}",
        )
        for index in range(1, length)
    )
    return tuple(modules)


def test_model_chain_rejects_whole_round_before_partial_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _model_chain(80)
    calls = 0

    def spy(*args: object, **kwargs: object) -> frozenset[str]:
        nonlocal calls
        calls += 1
        return discover_pydantic_models(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery, "discover_pydantic_models", spy, raising=False)

    result = discovery.discover_project_pydantic_models(files)

    assert result.degraded_reason == "work_budget_exceeded"
    assert result.round_number == 18
    assert result.work_completed == 14_960
    assert result.next_round_cost == 1_600
    assert result.required_total == 16_560
    assert result.known_model_count == 17
    assert result.models == frozenset(name for file in files for name in file.class_qualnames)
    assert calls == 17 * 80 == 1_360
    assert calls % len(files) == 0


def test_model_chain_converges_without_degradation() -> None:
    result = discovery.discover_project_pydantic_models(_model_chain(3))

    assert result.models == frozenset({"m0.Model0", "m1.Model1", "m2.Model2"})
    assert result.degraded_reason is None
    assert result.model_counts_by_round == (1, 2, 3, 3)
    assert result.round_number == 4


def test_repeated_model_state_degrades_to_all_declared_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed = _parsed("class A:\n    pass\n\nclass B:\n    pass\n", module="m")
    states = iter(
        (
            frozenset({"m.A", "m.B"}),
            frozenset({"m.A"}),
            frozenset({"m.A", "m.B"}),
        )
    )

    monkeypatch.setattr(discovery, "discover_pydantic_models", lambda *args, **kwargs: next(states), raising=False)

    result = discovery.discover_project_pydantic_models((parsed,))

    assert result.degraded_reason == "repeated_state"
    assert result.models == frozenset({"m.A", "m.B"})
    assert result.model_counts_by_round == (2, 1, 2)
    assert result.known_model_count == 2
    assert result.round_number == 3


def test_equal_size_repeated_model_state_degrades_to_all_declared_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed = _parsed("class A:\n    pass\n\nclass B:\n    pass\n", module="m")
    states = iter((frozenset({"m.A"}), frozenset({"m.B"}), frozenset({"m.A"})))

    monkeypatch.setattr(discovery, "discover_pydantic_models", lambda *args, **kwargs: next(states), raising=False)

    result = discovery.discover_project_pydantic_models((parsed,))

    assert result.degraded_reason == "repeated_state"
    assert result.models == frozenset({"m.A", "m.B"})
    assert result.model_counts_by_round == (1, 1, 1)
    assert result.round_number == 3


def test_round_limit_degrades_to_empty_declared_model_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed = _parsed("value = 1\n", module="m")
    monkeypatch.setattr(
        discovery,
        "discover_pydantic_models",
        lambda *args, **kwargs: frozenset({"m.Ghost"}),
        raising=False,
    )

    result = discovery.discover_project_pydantic_models((parsed,))

    assert result.degraded_reason == "round_limit_exceeded"
    assert result.models == frozenset()
    assert result.model_counts_by_round == (1,)
    assert result.round_number == 1


def test_elspeth_sized_budget_admits_all_discovery_rounds() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=593, statement_count=11_493)

    assert budget.work_budget == 773_504
    assert budget.absolute_cap_applied is False

    known_model_counts = (0, 206, 259, 263)
    round_costs = tuple(budget.round_cost(count) for count in known_model_counts)

    assert round_costs == (12_086, 134_244, 165_673, 168_045)
    assert sum(round_costs) == 480_048
    assert budget.admits_round(
        completed_work=sum(round_costs[:-1]),
        known_model_count=known_model_counts[-1],
    )


def test_tiny_project_receives_minimum_budget() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=1, statement_count=0)

    assert budget.work_budget == 4_096
    assert budget.absolute_cap_applied is False


def test_large_project_budget_is_limited_by_absolute_cap() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=100_000, statement_count=0)

    assert budget.work_budget == 5_000_000
    assert budget.absolute_cap_applied is True


def test_round_is_rejected_when_required_total_exceeds_budget() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=80, statement_count=160)

    assert budget.work_budget == 15_360
    assert budget.round_cost(known_model_count=17) == 1_600
    assert budget.required_total(completed_work=14_960, known_model_count=17) == 16_560
    assert budget.admits_round(completed_work=14_960, known_model_count=17) is False


def test_round_is_admitted_when_required_total_equals_budget() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=80, statement_count=160)

    assert budget.required_total(completed_work=13_760, known_model_count=17) == budget.work_budget
    assert budget.admits_round(completed_work=13_760, known_model_count=17) is True


@pytest.mark.parametrize(
    ("file_count", "statement_count"),
    [(-1, 0), (0, -1)],
)
def test_from_counts_rejects_negative_structural_counts(file_count: int, statement_count: int) -> None:
    with pytest.raises(ValueError, match="must be non-negative"):
        PydanticDiscoveryBudget.from_counts(file_count=file_count, statement_count=statement_count)


def test_direct_construction_rejects_negative_structural_counts() -> None:
    with pytest.raises(ValueError, match="must be non-negative"):
        PydanticDiscoveryBudget(file_count=-1, statement_count=0)


def test_round_cost_rejects_negative_known_model_count() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=1, statement_count=1)

    with pytest.raises(ValueError, match="known_model_count must be non-negative"):
        budget.round_cost(known_model_count=-1)


def test_required_total_rejects_negative_completed_work() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=1, statement_count=1)

    with pytest.raises(ValueError, match="completed_work must be non-negative"):
        budget.required_total(completed_work=-1, known_model_count=0)


def test_budget_is_frozen_and_slotted() -> None:
    budget = PydanticDiscoveryBudget.from_counts(file_count=1, statement_count=1)

    with pytest.raises(FrozenInstanceError):
        budget.work_budget = 0  # type: ignore[misc]
    assert not hasattr(budget, "__dict__")
