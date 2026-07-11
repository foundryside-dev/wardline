from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from wardline.scanner.taint.pydantic_discovery import PydanticDiscoveryBudget


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
    budget = PydanticDiscoveryBudget(
        file_count=80,
        statement_count=160,
        work_budget=15_360,
        absolute_cap_applied=False,
    )

    assert budget.round_cost(known_model_count=17) == 1_600
    assert budget.required_total(completed_work=14_960, known_model_count=17) == 16_560
    assert budget.admits_round(completed_work=14_960, known_model_count=17) is False


@pytest.mark.parametrize(
    ("file_count", "statement_count"),
    [(-1, 0), (0, -1)],
)
def test_from_counts_rejects_negative_structural_counts(file_count: int, statement_count: int) -> None:
    with pytest.raises(ValueError, match="must be non-negative"):
        PydanticDiscoveryBudget.from_counts(file_count=file_count, statement_count=statement_count)


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
