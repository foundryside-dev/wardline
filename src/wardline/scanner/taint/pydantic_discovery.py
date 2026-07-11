"""Adaptive work-budget accounting for Pydantic model discovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

_MINIMUM_WORK_BUDGET = 4_096
_WORK_PER_STRUCTURAL_UNIT = 64
_ABSOLUTE_WORK_BUDGET_CAP = 5_000_000


@dataclass(frozen=True, slots=True)
class PydanticDiscoveryBudget:
    """Project-scaled budget and round-cost accounting for model discovery."""

    file_count: int
    statement_count: int
    work_budget: int
    absolute_cap_applied: bool

    @classmethod
    def from_counts(cls, *, file_count: int, statement_count: int) -> Self:
        """Build a budget scaled from project structure counts."""
        if file_count < 0 or statement_count < 0:
            raise ValueError("file_count and statement_count must be non-negative")

        scaled = (file_count + statement_count) * _WORK_PER_STRUCTURAL_UNIT
        work_budget = min(_ABSOLUTE_WORK_BUDGET_CAP, max(_MINIMUM_WORK_BUDGET, scaled))
        return cls(
            file_count=file_count,
            statement_count=statement_count,
            work_budget=work_budget,
            absolute_cap_applied=scaled > _ABSOLUTE_WORK_BUDGET_CAP,
        )

    def round_cost(self, known_model_count: int) -> int:
        """Return the work required for one discovery round."""
        if known_model_count < 0:
            raise ValueError("known_model_count must be non-negative")
        return self.statement_count + self.file_count * (known_model_count + 1)

    def required_total(self, completed_work: int, known_model_count: int) -> int:
        """Return cumulative work after adding the next discovery round."""
        if completed_work < 0:
            raise ValueError("completed_work must be non-negative")
        return completed_work + self.round_cost(known_model_count)

    def admits_round(self, completed_work: int, known_model_count: int) -> bool:
        """Return whether the next discovery round fits within the budget."""
        return self.required_total(completed_work, known_model_count) <= self.work_budget
