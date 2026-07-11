"""Adaptive work-budget accounting for Pydantic model discovery."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol, Self

from wardline.scanner.taint.fastapi_sources import discover_pydantic_models

_MINIMUM_WORK_BUDGET = 4_096
_WORK_PER_STRUCTURAL_UNIT = 64
_ABSOLUTE_WORK_BUDGET_CAP = 5_000_000


@dataclass(frozen=True, slots=True)
class PydanticDiscoveryBudget:
    """Project-scaled budget and round-cost accounting for model discovery."""

    file_count: int
    statement_count: int
    work_budget: int = field(init=False)
    absolute_cap_applied: bool = field(init=False)

    def __post_init__(self) -> None:
        """Validate structural counts and derive the immutable budget fields."""
        if self.file_count < 0 or self.statement_count < 0:
            raise ValueError("file_count and statement_count must be non-negative")

        scaled = (self.file_count + self.statement_count) * _WORK_PER_STRUCTURAL_UNIT
        object.__setattr__(
            self,
            "work_budget",
            min(_ABSOLUTE_WORK_BUDGET_CAP, max(_MINIMUM_WORK_BUDGET, scaled)),
        )
        object.__setattr__(self, "absolute_cap_applied", scaled > _ABSOLUTE_WORK_BUDGET_CAP)

    @classmethod
    def from_counts(cls, *, file_count: int, statement_count: int) -> Self:
        """Build a budget scaled from project structure counts."""
        return cls(file_count=file_count, statement_count=statement_count)

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


class ParsedPydanticModule(Protocol):
    """Structural project-file input required by Pydantic discovery."""

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
    """Complete fixed-point outcome and its deterministic work accounting."""

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
    """Discover project models to a fixed point within a whole-round work budget."""
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
    max_rounds = sum(isinstance(statement, ast.ClassDef) for parsed in files for statement in parsed.tree.body) + 1

    for round_index in range(max_rounds):
        round_number = round_index + 1
        known_model_count = len(models)
        next_round_cost = budget.round_cost(known_model_count)
        required_total = budget.required_total(completed_work, known_model_count)
        if not budget.admits_round(completed_work, known_model_count):
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
            next_models.update(name for name in discovered if name.rpartition(".")[0] == parsed.module)
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
                known_model_count=len(next_state),
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
