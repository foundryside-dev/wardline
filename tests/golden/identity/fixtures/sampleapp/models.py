"""Domain models: an abstract Entity base, a Protocol, a frozen value object
with operator overloading, and concrete entities via inheritance."""

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Protocol, runtime_checkable


class Genre(Enum):
    FICTION = auto()
    NONFICTION = auto()
    REFERENCE = auto()
    PERIODICAL = auto()


@runtime_checkable
class Identifiable(Protocol):
    """Structural type: anything with a stable string key."""

    @property
    def key(self) -> str: ...


class Entity(ABC):
    """Abstract base giving identity, equality, and hashing to all models."""

    _ids = itertools.count(1)

    def __init__(self) -> None:
        self.uid: int = next(self._ids)

    @property
    @abstractmethod
    def key(self) -> str:
        """Stable natural key used by repositories."""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Entity) and other.key == self.key

    def __hash__(self) -> int:
        return hash(self.key)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.key!r})"


@dataclass(frozen=True)
class Money:
    """Immutable value object supporting addition and ordering."""

    cents: int
    currency: str = "USD"

    def __add__(self, other: Money) -> Money:
        if self.currency != other.currency:
            raise ValueError("currency mismatch")
        return Money(self.cents + other.cents, self.currency)

    def __lt__(self, other: Money) -> bool:
        return self.cents < other.cents

    def __str__(self) -> str:
        return f"{self.cents / 100:.2f} {self.currency}"


class Book(Entity):
    def __init__(self, isbn: str, title: str, author: str, genre: Genre) -> None:
        super().__init__()
        self.isbn = isbn
        self.title = title
        self.author = author
        self.genre = genre

    @property
    def key(self) -> str:
        return self.isbn


class User(Entity):
    def __init__(self, username: str, name: str) -> None:
        super().__init__()
        self.username = username
        self.name = name

    @property
    def key(self) -> str:
        return self.username


@dataclass
class Loan:
    """Associates a Book with a User; composes the Money value object."""

    book: Book
    user: User
    days: int = 14
    fee: Money = field(default_factory=lambda: Money(0))

    def overdue_fee(self, days_late: int, per_day: Money) -> Money:
        total = self.fee
        for _ in range(max(0, days_late)):
            total = total + per_day
        return total
