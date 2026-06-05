"""Application service wiring repositories, a pluggable loan policy (strategy),
an audit decorator factory, and an observer-style event feed."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Protocol

from sampleapp.models import Book, Loan, Money, User
from sampleapp.repository import BookRepository, UserRepository

Listener = Callable[[str], None]


def audited(action: str) -> Callable[[Callable[..., object]], Callable[..., object]]:
    """Decorator factory: emit an audit event after the wrapped method runs."""

    def decorator(fn: Callable[..., object]) -> Callable[..., object]:
        @functools.wraps(fn)
        def wrapper(self: "LibraryService", *args: object, **kwargs: object) -> object:
            result = fn(self, *args, **kwargs)
            self._emit(f"{action}:{getattr(result, 'key', result)}")
            return result

        return wrapper

    return decorator


class LoanPolicy(Protocol):
    """Strategy interface: how many days a user may borrow a book."""

    def loan_days(self, user: User, book: Book) -> int: ...


class StandardPolicy:
    def loan_days(self, user: User, book: Book) -> int:
        return 14


class PremiumPolicy:
    """Decorator over another policy — doubles whatever the base allows."""

    def __init__(self, base: LoanPolicy) -> None:
        self._base = base

    def loan_days(self, user: User, book: Book) -> int:
        return self._base.loan_days(user, book) * 2


class LibraryService:
    """Orchestrates repositories + policy and notifies subscribed listeners."""

    def __init__(
        self,
        books: BookRepository,
        users: UserRepository,
        policy: LoanPolicy | None = None,
    ) -> None:
        self._books = books
        self._users = users
        self._policy = policy or StandardPolicy()
        self._listeners: list[Listener] = []

    @classmethod
    def in_memory(cls) -> "LibraryService":
        return cls(BookRepository(), UserRepository())

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def _emit(self, event: str) -> None:
        for listener in self._listeners:
            listener(event)

    @audited("register")
    def register_user(self, username: str, name: str) -> User:
        return self._users.add(User(username, name))

    @audited("catalog")
    def add_book(self, book: Book) -> Book:
        return self._books.add(book)

    def checkout(self, username: str, isbn: str) -> Loan:
        user = self._users.get(username)
        book = self._books.get(isbn)
        if user is None or book is None:
            raise LookupError("unknown user or book")
        days = self._policy.loan_days(user, book)
        loan = Loan(book=book, user=user, days=days, fee=Money(0))
        self._emit(f"checkout:{book.key}")
        return loan
