"""Generic repositories: an abstract ``Repository[T]`` with container dunders,
a ``TimestampMixin`` folded in by multiple inheritance, and typed concretes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Generic, Iterator, TypeVar

from sampleapp.models import Book, Entity, User

T = TypeVar("T", bound=Entity)


class TimestampMixin:
    """Records the last mutation time; mixed in alongside Repository."""

    def touch(self) -> None:
        self._mtime = datetime.now(timezone.utc)

    @property
    def last_modified(self) -> datetime | None:
        return getattr(self, "_mtime", None)


class Repository(ABC, Generic[T]):
    """Abstract key->entity collection that behaves like a container."""

    def __init__(self) -> None:
        self._items: dict[str, T] = {}

    @abstractmethod
    def validate(self, item: T) -> None:
        """Raise if ``item`` may not enter the collection."""

    def add(self, item: T) -> T:
        self.validate(item)
        self._items[item.key] = item
        return item

    def get(self, key: str) -> T | None:
        return self._items.get(key)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[T]:
        return iter(self._items.values())

    def __getitem__(self, key: str) -> T:
        return self._items[key]

    def __contains__(self, key: str) -> bool:
        return key in self._items


class InMemoryRepository(Repository[T], TimestampMixin):
    """Concrete generic repo; MRO resolves Repository then the mixin."""

    def validate(self, item: T) -> None:
        if not item.key:
            raise ValueError("entity needs a non-empty key")

    def add(self, item: T) -> T:
        result = super().add(item)
        self.touch()
        return result


class BookRepository(InMemoryRepository[Book]):
    def by_author(self, author: str) -> list[Book]:
        return [book for book in self if book.author == author]


class UserRepository(InMemoryRepository[User]):
    def by_username(self, username: str) -> User | None:
        return self.get(username)
