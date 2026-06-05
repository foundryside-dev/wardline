"""CLI front-end: a decorator-driven command registry and the untrusted-input
boundary (argv) that flows into the service layer."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence

from sampleapp.models import Book, Genre
from sampleapp.service import LibraryService

Command = Callable[["App", Sequence[str]], str]


class App:
    """Holds a service instance and a class-level registry of commands."""

    _commands: dict[str, Command] = {}

    def __init__(self) -> None:
        self.service = LibraryService.in_memory()
        self.service.subscribe(lambda event: print(f"[audit] {event}", file=sys.stderr))

    @classmethod
    def command(cls, name: str) -> Callable[[Command], Command]:
        """Decorator registering a handler under ``name``."""

        def register(fn: Command) -> Command:
            cls._commands[name] = fn
            return fn

        return register

    def run(self, argv: Sequence[str]) -> str:
        if not argv:
            return "usage: <command> [args...]"
        name, *rest = argv  # rest is untrusted user input
        handler = self._commands.get(name)
        if handler is None:
            return f"unknown command: {name}"
        return handler(self, rest)


@App.command("add-book")
def _add_book(app: App, args: Sequence[str]) -> str:
    isbn, title, author = args[0], args[1], args[2]
    book = app.service.add_book(Book(isbn, title, author, Genre.FICTION))
    return f"added {book!r}"


@App.command("register")
def _register(app: App, args: Sequence[str]) -> str:
    user = app.service.register_user(args[0], args[1])
    return f"registered {user!r}"


def main(argv: Sequence[str] | None = None) -> int:
    app = App()
    raw = list(argv) if argv is not None else sys.argv[1:]
    print(app.run(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
