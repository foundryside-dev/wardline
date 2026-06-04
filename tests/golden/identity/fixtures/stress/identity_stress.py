"""Identity-stress fixture for the parity oracle.

Parsed, never executed. Deliberately piles up the qualname / span / fingerprint
edges a Rust parser is most likely to render differently: decorated boundaries
(``external_boundary`` / ``trust_boundary`` / ``trusted``), nested / async /
overloaded functions, methods, classmethods, decorated classes, lambdas,
comprehensions, multi-line signatures, and unicode identifiers. It also triggers
two identity-bearing policy rules — PY-WL-101 (untrusted reaches a trusted
producer) and an assert-only boundary (PY-WL-111 / CWE-617).

Imports are confined to the public ``wardline.decorators`` surface (which the
scanner resolves statically) and the stdlib — no ``wardline.core.*`` import, so
the fixture carries no first-party engine-diagnostic imports.
"""

from __future__ import annotations

from typing import overload

from wardline.decorators import external_boundary, trust_boundary, trusted


@external_boundary
def ingest(raw: str) -> str:
    """Untrusted source crossing the boundary."""
    return raw


@trust_boundary(to_level="ASSURED")
def sanitize(
    value: str,
    *,
    strict: bool = True,
) -> str:
    """Multi-line signature; a real boundary that rejects."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("empty value rejected at the boundary")
    return cleaned


@trust_boundary(to_level="ASSURED")
def assert_only_boundary(value: str) -> str:
    """Boundary whose ONLY rejection path is ``assert`` (stripped under -O) — PY-WL-111."""
    assert value, "value must be truthy"
    return value


@trusted(level="ASSURED")
def privileged_producer(username: str) -> str:
    """Trusted producer that expects validated input."""
    return f"user:{username}"


@trusted(level="ASSURED")
def untrusted_reaches_trusted(raw: str) -> str:
    """PY-WL-101: raw untrusted input flows straight into a trusted producer."""
    return ingest(raw)


async def async_boundary(raw: str) -> str:
    """Async function — qualname/span edge."""
    return raw


def outer() -> int:
    """Nested function — qualname carries the ``<locals>`` segment."""

    def nested() -> int:
        return 1

    return nested()


@overload
def overloaded(x: int) -> int: ...
@overload
def overloaded(x: str) -> str: ...
def overloaded(x: object) -> object:
    """Overloaded function — three defs share a name."""
    return x


class Service:
    """Decorated-class / method / classmethod qualname edges."""

    @classmethod
    def make(cls) -> "Service":
        return cls()

    def method(self, raw: str) -> str:
        return raw


def comprehensions(items: list[str]) -> list[str]:
    """Comprehension + lambda qualname edges."""
    doubled = [i for i in items]
    fn = lambda v: v  # noqa: E731 — lambda qualname edge on purpose
    return [fn(s) for s in doubled]


def func_with_unicode_café(naïve_x: str) -> str:
    """Unicode identifiers in the name and the parameter."""
    return naïve_x
