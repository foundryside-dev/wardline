"""Boundary-integrity family partition oracle (wardline-718048a518).

The four rules partition the declared-boundary defect space — AT MOST ONE of
{PY-WL-102, PY-WL-111, PY-WL-113, PY-WL-119} fires per boundary:

  - PY-WL-119 — the bare degenerate shape (single ``return <param>``);
  - PY-WL-102 — every other shape with NO rejection path;
  - PY-WL-111 — the only rejection is ``assert`` (vanishes under ``python -O``);
  - PY-WL-113 — a real rejection exists but a fail-open handler defeats it.

This file is the executable form of that contract: each canonical shape is run
through the full analyzer and pinned to EXACTLY its owning rule. The partition
regressed silently before because no test asserted exactly-one-of; these do.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import WardlineAnalyzer

FAMILY = frozenset({"PY-WL-102", "PY-WL-111", "PY-WL-113", "PY-WL-119"})

_HEADER = "from wardline.decorators import trust_boundary\n"


def _family_ids(tmp_path: Path, src: str) -> set[str]:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    findings = WardlineAnalyzer().analyze([p], WardlineConfig(), root=tmp_path)
    return {f.rule_id for f in findings if f.rule_id in FAMILY}


_CASES = [
    pytest.param(
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            return p
        """,
        {"PY-WL-119"},
        id="degenerate-bare-passthrough-is-119-only",
    ),
    pytest.param(
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            x = p
            return x
        """,
        {"PY-WL-102"},
        id="laundered-passthrough-is-102-only",
    ),
    pytest.param(
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            assert p
            return p
        """,
        {"PY-WL-111"},
        id="assert-only-is-111-only",
    ),
    pytest.param(
        # canonical self-catch fail-open
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                return p
            except ValueError:
                return p
        """,
        {"PY-WL-113"},
        id="self-catch-failopen-is-113-only",
    ),
    pytest.param(
        # wardline-718048a518 repro A: no rejection anywhere + substituting handler
        """
        def compute(p):
            return p
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                x = compute(p)
            except Exception:
                return p
            return x
        """,
        {"PY-WL-102"},
        id="repro-a-no-rejection-substituting-handler-is-102-only",
    ),
    pytest.param(
        # wardline-718048a518 repro B: assert-only rejection + substituting handler
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            assert p
            try:
                return p
            except Exception:
                return "x"
        """,
        {"PY-WL-111"},
        id="repro-b-assert-only-substituting-handler-is-111-only",
    ),
    pytest.param(
        # docstring precedence: the assert IS inside the try and caught by a
        # substituting handler — the rejection is still assert-only, so 111 wins.
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                assert p
                return p
            except AssertionError:
                return "x"
        """,
        {"PY-WL-111"},
        id="assert-inside-try-swallowed-is-111-not-113",
    ),
    pytest.param(
        # clean validator: real raise, fail-closed
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            if not p:
                raise ValueError
            return p
        """,
        set(),
        id="raising-validator-is-clean",
    ),
    pytest.param(
        # boundary.json FP 5: rejection outside the try; cache-miss fallback handler
        """
        _cache = {}
        @trust_boundary(to_level='ASSURED')
        def v(p):
            if not p.isdigit():
                raise ValueError
            try:
                cached = _cache[p]
                return cached
            except KeyError:
                result = int(p)
                _cache[p] = result
                return result
        """,
        set(),
        id="fail-closed-cache-fallback-is-clean",
    ),
    pytest.param(
        # one-hop helper rejection: clean for 102/111, and fail-closed (no try)
        """
        def _require_nonempty(p):
            if not p:
                raise ValueError("empty")
        @trust_boundary(to_level='ASSURED')
        def v(p):
            _require_nonempty(p)
            return p
        """,
        set(),
        id="helper-rejecting-validator-is-clean",
    ),
    pytest.param(
        # delegation to a raising boundary: single Return of a CALL — not degenerate
        """
        @trust_boundary(to_level='ASSURED')
        def inner(p):
            if not p:
                raise ValueError
            return p
        @trust_boundary(to_level='ASSURED')
        def v(p):
            return inner(p)
        """,
        set(),
        id="delegating-validator-is-clean",
    ),
    pytest.param(
        # helper rejection inside the try, swallowed by a substituting handler:
        # the rejection exists (not 102) and is not assert-only (not 111) — 113 owns it.
        """
        def _require_nonempty(p):
            if not p:
                raise ValueError("empty")
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                _require_nonempty(p)
                return p
            except ValueError:
                return p
        """,
        {"PY-WL-113"},
        id="helper-rejection-swallowed-is-113-only",
    ),
]


@pytest.mark.parametrize(("src", "expected"), _CASES)
def test_family_partition_exactly_one_owner(tmp_path: Path, src: str, expected: set[str]) -> None:
    ids = _family_ids(tmp_path, src)
    assert ids == expected
    assert len(ids) <= 1, f"family partition violated — co-fired: {sorted(ids)}"
