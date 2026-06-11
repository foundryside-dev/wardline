"""Soundness-regression locks for closures B / C / D.

The Track-1.6 soundness review (docs/notes/improvements.md) listed five candidate
FN/precision closures. Probing showed THREE are already sound in the engine —
``*args``/``**kwargs`` at call sites, comprehension/walrus targets, and
decorator-wrapped callees all propagate taint correctly today. Per the DoD
("soundness-regression test per closed hole"), this module PINS that behavior so a
future refactor cannot silently reopen the hole. (Closures A and E are the genuine
holes; see test_flow_sensitive_sink.py for E and the class-attribute work for A.)
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer

_HEADER = (
    "import functools\n"
    "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
)


def _defects(tmp_path: Path, body: str) -> set[str]:
    # Assertions below pin the EXACT defect set (wardline-e159060db7): a
    # membership-only check would let a spurious co-firing (e.g. a boundary
    # heuristic regression adding PY-WL-102) ship invisibly.
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(body), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    return {f.rule_id for f in findings if f.kind is Kind.DEFECT}


# ── Closure C: comprehension / walrus targets ────────────────────────────────


def test_comprehension_propagates_raw_to_trusted_return(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "@trusted(level='ASSURED')\ndef f(p):\n    return [x for x in read_raw(p)]",
    )


def test_walrus_propagates_raw_to_trusted_return(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "@trusted(level='ASSURED')\ndef f(p):\n    (y := read_raw(p))\n    return y",
    )


def test_match_subject_nested_walrus_propagates_raw_to_trusted_return(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "@trusted(level='ASSURED')\n"
        "def f(p):\n"
        "    match (s := read_raw(p))[0]:\n"
        "        case _:\n"
        "            pass\n"
        "    return s",
    )


def test_starred_unpack_raw_slice_propagates_to_trusted_return(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "@trusted(level='ASSURED')\ndef f(p):\n    (a, *rest, c) = (1, read_raw(p), 2)\n    return rest",
    )


def test_existing_comprehension_walrus_target_propagates_to_trusted_return(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "@trusted(level='ASSURED')\ndef f(p):\n    x = 1\n    [(x := read_raw(p)) for _ in items]\n    return x",
    )


def test_async_for_body_propagates_to_trusted_return(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "@trusted(level='ASSURED')\n"
        "async def f(p):\n"
        "    async for item in read_raw(p):\n"
        "        x = item\n"
        "    return x",
    )


def test_trystar_handler_propagates_to_trusted_return(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "@trusted(level='ASSURED')\ndef f(p):\n"
        "    x = 1\n"
        "    try:\n"
        "        risky()\n"
        "    except* ValueError:\n"
        "        x = read_raw(p)\n"
        "    return x",
    )


# ── Closure B: *args / **kwargs at call sites ────────────────────────────────


@pytest.mark.parametrize("sink_arg", ["*args", "**kwargs"])
def test_starred_raw_into_sink_fires(tmp_path: Path, sink_arg: str) -> None:
    binder = "args = read_raw(p)" if sink_arg == "*args" else "kwargs = read_raw(p)"
    assert {"PY-WL-107"} == _defects(
        tmp_path,
        f"@trusted(level='ASSURED')\ndef f(p):\n    {binder}\n    eval({sink_arg})",
    )


def test_trusted_function_own_varargs_do_not_fire(tmp_path: Path) -> None:
    # *args/**kwargs of a @trusted function ARE that function's own params at its
    # declared tier — nothing untrusted entered, so returning them is clean.
    assert set() == _defects(
        tmp_path,
        "@trusted(level='ASSURED')\ndef f(*args, **kwargs):\n    return kwargs",
    )


# ── Closure D: decorator-wrapped callees ─────────────────────────────────────


def test_call_through_wrapped_callee_propagates(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "def deco(fn):\n"
        "    @functools.wraps(fn)\n    def w(*a, **k):\n        return fn(*a, **k)\n    return w\n"
        "@deco\ndef wrapped(p):\n    return read_raw(p)\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    return wrapped(p)",
    )


def test_wraps_decorator_stacked_on_producer_propagates(tmp_path: Path) -> None:
    assert {"PY-WL-101"} == _defects(
        tmp_path,
        "def deco(fn):\n"
        "    @functools.wraps(fn)\n    def w(*a, **k):\n        return fn(*a, **k)\n    return w\n"
        "@trusted(level='ASSURED')\n@deco\ndef f(p):\n    return read_raw(p)",
    )
