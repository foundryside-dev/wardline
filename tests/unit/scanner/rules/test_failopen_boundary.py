from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.failopen_boundary import FailOpenBoundary

_BOUNDARY_HEADER = (
    "from wardline.decorators import trust_boundary, external_boundary\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_BOUNDARY_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def test_failopen_boundary_fires_on_substitution(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                return read_raw(p)
            except ValueError:
                return p
        """,
    )
    findings = FailOpenBoundary().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-113", "m.v")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR


def test_failopen_boundary_silent_on_re_raise(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                return read_raw(p)
            except ValueError:
                raise
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_falsy_constant_return(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                return read_raw(p)
            except ValueError:
                return None
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_non_boundary(tmp_path) -> None:
    # A plain @trusted function with body == return (no trust-raising) is not a boundary,
    # so we shouldn't trigger PY-WL-113 even if we swallow and return.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f(p):
            try:
                if not p:
                    raise ValueError
                return p
            except ValueError:
                return p
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_undecorated(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def f(p):
            try:
                if not p:
                    raise ValueError
                return p
            except ValueError:
                return p
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_fires_on_assignment_then_fallthrough(tmp_path) -> None:
    # PY-WL-113 FN (wardline-c314a7140b): the handler swallows the rejection and
    # substitutes via an ASSIGNMENT to a name that the function then returns by
    # fall-through. Structurally identical to the `return p` self-catch, which fires.
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                result = read_raw(p)
            except ValueError:
                result = p
            return result
        """,
    )
    findings = FailOpenBoundary().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-113", "m.v")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR


def test_failopen_boundary_silent_on_assignment_of_falsy_rejection(tmp_path) -> None:
    # CONTROL: handler assigns a falsy/rejection value (None) to the returned name.
    # That is a rejection signal, not a value-bearing substitution -> must stay silent,
    # mirroring `return None`.
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                result = read_raw(p)
            except ValueError:
                result = None
            return result
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_assignment_to_unreturned_name(tmp_path) -> None:
    # CONTROL (FP guard): handler assigns the untrusted value to a scratch name that
    # the function does NOT return; the boundary still returns the validated `result`.
    # The substitution does not escape, so it must stay silent.
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                result = read_raw(p)
            except ValueError:
                tmp = p
            return result
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_assignment_then_reraise(tmp_path) -> None:
    # CONTROL: handler assigns then re-raises (fail-closed) -> must stay silent.
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                result = read_raw(p)
            except ValueError:
                result = p
                raise
            return result
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_assign_then_reject_return(tmp_path) -> None:
    # CONTROL (panel FP, wardline-c314a7140b): handler assigns `result = p` then rejects
    # via `return None`. The assignment is a dead store; the boundary fails CLOSED. The
    # assign-substitution must be gated on the handler falling through — must stay silent.
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                result = read_raw(p)
            except ValueError:
                result = p
                return None
            return result
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_idempotent_self_assignment(tmp_path) -> None:
    # CONTROL (panel FP): an idempotent `result = result` in an unrelated handler
    # substitutes nothing new — must stay silent.
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            if not p:
                raise ValueError
            result = read_raw(p)
            try:
                pass
            except Exception:
                result = result
            return result
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_fires_on_conditional_return_then_fallthrough_assign(tmp_path) -> None:
    # panel-2 FN (wardline-c314a7140b): the handler returns only CONDITIONALLY (nested if)
    # and otherwise FALLS THROUGH with a value-substituting assignment. The fall-through
    # gate must key on TOP-LEVEL returns only — a conditional nested return does not stop
    # the assignment escaping on the other path, so this is a real fail-open and must fire.
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p, check):
            try:
                result = read_raw(p)
            except ValueError:
                if check:
                    return None
                result = p
            return result
        """,
    )
    assert [(f.rule_id, f.qualname) for f in FailOpenBoundary().check(ctx)] == [("PY-WL-113", "m.v")]
