# tests/unit/scanner/rules/test_invalid_decorator_level.py
"""Tests for PY-WL-114: invalid or out-of-range builtin trust decorator levels."""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.invalid_decorator_level import InvalidDecoratorLevel


def _analyze(tmp_path: Path, src: str) -> tuple[WardlineAnalyzer, object]:
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer, analyzer.last_context


def test_invalid_decorator_level_trusted_typo(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted

        @trusted(level='ASURED')
        def f(p):
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR
    assert "ASURED" in findings[0].message


def test_invalid_decorator_level_boundary_out_of_range(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trust_boundary

        @trust_boundary(to_level='INTEGRAL')
        def g(p):
            if not p: raise ValueError
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.g")]
    assert "INTEGRAL" in findings[0].message


def test_invalid_decorator_level_invalid_name(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted

        @trusted(level='BOGUS')
        def h(p):
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.h")]


def test_invalid_decorator_level_clean_cases(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted, trust_boundary

        @trusted(level='INTEGRAL')
        def clean_1(p):
            return p

        @trusted(level='ASSURED')
        def clean_2(p):
            return p

        @trust_boundary(to_level='GUARDED')
        def clean_3(p):
            if not p: raise ValueError
            return p

        @trusted(level=cfg.LEVEL)
        def clean_dynamic(p):
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert len(findings) == 0


def test_invalid_decorator_level_aliased_builtin_fires(tmp_path) -> None:
    # The FN: an aliased builtin decorator with a typo'd level silently disables the gate
    # AND escaped the rule meant to catch it. Resolving through the alias map fixes it
    # (wardline-0267c31cd8).
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted as t

        @t(level='ASURED')
        def f(p):
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.f")]


def test_invalid_decorator_level_aliased_valid_does_not_fire(tmp_path) -> None:
    # Guard: the alias resolution must not over-fire on a VALID aliased level.
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted as t

        @t(level='ASSURED')
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_invalid_decorator_level_foreign_same_name_does_not_fire(tmp_path) -> None:
    # The FP: a non-wardline decorator that merely happens to be spelled ``trusted`` is not
    # the builtin marker — an invalid level on it is out of scope (wardline-0267c31cd8).
    _, ctx = _analyze(
        tmp_path,
        """
        import other_pkg

        @other_pkg.trusted(level='BOGUS')
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_invalid_decorator_level_local_same_name_does_not_fire(tmp_path) -> None:
    # The FP: a locally-defined ``trusted`` decorator is not the builtin marker.
    _, ctx = _analyze(
        tmp_path,
        """
        def trusted(**kw):
            def deco(fn):
                return fn
            return deco

        @trusted(level='BOGUS')
        def f(p):
            return p
        """,
    )
    assert InvalidDecoratorLevel().check(ctx) == []


def test_stacked_identical_decorators_have_distinct_fingerprints(tmp_path) -> None:
    # Soundness / fingerprint collision (wardline-377b896a87): two stacked identical invalid
    # decorators on ONE def are two distinct findings, but the fingerprint anchored at the
    # ENTITY line with taint_path=f"{name}:{token}" (no within-def discriminator) collapsed them
    # to one key — one silently masking the other on the baseline/waiver/judge/Filigree joins.
    # The decorators share name, token, AND entity line; the only thing that tells them apart is
    # their POSITION in the decorator_list, so the discriminator carries the decorator ordinal
    # (move-stable: invariant to the def moving and to column shifts; collision-complete since at
    # most one finding is emitted per decorator).
    _, ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trust_boundary

        @trust_boundary(to_level='bogus')
        @trust_boundary(to_level='bogus')
        def handler(p):
            if not p: raise ValueError
            return p
        """,
    )
    findings = InvalidDecoratorLevel().check(ctx)
    assert len(findings) == 2, "both invalid decorators must be reported"
    fps = {f.fingerprint for f in findings}
    assert len(fps) == 2, "two distinct findings must not share a fingerprint (collision)"
