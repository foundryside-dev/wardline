from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.none_leak import NoneLeak


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def _ids(ctx):
    return [(f.rule_id, f.qualname) for f in NoneLeak().check(ctx)]


def test_non_none_annotation_with_bare_return_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> int:
            if flag:
                return 1
            return
        """,
    )
    findings = NoneLeak().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-109", "m.maybe")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN


def test_explicit_return_none_also_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> int:
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx) == [("PY-WL-109", "m.maybe")]


def test_optional_annotation_does_not_fire(tmp_path) -> None:
    # A declared-nullable contract (-> int | None) is legitimate, not a leak.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> int | None:
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx) == []


def test_optional_subscript_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from typing import Optional
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> Optional[int]:
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx) == []


def test_unannotated_does_not_fire(tmp_path) -> None:
    # No explicit non-None contract -> not a provable leak (the FP guard).
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag):
            if flag:
                return 1
            return
        """,
    )
    assert _ids(ctx) == []


def test_all_value_returns_do_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def always(flag) -> int:
            if flag:
                return 1
            return 2
        """,
    )
    assert _ids(ctx) == []


def test_generator_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def gen(flag) -> int:
            if flag:
                yield 1
            return
        """,
    )
    assert _ids(ctx) == []


def test_trust_boundary_shape_delegates_to_102(tmp_path) -> None:
    # A trust-RAISING shape (body less trusted than declared) is PY-WL-102's territory;
    # 109 must skip it even with a non-None annotation and a None path.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trust_boundary
        @trust_boundary(to_level='ASSURED')
        def v(flag) -> int:
            if flag:
                return 1
            return
        """,
    )
    assert _ids(ctx) == []


def test_union_annotation_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from typing import Union
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> Union[int, None]:
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx) == []
