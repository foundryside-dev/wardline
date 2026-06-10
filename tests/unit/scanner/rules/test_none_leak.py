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


def test_any_annotation_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from typing import Any
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> Any:
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx) == []

    ctx2 = _analyze(
        tmp_path,
        """
        import typing
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> typing.Any:
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx2) == []


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


def test_undecorated_does_not_fire(tmp_path) -> None:
    # Tier-suppression matrix slot (wardline-e159060db7): PY-WL-109 is gated on
    # an ANCHORED trusted producer. The identical annotated mixed-return shape
    # without a trust marker makes no trusted-output claim -> silent.
    ctx = _analyze(
        tmp_path,
        """
        def maybe(flag) -> int:
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


def test_try_except_all_value_returns_do_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def always(flag) -> int:
            try:
                if flag:
                    return 1
                return 2
            except ValueError:
                return 3
        """,
    )
    assert _ids(ctx) == []


def test_with_wrapped_all_value_returns_do_not_fire(tmp_path) -> None:
    # A with body where every path returns a value cannot leak None — the with
    # block is transparent to control flow (terminal iff its body is terminal).
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def always(flag) -> int:
            with open("x") as fh:
                if flag:
                    return 1
                else:
                    return 2
        """,
    )
    assert _ids(ctx) == []


def test_async_with_wrapped_all_value_returns_do_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        async def always(flag) -> int:
            async with ctxmgr() as fh:
                if flag:
                    return 1
                else:
                    return 2
        """,
    )
    assert _ids(ctx) == []


def test_with_body_falls_through_still_fires(tmp_path) -> None:
    # SOUNDNESS GUARD: a with body that does NOT always return still leaks None.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> int:
            with open("x") as fh:
                if flag:
                    return 1
        """,
    )
    assert _ids(ctx) == [("PY-WL-109", "m.maybe")]


def test_while_true_no_break_single_value_return_does_not_fire(tmp_path) -> None:
    # A constant-true loop with no break never exits to fall through — the only
    # way out is the value-bearing return, so None cannot leak.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f(flag) -> int:
            while True:
                if flag:
                    return 1
        """,
    )
    assert _ids(ctx) == []


def test_while_true_with_break_can_fall_through_fires(tmp_path) -> None:
    # SOUNDNESS GUARD: a break exits the loop, so control can fall through to the
    # implicit None return — this is a real leak.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f(flag) -> int:
            while True:
                if flag:
                    return 1
                break
        """,
    )
    assert _ids(ctx) == [("PY-WL-109", "m.f")]


def test_while_non_constant_test_can_fall_through_fires(tmp_path) -> None:
    # SOUNDNESS GUARD: a non-constant test can be false from the start (or become
    # false), so the loop can be skipped and fall through to implicit None.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f(flag) -> int:
            while flag:
                return 1
        """,
    )
    assert _ids(ctx) == [("PY-WL-109", "m.f")]


def test_while_true_break_in_nested_loop_does_not_fall_through(tmp_path) -> None:
    # SOUNDNESS GUARD (no over-firing): a break that binds to a NESTED loop does
    # not let the outer constant-true loop fall through.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f(flag) -> int:
            while True:
                for _ in range(3):
                    break
                if flag:
                    return 1
        """,
    )
    assert _ids(ctx) == []


def test_while_true_break_in_nested_loop_else_can_fall_through_fires(tmp_path) -> None:
    # SOUNDNESS GUARD: a break in a nested loop's else-clause binds to the OUTER
    # while, so that loop can exit and fall through to implicit None — real leak.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f(flag) -> int:
            while True:
                for _ in range(3):
                    pass
                else:
                    break
                if flag:
                    return 1
        """,
    )
    assert _ids(ctx) == [("PY-WL-109", "m.f")]


def test_guarded_wildcard_match_can_fall_through(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(value) -> int:
            match value:
                case _ if value > 0:
                    return 1
        """,
    )
    assert _ids(ctx) == [("PY-WL-109", "m.maybe")]


def test_unguarded_wildcard_match_all_value_returns_do_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def always(value) -> int:
            match value:
                case _:
                    return 1
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


def test_string_literal_annotations(tmp_path) -> None:
    # Forward-references in string literals must be parsed and check nullable (LOG-04)
    ctx1 = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> "int | None":
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx1) == []

    ctx2 = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe_not(flag) -> "int":
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx2) == [("PY-WL-109", "m.maybe_not")]

    ctx3 = _analyze(
        tmp_path,
        """
        from typing import Any
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag) -> "Any":
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx3) == []


def test_none_leak_with_imported_aliases(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from typing import Optional as Opt, Union as U
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f1(flag) -> Opt[int]:
            if flag:
                return 1
            return None
        @trusted(level='ASSURED')
        def f2(flag) -> U[int, None]:
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx) == []


def test_none_leak_with_implicit_none_return(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f(flag) -> int:
            if flag:
                return 1
            # Implicitly returns None here
        """,
    )
    assert _ids(ctx) == [("PY-WL-109", "m.f")]
