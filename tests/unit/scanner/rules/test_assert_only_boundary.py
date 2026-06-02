from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.assert_only_boundary import AssertOnlyBoundary
from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


_BOUNDARY = "from wardline.decorators import trust_boundary\n@trust_boundary(to_level='ASSURED')\ndef v(p):\n"


def _ids(ctx) -> set[str]:
    return {f.rule_id for f in (*AssertOnlyBoundary().check(ctx), *BoundaryWithoutRejection().check(ctx))}


def test_assert_only_boundary_fires_111_not_102(tmp_path) -> None:
    # The whole point: an assert-only boundary is 111's, NOT 102's — never both.
    ctx = _analyze(tmp_path, _BOUNDARY + "    assert p\n    return p\n")
    findings = AssertOnlyBoundary().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-111", "m.v")]
    assert findings[0].kind == Kind.DEFECT
    assert _ids(ctx) == {"PY-WL-111"}


def test_no_rejection_at_all_is_102_not_111(tmp_path) -> None:
    ctx = _analyze(tmp_path, _BOUNDARY + "    return p\n")
    assert AssertOnlyBoundary().check(ctx) == []
    assert _ids(ctx) == {"PY-WL-102"}


def test_assert_plus_real_raise_is_clean(tmp_path) -> None:
    # A real raise alongside an assert: the boundary CAN reject in production -> neither rule.
    ctx = _analyze(
        tmp_path,
        _BOUNDARY + "    assert isinstance(p, str)\n    if not p:\n        raise ValueError\n    return p\n",
    )
    assert AssertOnlyBoundary().check(ctx) == []
    assert _ids(ctx) == set()


def test_assert_plus_falsy_return_is_clean(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        _BOUNDARY + "    assert p\n    if not p:\n        return None\n    return p\n",
    )
    assert AssertOnlyBoundary().check(ctx) == []
    assert _ids(ctx) == set()


def test_trusted_producer_is_not_a_boundary(tmp_path) -> None:
    # @trusted (body == return, no trust-raise) is never a boundary -> 111 silent.
    ctx = _analyze(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted(level='ASSURED')\ndef f():\n    assert True\n    return 1\n",
    )
    assert AssertOnlyBoundary().check(ctx) == []


def test_undecorated_assert_is_silent(tmp_path) -> None:
    ctx = _analyze(tmp_path, "def v(p):\n    assert p\n    return p\n")
    assert AssertOnlyBoundary().check(ctx) == []
