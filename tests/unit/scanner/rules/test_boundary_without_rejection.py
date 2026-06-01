from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection


def _analyze(tmp_path: Path, files: dict[str, str]):
    paths = []
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        paths.append(p)
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(sorted(paths), WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, findings


def _run(ctx):
    return BoundaryWithoutRejection().check(ctx)


def test_boundary_without_rejection_fires(tmp_path) -> None:
    # @trust_boundary that just returns its input — cannot reject -> DEFECT.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    return p\n",
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-102", "m.v")]
    assert findings[0].kind == Kind.DEFECT


def test_boundary_with_raise_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='ASSURED')\n"
            "def v(p):\n    if not p:\n        raise ValueError\n    return p\n",
        },
    )
    assert _run(ctx) == []


def test_boundary_with_falsy_return_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trust_boundary\n"
            "@trust_boundary(to_level='GUARDED')\n"
            "def v(p):\n    if not p:\n        return None\n    return p\n",
        },
    )
    assert _run(ctx) == []


def test_non_boundary_decorators_are_ignored(tmp_path) -> None:
    # @trusted (body == return, not a trust-raising transition) and @external_boundary
    # are NOT trust boundaries -> never flagged by PY-WL-102.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted, external_boundary\n"
            "@trusted\ndef a():\n    return 1\n"
            "@external_boundary\ndef b(p):\n    return p\n",
        },
    )
    assert _run(ctx) == []


def test_undecorated_is_silent(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {"m.py": "def v(p):\n    return p\n"})
    assert _run(ctx) == []
