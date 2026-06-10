from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.silent_exception import SilentException


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
    return SilentException().check(ctx)


def test_silent_handler_in_trusted_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        pass\n",
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-104", "m.f")]
    assert findings[0].severity == Severity.WARN  # base, trusted tier unchanged


def test_except_star_silent_handler_in_trusted_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except* ValueError:\n        pass\n",
        },
    )
    assert [(f.rule_id, f.qualname) for f in _run(ctx)] == [("PY-WL-104", "m.f")]


def test_silent_handler_in_undecorated_is_suppressed(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "def f():\n    try:\n        g()\n    except ValueError:\n        pass\n",
        },
    )
    assert _run(ctx) == []


def test_handled_exception_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        log()\n",
        },
    )
    assert _run(ctx) == []


def test_reraise_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        raise\n",
        },
    )
    assert _run(ctx) == []


def test_nested_trusted_def_uses_its_own_tier(tmp_path) -> None:
    # A nested def carrying its OWN trust declaration is governed by that tier, not
    # the undecorated outer's UNKNOWN_RAW (which would wrongly suppress the rule).
    # Aligns PY-WL-104 with the sink family's enclosing_declared_tier semantics
    # (wardline-bb8396f96e).
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": """\
            from wardline.decorators import trusted

            def outer(p):
                @trusted(level="ASSURED")
                def inner():
                    try:
                        g()
                    except ValueError:
                        pass
                return inner
            """,
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-104", "m.outer.<locals>.inner")]
    assert findings[0].severity == Severity.WARN
    assert findings[0].properties["tier"] == "ASSURED"


def test_nested_external_boundary_def_inside_trusted_is_suppressed(tmp_path) -> None:
    # A nested @external_boundary def is explicitly in the raw zone; the @trusted
    # OUTER's tier must not leak onto it (the FP direction of the .<locals>. strip).
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": """\
            from wardline.decorators import external_boundary, trusted

            @trusted(level="ASSURED")
            def outer(p):
                @external_boundary
                def inner():
                    try:
                        g()
                    except ValueError:
                        pass
                return inner
            """,
        },
    )
    assert _run(ctx) == []


def test_undeclared_nested_def_inherits_enclosing_declared_tier(tmp_path) -> None:
    # A genuinely undeclared nested def inherits the nearest DECLARED enclosing
    # scope's tier (wardline-9b88ec5419) — pins the inheritance half of the walk.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": """\
            from wardline.decorators import trusted

            @trusted(level="ASSURED")
            def outer(p):
                def inner():
                    try:
                        g()
                    except ValueError:
                        pass
                return inner
            """,
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-104", "m.outer.<locals>.inner")]
    assert findings[0].properties["tier"] == "ASSURED"
