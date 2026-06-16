from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.broad_exception import BroadException


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
    return BroadException().check(ctx)


def test_broad_except_in_trusted_fires_at_base(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except Exception:\n        h()\n",
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-103", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN  # base for PY-WL-103, trusted tier -> unchanged


def test_broad_except_in_undecorated_is_suppressed(tmp_path) -> None:
    # Undecorated -> UNKNOWN_RAW (freedom zone) -> modulate to NONE -> no finding.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "def f():\n    try:\n        g()\n    except Exception:\n        h()\n",
        },
    )
    assert _run(ctx) == []


def test_bare_except_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except:\n        h()\n",
        },
    )
    assert [f.rule_id for f in _run(ctx)] == ["PY-WL-103"]


def test_except_star_broad_exception_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except* Exception:\n        h()\n",
        },
    )
    assert [f.rule_id for f in _run(ctx)] == ["PY-WL-103"]


def test_specific_except_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        h()\n",
        },
    )
    assert _run(ctx) == []


def test_tuple_containing_broad_name_fires(tmp_path) -> None:
    # `except (Exception, OSError)` is just as broad as `except Exception`.
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n"
            "    except (Exception, OSError):\n        h()\n",
        },
    )
    assert [f.rule_id for f in _run(ctx)] == ["PY-WL-103"]


def test_specific_tuple_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n    try:\n        g()\n"
            "    except (KeyError, IndexError):\n        h()\n",
        },
    )
    assert _run(ctx) == []


def test_multiple_handlers_one_function_are_distinguished_only_by_line_start(tmp_path) -> None:
    # Cardinality + latent-collision precondition (wardline-6102d4c833). PY-WL-103 is
    # MULTI-EMIT per (rule, path, qualname): one finding per broad handler, with
    # taint_path=None, so two handlers in ONE function are kept distinct SOLELY by
    # line_start (each handler is on its own line). This is correct under the CURRENT
    # contract (line_start is in the join key). It is a documented PRECONDITION for the
    # move-stability redesign: when line_start is removed from the key these two distinct
    # findings collide unless the rule is first given a source-derived within-scope
    # discriminator (the fix is sequenced into that redesign to avoid a double rekey).
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import trusted\n"
            "@trusted\ndef f():\n"
            "    try:\n        a()\n    except:\n        pass\n"
            "    try:\n        b()\n    except:\n        pass\n",
        },
    )
    findings = _run(ctx)
    assert [f.qualname for f in findings] == ["m.f", "m.f"], "multi-emit: one finding per handler"
    fps = {f.fingerprint for f in findings}
    assert len(fps) == 2, "distinct today (via line_start); collides iff line_start leaves the key"


def test_nested_trusted_def_uses_its_own_tier(tmp_path) -> None:
    # A nested def carrying its OWN trust declaration is governed by that tier, not
    # the undecorated outer's UNKNOWN_RAW (which would wrongly suppress the rule).
    # Aligns PY-WL-103 with the sink family's enclosing_declared_tier semantics
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
                    except Exception:
                        pass
                return inner
            """,
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-103", "m.outer.<locals>.inner")]
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
                    except Exception:
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
                    except Exception:
                        pass
                return inner
            """,
        },
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-103", "m.outer.<locals>.inner")]
    assert findings[0].properties["tier"] == "ASSURED"
