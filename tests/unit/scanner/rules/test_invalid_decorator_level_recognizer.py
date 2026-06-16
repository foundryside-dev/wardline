# tests/unit/scanner/rules/test_invalid_decorator_level_recognizer.py
"""PY-WL-114 marker recognition must match the engine's seeding predicate.

The rule may only recognise a builtin level-bearing marker the engine's seeding
would honour (``_is_builtin_decorator_fqn`` exact exports + shadowed-root
fail-closed rejection). Recognising a marker the seeding rejects produces a
false "a typo disables all taint gates" finding for a gate that never existed
(the same drift PY-WL-110 closed under wardline-09c09f14df).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.invalid_decorator_level import InvalidDecoratorLevel


def _findings_114(tmp_path: Path, files: dict[str, str]) -> list[Finding]:
    paths = []
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        paths.append(p)
    analyzer = WardlineAnalyzer()
    analyzer.analyze(sorted(paths), WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return InvalidDecoratorLevel().check(analyzer.last_context)


def test_nested_path_under_builtin_prefix_does_not_fire(tmp_path) -> None:
    # The engine seeds ONLY the exact exports P.<name> / P.trust.<name>;
    # an arbitrarily-nested path like wardline.decorators.evil.trusted is
    # rejected by seeding, so no gate exists for a bad level to disable.
    findings = _findings_114(
        tmp_path,
        {
            "m.py": """\
            import wardline.decorators.evil

            @wardline.decorators.evil.trusted(level="BOGUS")
            def f(p):
                return p
            """,
        },
    )
    assert findings == []


def test_shadowed_marker_root_does_not_fire(tmp_path) -> None:
    # A project shipping its OWN top-level weft_markers module shadows the
    # builtin marker root: seeding fails closed for every marker under it, so
    # the decorator is a project-local foreign decorator, not the builtin.
    findings = _findings_114(
        tmp_path,
        {
            "weft_markers.py": """\
            def trusted(level=None):
                def deco(fn):
                    return fn
                return deco
            """,
            "m.py": """\
            from weft_markers import trusted

            @trusted(level="BOGUS")
            def f(p):
                return p
            """,
        },
    )
    assert findings == []


def test_shadowed_wardline_root_does_not_fire(tmp_path) -> None:
    # Same fail-closed rejection for a project-local top-level ``wardline`` module.
    findings = _findings_114(
        tmp_path,
        {
            "wardline.py": "X = 1\n",
            "m.py": """\
            from wardline.decorators import trusted

            @trusted(level="BOGUS")
            def f(p):
                return p
            """,
        },
    )
    assert findings == []


def test_exact_export_still_fires(tmp_path) -> None:
    # Control: the real builtin export keeps firing after the recognizer tightening.
    findings = _findings_114(
        tmp_path,
        {
            "m.py": """\
            from wardline.decorators import trusted

            @trusted(level="BOGUS")
            def f(p):
                return p
            """,
        },
    )
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.f")]


def test_trust_submodule_export_still_fires(tmp_path) -> None:
    # The implementation-module export P.trust.<name> is also a seeded spelling.
    findings = _findings_114(
        tmp_path,
        {
            "m.py": """\
            from wardline.decorators.trust import trust_boundary

            @trust_boundary(to_level="INTEGRAL")
            def g(p):
                if not p:
                    raise ValueError
                return p
            """,
        },
    )
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.g")]


def test_unshadowed_weft_markers_still_fires(tmp_path) -> None:
    # Control: the weft_markers shim is a builtin root; with no project-local
    # shadow it is seeded, so an invalid level on it is a real PY-WL-114.
    findings = _findings_114(
        tmp_path,
        {
            "m.py": """\
            from weft_markers import trusted

            @trusted(level="BOGUS")
            def f(p):
                return p
            """,
        },
    )
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-114", "m.f")]
