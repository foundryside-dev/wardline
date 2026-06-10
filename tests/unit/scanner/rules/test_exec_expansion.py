# tests/unit/scanner/rules/test_exec_expansion.py
"""PY-WL-107 coverage expansion: exec()/compile() positives + the __builtins__ spelling.

The pre-existing suite only had an eval() positive for PY-WL-107; exec() and
compile() were sinks with no positive regression cover, and the
``__builtins__.eval`` / ``__builtins__.exec`` spelling was unmatched entirely
(ticket wardline-c83b40c73a).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_exec import UntrustedToExec

_HEADER = (
    "from wardline.decorators import external_boundary, trusted\n@external_boundary\ndef read_raw(p):\n    return p\n"
)


def _analyze(tmp_path: Path, src: str) -> tuple[WardlineAnalyzer, object]:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer, analyzer.last_context


def test_107_raw_reaches_exec(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            src = read_raw(p)
            exec(src)
            return 1
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert [(f.rule_id, f.qualname, f.kind, f.severity) for f in findings] == [
        ("PY-WL-107", "m.f", Kind.DEFECT, Severity.WARN)
    ]
    assert findings[0].properties["sink"] == "exec"


def test_107_raw_reaches_compile(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            compile(read_raw(p), '<dyn>', 'exec')
            return 1
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert [(f.rule_id, f.qualname, f.kind, f.severity) for f in findings] == [
        ("PY-WL-107", "m.f", Kind.DEFECT, Severity.WARN)
    ]
    assert findings[0].properties["sink"] == "compile"


def test_107_raw_reaches_dunder_builtins_eval(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            src = read_raw(p)
            __builtins__.eval(src)
            return 1
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert [(f.rule_id, f.qualname, f.kind, f.severity) for f in findings] == [
        ("PY-WL-107", "m.f", Kind.DEFECT, Severity.WARN)
    ]
    assert findings[0].properties["sink"] == "__builtins__.eval"


def test_107_raw_reaches_dunder_builtins_exec(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            __builtins__.exec(read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-107", "m.f")]
    assert findings[0].properties["sink"] == "__builtins__.exec"


def test_107_raw_reaches_dunder_builtins_compile(tmp_path) -> None:
    # Same spelling class as __builtins__.eval/.exec — covered for parity with
    # the builtins.compile form the sink table already carries.
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            __builtins__.compile(read_raw(p), '<dyn>', 'exec')
            return 1
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-107", "m.f")]
    assert findings[0].properties["sink"] == "__builtins__.compile"


def test_107_exec_clean_constant(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            exec('x = 1')
            return 1
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert findings == []


def test_107_compile_clean_constant(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            compile('x = 1', '<s>', 'exec')
            return 1
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert findings == []


def test_107_dunder_builtins_eval_undecorated_suppressed(tmp_path) -> None:
    # New spelling obeys the same tier gate as every other sink form.
    _, ctx = _analyze(
        tmp_path,
        """
        def f(p):
            __builtins__.eval(read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert findings == []
