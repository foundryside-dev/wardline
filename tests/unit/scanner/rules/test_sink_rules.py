from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_command import UntrustedToCommand
from wardline.scanner.rules.untrusted_to_deserialization import UntrustedToDeserialization
from wardline.scanner.rules.untrusted_to_exec import UntrustedToExec
from wardline.scanner.rules.untrusted_to_shell_subprocess import UntrustedToShellSubprocess

_HEADER = (
    "import os, pickle\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def test_106_raw_reaches_pickle_loads(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            b = read_raw(p)
            obj = pickle.loads(b)
            return 1
        """,
    )
    findings = UntrustedToDeserialization().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-106", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN


def test_106_nested_call_arg_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            return pickle.loads(read_raw(p))
        """,
    )
    assert [x.rule_id for x in UntrustedToDeserialization().check(ctx)] == ["PY-WL-106"]


def test_106_undecorated_is_suppressed(tmp_path) -> None:
    # Freedom zone -> modulate -> NONE -> no finding (opt-in preserved).
    ctx = _analyze(
        tmp_path,
        """
        def f(p):
            return pickle.loads(read_raw(p))
        """,
    )
    assert UntrustedToDeserialization().check(ctx) == []


def test_106_safe_loader_not_a_sink(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import json
        @trusted(level='ASSURED')
        def f(p):
            obj = json.loads(read_raw(p))
            return 1
        """,
    )
    assert UntrustedToDeserialization().check(ctx) == []


def test_107_raw_reaches_eval(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            src = read_raw(p)
            r = eval(src)
            return 1
        """,
    )
    assert [(x.rule_id, x.qualname) for x in UntrustedToExec().check(ctx)] == [("PY-WL-107", "m.f")]


def test_108_raw_reaches_os_system(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            cmd = read_raw(p)
            os.system(cmd)
            return 1
        """,
    )
    assert [(x.rule_id, x.qualname) for x in UntrustedToCommand().check(ctx)] == [("PY-WL-108", "m.f")]


def test_108_trusted_literal_arg_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            os.system('ls -la')
            return 1
        """,
    )
    assert UntrustedToCommand().check(ctx) == []


def test_107_self_method_call_arg_fires(tmp_path) -> None:
    # Sibling method call (self.get_raw) should resolve to EXTERNAL_RAW and trigger PY-WL-107.
    ctx = _analyze(
        tmp_path,
        """
        class Service:
            def get_raw(self, p):
                return read_raw(p)
            
            @trusted(level='ASSURED')
            def run(self, p):
                eval(self.get_raw(p))
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-107", "m.Service.run")]


def test_112_raw_reaches_subprocess_shell_true(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import subprocess
        @trusted(level='ASSURED')
        def f(p):
            subprocess.run(read_raw(p), shell=True)
            return 1
        """,
    )
    findings = UntrustedToShellSubprocess().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-112", "m.f")]


def test_112_literal_command_shell_true_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import subprocess
        @trusted(level='ASSURED')
        def f():
            subprocess.run('ls -la', shell=True)
            return 1
        """,
    )
    assert UntrustedToShellSubprocess().check(ctx) == []


def test_112_raw_reaches_subprocess_shell_false_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import subprocess
        @trusted(level='ASSURED')
        def f(p):
            subprocess.run(['ls', read_raw(p)])
            subprocess.run(read_raw(p), shell=False)
            return 1
        """,
    )
    assert UntrustedToShellSubprocess().check(ctx) == []


def test_112_non_constant_shell_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import subprocess
        @trusted(level='ASSURED')
        def f(p):
            flag = True
            subprocess.run(read_raw(p), shell=flag)
            return 1
        """,
    )
    assert UntrustedToShellSubprocess().check(ctx) == []


def test_112_undecorated_is_suppressed(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import subprocess
        def f(p):
            subprocess.run(read_raw(p), shell=True)
            return 1
        """,
    )
    assert UntrustedToShellSubprocess().check(ctx) == []
