from __future__ import annotations

import ast
import textwrap
import warnings
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules._sink_helpers import _own_calls, sink_calls
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


def test_sink_calls_do_not_enter_lambda_body() -> None:
    func = ast.parse("def f():\n    cb = lambda: wrapper(eval('1 + 1'))\n    return cb\n").body[0]
    assert list(_own_calls(func)) == []
    assert list(sink_calls(func, frozenset({"eval"}), {}, "m")) == []


def test_own_calls_preserve_lambda_default_calls() -> None:
    func = ast.parse("def f(raw):\n    cb = lambda value=eval(raw): wrapper(raw)\n    return cb\n").body[0]
    calls = list(sink_calls(func, frozenset({"eval", "wrapper"}), {}, "m"))
    assert [(call.lineno, sink) for call, sink in calls] == [(2, "eval")]


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


def test_107_raw_reaches_eval_in_lambda_default(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            src = read_raw(p)
            cb = lambda value=eval(src): value
            return cb()
        """,
    )
    assert [(x.rule_id, x.qualname) for x in UntrustedToExec().check(ctx)] == [("PY-WL-107", "m.f")]


def test_107_safe_eval_in_lambda_default_does_not_fallback_or_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            cb = lambda value=eval('1 + 1'): value
            return cb()
        """,
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        findings = UntrustedToExec().check(ctx)
    assert findings == []
    assert not any(str(w.message).startswith("WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK") for w in caught)


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


def test_106_resolves_aliased_deserialization_sinks(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import pickle as pkl
        from pickle import loads as pickle_loads

        @trusted(level='ASSURED')
        def via_module_alias(p):
            pkl.loads(read_raw(p))

        @trusted(level='ASSURED')
        def via_from_import_alias(p):
            pickle_loads(read_raw(p))
        """,
    )
    findings = UntrustedToDeserialization().check(ctx)
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [
        ("PY-WL-106", "m.via_module_alias", "pickle.loads"),
        ("PY-WL-106", "m.via_from_import_alias", "pickle.loads"),
    ]


def test_107_resolves_aliased_dynamic_exec_sinks(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import builtins as b
        from builtins import eval as builtin_eval

        @trusted(level='ASSURED')
        def via_module_alias(p):
            b.eval(read_raw(p))

        @trusted(level='ASSURED')
        def via_from_import_alias(p):
            builtin_eval(read_raw(p))
        """,
    )
    findings = UntrustedToExec().check(ctx)
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [
        ("PY-WL-107", "m.via_module_alias", "builtins.eval"),
        ("PY-WL-107", "m.via_from_import_alias", "builtins.eval"),
    ]


def test_108_resolves_aliased_command_sinks(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import subprocess as sp
        from os import system as os_system

        @trusted(level='ASSURED')
        def via_module_alias(p):
            sp.getoutput(read_raw(p))

        @trusted(level='ASSURED')
        def via_from_import_alias(p):
            os_system(read_raw(p))
        """,
    )
    findings = UntrustedToCommand().check(ctx)
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [
        ("PY-WL-108", "m.via_module_alias", "subprocess.getoutput"),
        ("PY-WL-108", "m.via_from_import_alias", "os.system"),
    ]


def test_112_resolves_aliased_shell_subprocess_sinks(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        import subprocess as sp
        from subprocess import run as subprocess_run

        @trusted(level='ASSURED')
        def via_module_alias(p):
            sp.run(read_raw(p), shell=True)

        @trusted(level='ASSURED')
        def via_from_import_alias(p):
            subprocess_run(read_raw(p), shell=True)
        """,
    )
    findings = UntrustedToShellSubprocess().check(ctx)
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [
        ("PY-WL-112", "m.via_module_alias", "subprocess.run"),
        ("PY-WL-112", "m.via_from_import_alias", "subprocess.run"),
    ]


def test_fallback_flow_insensitive_warnings() -> None:
    # If flow-sensitive map is missing, we warn and pessimistically assume UNKNOWN_RAW.
    import ast
    import warnings

    from wardline.core.taints import TaintState
    from wardline.scanner.context import AnalysisContext
    from wardline.scanner.rules._sink_helpers import worst_arg_taint

    call = ast.parse("eval(x)").body[0].value
    assert isinstance(call, ast.Call)
    context = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={},
        function_return_taints={},
        function_return_callee={},
        entities={},
        taint_provenance={},
    )  # Empty context has no flow-sensitive mappings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        res = worst_arg_taint(call, "m.f", context, {})
        assert len(w) == 1
        assert "WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK" in str(w[0].message)
        assert res == TaintState.UNKNOWN_RAW
