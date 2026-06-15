"""PY-WL-108/112 command-family expansion + calibration (wardline-13cfdd7b31).

Covers the four decided behavior changes plus the eval-flagged test gaps:

* 108's charter is now **command/program-execution** — the always-shell string
  APIs PLUS the argv-style program-execution family (``os.exec*`` / ``os.spawn*``
  / ``os.posix_spawn*`` / ``pty.spawn``), all CWE-78.
* ``shlex.quote`` neutralizes shell-string taint for 108 **in concatenation
  context only**: a quoted fragment inside a larger constant command is GUARDED
  (clean); a bare whole-command quote still fires (a fully-quoted single token
  IS the attacker-chosen program name); the guard never applies to the argv
  program-execution sinks (no shell — quoting protects nothing).
* Variable-binding aliases resolve: ``runner = subprocess.run; runner(raw,
  shell=True)`` fires PY-WL-112 (and the same for 108's sinks).
* Severity calibration: 108/112 are base ERROR — same exploit class as SQLi
  (PY-WL-118).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_command import UntrustedToCommand
from wardline.scanner.rules.untrusted_to_shell_subprocess import UntrustedToShellSubprocess

_HEADER = (
    "import os, pty, shlex, subprocess\n"
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


# ---------------------------------------------------------------------------
# (1) Program-execution charter expansion: os.exec* / os.spawn* / posix_spawn /
#     pty.spawn are PY-WL-108 sinks (attacker-controlled program path/argv).
# ---------------------------------------------------------------------------

_PROGRAM_EXEC_SINKS = [
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.posix_spawn",
    "os.posix_spawnp",
    "pty.spawn",
]


@pytest.mark.parametrize("sink", _PROGRAM_EXEC_SINKS)
def test_108_raw_reaches_program_execution_sink(tmp_path, sink: str) -> None:
    ctx = _analyze(
        tmp_path,
        f"""
        @trusted(level='ASSURED')
        def f(p):
            {sink}(read_raw(p))
        """,
    )
    findings = UntrustedToCommand().check(ctx)
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [("PY-WL-108", "m.f", sink)]
    assert findings[0].kind is Kind.DEFECT
    assert findings[0].severity is Severity.ERROR


def test_108_spawn_with_constant_mode_and_raw_path_fires(tmp_path) -> None:
    # The realistic spawn shape: a clean mode slot (os.P_WAIT) must not mask the
    # raw program path in slot 1.
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            os.spawnl(os.P_WAIT, read_raw(p), 'x')
        """,
    )
    assert [(x.rule_id, x.qualname) for x in UntrustedToCommand().check(ctx)] == [("PY-WL-108", "m.f")]


def test_108_spawn_all_constant_args_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            os.spawnl(os.P_WAIT, '/bin/ls', 'ls')
        """,
    )
    assert UntrustedToCommand().check(ctx) == []


# ---------------------------------------------------------------------------
# (2) shlex.quote semantics: GUARDED as a fragment of a constant concatenation;
#     NOT guarded as the whole command; NEVER guarding the argv exec sinks.
# ---------------------------------------------------------------------------


def test_108_shlex_quoted_fragment_concat_is_clean(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            os.system("echo " + shlex.quote(raw))
        """,
    )
    assert UntrustedToCommand().check(ctx) == []


def test_108_shlex_quoted_fragment_fstring_is_clean(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            os.system(f"echo {shlex.quote(raw)}")
        """,
    )
    assert UntrustedToCommand().check(ctx) == []


def test_108_from_import_quote_alias_is_clean(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from shlex import quote
        @trusted(level='ASSURED')
        def f(p):
            os.system("echo " + quote(read_raw(p)))
        """,
    )
    assert UntrustedToCommand().check(ctx) == []


def test_108_unquoted_concat_of_raw_still_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            os.system("echo " + raw)
        """,
    )
    findings = UntrustedToCommand().check(ctx)
    assert [(x.rule_id, x.qualname, x.severity) for x in findings] == [("PY-WL-108", "m.f", Severity.ERROR)]


def test_108_whole_command_quote_still_fires(tmp_path) -> None:
    # A fully-quoted single token passed to a shell EXECUTES that token as the
    # program name — quoting the whole command is not a remediation.
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            os.system(shlex.quote(raw))
        """,
    )
    assert [(x.rule_id, x.qualname) for x in UntrustedToCommand().check(ctx)] == [("PY-WL-108", "m.f")]


def test_108_quoted_command_with_constant_arg_still_fires(tmp_path) -> None:
    # The command WORD is quoted-and-attacker-chosen, with only a CONSTANT arg
    # suffix: `shlex.quote(raw) + " --version"`. The constant fragment + all-leaves-
    # quoted-or-constant shape used to look "guarded", but shlex.quote sanitizes an
    # argument, not the identity of the executable — the attacker still picks the
    # program. Must fire (regression for the quoted-command-vs-quoted-arg gap).
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            os.system(shlex.quote(raw) + " --version")
        """,
    )
    assert [(x.rule_id, x.qualname) for x in UntrustedToCommand().check(ctx)] == [("PY-WL-108", "m.f")]


def test_108_quoted_command_fstring_with_constant_arg_still_fires(tmp_path) -> None:
    # Same gap in f-string form: the quoted leaf leads, a constant trails.
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            os.system(f"{shlex.quote(raw)} --version")
        """,
    )
    assert [(x.rule_id, x.qualname) for x in UntrustedToCommand().check(ctx)] == [("PY-WL-108", "m.f")]


def test_108_mixed_concat_with_unquoted_raw_leaf_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            os.system("echo " + shlex.quote(raw) + raw)
        """,
    )
    assert [x.rule_id for x in UntrustedToCommand().check(ctx)] == ["PY-WL-108"]


def test_108_variable_mediated_quote_still_fires(tmp_path) -> None:
    # The guard is INLINE-syntactic only (see the rule docstring): resolving a
    # NAME leaf through the last-binding-wins binding collector would let a
    # later ``x = shlex.quote(x)`` launder an earlier raw use — so the
    # variable-mediated form deliberately stays a (conservative) positive.
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            safe = shlex.quote(read_raw(p))
            os.system("echo " + safe)
        """,
    )
    assert [x.rule_id for x in UntrustedToCommand().check(ctx)] == ["PY-WL-108"]


def test_108_quote_guard_does_not_apply_to_program_execution_sinks(tmp_path) -> None:
    # No shell mediates os.execv — shlex.quote protects nothing; the program
    # path is still attacker-controlled.
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            raw = read_raw(p)
            os.execv("/bin/" + shlex.quote(raw), ["x"])
        """,
    )
    assert [(x.rule_id, x.properties["sink"]) for x in UntrustedToCommand().check(ctx)] == [("PY-WL-108", "os.execv")]


# ---------------------------------------------------------------------------
# (3) Variable-binding aliases (function-local) resolve to the sink FQN.
# ---------------------------------------------------------------------------


def test_112_local_binding_alias_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            runner = subprocess.run
            runner(read_raw(p), shell=True)
        """,
    )
    findings = UntrustedToShellSubprocess().check(ctx)
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [("PY-WL-112", "m.f", "subprocess.run")]
    assert findings[0].severity is Severity.ERROR


def test_112_local_binding_alias_without_shell_true_does_not_fire(tmp_path) -> None:
    # The literal shell=True gate applies to binding-resolved calls too.
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            runner = subprocess.run
            runner(read_raw(p))
        """,
    )
    assert UntrustedToShellSubprocess().check(ctx) == []


def test_108_local_binding_alias_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            run_cmd = os.system
            run_cmd(read_raw(p))
        """,
    )
    assert [(x.rule_id, x.properties["sink"]) for x in UntrustedToCommand().check(ctx)] == [("PY-WL-108", "os.system")]


# ---------------------------------------------------------------------------
# (4) Severity calibration: 108/112 base ERROR (same exploit class as PY-WL-118).
# ---------------------------------------------------------------------------


def test_108_and_112_base_severity_is_error() -> None:
    # Tier MODULATION is unchanged machinery (severity_model tests); the
    # calibration decision is the BASE severity, pinned here and exercised at
    # ASSURED tier (base kept) by every positive test in this module.
    assert UntrustedToCommand.metadata.base_severity is Severity.ERROR
    assert UntrustedToShellSubprocess.metadata.base_severity is Severity.ERROR


# ---------------------------------------------------------------------------
# (5) Eval-flagged test gaps: per-sink positives for the pre-existing tables.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sink", ["os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"])
def test_108_raw_reaches_shell_string_sink(tmp_path, sink: str) -> None:
    ctx = _analyze(
        tmp_path,
        f"""
        @trusted(level='ASSURED')
        def f(p):
            {sink}(read_raw(p))
        """,
    )
    findings = UntrustedToCommand().check(ctx)
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [("PY-WL-108", "m.f", sink)]
    assert findings[0].severity is Severity.ERROR


@pytest.mark.parametrize(
    "sink",
    ["subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"],
)
def test_112_raw_reaches_family_member_shell_true(tmp_path, sink: str) -> None:
    ctx = _analyze(
        tmp_path,
        f"""
        @trusted(level='ASSURED')
        def f(p):
            {sink}(read_raw(p), shell=True)
        """,
    )
    findings = UntrustedToShellSubprocess().check(ctx)
    assert [(x.rule_id, x.qualname, x.properties["sink"]) for x in findings] == [("PY-WL-112", "m.f", sink)]
    assert findings[0].severity is Severity.ERROR
