# src/wardline/scanner/rules/untrusted_to_command.py
"""PY-WL-108 — untrusted data reaches a command/program-execution sink.

**Charter (expanded 2026-06-10, wardline-13cfdd7b31 / wardline-c83b40c73a):** the
rule covers two CWE-78 sink shapes, both stdlib:

* **always-shell string APIs** — ``os.system``, ``os.popen``,
  ``subprocess.getoutput`` / ``getstatusoutput``: these take a shell *string*,
  so an untrusted argument is directly injectable;
* **argv-style program execution** — ``os.exec*`` / ``os.spawn*`` /
  ``os.posix_spawn`` / ``os.posix_spawnp`` / ``pty.spawn``: no shell mediates,
  but an attacker-controlled program path or argv element IS arbitrary-program
  execution — neither always-shell nor ``shell=True``, so previously covered by
  neither 108 nor 112.

Tier-modulated; fires only where trust is declared.

**Scope (FP-safe):** the ``subprocess.run`` / ``call`` / ``Popen`` / ``check_*``
family is intentionally NOT in the sink set — with the default ``shell=False`` an
argv-LIST is safe (no shell), so firing on them floods false positives; only
``shell=True`` makes them injectable, and detecting that keyword reliably is
policed separately by PY-WL-112.

**shlex.quote semantics (decided, wardline-13cfdd7b31):** ``shlex.quote(x)``
neutralizes shell-string taint for the ALWAYS-SHELL sinks **in concatenation
context only**. The command argument is GUARDED when it is a string
concatenation (``+`` chain or f-string) with at least one constant fragment in
which every non-constant leaf is a ``shlex.quote(...)`` call — the attacker
bytes then enter the shell line solely as a single quoted token of a
constant-shaped command (``os.system("echo " + shlex.quote(raw))`` is clean).
A BARE whole-command quote (``os.system(shlex.quote(raw))``) still fires: a
fully-quoted single token handed to a shell executes that token as the program
name, so the attacker still picks what runs. The guard NEVER applies to the
argv program-execution sinks — no shell parses the value, so quoting protects
nothing there. ``%``-formatting and ``str.format`` are not recognized as
concatenation (bounded: they keep firing).

The guard is INLINE-syntactic only: a quote result routed through a variable
(``safe = shlex.quote(raw); os.system("echo " + safe)``) still fires. That is
deliberate — resolving the name through the (non-branch-aware,
last-binding-wins) binding collector would let a LATER ``x = shlex.quote(x)``
launder an EARLIER raw use of ``x``; for a sink MATCH that over-approximation
is silent, but for a NEUTRALIZER it would be a false-negative hole. Clearing
the variable-mediated form soundly needs a flow-sensitive context-encoder
taint (engine-level), not a rule-side syntax check.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import (
    TaintedSinkRule,
    canonical_call_name,
    dotted_name,
)
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from collections.abc import Mapping

# The always-shell string APIs — the only sinks the shlex.quote guard applies to.
_SHELL_STRING_SINKS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)

# Argv-style program execution: the value is a program path / argv, not a shell
# string. shlex.quote does NOT protect these (no shell parses the value).
_PROGRAM_EXEC_SINKS = frozenset(
    {
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
    }
)

_SINKS = _SHELL_STRING_SINKS | _PROGRAM_EXEC_SINKS


def _is_shlex_quote_call(expr: ast.expr, alias_map: Mapping[str, str]) -> bool:
    """True iff *expr* is a call whose func canonicalizes to ``shlex.quote``
    (covers ``shlex.quote(x)``, ``from shlex import quote``, module aliases)."""
    if not isinstance(expr, ast.Call):
        return False
    dotted = dotted_name(expr.func)
    return dotted is not None and canonical_call_name(dotted, dict(alias_map)) == "shlex.quote"


def _quote_guarded_concat(expr: ast.expr, alias_map: Mapping[str, str]) -> bool:
    """True iff *expr* is a string CONCATENATION (``+`` chain / f-string) with at
    least one constant fragment whose every non-constant leaf is
    ``shlex.quote(...)`` — the GUARDED shape for a shell-string command.

    The constant-fragment requirement is what excludes the bare whole-command
    quote: ``shlex.quote(raw)`` alone is not a concatenation, and ``f"{...}"``
    of nothing but quote calls has no constant command around the token.
    """
    leaves: list[ast.expr] = []

    def flatten(e: ast.expr) -> None:
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
            flatten(e.left)
            flatten(e.right)
        elif isinstance(e, ast.JoinedStr):
            for part in e.values:
                if isinstance(part, ast.FormattedValue):
                    leaves.append(part.value)
                else:
                    leaves.append(part)  # the f-string's constant fragments
        else:
            leaves.append(e)

    flatten(expr)
    has_const = any(isinstance(leaf, ast.Constant) for leaf in leaves)
    has_quote = any(_is_shlex_quote_call(leaf, alias_map) for leaf in leaves)
    if not (has_const and has_quote):
        return False
    return all(isinstance(leaf, ast.Constant) or _is_shlex_quote_call(leaf, alias_map) for leaf in leaves)


METADATA = RuleMetadata(
    rule_id="PY-WL-108",
    # Calibrated with PY-WL-118 (SQLi): tainted command/program execution is the
    # same exploit class (CWE-78 ≅ CWE-89 in blast radius), so the same base.
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches a command/program-execution sink "
        "(os.system/os.popen/subprocess.getoutput, os.exec*/os.spawn*/os.posix_spawn/pty.spawn)."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    os.system(read_raw(p))",
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    os.execv(read_raw(p), ['prog'])",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f():\n    os.system('ls -la')",
        # shlex.quote as a FRAGMENT of a constant command is the blessed remediation.
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    os.system('echo ' + shlex.quote(read_raw(p)))",
    ),
)


class UntrustedToCommand(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "OS-command"

    def _arg_guarded(self, expr: ast.expr, fqn: str, alias_map: Mapping[str, str]) -> bool:  # noqa: PLR6301
        # shlex.quote guards shell-STRING sinks only (see module docstring); a
        # quoted value reaching an argv exec/spawn sink is still attacker-chosen.
        return fqn in _SHELL_STRING_SINKS and _quote_guarded_concat(expr, alias_map)
