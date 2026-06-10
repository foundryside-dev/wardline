# tests/unit/scanner/taint/test_review_fixups_engine.py
"""Regression tests for the 2026-06-10 review-panel engine fixups.

Covers four confirmed soundness defects in the L2 walk
(``wardline.scanner.taint.variable_level``):

1. **Compare/Raise/Assert/Delete expression positions** — a call nested in an
   ``ast.Compare`` operand (or a Raise/Assert/Delete statement) was never
   resolved by ``_resolve_expr``/``_process_stmt``, so its per-call arg-taint
   snapshot was missing: PY-WL-105's provably-untrusted gate stayed silent (FN)
   and a CONSTANT-arg sink call degraded to the pessimistic UNKNOWN_RAW
   fallback (a gate-tripping PY-WL-108 FP after the WARN→ERROR recalibration).

2. **Stale receiver-type candidates across non-Assign rebinds** — for/with/
   walrus/tuple-unpack/except-handler rebinds updated ``var_taints`` but not
   ``_CURRENT_VAR_TYPES``, so a stale class candidate resolved a clean
   ``@trusted`` method summary onto a rebound raw receiver (PY-WL-101 FN).

3. **Provenance-only re-resolution polluting the flow-sensitive snapshot** —
   ``compute_return_callee``'s ``_assignment_callee`` re-resolved direct-call
   assignment RHS against the FINAL var_taints with the arg-taint recorder
   still active, combining post-call taint into the at-call snapshot
   (PY-WL-105/108 FPs on values that were clean AT the call).

4. **Nested local helper calls** — the bare-name worst-arg conservatism
   (wardline-93d608c997) hit nested defs the engine had already analyzed
   (``m.f.<locals>.helper``), marking validated values raw (PY-WL-101 FP).
"""

from __future__ import annotations

import textwrap
import warnings
from typing import TYPE_CHECKING

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import WardlineAnalyzer

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from wardline.core.finding import Finding

_PREAMBLE = (
    "import os\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
    "@trusted(level='ASSURED')\n"
    "def store(x):\n"
    "    return 1\n"
)


def _scan(tmp_path: Path, body: str, name: str = "m.py", preamble: str = _PREAMBLE) -> Sequence[Finding]:
    p = tmp_path / name
    p.write_text(preamble + textwrap.dedent(body), encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # the engine must not warn from rule checks
        return WardlineAnalyzer().analyze([p], WardlineConfig(), root=tmp_path)


def _rule_hits(findings: Sequence[Finding], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.rule_id == rule_id]


# ── 1. Compare / Raise / Assert / Delete positions ───────────────────────────


def test_105_fires_on_call_inside_compare(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        def h(p):
            if store(read_raw(p)) == 1:
                return 1
            return 0
        """,
    )
    hits = _rule_hits(findings, "PY-WL-105")
    assert len(hits) == 1
    assert hits[0].qualname == "m.h"


def test_105_fires_on_call_inside_raise(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        def h(p):
            raise ValueError(store(read_raw(p)))
        """,
    )
    assert len(_rule_hits(findings, "PY-WL-105")) == 1


def test_105_fires_on_call_inside_assert(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        def h(p):
            assert store(read_raw(p))
        """,
    )
    assert len(_rule_hits(findings, "PY-WL-105")) == 1


def test_105_fires_on_call_inside_assert_msg_and_raise_cause(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        def h_msg(p):
            assert p, store(read_raw(p))

        def h_cause(p):
            raise ValueError("x") from store(read_raw(p))
        """,
    )
    assert {f.qualname for f in _rule_hits(findings, "PY-WL-105")} == {"m.h_msg", "m.h_cause"}


def test_108_constant_command_inside_compare_is_clean(tmp_path: Path) -> None:
    """FP-corpus sentinel: ``if os.system(CONST) == 0:`` is THE idiomatic
    command-success check — the missing-Compare pessimistic fallback must not
    turn the constant into a gate-tripping ERROR."""
    findings = _scan(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def const_cmd():
            if os.system("ls") == 0:
                return 1
            return 0
        """,
    )
    assert _rule_hits(findings, "PY-WL-108") == []


def test_del_subscript_resolves_walrus_and_call(tmp_path: Path) -> None:
    """A Delete statement's target expressions are resolved (slice calls record)."""
    findings = _scan(
        tmp_path,
        """
        def h(p, d):
            del d[store(read_raw(p))]
        """,
    )
    assert len(_rule_hits(findings, "PY-WL-105")) == 1


# ── 2. Receiver-type invalidation on non-Assign rebinds ──────────────────────

_VAULT_PREAMBLE = (
    "import junklib\n"
    "from wardline.decorators import trusted\n"
    "class Vault:\n"
    "    @trusted(level='ASSURED')\n"
    "    def get(self):\n"
    "        return 'safe'\n"
)


def _vault_101(tmp_path: Path, body: str) -> list[Finding]:
    findings = _scan(tmp_path, body, name="vault.py", preamble=_VAULT_PREAMBLE)
    return _rule_hits(findings, "PY-WL-101")


def test_101_fires_after_for_target_rebind(tmp_path: Path) -> None:
    hits = _vault_101(
        tmp_path,
        """
        @trusted(level='ASSURED', to_level='ASSURED')
        def f():
            v = Vault()
            for v in junklib.items():
                pass
            x = v.get()
            return x
        """,
    )
    assert len(hits) == 1


def test_101_fires_after_with_target_rebind(tmp_path: Path) -> None:
    hits = _vault_101(
        tmp_path,
        """
        @trusted(level='ASSURED', to_level='ASSURED')
        def f():
            v = Vault()
            with junklib.ctx() as v:
                pass
            x = v.get()
            return x
        """,
    )
    assert len(hits) == 1


def test_101_fires_after_walrus_rebind(tmp_path: Path) -> None:
    hits = _vault_101(
        tmp_path,
        """
        @trusted(level='ASSURED', to_level='ASSURED')
        def f():
            v = Vault()
            if (v := junklib.one()):
                pass
            x = v.get()
            return x
        """,
    )
    assert len(hits) == 1


def test_101_fires_after_tuple_unpack_rebind(tmp_path: Path) -> None:
    hits = _vault_101(
        tmp_path,
        """
        @trusted(level='ASSURED', to_level='ASSURED')
        def f():
            v = Vault()
            v, w = junklib.pair()
            x = v.get()
            return x
        """,
    )
    assert len(hits) == 1


def test_except_handler_rebind_invalidates_receiver_type() -> None:
    """``except E as v`` rebinds ``v`` to the exception instance — the stale
    [Vault] candidate must not resolve ``Vault.fetch -> ASSURED`` on the handler
    path (the launder is observable at the L2 unit level: with the stale type,
    ``x`` came back ASSURED; with the invalidation it stays UNKNOWN_RAW).

    Note the END-TO-END except shape (rebind in the handler, method call after
    the try) stays silent for a DIFFERENT, pre-existing reason: the handler
    binds the exception name to the enclosing function's trusted seed (a value-
    channel conservatism, not the receiver-type launder this fix closes).
    """
    import ast

    from wardline.core.taints import TaintState
    from wardline.scanner.taint.variable_level import (
        VariableTaintContext,
        analyze_function_variables,
    )

    src = textwrap.dedent(
        """
        def f():
            v = Vault()
            try:
                go()
            except Exception as v:
                x = v.fetch()
            return x
        """
    )
    fn = ast.parse(src).body[0]
    assert isinstance(fn, ast.FunctionDef)
    result = analyze_function_variables(
        fn,
        TaintState.UNKNOWN_RAW,
        {"vault.Vault.fetch": TaintState.ASSURED},
        VariableTaintContext(alias_map={}, module_prefix="vault"),
    )
    assert result.variable_taints["x"] is TaintState.UNKNOWN_RAW


def test_walrus_constructor_rebind_keeps_type_precision(tmp_path: Path) -> None:
    """A walrus that REBINDS to a constructor is a typed strong update, not an
    invalidation: ``(v := Vault())`` then ``v.get()`` must stay clean."""
    hits = _vault_101(
        tmp_path,
        """
        @trusted(level='ASSURED', to_level='ASSURED')
        def f():
            if (v := Vault()):
                pass
            x = v.get()
            return x
        """,
    )
    assert hits == []


# ── 3. Provenance re-resolution must not pollute the at-call snapshot ────────


def test_no_105_when_arg_becomes_raw_only_after_the_call(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        def f(p):
            x = "const"
            v = store(x)
            x = read_raw(p)
            return v
        """,
    )
    assert _rule_hits(findings, "PY-WL-105") == []


def test_no_108_when_command_becomes_raw_only_after_the_call(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            cmd = "ls"
            v = os.system(cmd)
            cmd = read_raw(p)
            return v
        """,
    )
    assert _rule_hits(findings, "PY-WL-108") == []


# ── 4. Nested local helper calls resolve via the engine's own summary ────────


def test_nested_local_helper_validating_raw_is_not_a_101_fp(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        @trusted(level='ASSURED', to_level='ASSURED')
        def f(p):
            def clean(x):
                return 1
            raw = read_raw(p)
            v = clean(raw)
            return v
        """,
    )
    assert _rule_hits(findings, "PY-WL-101") == []


def test_nested_local_helper_returning_raw_still_fires_101(tmp_path: Path) -> None:
    """The nested-def lookup must use the helper's REAL summary — a helper that
    passes raw through keeps firing (no launder through the bare-name hop)."""
    findings = _scan(
        tmp_path,
        """
        @trusted(level='ASSURED', to_level='ASSURED')
        def f(p):
            def passthrough(x):
                return x
            raw = read_raw(p)
            v = passthrough(raw)
            return v
        """,
    )
    assert len(_rule_hits(findings, "PY-WL-101")) == 1


def test_bare_param_callee_still_pessimistic(tmp_path: Path) -> None:
    """wardline-93d608c997 stays closed: an UNKNOWN bare-name callee (a param)
    cannot be assumed to clean a raw argument."""
    findings = _scan(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def launder_check(transform, p):
            raw = read_raw(p)
            os.system(transform(raw))
        """,
    )
    assert len(_rule_hits(findings, "PY-WL-108")) == 1
