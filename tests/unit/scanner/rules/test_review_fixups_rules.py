# tests/unit/scanner/rules/test_review_fixups_rules.py
"""Regression tests for the 2026-06-10 review-panel RULE-side fixups.

Covers the confirmed rule-design / quality defects:

1. **PY-WL-120 suppress-and-delegate must honor rule enablement** — with
   ``rules.enable = ("PY-WL-120",)`` the delegate (PY-WL-101) never runs, so
   the suppression dropped the raw-storage-return defect entirely.

2. **PY-WL-124 slot precision** — the only 121–126 family member built on
   worst-of-all-args fired ERROR on a tainted ``mode=``/``use_errno=`` flag
   with a CONSTANT library name.

3. **PY-WL-125/126 parameter-annotation receivers** — the docstrings claimed
   the ``log: logging.Logger`` / ``s: smtplib.SMTP`` parameter forms bind, but
   only body AnnAssign seeded ``instance_classes``.

4. **Operator severity override equal to the metadata default** — the per-sink
   severity table detected an override by value identity, so an explicit
   ``rules.severity = {PY-WL-121: ERROR}`` (equal to the default) was ignored.

5. **WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK** is an engine FACT finding now, not
   a per-qualname ``UserWarning`` from inside rule ``check()`` calls.

6. **Sink-loop consolidation** — the base :class:`TaintedSinkRule` is
   binding-aware, so the historical base rules (106/107/115/124) resolve
   callable aliases / construct-then-method forms (new findings only).
"""

from __future__ import annotations

import textwrap
import warnings
from typing import TYPE_CHECKING

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
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
)


def _scan(
    tmp_path: Path,
    body: str,
    config: WardlineConfig | None = None,
    preamble: str = _PREAMBLE,
) -> Sequence[Finding]:
    p = tmp_path / "m.py"
    p.write_text(preamble + textwrap.dedent(body), encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # the engine must not warn from rule checks
        return WardlineAnalyzer().analyze([p], config or WardlineConfig(), root=tmp_path)


def _rule_hits(findings: Sequence[Finding], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.rule_id == rule_id]


_STORAGE_RETURN = """
@trusted(level='ASSURED')
def f(fd):
    data = os.read(fd, 10)
    return data
"""


# ── 1. PY-WL-120 suppression gated on PY-WL-101 enablement ───────────────────


def test_120_fires_when_101_is_not_enabled(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _STORAGE_RETURN, WardlineConfig(rules_enable=("PY-WL-120",)))
    assert _rule_hits(findings, "PY-WL-101") == []  # the delegate never ran
    hits = _rule_hits(findings, "PY-WL-120")
    assert len(hits) == 1  # ...so 120 must NOT suppress its return finding
    assert hits[0].qualname == "m.f"


def test_120_still_delegates_to_101_under_the_default_config(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _STORAGE_RETURN)
    assert len(_rule_hits(findings, "PY-WL-101")) == 1
    assert _rule_hits(findings, "PY-WL-120") == []  # delegate fired — suppression stands


# ── 2. PY-WL-124 ArgSpec slot precision ──────────────────────────────────────


def test_124_tainted_mode_flag_with_constant_name_is_clean(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        import ctypes
        @trusted(level='ASSURED')
        def f(p):
            a = ctypes.CDLL('libm.so.6', mode=read_raw(p))
            b = ctypes.CDLL('libm.so.6', use_errno=read_raw(p))
            return 1
        """,
    )
    assert _rule_hits(findings, "PY-WL-124") == []


def test_124_tainted_library_name_still_fires(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        import ctypes
        @trusted(level='ASSURED')
        def f(p):
            a = ctypes.CDLL(read_raw(p))
            b = ctypes.CDLL(name=read_raw(p))
            c = ctypes.cdll.LoadLibrary(read_raw(p))
            return 1
        """,
    )
    assert len(_rule_hits(findings, "PY-WL-124")) == 3


# ── 3. PY-WL-125/126 parameter-annotation receivers ──────────────────────────


def test_125_param_annotated_logger_fires(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        import logging
        @trusted(level='ASSURED')
        def f(p, log: logging.Logger):
            log.info(read_raw(p))
            return 1
        """,
    )
    hits = _rule_hits(findings, "PY-WL-125")
    assert len(hits) == 1
    assert hits[0].properties["sink"] == "logging.Logger.info"


def test_126_param_annotated_smtp_client_fires(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        import smtplib
        @trusted(level='ASSURED')
        def f(p, s: smtplib.SMTP):
            s.sendmail('f@x.com', 't@x.com', read_raw(p))
            return 1
        """,
    )
    assert len(_rule_hits(findings, "PY-WL-126")) == 1


def test_param_annotation_is_shadowed_by_a_body_rebind(tmp_path: Path) -> None:
    # A body rebind to an unresolvable RHS invalidates the parameter seed —
    # the stale Logger class must not keep matching.
    findings = _scan(
        tmp_path,
        """
        import logging
        @trusted(level='ASSURED')
        def f(p, log: logging.Logger):
            log = make_thing()
            log.info(read_raw(p))
            return 1
        """,
    )
    assert _rule_hits(findings, "PY-WL-125") == []


# ── 4. Operator severity override equal to the metadata default ──────────────

_STDLIB_XML = """
import xml.etree.ElementTree as ET
@trusted(level='ASSURED')
def f(p):
    return ET.fromstring(read_raw(p))
"""


def test_121_stdlib_sink_keeps_per_sink_warn_without_override(tmp_path: Path) -> None:
    hits = _rule_hits(_scan(tmp_path, _STDLIB_XML), "PY-WL-121")
    assert [f.severity for f in hits] == [Severity.WARN]


def test_121_explicit_override_equal_to_default_rebases_per_sink_severity(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _STDLIB_XML, WardlineConfig(rules_severity={"PY-WL-121": "ERROR"}))
    hits = _rule_hits(findings, "PY-WL-121")
    assert [f.severity for f in hits] == [Severity.ERROR]


def test_121_explicit_lower_override_still_rebases(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _STDLIB_XML, WardlineConfig(rules_severity={"PY-WL-121": "INFO"}))
    hits = _rule_hits(findings, "PY-WL-121")
    assert [f.severity for f in hits] == [Severity.INFO]


# ── 5. Flow-insensitive fallback is a FACT finding, not a UserWarning ────────


def test_flow_insensitive_fallback_emits_one_fact_finding(tmp_path: Path, monkeypatch) -> None:
    import ast

    import wardline.scanner.analyzer as analyzer_mod

    real = analyzer_mod.run_l2_function_stage

    def _boom(stage_input):  # noqa: ANN001, ANN202
        if any(isinstance(n, ast.Name) and n.id == "boom" for n in ast.walk(stage_input.node)):
            raise RecursionError("simulated deep L2")
        return real(stage_input)

    monkeypatch.setattr(analyzer_mod, "run_l2_function_stage", _boom)

    findings = _scan(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            boom = read_raw(p)
            return eval(boom)
        """,
    )
    # The L2-skipped function degrades the sink rules to the pessimistic
    # fallback. That degradation is one NONE/FACT finding per scan — never a
    # warning (the _scan harness runs with warnings-as-error to prove it).
    facts = _rule_hits(findings, "WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK")
    assert len(facts) == 1
    assert facts[0].kind == Kind.FACT
    assert facts[0].severity == Severity.NONE
    assert facts[0].properties["qualnames"] == ["m.f"]
    # The pessimistic fallback itself still fails closed: the sink fires.
    assert len(_rule_hits(findings, "PY-WL-107")) == 1


def test_no_fallback_fact_on_a_clean_scan(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            return eval(read_raw(p))
        """,
    )
    assert _rule_hits(findings, "WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK") == []


# ── 6. Consolidated base: historical sink rules gain binding-awareness ───────


def test_106_callable_alias_resolves_after_consolidation(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        import pickle
        @trusted(level='ASSURED')
        def f(p):
            loader = pickle.loads
            return loader(read_raw(p))
        """,
    )
    hits = _rule_hits(findings, "PY-WL-106")
    assert len(hits) == 1
    assert hits[0].properties["sink"] == "pickle.loads"


def test_107_callable_alias_resolves_after_consolidation(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            e = eval
            return e(read_raw(p))
        """,
    )
    assert len(_rule_hits(findings, "PY-WL-107")) == 1
