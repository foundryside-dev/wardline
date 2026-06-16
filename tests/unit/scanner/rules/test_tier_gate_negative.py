"""Negative tier-gate tests: rules must stay SILENT below their tier gate.

Issue wardline-f2cbf07013: the rule suite tests positive (fires) cases and a
couple of ``undecorated`` (UNKNOWN_RAW) suppressions, but it does NOT pin the
gate BOUNDARY for the tier-gated / tier-modulated rules in the *declared*
freedom zone (``@external_boundary`` -> EXTERNAL_RAW) nor assert the
declaration-gated rules (101/102/105) stay silent below their gate. A silently
loosened gate (a rule that begins to fire too eagerly, or a gate that stops
suppressing) would ship undetected.

Each test pairs a NEGATIVE assertion (silent below the gate) with a POSITIVE
control (the SAME code shape fires at the trusted tier), so the test genuinely
pins the boundary rather than asserting a rule that never fires.

Gate model (src/wardline/scanner/rules/severity_model.py):
  - _TRUSTED  = {INTEGRAL, ASSURED}                          -> base severity
  - _PARTIAL  = {GUARDED, UNKNOWN_GUARDED, UNKNOWN_ASSURED}  -> downgrade one step
  - freedom   = {EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW}       -> modulate -> NONE (silent)

A ``@external_boundary``-bodied function resolves to EXTERNAL_RAW: a *declared*
freedom-zone tier (distinct from the undecorated UNKNOWN_RAW case the suite
already covers). The body-taint-keyed rules (103/104/120) and the
enclosing-declared-tier sink rules (106/107/108/110/111/112/118) must all
suppress to NONE on it. Rules 101/102/105 are declaration-gated (not modulated);
they have their own below-gate predicates (declared-return in RAW_ZONE for 101;
anchored trust-raising shape for 102; raw-body callee / non-provably-untrusted
arg for 105).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.finding import Severity
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection
from wardline.scanner.rules.broad_exception import BroadException
from wardline.scanner.rules.path_traversal import PathTraversal
from wardline.scanner.rules.severity_model import modulate
from wardline.scanner.rules.silent_exception import SilentException
from wardline.scanner.rules.sql_injection import SQLInjection
from wardline.scanner.rules.ssrf import SSRF
from wardline.scanner.rules.stored_taint import StoredTaint
from wardline.scanner.rules.untrusted_reaches_trusted import UntrustedReachesTrusted
from wardline.scanner.rules.untrusted_to_command import UntrustedToCommand
from wardline.scanner.rules.untrusted_to_deserialization import UntrustedToDeserialization
from wardline.scanner.rules.untrusted_to_exec import UntrustedToExec
from wardline.scanner.rules.untrusted_to_shell_subprocess import UntrustedToShellSubprocess
from wardline.scanner.rules.untrusted_to_trusted_callee import UntrustedReachesTrustedCallee

_HEADER = (
    "import os, pickle, subprocess, sqlite3\n"
    "import requests\n"
    "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


# ---------------------------------------------------------------------------
# severity_model.modulate — the single gate function. Pin its exact boundary.
# ---------------------------------------------------------------------------

_FREEDOM = (TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW)
_PARTIAL = (TaintState.GUARDED, TaintState.UNKNOWN_GUARDED, TaintState.UNKNOWN_ASSURED)
_TRUSTED = (TaintState.INTEGRAL, TaintState.ASSURED)


@pytest.mark.parametrize("tier", _FREEDOM)
@pytest.mark.parametrize("base", [Severity.CRITICAL, Severity.ERROR, Severity.WARN, Severity.INFO])
def test_modulate_suppresses_every_base_in_freedom_zone(base: Severity, tier: TaintState) -> None:
    # The load-bearing gate invariant: ANY base severity is suppressed to NONE in
    # the freedom zone. If a future edit ever let a freedom-zone tier return the
    # base (or a non-NONE downgrade), every tier-modulated rule would loosen at once.
    assert modulate(base, tier) is Severity.NONE


@pytest.mark.parametrize("tier", _TRUSTED)
def test_modulate_preserves_base_in_trusted_zone(tier: TaintState) -> None:
    assert modulate(Severity.ERROR, tier) is Severity.ERROR


@pytest.mark.parametrize("tier", _PARTIAL)
def test_modulate_downgrades_one_step_in_partial_zone(tier: TaintState) -> None:
    # Partial tiers DOWNGRADE (not suppress) — the boundary between PARTIAL and
    # freedom. A regression that folded PARTIAL into freedom would silence the
    # partial-tier findings; folding it into TRUSTED would over-report.
    assert modulate(Severity.ERROR, tier) is Severity.WARN
    assert modulate(Severity.WARN, tier) is Severity.INFO


# ---------------------------------------------------------------------------
# Tier-MODULATED sink rules (106/107/108/112/116/117/118): a declared
# freedom-zone function (@external_boundary -> EXTERNAL_RAW) must stay SILENT
# even when raw data reaches the sink. Each test carries a trusted-tier control.
# ---------------------------------------------------------------------------


def test_106_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    b = read_raw(p)\n    pickle.loads(b)\n    return 1\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert UntrustedToDeserialization().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in UntrustedToDeserialization().check(fires)] == ["PY-WL-106"]


def test_107_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    src = read_raw(p)\n    eval(src)\n    return 1\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert UntrustedToExec().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in UntrustedToExec().check(fires)] == ["PY-WL-107"]


def test_108_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    cmd = read_raw(p)\n    os.system(cmd)\n    return 1\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert UntrustedToCommand().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in UntrustedToCommand().check(fires)] == ["PY-WL-108"]


def test_112_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    subprocess.run(read_raw(p), shell=True)\n    return 1\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert UntrustedToShellSubprocess().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in UntrustedToShellSubprocess().check(fires)] == ["PY-WL-112"]


def test_116_path_traversal_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    open(read_raw(p))\n    return 1\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert PathTraversal().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in PathTraversal().check(fires)] == ["PY-WL-116"]


def test_117_ssrf_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    requests.get(read_raw(p))\n    return 1\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert SSRF().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in SSRF().check(fires)] == ["PY-WL-117"]


def test_118_sql_injection_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    cursor = sqlite3.connect(':memory:').cursor()\n    cursor.execute(read_raw(p))\n    return 1\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert SQLInjection().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in SQLInjection().check(fires)] == ["PY-WL-118"]


# ---------------------------------------------------------------------------
# Tier-MODULATED exception rules (103/104) keyed on the function's OWN body
# taint. @external_boundary body (EXTERNAL_RAW) must stay silent.
# ---------------------------------------------------------------------------


def test_103_broad_except_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    try:\n        g()\n    except Exception:\n        h()\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert BroadException().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in BroadException().check(fires)] == ["PY-WL-103"]


def test_104_silent_except_external_boundary_tier_is_silent_but_trusted_fires(tmp_path) -> None:
    body = "\n    try:\n        g()\n    except ValueError:\n        pass\n"
    silent = _analyze(tmp_path, f"@external_boundary\ndef f(p):{body}")
    assert SilentException().check(silent) == []
    fires = _analyze(tmp_path, f"@trusted(level='ASSURED')\ndef f(p):{body}")
    assert [x.rule_id for x in SilentException().check(fires)] == ["PY-WL-104"]


# ---------------------------------------------------------------------------
# Stored-taint (120) is tier-modulated on the function body too.
# ---------------------------------------------------------------------------


def test_120_stored_taint_external_boundary_tier_is_silent(tmp_path) -> None:
    # Stored-taint is modulate-gated on the enclosing function body taint
    # (project_taints[qualname] -> modulate -> NONE on EXTERNAL_RAW). Whatever it
    # would flag inside a trusted producer, it must stay silent in the freedom zone.
    silent = _analyze(
        tmp_path,
        """
        class Repo:
            store = None
        @external_boundary
        def f(p):
            Repo.store = read_raw(p)
            return 1
        """,
    )
    assert StoredTaint().check(silent) == []


# ---------------------------------------------------------------------------
# Declaration-gated rules — NOT modulated, but have their own below-gate
# predicates that must keep them silent.
# ---------------------------------------------------------------------------


def test_102_below_anchor_and_non_raising_gate_is_silent_but_trust_boundary_fires(tmp_path) -> None:
    # PY-WL-102 is declaration-gated (NOT modulated): it fires only on an ANCHORED,
    # trust-RAISING transition (body strictly less trusted than the declared return —
    # the @trust_boundary shape) that lacks a rejection path. Two below-gate cases must
    # stay silent: (a) an undecorated boundary-shaped function (not anchored), and
    # (b) a @trusted producer (anchored but body == declared, so not trust-raising).
    # The positive control is a @trust_boundary with no raise -> fires at base ERROR.
    # (Laundered shape: the bare `return p` single-statement body is PY-WL-119's in the
    # four-way partition, so 102's control routes through a local.)
    undecorated = _analyze(tmp_path, "def v(p):\n    return p\n")
    assert BoundaryWithoutRejection().check(undecorated) == []
    trusted_not_raising = _analyze(tmp_path, "@trusted(level='ASSURED')\ndef v(p):\n    return p\n")
    assert BoundaryWithoutRejection().check(trusted_not_raising) == []
    fires = _analyze(tmp_path, "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    cleaned = p\n    return cleaned\n")
    findings = BoundaryWithoutRejection().check(fires)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-102", "m.v")]
    assert findings[0].severity is Severity.ERROR
    # And a @trust_boundary that DOES reject (has a raise) is above the gate -> silent.
    rejects = _analyze(
        tmp_path,
        "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    if not p:\n        raise ValueError\n    return p\n",
    )
    assert BoundaryWithoutRejection().check(rejects) == []


def test_101_declared_raw_return_is_silent_but_trusted_return_fires(tmp_path) -> None:
    # PY-WL-101 is gated by a trust CLAIM: the declared return must NOT be in the
    # raw/freedom zone. An @external_boundary producer DECLARES EXTERNAL_RAW (in
    # RAW_ZONE), so returning raw is its job -> must stay silent. The same body in
    # a @trusted(ASSURED) producer (declared ASSURED, NOT raw) fires.
    silent = _analyze(tmp_path, "@external_boundary\ndef f(p):\n    return read_raw(p)\n")
    assert UntrustedReachesTrusted().check(silent) == []
    fires = _analyze(tmp_path, "@trusted(level='ASSURED')\ndef f(p):\n    return read_raw(p)\n")
    findings = UntrustedReachesTrusted().check(fires)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-101", "m.f")]
    # 101 is declaration-gated, so it emits at BASE severity (ERROR), never modulated.
    assert findings[0].severity is Severity.ERROR


def test_105_raw_body_callee_is_silent_but_trusted_callee_fires(tmp_path) -> None:
    # PY-WL-105's below-gate predicate: the callee must be a trust-declared producer
    # whose BODY is NOT in the raw zone. An @external_boundary callee (raw body)
    # expects raw input -> silent. A @trusted(ASSURED) callee fires.
    silent = _analyze(tmp_path, "def h(p):\n    read_raw(read_raw(p))\n")
    assert UntrustedReachesTrustedCallee().check(silent) == []
    fires = _analyze(
        tmp_path,
        "@trusted(level='ASSURED')\ndef store(x):\n    return 1\ndef h(p):\n    store(read_raw(p))\n",
    )
    assert [(x.rule_id, x.qualname) for x in UntrustedReachesTrustedCallee().check(fires)] == [("PY-WL-105", "m.h")]


def test_105_unknown_raw_arg_below_provable_gate_is_silent_but_external_raw_fires(tmp_path) -> None:
    # PY-WL-105's ARG gate fires only on PROVABLY-untrusted args (EXTERNAL_RAW /
    # MIXED_RAW), NOT the merely-unprovable UNKNOWN_RAW freedom-zone arg. An
    # undecorated param (UNKNOWN_RAW) must stay silent; a value from an
    # @external_boundary source (EXTERNAL_RAW) crosses the gate and fires.
    silent = _analyze(
        tmp_path,
        "@trusted(level='ASSURED')\ndef store(x):\n    return 1\ndef h(p):\n    store(p)\n",
    )
    assert UntrustedReachesTrustedCallee().check(silent) == []
    fires = _analyze(
        tmp_path,
        "@trusted(level='ASSURED')\ndef store(x):\n    return 1\ndef h(p):\n    store(read_raw(p))\n",
    )
    assert [x.rule_id for x in UntrustedReachesTrustedCallee().check(fires)] == ["PY-WL-105"]
