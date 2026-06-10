"""Attribute-write flow soundness (wardline-b369c7d06c).

The per-class attribute summary (``class_attr_taints``) used to be built by a
POST-HOC second walk (``collect_attribute_writes``) that resolved each write's
RHS against the function's FINAL ``var_taints`` and tracked receiver classes in
a branch-unaware, single-slot ``var_types`` map. Two laundering mechanisms
followed — both silent false negatives in the exact summaries the
secure-by-default gate's @trusted-method sink rules rely on:

1. FINAL-STATE LAUNDER: ``v = read_raw(p); self.x = v; v = "safe"`` resolved
   ``v`` post-reassignment, recording ``Store.x`` as INTEGRAL.
2. BRANCH-UNAWARE RECEIVER: ``box = Vault();  if flag: box = Ledger();
   box.token = read_raw(p)`` kept only the last class binding, attributing the
   raw write solely to ``Ledger`` while on the no-flag path the receiver is
   still the ``Vault`` instance.

Attribute writes are now recorded DURING the main L2 walk (per-statement
``var_taints``, full branch handling) into a side channel
(:func:`attribute_write_recording`), and receiver class tracking is set-valued
and branch-aware: a straight-line class rebind is a strong update, a branch
join unions the arms, and a write through a multi-candidate receiver attributes
to EVERY candidate class.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.taint.variable_level import (
    SELF_ATTRIBUTE_KEY,
    attribute_write_recording,
    compute_variable_taints,
    project_attribute_writes,
)

T = TaintState

_HEADER = (
    "import pickle\n"
    "from wardline.decorators import external_boundary, trusted, trust_boundary\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
)


def _analyze(tmp_path: Path, body: str) -> WardlineAnalyzer:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(body), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    return analyzer


def _defect_ids(tmp_path: Path, body: str) -> set[str]:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(body), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    return {f.rule_id for f in findings if f.kind is Kind.DEFECT}


def _attr_taints(analyzer: WardlineAnalyzer) -> dict[str, dict[str, TaintState]]:
    ctx = analyzer.last_context
    assert ctx is not None
    return ctx.class_attr_taints


def _record(
    src: str,
    taint_map: dict[str, TaintState] | None = None,
    function_taint: TaintState = T.UNKNOWN_RAW,
) -> dict[str, dict[str, TaintState]]:
    func = ast.parse(textwrap.dedent(src)).body[0]
    assert isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
    out: dict[str, dict[str, TaintState]] = {}
    with attribute_write_recording(out):
        compute_variable_taints(func, function_taint, taint_map or {}, alias_map={})
    return out


# ── s1/s2 — per-statement RHS taint (final-state launder) ─────────────────────

_STORE_CONTROL = """
class Store:
    def put(self, p):
        v = read_raw(p)
        self.x = v

    @trusted(level='ASSURED')
    def use(self):
        return pickle.loads(self.x)
"""

_STORE_FINAL_STATE_LAUNDER = """
class Store:
    def put(self, p):
        v = read_raw(p)
        self.x = v
        v = "safe"

    @trusted(level='ASSURED')
    def use(self):
        return pickle.loads(self.x)
"""


def test_s1_control_raw_attr_fires_sink_in_trusted_method(tmp_path: Path) -> None:
    analyzer = _analyze(tmp_path, _STORE_CONTROL)
    assert _attr_taints(analyzer)["m.Store"]["x"] == T.EXTERNAL_RAW
    assert "PY-WL-106" in _defect_ids(tmp_path, _STORE_CONTROL)


def test_s2_reassignment_after_attr_write_does_not_launder(tmp_path: Path) -> None:
    # ``v`` is RAW at the ``self.x = v`` statement; the trailing ``v = "safe"``
    # must not retroactively clean the recorded attribute write.
    analyzer = _analyze(tmp_path, _STORE_FINAL_STATE_LAUNDER)
    assert _attr_taints(analyzer)["m.Store"]["x"] == T.EXTERNAL_RAW
    assert "PY-WL-106" in _defect_ids(tmp_path, _STORE_FINAL_STATE_LAUNDER)


def test_s4_branch_local_reassignment_after_write_stays_raw(tmp_path: Path) -> None:
    # Already-sound pin: ``self.x = v`` then ``if flag: v = "safe"`` — the write
    # happened while v was raw; the branch merge must not launder it either.
    body = """
    class Store:
        def put(self, p, flag):
            v = read_raw(p)
            self.x = v
            if flag:
                v = "safe"

        @trusted(level='ASSURED')
        def use(self):
            return pickle.loads(self.x)
    """
    analyzer = _analyze(tmp_path, body)
    assert _attr_taints(analyzer)["m.Store"]["x"] == T.EXTERNAL_RAW
    assert "PY-WL-106" in _defect_ids(tmp_path, body)


def test_s3_raw_in_one_branch_arm_stays_raw(tmp_path: Path) -> None:
    # Already-sound pin: a raw write in one arm joins (least-trusted) with the
    # clean arm's write — the summary keeps the raw rank.
    body = """
    class Store:
        def put(self, p, flag):
            if flag:
                self.x = read_raw(p)
            else:
                self.x = "safe"

        @trusted(level='ASSURED')
        def use(self):
            return pickle.loads(self.x)
    """
    analyzer = _analyze(tmp_path, body)
    assert _attr_taints(analyzer)["m.Store"]["x"] == T.EXTERNAL_RAW
    assert "PY-WL-106" in _defect_ids(tmp_path, body)


def test_augassign_attr_write_uses_per_statement_taint(tmp_path: Path) -> None:
    body = """
    class Store:
        def put(self, p):
            v = read_raw(p)
            self.x = ""
            self.x += v
            v = "safe"

        @trusted(level='ASSURED')
        def use(self):
            return pickle.loads(self.x)
    """
    analyzer = _analyze(tmp_path, body)
    assert _attr_taints(analyzer)["m.Store"]["x"] == T.EXTERNAL_RAW


def test_annassign_attr_write_uses_per_statement_taint(tmp_path: Path) -> None:
    body = """
    class Store:
        def put(self, p):
            v = read_raw(p)
            self.x: str = v
            v = "safe"

        @trusted(level='ASSURED')
        def use(self):
            return pickle.loads(self.x)
    """
    analyzer = _analyze(tmp_path, body)
    assert _attr_taints(analyzer)["m.Store"]["x"] == T.EXTERNAL_RAW


# ── s5/s6/s7 — branch-aware, set-valued receiver class tracking ──────────────

_VAULT_LEDGER = """
class Vault:
    def __init__(self):
        self.token = "init"

    @trusted(level='ASSURED')
    def use(self):
        return pickle.loads(self.token)

class Ledger:
    def __init__(self):
        self.token = "init"
"""


def test_s5_control_external_write_attributes_to_receiver_class(tmp_path: Path) -> None:
    body = (
        _VAULT_LEDGER
        + """
def route(p, flag):
    box = Vault()
    box.token = read_raw(p)
"""
    )
    analyzer = _analyze(tmp_path, body)
    taints = _attr_taints(analyzer)
    assert taints["m.Vault"]["token"] == T.EXTERNAL_RAW
    assert taints["m.Ledger"]["token"] == T.INTEGRAL
    assert "PY-WL-106" in _defect_ids(tmp_path, body)


def test_s6_branch_rebound_receiver_attributes_to_all_candidate_classes(tmp_path: Path) -> None:
    # On the no-flag arm ``box`` is still the Vault instance, so the raw write
    # must attribute to BOTH Vault and Ledger (union of arms), not just the
    # last-bound class.
    body = (
        _VAULT_LEDGER
        + """
def route(p, flag):
    box = Vault()
    if flag:
        box = Ledger()
    box.token = read_raw(p)
"""
    )
    analyzer = _analyze(tmp_path, body)
    taints = _attr_taints(analyzer)
    assert taints["m.Vault"]["token"] == T.EXTERNAL_RAW
    assert taints["m.Ledger"]["token"] == T.EXTERNAL_RAW
    assert "PY-WL-106" in _defect_ids(tmp_path, body)


def test_s7_receiver_rebound_to_nonclass_in_one_arm_keeps_class_candidate(tmp_path: Path) -> None:
    # Already-sound pin: one arm rebinds ``box`` to an untypeable raw value; the
    # fall-through arm still holds the Vault instance, so Vault.token records raw.
    body = (
        _VAULT_LEDGER
        + """
def route(p, flag):
    box = Vault()
    if flag:
        box = read_raw(p)
    box.token = read_raw(p)
"""
    )
    analyzer = _analyze(tmp_path, body)
    assert _attr_taints(analyzer)["m.Vault"]["token"] == T.EXTERNAL_RAW
    assert "PY-WL-106" in _defect_ids(tmp_path, body)


def test_straight_line_class_rebind_is_a_strong_update(tmp_path: Path) -> None:
    # Straight-line rebind: after ``box = Ledger()`` the receiver is a Ledger on
    # EVERY path, so the raw write attributes only to Ledger — Vault stays clean.
    body = (
        _VAULT_LEDGER
        + """
def route(p):
    box = Vault()
    box = Ledger()
    box.token = read_raw(p)
"""
    )
    analyzer = _analyze(tmp_path, body)
    taints = _attr_taints(analyzer)
    assert taints["m.Vault"]["token"] == T.INTEGRAL
    assert taints["m.Ledger"]["token"] == T.EXTERNAL_RAW
    assert "PY-WL-106" not in _defect_ids(tmp_path, body)


def test_try_except_rebound_receiver_attributes_to_both_arms(tmp_path: Path) -> None:
    body = (
        _VAULT_LEDGER
        + """
def route(p):
    box = Vault()
    try:
        box = Ledger()
    except ValueError:
        pass
    box.token = read_raw(p)
"""
    )
    analyzer = _analyze(tmp_path, body)
    taints = _attr_taints(analyzer)
    assert taints["m.Vault"]["token"] == T.EXTERNAL_RAW
    assert taints["m.Ledger"]["token"] == T.EXTERNAL_RAW


def test_match_rebound_receiver_attributes_to_both_arms(tmp_path: Path) -> None:
    body = (
        _VAULT_LEDGER
        + """
def route(p, flag):
    box = Vault()
    match flag:
        case 1:
            box = Ledger()
    box.token = read_raw(p)
"""
    )
    analyzer = _analyze(tmp_path, body)
    taints = _attr_taints(analyzer)
    assert taints["m.Vault"]["token"] == T.EXTERNAL_RAW
    assert taints["m.Ledger"]["token"] == T.EXTERNAL_RAW


def test_zero_trip_loop_receiver_rebind_keeps_pre_loop_candidate(tmp_path: Path) -> None:
    # A loop body is a conditionally-executed arm: on the zero-trip path the
    # receiver is still the pre-loop Vault instance.
    body = (
        _VAULT_LEDGER
        + """
def route(p, items):
    box = Vault()
    for _ in items:
        box = Ledger()
    box.token = read_raw(p)
"""
    )
    analyzer = _analyze(tmp_path, body)
    taints = _attr_taints(analyzer)
    assert taints["m.Vault"]["token"] == T.EXTERNAL_RAW
    assert taints["m.Ledger"]["token"] == T.EXTERNAL_RAW


# ── recording side channel (unit level) ──────────────────────────────────────


def test_recording_self_write_uses_per_statement_var_taints() -> None:
    out = _record(
        """
        def put(self, p):
            v = read_raw(p)
            self.x = v
            v = "safe"
        """,
        taint_map={"read_raw": T.EXTERNAL_RAW},
        function_taint=T.INTEGRAL,
    )
    assert out[SELF_ATTRIBUTE_KEY]["x"] == T.EXTERNAL_RAW


def test_recording_cls_write_maps_to_self_key() -> None:
    out = _record(
        """
        def put(cls, p):
            cls.x = read_raw(p)
        """,
        taint_map={"read_raw": T.EXTERNAL_RAW},
        function_taint=T.INTEGRAL,
    )
    assert out[SELF_ATTRIBUTE_KEY]["x"] == T.EXTERNAL_RAW


def test_recording_joins_multiple_writes_least_trusted() -> None:
    out = _record(
        """
        def put(self, p):
            self.x = "clean"
            self.x = read_raw(p)
        """,
        taint_map={"read_raw": T.EXTERNAL_RAW},
        function_taint=T.INTEGRAL,
    )
    assert out[SELF_ATTRIBUTE_KEY]["x"] == T.EXTERNAL_RAW


def test_recording_typed_receiver_records_under_candidate_fqns() -> None:
    out = _record(
        """
        def route(p, flag):
            box = Vault()
            if flag:
                box = Ledger()
            box.token = read_raw(p)
        """,
        taint_map={"read_raw": T.EXTERNAL_RAW},
        function_taint=T.INTEGRAL,
    )
    assert out["Vault"]["token"] == T.EXTERNAL_RAW
    assert out["Ledger"]["token"] == T.EXTERNAL_RAW


def test_recording_disabled_by_default() -> None:
    func = ast.parse("def put(self, p):\n    self.x = p\n").body[0]
    assert isinstance(func, ast.FunctionDef)
    # No recording context — must not raise, and the walk stays pure.
    compute_variable_taints(func, T.UNKNOWN_RAW, {})


def test_project_attribute_writes_filters_and_maps_self() -> None:
    recorded = {
        SELF_ATTRIBUTE_KEY: {"x": T.EXTERNAL_RAW},
        "m.Vault": {"token": T.EXTERNAL_RAW},
        "m.not_a_class": {"y": T.EXTERNAL_RAW},
    }
    projected = project_attribute_writes(recorded, frozenset({"m.Vault", "m.Store"}), "m.Store")
    assert projected == {
        "m.Store": {"x": T.EXTERNAL_RAW},
        "m.Vault": {"token": T.EXTERNAL_RAW},
    }
    # Outside a method the self/cls writes have no class to attribute to.
    projected_fn = project_attribute_writes(recorded, frozenset({"m.Vault", "m.Store"}), None)
    assert projected_fn == {"m.Vault": {"token": T.EXTERNAL_RAW}}


def test_project_attribute_writes_joins_self_and_typed_keys_for_same_class() -> None:
    recorded = {
        SELF_ATTRIBUTE_KEY: {"x": T.INTEGRAL},
        "m.Store": {"x": T.EXTERNAL_RAW},
    }
    projected = project_attribute_writes(recorded, frozenset({"m.Store"}), "m.Store")
    assert projected == {"m.Store": {"x": T.EXTERNAL_RAW}}
