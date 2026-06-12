# tests/unit/core/test_explain.py
from pathlib import Path

from wardline.core.explain import TaintExplanation, explain_finding
from wardline.core.finding import Kind, SuppressionState
from wardline.core.run import run_scan

# A @trusted function returning an @external_boundary-tainted value: PY-WL-101.
# sample_project itself is clean, so we build a known-leaky project per test.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)

# A @trusted function whose worst return path is a bare variable (``return x``),
# NOT a direct call — so the immediate callee is unresolvable (SP9 territory).
_LEAKY_VAR = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky_var(p):\n    x = read_raw(p)\n    return x\n"
)


def _leaky_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _leaky_var_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_VAR, encoding="utf-8")
    return proj


def _first_active_taint_finding(root: Path):
    result = run_scan(root)
    for f in result.findings:
        if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE and "actual_return" in f.properties:
            return f
    raise AssertionError("leaky project has no active untrusted-reaches-trusted defect")


def test_explain_by_fingerprint_projects_provenance(tmp_path: Path) -> None:
    root = _leaky_project(tmp_path)
    f = _first_active_taint_finding(root)
    exp = explain_finding(root, fingerprint=f.fingerprint)
    assert isinstance(exp, TaintExplanation)
    assert exp.fingerprint == f.fingerprint
    assert exp.sink_qualname == f.qualname
    assert exp.tier_in == f.properties["actual_return"]
    assert exp.tier_out == f.properties["declared_return"]
    # leaky's worst return path is a direct call to read_raw → that callee, and
    # read_raw is a same-module leaf source → it is the 1-hop boundary.
    assert exp.immediate_tainted_callee == "read_raw"
    assert exp.source_boundary_qualname == "svc.read_raw"
    assert exp.resolved_call_count == 1
    assert exp.unresolved_call_count == 0


def test_explain_indirect_return_names_single_hop_callee(tmp_path: Path) -> None:
    # The worst return path is ``return x`` (a bare Name), where ``x = read_raw(p)``.
    # T1.3 resolves a single hop: explain now names the contributing callee
    # (``read_raw``) and the boundary it resolves to (``svc.read_raw``, a leaf
    # @external_boundary). Provenance only — the verdict (PY-WL-101) is unchanged.
    root = _leaky_var_project(tmp_path)
    f = _first_active_taint_finding(root)
    assert f.qualname == "svc.leaky_var"
    exp = explain_finding(root, fingerprint=f.fingerprint)
    assert exp is not None
    assert exp.immediate_tainted_callee == "read_raw"
    assert exp.source_boundary_qualname == "svc.read_raw"


def test_explain_unknown_fingerprint_returns_none(tmp_path: Path) -> None:
    root = _leaky_project(tmp_path)
    assert explain_finding(root, fingerprint="0" * 64) is None


def test_explain_by_path_line_matches(tmp_path: Path) -> None:
    root = _leaky_project(tmp_path)
    f = _first_active_taint_finding(root)
    exp = explain_finding(root, path=f.location.path, line=f.location.line_start)
    assert exp is not None
    assert exp.fingerprint == f.fingerprint


def test_explain_finding_still_projects_provenance(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    finding = next(f for f in run_scan(tmp_path).findings if f.rule_id == "PY-WL-101")
    exp = explain_finding(tmp_path, fingerprint=finding.fingerprint)
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"
    assert exp.immediate_tainted_callee == "read_raw"
    assert exp.source_boundary_qualname == "svc.read_raw"


# --- B7 (weft-0d24cf9152): sink-rule findings must name their taint source ---------

# A PY-WL-125-style sink finding: the tainted value reaches the sink ARGUMENT (never
# the return), so the return-callee path cannot explain it — the sink-argument
# derivation must.
_SINK_LEAKY = (
    "import logging\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "logger = logging.getLogger(__name__)\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef log_it(p):\n    msg = read_raw(p)\n    logger.info(msg)\n"
)

# Same sink, the source call INLINE in the sink's argument list.
_SINK_LEAKY_INLINE = (
    "import logging\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "logger = logging.getLogger(__name__)\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef log_it(p):\n    logger.info(read_raw(p))\n"
)

# The tainted argument comes from an IMPORTED callee wardline cannot resolve — the
# source is genuinely underivable from the single-scan analysis.
_SINK_UNDERIVABLE = (
    "import logging\n"
    "from somewhere_else import fetch_text\n"
    "from wardline.decorators import trusted\n"
    "logger = logging.getLogger(__name__)\n"
    "@trusted\ndef log_it(p):\n    msg = fetch_text(p)\n    logger.info(msg)\n"
)


def _sink_project(tmp_path: Path, source: str) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(source, encoding="utf-8")
    return proj


def _finding_125(root: Path):
    result = run_scan(root)
    for f in result.findings:
        if f.rule_id == "PY-WL-125":
            return f
    raise AssertionError("sink project has no PY-WL-125 finding")


def test_explain_sink_finding_names_the_taint_source(tmp_path: Path) -> None:
    root = _sink_project(tmp_path, _SINK_LEAKY)
    f = _finding_125(root)
    exp = explain_finding(root, fingerprint=f.fingerprint)
    assert exp is not None
    # The actual source — read_raw, assigned to msg three lines above the sink —
    # is named, with its one-hop boundary resolution.
    assert exp.immediate_tainted_callee == "read_raw"
    assert exp.source_boundary_qualname == "svc.read_raw"
    # Sink findings carry tier facts in tier/arg_taint properties, not the
    # return-mismatch keys — the explanation must project them, not null out.
    assert exp.tier_in == "EXTERNAL_RAW"
    assert exp.tier_out == "INTEGRAL"


def test_explain_sink_finding_names_an_inline_call_source(tmp_path: Path) -> None:
    root = _sink_project(tmp_path, _SINK_LEAKY_INLINE)
    f = _finding_125(root)
    exp = explain_finding(root, fingerprint=f.fingerprint)
    assert exp is not None
    assert exp.immediate_tainted_callee == "read_raw"
    assert exp.source_boundary_qualname == "svc.read_raw"


def test_explain_taint_result_marks_source_resolution_resolved(tmp_path: Path) -> None:
    from wardline.core.explain import explain_taint_result

    root = _sink_project(tmp_path, _SINK_LEAKY)
    f = _finding_125(root)
    result = explain_taint_result(root, fingerprint=f.fingerprint)
    assert result is not None
    res = result["source_resolution"]
    assert res["status"] == "resolved"
    assert res["missing_capability"] is None


def test_explain_taint_result_degrades_honestly_when_source_underivable(tmp_path: Path) -> None:
    # C-10(c): an unresolved source must SAY what is missing and how to enable it —
    # never nulls that read as a complete-but-empty answer.
    from wardline.core.explain import explain_taint_result

    root = _sink_project(tmp_path, _SINK_UNDERIVABLE)
    f = _finding_125(root)
    result = explain_taint_result(root, fingerprint=f.fingerprint, loomweave=None)
    assert result is not None
    assert result["immediate_tainted_callee"] is None
    res = result["source_resolution"]
    assert res["status"] == "unresolved"
    assert res["reason"]  # names WHY, not just null
    assert res["missing_capability"] == "loomweave_taint_store"
    assert "loomweave" in res["enablement"].lower()


def test_explain_taint_result_chain_unavailable_is_explicit(tmp_path: Path) -> None:
    # chain=true without a Loomweave store used to degrade SILENTLY (no chain block);
    # C-10(c) requires an explicit marker naming the capability and enablement path.
    from wardline.core.explain import explain_taint_result

    root = _sink_project(tmp_path, _SINK_LEAKY)
    f = _finding_125(root)
    result = explain_taint_result(root, fingerprint=f.fingerprint, chain=True, loomweave=None)
    assert result is not None
    chain = result["chain"]
    assert chain["status"] == "unavailable"
    assert chain["hops"] == []
    assert chain["missing_capability"] == "loomweave_taint_store"
    assert "loomweave" in chain["enablement"].lower()


def test_remediation_is_rule_specific_for_known_sink_rules(tmp_path: Path) -> None:
    # B7: generic "review the finding" text on a SPECIFIC finding is part of the
    # defect — PY-WL-125 has a canonical fix (lazy %-parameterization).
    from wardline.core.explain import explain_taint_result

    root = _sink_project(tmp_path, _SINK_LEAKY)
    f = _finding_125(root)
    result = explain_taint_result(root, fingerprint=f.fingerprint)
    assert result is not None
    rem = result["remediation"]
    assert rem["kind"] == "sink_hygiene"
    assert rem["source_qualname"] == "svc.read_raw"
    assert "parameteriz" in rem["summary"] or "%s" in rem["summary"]
    assert "Review the finding and apply the rule-specific fix" not in rem["summary"]
