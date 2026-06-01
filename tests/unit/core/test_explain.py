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


def test_explain_non_call_return_has_no_immediate_callee(tmp_path: Path) -> None:
    # The worst return path is ``return x`` (a bare Name, not a direct call), so the
    # immediate tainted callee is unresolvable — and the boundary with it. That
    # indirection is deferred to SP9; explain must NOT guess.
    root = _leaky_var_project(tmp_path)
    f = _first_active_taint_finding(root)
    assert f.qualname == "svc.leaky_var"
    exp = explain_finding(root, fingerprint=f.fingerprint)
    assert exp is not None
    assert exp.immediate_tainted_callee is None
    assert exp.source_boundary_qualname is None


def test_explain_unknown_fingerprint_returns_none(tmp_path: Path) -> None:
    root = _leaky_project(tmp_path)
    assert explain_finding(root, fingerprint="0" * 64) is None


def test_explain_by_path_line_matches(tmp_path: Path) -> None:
    root = _leaky_project(tmp_path)
    f = _first_active_taint_finding(root)
    exp = explain_finding(root, path=f.location.path, line=f.location.line_start)
    assert exp is not None
    assert exp.fingerprint == f.fingerprint
