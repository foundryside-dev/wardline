from wardline.core.explain import TaintExplanation, explanation_to_dict


def test_explanation_remediation_degrades_when_source_is_unknown() -> None:
    exp = TaintExplanation(
        fingerprint="f" * 64,
        rule_id="PY-WL-101",
        sink_qualname="svc.leaky",
        path="svc.py",
        line=10,
        tier_in="EXTERNAL_RAW",
        tier_out="INTEGRAL",
        immediate_tainted_callee=None,
        source_boundary_qualname=None,
        resolved_call_count=0,
        unresolved_call_count=1,
    )

    remediation = explanation_to_dict(exp)["remediation"]

    assert remediation["kind"] == "boundary_placement"
    assert remediation["sink_qualname"] == "svc.leaky"
    assert remediation["source_qualname"] is None
    assert "source is unresolved" in remediation["summary"]
    assert "blind decorator insertion" in remediation["caveat"]
