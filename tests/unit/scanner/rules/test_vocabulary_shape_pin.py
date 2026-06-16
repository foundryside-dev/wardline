from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Maturity, Severity
from wardline.core.taints import TRUST_RANK
from wardline.core.taints import TaintState as T
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules import build_default_registry


def _analyze(tmp_path: Path, files: dict[str, str]):
    paths = []
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        paths.append(p)
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(sorted(paths), WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, findings


def test_decorator_taint_shapes_are_distinct_and_stable(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        {
            "m.py": "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
            "@external_boundary\ndef eb(p):\n    return p\n"
            "@trust_boundary(to_level='ASSURED')\ndef tb(p):\n    return p\n"
            "@trusted(level='ASSURED')\ndef tr(p):\n    return p\n",
        },
    )
    body = ctx.project_taints
    ret = ctx.project_return_taints
    # @external_boundary: body == return == EXTERNAL_RAW (raw-zone return -> PY-WL-101 gated)
    assert body["m.eb"] == T.EXTERNAL_RAW and ret["m.eb"] == T.EXTERNAL_RAW
    # @trust_boundary: trust-RAISING transition (body strictly less trusted than return)
    assert TRUST_RANK[body["m.tb"]] > TRUST_RANK[ret["m.tb"]]
    # @trusted: body == return, both trusted (NOT a transition)
    assert body["m.tr"] == ret["m.tr"] == T.ASSURED


# The full rule-metadata shape pin: every builtin PY-WL rule's (severity, kind,
# maturity) triple is part of the product vocabulary (gate behavior, baseline
# eligibility, doc tables). Asserting dict EQUALITY pins all three drift axes at
# once: a renamed/removed/added rule id changes the key set; a recalibrated
# severity (e.g. the 108/112 WARN->ERROR calibration), a kind change, or a
# PREVIEW->STABLE graduation changes a value. Any such drift must be a
# deliberate edit HERE, not an accident.
_EXPECTED_RULE_SHAPE = {
    "PY-WL-101": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-102": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-103": (Severity.WARN, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-104": (Severity.WARN, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-105": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-106": (Severity.WARN, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-107": (Severity.WARN, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-108": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-109": (Severity.WARN, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-110": (Severity.WARN, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-111": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-112": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-113": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-114": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-115": (Severity.WARN, Kind.DEFECT, Maturity.STABLE),
    "PY-WL-116": (Severity.WARN, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-117": (Severity.WARN, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-118": (Severity.ERROR, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-119": (Severity.ERROR, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-120": (Severity.ERROR, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-121": (Severity.ERROR, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-122": (Severity.ERROR, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-123": (Severity.WARN, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-124": (Severity.ERROR, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-125": (Severity.INFO, Kind.DEFECT, Maturity.PREVIEW),
    "PY-WL-126": (Severity.WARN, Kind.DEFECT, Maturity.PREVIEW),
}


def test_builtin_rule_metadata_shape_is_pinned() -> None:
    reg = build_default_registry(WardlineConfig())
    actual = {r.metadata.rule_id: (r.metadata.base_severity, r.metadata.kind, r.metadata.maturity) for r in reg.rules}
    assert actual == _EXPECTED_RULE_SHAPE


def test_rule_metadata_id_matches_class_rule_id() -> None:
    # The registry keys findings by `rule.rule_id` while docs/vocab read
    # `rule.metadata.rule_id`; a divergence would mislabel every finding of that rule.
    reg = build_default_registry(WardlineConfig())
    assert [(r.rule_id, r.metadata.rule_id) for r in reg.rules if r.rule_id != r.metadata.rule_id] == []
