from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.taints import TRUST_RANK
from wardline.core.taints import TaintState as T
from wardline.scanner.analyzer import WardlineAnalyzer


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
