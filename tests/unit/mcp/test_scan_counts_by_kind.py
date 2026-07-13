from __future__ import annotations

from pathlib import Path

from wardline.core.baseline import write_baseline
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.paths import baseline_path
from wardline.core.run import run_scan
from wardline.mcp.server import _SCAN_OUTPUT_SCHEMA, _counts_by_kind, _scan


def _many_leaks(count: int) -> str:
    head = "from wardline.decorators import external_boundary, trusted\n@external_boundary\ndef raw(p):\n    return p\n"
    body = "".join(f"@trusted\ndef leak_{index}(p):\n    return raw(p)\n" for index in range(count))
    return head + body


def _baseline_defects(root: Path) -> None:
    findings = run_scan(root).findings
    defects = [finding for finding in findings if finding.kind is Kind.DEFECT]
    path = baseline_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_baseline(path, defects)


def _finding(
    kind: Kind,
    index: int,
    *,
    suppressed: SuppressionState = SuppressionState.ACTIVE,
) -> Finding:
    severity = Severity.ERROR if kind is Kind.DEFECT else Severity.NONE
    return Finding(
        rule_id=f"TEST-{index}",
        message=f"test finding {index}",
        severity=severity,
        kind=kind,
        location=Location(path="fixture.py", line_start=index + 1),
        fingerprint=f"fp-{index}",
        suppressed=suppressed,
    )


def test_counts_by_kind_uses_canonical_order_and_counts_suppressed_findings() -> None:
    findings = [
        _finding(Kind.DEFECT, 0),
        _finding(Kind.FACT, 1),
        _finding(Kind.CLASSIFICATION, 2),
        _finding(Kind.METRIC, 3),
        _finding(Kind.SUGGESTION, 4),
        _finding(Kind.DEFECT, 5, suppressed=SuppressionState.BASELINED),
    ]

    counts = _counts_by_kind(findings)

    assert list(counts) == [kind.value for kind in Kind]
    assert counts == {
        "defect": 2,
        "fact": 1,
        "classification": 1,
        "metric": 1,
        "suggestion": 1,
    }
    assert sum(counts.values()) == len(findings)


def test_counts_by_kind_zero_fills_absent_kinds() -> None:
    counts = _counts_by_kind([_finding(Kind.FACT, 0)])

    assert counts == {
        "defect": 0,
        "fact": 1,
        "classification": 0,
        "metric": 0,
        "suggestion": 0,
    }


def test_scan_counts_by_kind_cover_complete_population_across_display_lenses(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text(_many_leaks(4), encoding="utf-8")
    _baseline_defects(tmp_path)

    full = _scan({"full": True, "trust_suppressions": True}, root=tmp_path)
    counts = full["summary"]["counts_by_kind"]

    assert list(counts) == [kind.value for kind in Kind]
    assert counts["defect"] == 4
    assert full["summary"]["baselined"] == 4
    assert sum(counts.values()) == full["summary"]["total"]

    variants = [
        _scan(
            {
                "where": {"suppression": "active", "severity": "CRITICAL"},
                "trust_suppressions": True,
            },
            root=tmp_path,
        ),
        _scan(
            {
                "offset": 1,
                "max_findings": 1,
                "trust_suppressions": True,
            },
            root=tmp_path,
        ),
        _scan({"summary_only": True, "trust_suppressions": True}, root=tmp_path),
        _scan({"include_suppressed": False, "trust_suppressions": True}, root=tmp_path),
    ]
    assert all(variant["summary"]["counts_by_kind"] == counts for variant in variants)


def test_scan_counts_by_kind_schema_is_exact_and_required() -> None:
    summary_schema = _SCAN_OUTPUT_SCHEMA["properties"]["summary"]

    assert summary_schema["properties"]["counts_by_kind"] == {
        "type": "object",
        "description": (
            "Whole-scan finding counts by canonical finding kind, including active and suppressed findings."
        ),
        "properties": {
            "defect": {"type": "integer", "minimum": 0},
            "fact": {"type": "integer", "minimum": 0},
            "classification": {"type": "integer", "minimum": 0},
            "metric": {"type": "integer", "minimum": 0},
            "suggestion": {"type": "integer", "minimum": 0},
        },
        "required": ["defect", "fact", "classification", "metric", "suggestion"],
        "additionalProperties": False,
    }
    assert "counts_by_kind" in summary_schema["required"]


def test_nested_agent_summary_contract_is_unchanged(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_many_leaks(1), encoding="utf-8")

    output = _scan({"full": True}, root=tmp_path)

    assert output["agent_summary"]["schema"] == "wardline-agent-summary-1"
    assert "counts_by_kind" not in output["agent_summary"]
    assert "counts_by_kind" not in output["agent_summary"]["summary"]
