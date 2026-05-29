import json
from pathlib import Path

from wardline.core.emit import JsonlSink
from wardline.core.finding import Finding, Kind, Location, Severity


def _finding() -> Finding:
    return Finding(
        rule_id="WLN-001",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="a.py", line_start=1),
        fingerprint="fp",
    )


def test_jsonl_sink_writes_one_line_per_finding(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "findings.jsonl"
    JsonlSink(out).write([_finding(), _finding()])
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["rule_id"] == "WLN-001"


def test_jsonl_sink_writes_empty_file_for_no_findings(tmp_path: Path) -> None:
    out = tmp_path / "findings.jsonl"
    JsonlSink(out).write([])
    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""
