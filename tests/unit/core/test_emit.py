import json
from pathlib import Path

import pytest

from wardline.core.emit import JsonlSink
from wardline.core.errors import WardlineError
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


def test_jsonl_sink_refuses_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text("keep\n", encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    out.symlink_to(outside)

    with pytest.raises(WardlineError, match="refusing to write through a symlink"):
        JsonlSink(out).write([_finding()])

    assert outside.read_text(encoding="utf-8") == "keep\n"


def test_jsonl_sink_with_root_refuses_parent_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "reports").symlink_to(outside, target_is_directory=True)

    with pytest.raises(WardlineError, match="escapes project root"):
        JsonlSink(root / "reports" / "findings.jsonl", root=root).write([_finding()])

    assert not (outside / "findings.jsonl").exists()
