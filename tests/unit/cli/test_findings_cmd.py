"""WS-B1 CLI parity: `wardline findings` runs a scan and prints filtered findings
as JSONL to stdout (read-only; no emission side effects)."""

import json

from click.testing import CliRunner

from wardline.cli.main import cli

_SRC = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_a(p):\n    return p\n"
    "@trusted\ndef leak_a(p):\n    return read_a(p)\n"
)


def test_findings_filters_by_rule_id(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--where", json.dumps({"rule_id": "PY-WL-101"})])
    assert res.exit_code == 0
    lines = [json.loads(line) for line in res.output.splitlines() if line.strip()]
    assert lines and all(d["rule_id"] == "PY-WL-101" for d in lines)


def test_findings_unknown_key_exits_2(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--where", json.dumps({"bogus": 1})])
    assert res.exit_code == 2
    assert "unknown filter key" in res.output


def test_findings_invalid_json_exits_2(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--where", "not json"])
    assert res.exit_code == 2
    assert "valid JSON" in res.output


def test_findings_non_object_where_exits_2(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--where", "[1,2]"])
    assert res.exit_code == 2
    assert "JSON object" in res.output
