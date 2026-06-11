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


# --- N-5 (wardline-dc6f44707d): case-insensitive severity + flat flags --------


def test_findings_lowercase_severity_matches(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--where", json.dumps({"severity": "error"})])
    assert res.exit_code == 0
    lines = [json.loads(line) for line in res.output.splitlines() if line.strip()]
    assert lines and all(d["severity"] == "ERROR" for d in lines)


def test_findings_out_of_domain_severity_exits_2_with_vocab(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--where", json.dumps({"severity": "medium"})])
    assert res.exit_code == 2
    err = res.output + res.stderr
    assert "medium" in err and "ERROR" in err  # names the offender and the vocabulary


def test_findings_flat_flags_filter(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--rule-id", "PY-WL-101", "--severity", "error"])
    assert res.exit_code == 0, res.output
    lines = [json.loads(line) for line in res.output.splitlines() if line.strip()]
    assert lines and all(d["rule_id"] == "PY-WL-101" and d["severity"] == "ERROR" for d in lines)


def test_findings_flat_flag_conflicts_with_where_key(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(
        cli,
        ["findings", str(tmp_path), "--rule-id", "PY-WL-101", "--where", json.dumps({"rule_id": "PY-WL-106"})],
    )
    assert res.exit_code == 2
    assert "rule_id" in (res.output + res.stderr)


def test_findings_sink_flat_flag_accepted(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--sink", "subprocess.run"])
    assert res.exit_code == 0, res.output  # no sink-family finding here: empty, not an error
