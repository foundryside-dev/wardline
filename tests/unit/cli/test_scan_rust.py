"""WP6: ``wardline scan --lang rust`` end-to-end through the CLI.

Drives the real Click command over a tmp ``.rs`` tree: the gate fires (exit 1) on an
``RS-WL-108`` injection, a clean tree exits 0, the preview banner prints to stderr, and a
malformed file is surfaced via ``--fail-on-unanalyzed``.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from click.testing import CliRunner  # noqa: E402

from wardline.cli.scan import scan  # noqa: E402

_TRUSTED = "/// @trusted(level=ASSURED)\n"
_INJECTION = _TRUSTED + 'fn run() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n'


def test_scan_lang_rust_gate_trips_on_injection(tmp_path) -> None:
    (tmp_path / "m.rs").write_text(_INJECTION, encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--lang", "rust", "--fail-on", "ERROR", "--output", str(out)])
    assert result.exit_code == 1  # gate tripped
    rule_ids = [json.loads(line)["rule_id"] for line in out.read_text().splitlines() if line.strip()]
    assert "RS-WL-108" in rule_ids
    # The preview posture banner is loud on stderr (provisional identity / no config parity).
    assert "preview" in result.output.lower()


def test_scan_lang_rust_clean_tree_exits_zero(tmp_path) -> None:
    (tmp_path / "m.rs").write_text(_TRUSTED + 'fn run() {\n    Command::new("ls").output();\n}\n', encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--lang", "rust", "--fail-on", "ERROR", "--output", str(out)])
    assert result.exit_code == 0


def test_scan_lang_rust_malformed_file_fails_unanalyzed_gate(tmp_path) -> None:
    (tmp_path / "broken.rs").write_text("fn f( {\n    std::env::var(\n", encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--lang", "rust", "--fail-on-unanalyzed", "--output", str(out)])
    assert result.exit_code == 1
    assert "could not be analyzed" in result.output


def test_scan_lang_rust_warns_on_empty_trust_surface(tmp_path) -> None:
    # A repo with NO @trusted markers is vacuously green (default-clean). The CLI must say
    # so loudly — "0 active" without an empty-trust-surface warning is the false green.
    (tmp_path / "m.rs").write_text(
        'fn a() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n', encoding="utf-8"
    )
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--lang", "rust", "--output", str(out)])
    assert result.exit_code == 0
    assert "trust surface" in result.output.lower() and "0 of 1" in result.output


def test_scan_lang_rust_reports_coverage_when_markers_present(tmp_path) -> None:
    (tmp_path / "m.rs").write_text(_INJECTION, encoding="utf-8")  # one @trusted fn
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--lang", "rust", "--output", str(out)])
    assert "1 of 1" in result.output  # trust surface fully covered


def test_scan_default_lang_python_ignores_rs(tmp_path) -> None:
    # Without --lang rust, a .rs file is not swept and no preview banner prints.
    (tmp_path / "m.rs").write_text(_INJECTION, encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0
    assert "preview" not in result.output.lower()
