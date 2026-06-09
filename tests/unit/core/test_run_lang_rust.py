"""WP6: ``run_scan(root, lang="rust")`` routes discovery + analysis to the Rust frontend.

Pins the keystone integration: the ``lang`` discriminator selects ``.rs`` discovery and a
``RustAnalyzer`` while leaving the Python path (``lang`` defaulted) byte-identical, the gate
fires on an ``RS-WL-108`` ERROR, and a malformed ``.rs`` counts toward ``unanalyzed``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.finding import Severity  # noqa: E402
from wardline.core.run import gate_decision, run_scan  # noqa: E402

_TRUSTED = "/// @trusted(level=ASSURED)\n"
_INJECTION = _TRUSTED + 'fn run() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n'


def test_run_scan_rust_discovers_rs_and_gates_on_injection(tmp_path) -> None:
    (tmp_path / "m.rs").write_text(_INJECTION, encoding="utf-8")
    # A .py file in the same tree must be IGNORED under --lang rust (suffix routing).
    (tmp_path / "decoy.py").write_text("x = 1\n", encoding="utf-8")

    result = run_scan(tmp_path, lang="rust")

    rule_ids = [f.rule_id for f in result.findings]
    assert "RS-WL-108" in rule_ids
    assert result.files_scanned == 1  # only m.rs; decoy.py not swept
    assert result.context is None  # Rust last_context is None (slice-1)

    decision = gate_decision(result, Severity.ERROR)
    assert decision.tripped is True
    assert decision.verdict == "FAILED"


def test_run_scan_rust_clean_tree_passes(tmp_path) -> None:
    (tmp_path / "m.rs").write_text(_TRUSTED + 'fn run() {\n    Command::new("ls").output();\n}\n', encoding="utf-8")
    result = run_scan(tmp_path, lang="rust")
    assert [f for f in result.findings if f.rule_id.startswith("RS-WL-")] == []
    assert gate_decision(result, Severity.ERROR).tripped is False


def test_run_scan_rust_malformed_file_counts_unanalyzed(tmp_path) -> None:
    (tmp_path / "broken.rs").write_text("fn f( {\n    std::env::var(\n", encoding="utf-8")
    result = run_scan(tmp_path, lang="rust")
    assert result.summary.unanalyzed == 1


def test_run_scan_python_path_unchanged_by_lang_default(tmp_path) -> None:
    # The Python default path must be untouched: a .py leak still fires PY-WL-101, and
    # .rs files are NOT swept when lang defaults to python.
    (tmp_path / "leak.py").write_text(
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted\ndef leaky(p):\n    return read_raw(p)\n",
        encoding="utf-8",
    )
    (tmp_path / "ignored.rs").write_text(_INJECTION, encoding="utf-8")
    result = run_scan(tmp_path)  # lang defaults to python
    rule_ids = {f.rule_id for f in result.findings}
    assert "PY-WL-101" in rule_ids
    assert not any(r.startswith("RS-WL-") for r in rule_ids)
