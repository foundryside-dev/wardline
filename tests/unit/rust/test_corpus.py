"""WP6 corpus gate: the dense positive file fires exactly its intended sinks (≤5% FP,
target 0) and the clean file is hard-zero. Both must parse without ``has_error`` — a
silent PARSE-ERROR would masquerade as "no findings" and pass a naive count check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.rust.analyzer import RustAnalyzer  # noqa: E402
from wardline.rust.parse import has_errors, parse_rust  # noqa: E402

_CORPUS = Path(__file__).resolve().parents[2] / "corpus" / "rust"


def _rs_findings(text: str, module: str):
    findings = RustAnalyzer().analyze_source(text, module=module, path=f"{module}.rs")
    return [f for f in findings if f.rule_id.startswith("RS-WL-")]


def test_corpus_files_parse_without_error() -> None:
    # Guard: if a corpus construct trips tree-sitter-rust 0.24.2, the item walk drops it
    # and "0 findings" would be a false all-clear, not a real result.
    for name in ("command_sink.rs", "clean_commands.rs"):
        text = (_CORPUS / name).read_text(encoding="utf-8")
        assert not has_errors(parse_rust(text)), f"{name} must parse cleanly"


def test_dense_positive_corpus_fires_exactly_the_intended_sinks() -> None:
    text = (_CORPUS / "command_sink.rs").read_text(encoding="utf-8")
    findings = _rs_findings(text, "corpus.command_sink")
    by_rule = {"RS-WL-108": 0, "RS-WL-112": 0}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    # 6 program-injection + 3 shell-injection sinks, 0 from the 3 benign neighbours.
    assert by_rule == {"RS-WL-108": 6, "RS-WL-112": 3}

    # ≤5% false-positive gate, measured over the 12 @trusted functions in the file.
    intended = 9
    total_fns = 12
    false_positives = max(0, len(findings) - intended)
    assert false_positives / total_fns <= 0.05


def test_clean_corpus_is_hard_zero() -> None:
    text = (_CORPUS / "clean_commands.rs").read_text(encoding="utf-8")
    assert _rs_findings(text, "corpus.clean_commands") == []
