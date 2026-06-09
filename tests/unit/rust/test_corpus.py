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


# The 9 intended sink functions (by qualname leaf), split by rule. The 3 benign
# neighbours (benign_all_literal / benign_nonshell_tainted_arg / benign_rebound_to_clean)
# must NOT appear — they are the false-positive probes.
_EXPECTED_108 = frozenset(
    {
        "sink_env_var_output",
        "sink_env_var_os_status",
        "sink_fs_read_to_string_try",
        "sink_fs_read_await",
        "sink_return_position",
        "sink_stepwise",
    }
)
_EXPECTED_112 = frozenset({"sink_sh_dash_c", "sink_bin_bash_dash_c", "sink_powershell_command"})


def test_dense_positive_corpus_fires_exactly_the_intended_sinks() -> None:
    text = (_CORPUS / "command_sink.rs").read_text(encoding="utf-8")
    findings = _rs_findings(text, "corpus.command_sink")

    # Per-FUNCTION attribution, not just aggregate counts: assert the exact SET of functions
    # that fired each rule. This catches a compensating double-regression (a benign fn wrongly
    # firing while a real sink stops) that an aggregate {108:6, 112:3} count would mask — and
    # subsumes the "0 false positives over 12 @trusted fns" property (any benign_* fire fails).
    fired_108 = {f.qualname.rsplit(".", 1)[-1] for f in findings if f.rule_id == "RS-WL-108"}
    fired_112 = {f.qualname.rsplit(".", 1)[-1] for f in findings if f.rule_id == "RS-WL-112"}
    assert fired_108 == _EXPECTED_108
    assert fired_112 == _EXPECTED_112
    # No finding attributes to any benign probe (the explicit ≤5% → 0% FP floor).
    benign = {"benign_all_literal", "benign_nonshell_tainted_arg", "benign_rebound_to_clean"}
    assert {f.qualname.rsplit(".", 1)[-1] for f in findings} & benign == set()


def test_clean_corpus_is_hard_zero() -> None:
    text = (_CORPUS / "clean_commands.rs").read_text(encoding="utf-8")
    assert _rs_findings(text, "corpus.clean_commands") == []
