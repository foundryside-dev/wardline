"""WP5: the two rules end-to-end through RustAnalyzer (verdict layer).

Drives the analyzer over @trusted-fn specimens and asserts the emitted Finding shape:
RS-WL-108 (program injection, ERROR, cites both lines), RS-WL-112 (shell injection, WARN),
de-confliction single-fire, the modulate-to-NONE suppressions, and pinned taint_path golden
strings (the Rust analog of golden-identity — taint_path serialization is fingerprint-folded).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.finding import Kind, Severity  # noqa: E402
from wardline.rust.analyzer import RustAnalyzer  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Sequence

    from wardline.core.finding import Finding

_TRUSTED = "/// @trusted(level=ASSURED)\n"


def _findings(source: str) -> Sequence[Finding]:
    return RustAnalyzer().analyze_source(source, module="demo.m", path="src/m.rs")


# A stepwise 108 specimen so the constructor (L4) and trigger (L5) are on DISTINCT lines.
_PROGRAM_INJECTION = (
    _TRUSTED + "fn f() {\n"
    '    let t = std::env::var("X").unwrap();\n'
    "    let mut c = Command::new(t);\n"
    "    c.output();\n"
    "}\n"
)
_SHELL_INJECTION = (
    _TRUSTED + "fn f() {\n"
    '    let t = std::env::var("X").unwrap();\n'
    '    Command::new("sh").arg("-c").arg(t).output();\n'
    "}\n"
)


def test_program_injection_fires_error_citing_both_lines() -> None:
    (f,) = _findings(_PROGRAM_INJECTION)
    assert f.rule_id == "RS-WL-108"
    assert f.severity is Severity.ERROR
    assert f.kind is Kind.DEFECT
    assert f.location.line_start == 5  # anchored at the .output() trigger
    assert "line 4" in f.message and "line 5" in f.message  # cites constructor AND trigger
    assert f.qualname == "demo.m.f"


def test_shell_injection_fires_warn_anchored_at_trigger() -> None:
    (f,) = _findings(_SHELL_INJECTION)
    assert f.rule_id == "RS-WL-112"
    assert f.severity is Severity.WARN
    assert f.kind is Kind.DEFECT
    assert f.location.line_start == 4


def test_pinned_taint_path_golden_strings() -> None:
    (prog,) = _findings(_PROGRAM_INJECTION)
    (shell,) = _findings(_SHELL_INJECTION)
    assert prog.properties["taint_path"] == "EXTERNAL_RAW->Command::new(program)@L4->exec@L5"
    assert shell.properties["taint_path"] == "EXTERNAL_RAW->arg->'sh -c'->exec@L4"


def test_de_confliction_tainted_program_with_shell_flag_fires_once() -> None:
    # Tainted program AND a -c flag: exactly ONE finding (RS-WL-108), not two (spec §9.2).
    src = (
        _TRUSTED + "fn f() {\n"
        '    let t = std::env::var("X").unwrap();\n'
        '    Command::new(t).arg("-c").arg(t).output();\n'
        "}\n"
    )
    findings = _findings(src)
    assert [f.rule_id for f in findings] == ["RS-WL-108"]


def test_non_shell_arg_does_not_fire() -> None:
    src = _TRUSTED + 'fn f() {\n    let t = std::env::var("X").unwrap();\n    Command::new("ls").arg(t).output();\n}\n'
    assert _findings(src) == []


def test_unmarked_fn_is_suppressed_by_modulate() -> None:
    # No @trusted marker -> UNKNOWN_RAW tier -> modulate(_, UNKNOWN_RAW) == NONE -> nothing.
    src = 'fn f() {\n    let t = std::env::var("X").unwrap();\n    Command::new("sh").arg("-c").arg(t).output();\n}\n'
    assert _findings(src) == []


def test_guarded_tier_downgrades_severity() -> None:
    # @trusted(level=GUARDED) -> modulate(ERROR, GUARDED) == WARN (the partial-trust downgrade).
    src = (
        "/// @trusted(level=GUARDED)\n"
        "fn f() {\n"
        '    let t = std::env::var("X").unwrap();\n'
        "    let mut c = Command::new(t);\n"
        "    c.output();\n"
        "}\n"
    )
    (f,) = _findings(src)
    assert f.rule_id == "RS-WL-108"
    assert f.severity is Severity.WARN  # downgraded from ERROR
