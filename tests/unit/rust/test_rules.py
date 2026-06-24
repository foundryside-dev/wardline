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


_SEED = '    let t = std::env::var("X").unwrap();\n'


@pytest.mark.parametrize(
    "terminal",
    [
        "Command::new(t).output();",  # baseline
        "Command::new(t).output()?;",  # ? operator — the dominant Rust spawn idiom
        "Command::new(t).output().await;",  # async
        "Command::new(t).output().unwrap();",  # call wrapper
        "return Command::new(t).output();",  # return position
    ],
)
def test_program_injection_fires_through_idiomatic_terminators(terminal: str) -> None:
    # Regression: ?/await/return-wrapped Command calls were silently dropped (the widest
    # Tier-A hole the WP4+WP5 panel found). Each must still fire RS-WL-108.
    src = _TRUSTED + "fn f() {\n" + _SEED + "    " + terminal + "\n}\n"
    assert [f.rule_id for f in _findings(src)] == ["RS-WL-108"]


def test_program_injection_fires_in_tail_position() -> None:
    # A block's tail expression (no trailing `;`) is a bare call_expression child, not an
    # expression_statement — it was dropped. Must fire.
    src = _TRUSTED + "fn f() {\n" + _SEED + "    Command::new(t).output()\n}\n"
    assert [f.rule_id for f in _findings(src)] == ["RS-WL-108"]


@pytest.mark.parametrize("program", ["/bin/sh", "/usr/bin/bash", "powershell"])
def test_shell_injection_recognizes_path_qualified_and_powershell_shells(program: str) -> None:
    flag = "-Command" if program == "powershell" else "-c"
    src = _TRUSTED + "fn f() {\n" + _SEED + f'    Command::new("{program}").arg("{flag}").arg(t).output();\n}}\n'
    assert [f.rule_id for f in _findings(src)] == ["RS-WL-112"]


def test_rebind_to_a_clean_value_clears_stale_taint() -> None:
    # Regression: a local re-bound to a provably-clean literal must drop its prior taint
    # (a false positive the analyzer has full information to avoid).
    src = _TRUSTED + "fn f() {\n" + _SEED + '    let t = "safe";\n    Command::new(t).output();\n}\n'
    assert _findings(src) == []


def test_assignment_reassign_to_clean_command_clears_stale_tainted_builder() -> None:
    # An *assignment* re-bind (`cmd = ...;`, not a `let`) must clear a tracked builder the
    # same way `let` does. Here `cmd` is rebuilt with a CLEAN literal program, so `cmd.output()`
    # must reconstruct the clean builder — no RS-WL-108. Before the fix the assignment statement
    # was dropped (its node is an assignment_expression, not a call), leaving the stale tainted
    # L4 builder and firing a phantom RS-WL-108 ERROR (FP at the gating severity) on safe code.
    src = (
        _TRUSTED + "fn f() {\n" + _SEED + "    let mut cmd = Command::new(t);\n"
        '    cmd = Command::new("/usr/bin/ls");\n'
        '    cmd.arg("-la");\n'
        "    cmd.output();\n}\n"
    )
    assert _findings(src) == []


def test_assignment_reassign_to_tainted_command_fires() -> None:
    # The inverse: a CLEAN builder reassigned to a tainted-program builder must now fire (the
    # actually-attacker-controlled exec). Before the fix this was a silent false negative.
    src = (
        _TRUSTED + "fn f() {\n" + _SEED + '    let mut cmd = Command::new("/usr/bin/ls");\n'
        "    cmd = Command::new(t);\n"
        "    cmd.output();\n}\n"
    )
    assert [f.rule_id for f in _findings(src)] == ["RS-WL-108"]


def test_shadow_rebind_extending_command_builder_still_fires() -> None:
    # Rust evaluates the initializer before shadowing the old binding, so the RHS `cmd`
    # is still the tainted Command builder and the later terminal must remain visible.
    src = (
        _TRUSTED + "fn f() {\n" + _SEED + "    let cmd = Command::new(t);\n"
        '    let cmd = cmd.arg("--flag");\n'
        "    cmd.output();\n}\n"
    )
    assert [f.rule_id for f in _findings(src)] == ["RS-WL-108"]


def test_assignment_reassign_to_non_command_drops_the_builder() -> None:
    # Reassigning a Command-bound name to a non-command must drop the tracked builder entirely;
    # a later `.output()` on it is a method call on some other value, not a phantom spawn.
    src = (
        _TRUSTED + "fn f() {\n" + _SEED + "    let mut cmd = Command::new(t);\n"
        "    cmd = make_safe_command();\n"
        "    cmd.output();\n}\n"
    )
    assert _findings(src) == []


@pytest.mark.parametrize(
    "ctor",
    [
        "tokio::process::Command::new(t).output().await",  # the dominant async command sink
        "async_process::Command::new(t).output().await",  # smol/async-std ecosystem
    ],
)
def test_async_ecosystem_command_sinks_fire(ctor: str) -> None:
    # The crate qualifier must ADMIT the declared async-runtime Command sinks, not just std.
    # tokio::process::Command genuinely spawns an OS process, so a tainted program there is a
    # true RS-WL-108 — losing it (an FN) would blind the tool to the most common real sink.
    src = _TRUSTED + "fn f() {\n" + _SEED + f"    {ctor};\n}}\n"
    assert [f.rule_id for f in _findings(src)] == ["RS-WL-108"]


def test_foreign_crate_command_new_does_not_fire() -> None:
    # The vocab declares the sink for crate `std` (std::process::Command::new). A DIFFERENT
    # crate's `Command::new` (e.g. a user CQRS/command-bus type) spawns no OS process and must
    # not fire RS-WL-108 at ERROR. Matching is crate-consistent (a trailing segment-suffix of
    # the crate-qualified std path), so an explicit foreign root is rejected.
    src = _TRUSTED + "fn f() {\n" + _SEED + "    mycrate::Command::new(t).output();\n}\n"
    assert _findings(src) == []


@pytest.mark.parametrize(
    "ctor",
    [
        "Command::new(t)",  # bare (use std::process::Command) — the documented aliasing
        "process::Command::new(t)",  # use std::process
        "std::process::Command::new(t)",  # fully qualified
    ],
)
def test_std_command_new_aliases_still_fire(ctor: str) -> None:
    # No-regression: every crate-consistent spelling of the std sink must still fire.
    src = _TRUSTED + "fn f() {\n" + _SEED + f"    {ctor}.output();\n}}\n"
    assert [f.rule_id for f in _findings(src)] == ["RS-WL-108"]


def test_foreign_crate_env_var_is_not_a_taint_source() -> None:
    # The crate qualifier is honored on the SOURCE side too: a non-std `env::var` (some other
    # crate's like-named fn) is not the std external-input source, so a program built from it
    # is clean and RS-WL-108 must not fire.
    src = _TRUSTED + 'fn f() {\n    let t = myconfig::env::var("X").unwrap();\n    Command::new(t).output();\n}\n'
    assert _findings(src) == []


def test_a_typoed_trusted_marker_emits_gate_eligible_diagnostic() -> None:
    # A malformed @trusted level must fail closed for that fn, not crash the scan, and
    # must not disappear silently: otherwise a typo can turn a trusted sink green.
    src = "/// @trusted(level=BOGUS)\nfn f() {\n" + _SEED + "    Command::new(t).output();\n}\n"
    (diag,) = _findings(src)
    assert diag.rule_id == "WLN-ENGINE-RUST-INVALID-TRUST-MARKER"
    assert diag.severity is Severity.ERROR
    assert diag.kind is Kind.DEFECT
    assert diag.location.path == "src/m.rs"
    assert diag.location.line_start == 2
    assert diag.qualname == "demo.m.f"
    assert "invalid level 'BOGUS'" in diag.message


def test_two_commands_on_one_line_get_distinct_fingerprints() -> None:
    # The no-collision invariant: two DISTINCT triggers on the same physical line (identical
    # taint_path) must not share a fingerprint (the NodeId disambiguates).
    src = _TRUSTED + "fn f() {\n" + _SEED + "    Command::new(t).output(); Command::new(t).spawn();\n}\n"
    fps = [f.fingerprint for f in _findings(src)]
    assert len(fps) == 2 and len(set(fps)) == 2


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
