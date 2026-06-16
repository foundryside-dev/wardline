"""WP4: builder-dataflow L2 — Command receiver tracking + local string taint.

Drives ``analyze_command_dataflow`` over hand-built specimens and asserts the per-trigger
``CommandTrigger`` state (program literal/taint, shell-flag, arg taints keyed by NodeId).
This is the genuinely-new core: taint flows ONLY from known sources / tainted locals
(default-clean, a finding-producer flags provable taint, not fail-closed unknowns), the
``format!`` heuristic matches direct interpolation-arg tokens only, and ``.args`` is an
opaque vec. Specimens seed taint with ``std::env::var(...).unwrap()`` (a vocab source).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.taints import RAW_ZONE  # noqa: E402
from wardline.rust.dataflow import CommandTrigger, analyze_command_dataflow  # noqa: E402
from wardline.rust.nodeid import mint_node_ids  # noqa: E402
from wardline.rust.parse import parse_rust  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Sequence

_SEED = '    let t = std::env::var("X").unwrap();\n'


def _triggers(body_src: str) -> Sequence[CommandTrigger]:
    src = "fn f() {\n" + body_src + "}\n"
    tree = parse_rust(src)
    nmap = mint_node_ids(tree)
    fn = next(c for c in tree.root_node.children if c.type == "function_item")
    body = fn.child_by_field_name("body")
    assert body is not None
    return analyze_command_dataflow(body, nmap)


def _has_raw_arg(trig: CommandTrigger) -> bool:
    return any(taint in RAW_ZONE for _node_id, taint in trig.arg_taints)


# --------------------------------------------------------------------------- #
# Positives
# --------------------------------------------------------------------------- #


def test_stepwise_shell_builder_tracks_program_flag_and_arg_taint() -> None:
    (trig,) = _triggers(
        _SEED + '    let mut c = Command::new("sh");\n    c.arg("-c");\n    c.arg(t);\n    c.output();\n'
    )
    assert trig.program_literal == "sh"
    assert trig.shell_flag_seen is True
    assert _has_raw_arg(trig)


def test_program_injection_marks_program_taint_raw() -> None:
    (trig,) = _triggers(_SEED + "    Command::new(t).output();\n")
    assert trig.program_taint in RAW_ZONE
    assert trig.program_literal is None  # not a string literal


def test_format_string_carries_taint_to_the_shell_arg() -> None:
    (trig,) = _triggers(_SEED + '    let s = format!("rm {}", t);\n    Command::new("sh").arg("-c").arg(s).output();\n')
    assert trig.program_literal == "sh"
    assert trig.shell_flag_seen is True
    assert _has_raw_arg(trig)


def test_two_hop_format_propagation() -> None:
    (trig,) = _triggers(
        _SEED
        + '    let s = format!("{}", t);\n    let s2 = format!("{}", s);\n'
        + '    Command::new("sh").arg("-c").arg(s2).output();\n'
    )
    assert _has_raw_arg(trig)


# --------------------------------------------------------------------------- #
# Negatives — the FP guards (the rule decides; the dataflow state must be right)
# --------------------------------------------------------------------------- #


def test_non_shell_program_has_no_shell_flag() -> None:
    (trig,) = _triggers(_SEED + '    Command::new("ls").arg(t).output();\n')
    assert trig.program_literal == "ls"
    assert trig.shell_flag_seen is False
    assert _has_raw_arg(trig)  # the arg IS tainted; the rule won't fire (non-shell, no -c)


def test_shell_without_dash_c_sees_no_shell_flag() -> None:
    (trig,) = _triggers(_SEED + '    Command::new("sh").arg(t).output();\n')
    assert trig.program_literal == "sh"
    assert trig.shell_flag_seen is False  # RS-WL-112 must not fire without the -c flag


def test_dot_args_is_an_opaque_vec_no_arg_taint() -> None:
    (trig,) = _triggers(_SEED + '    Command::new("ls").args(t).output();\n')
    assert trig.shell_flag_seen is False
    assert not _has_raw_arg(trig)  # .args is opaque (a vec) — not introspected in slice 1


def test_sanitizer_is_an_accepted_bounded_fp() -> None:
    # The sanitizer is invisible to the dataflow, so the arg stays tainted (a bounded
    # FP the corpus measures against the <=5% gate). Pins current behavior.
    (trig,) = _triggers(_SEED + '    Command::new("sh").arg("-c").arg(format!("echo {}", sanitize(t))).output();\n')
    assert _has_raw_arg(trig)


def test_clean_literal_format_propagates_no_taint() -> None:
    (trig,) = _triggers(
        _SEED + '    let s = format!("rm {}", "ls");\n    Command::new("sh").arg("-c").arg(s).output();\n'
    )
    assert not _has_raw_arg(trig)


def test_captured_identifier_format_is_a_documented_fn() -> None:
    # format!("rm {t}") has no explicit interpolation arg token — the captured `{t}` is
    # invisible to the direct-arg heuristic, so `s` stays clean (documented FN).
    (trig,) = _triggers(_SEED + '    let s = format!("rm {t}");\n    Command::new("sh").arg("-c").arg(s).output();\n')
    assert not _has_raw_arg(trig)


def test_variable_bound_shell_name_is_a_documented_fn() -> None:
    # `let s = "sh"; Command::new(s)` — the program is an identifier, not a string
    # literal, so program_literal is None and RS-WL-112 cannot see it is a shell (FN).
    (trig,) = _triggers(_SEED + '    let s = "sh";\n    Command::new(s).arg("-c").arg(t).output();\n')
    assert trig.program_literal is None
    assert _has_raw_arg(trig)  # the arg is still tainted; only the shell-ness is lost


def test_let_rebind_clears_a_stale_command_builder() -> None:
    # A shadowing `let` re-binds the name to a NON-command; the old `_CmdAccum` must not
    # survive and have a later `.output()` falsely attributed to it. `_let` mirrors the
    # taint clear (`_local_taints.pop`) and must mirror the builder clear too — otherwise
    # `c.output()` emits a phantom trigger carrying the FIRST binding's program taint,
    # surfacing as a false RS-WL-108 that fires at ERROR and trips the gate.
    trigs = _triggers(
        _SEED
        + "    let c = Command::new(t);\n"  # c is a tainted-program builder...
        + "    let c = make_thing();\n"  # ...then shadowed by a non-command
        + "    c.output();\n"  # this terminal must NOT reconstruct the stale builder
    )
    assert list(trigs) == []  # the rebound `c` is not a tracked command -> zero triggers


def test_plain_command_builder_still_fires_after_the_rebind_fix() -> None:
    # No-regression guard: a builder bound once and never shadowed still reconstructs.
    (trig,) = _triggers(_SEED + "    let c = Command::new(t);\n    c.output();\n")
    assert trig.program_taint in RAW_ZONE


# --------------------------------------------------------------------------- #
# Format-family macros — write!/writeln!/format_args! value-taint (issue 8a34187941)
# --------------------------------------------------------------------------- #


def test_write_macro_value_taint_propagates() -> None:
    # write!(dst, "fmt", t) — value-taint = worst over the format args (the writer `dst` is
    # the destination, not a contributor). Modelled like format!'s result.
    (trig,) = _triggers(
        _SEED + '    let s = write!(dst, "rm {}", t);\n    Command::new("sh").arg("-c").arg(s).output();\n'
    )
    assert _has_raw_arg(trig)


def test_writeln_macro_value_taint_propagates() -> None:
    (trig,) = _triggers(
        _SEED + '    let s = writeln!(dst, "rm {}", t);\n    Command::new("sh").arg("-c").arg(s).output();\n'
    )
    assert _has_raw_arg(trig)


def test_format_args_macro_value_taint_propagates() -> None:
    # format_args! behaves like format! (no writer) and is the genuinely-realistic case:
    # it returns `Arguments` consumed format-like.
    (trig,) = _triggers(
        _SEED + '    let s = format_args!("rm {}", t);\n    Command::new("sh").arg("-c").arg(s).output();\n'
    )
    assert _has_raw_arg(trig)


def test_write_writer_arg_is_not_a_taint_contributor() -> None:
    # The leading writer of write!/writeln! is the destination, not a value contributor:
    # a tainted writer with clean format args must NOT taint the formatted value.
    (trig,) = _triggers(
        _SEED + '    let s = write!(t, "rm {}", "ls");\n    Command::new("sh").arg("-c").arg(s).output();\n'
    )
    assert not _has_raw_arg(trig)


def test_clean_format_args_propagates_no_taint() -> None:
    # No-FP guard: format_args! over only literals stays clean.
    (trig,) = _triggers(
        _SEED + '    let s = format_args!("rm {}", "ls");\n    Command::new("sh").arg("-c").arg(s).output();\n'
    )
    assert not _has_raw_arg(trig)
