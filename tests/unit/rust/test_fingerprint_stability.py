"""Rust fingerprint stability — the wlfp2 move-stability contract for RS-WL-*.

The Rust analogue of ``tests/unit/core/test_fingerprint_stability.py`` (identity
keystone panel, rust-sp2-2026-06-10). The fingerprint inputs are
``(rule_id, path, qualname, taint_path)`` — ``line_start`` is NOT hashed (wlfp2,
wardline-8654423823), so the RS-WL-* discriminator must be ENTITY-RELATIVE:

  * **Whole-entity moves** — a comment at the top of the file, a comment directly
    above the function, an unrelated sibling ``fn`` added ABOVE — shift every
    absolute line AND every pre-order ``NodeId`` below them, but keep the
    fingerprint, because both the line and the NodeId fold as deltas against the
    containing entity's own anchor (``line - entity_line_start``,
    ``trigger_node_id - entity_node_id``).
  * **In-entity edits** — a statement inserted INSIDE the function ABOVE the
    trigger — DO change the fingerprint (the trigger's offset relative to its own
    fn moved). Entity-relative, not move-stable in the strong sense: the contract
    is identical-source -> identical-fingerprint, and that edit is not identical
    source. Asserted ``!=`` here to document the accepted boundary.
  * **Same-line twins** — two distinct triggers on one physical line keep DISTINCT
    fingerprints (the relative-NodeId fold is the sole same-line discriminant; see
    also test_rules.test_two_commands_on_one_line_get_distinct_fingerprints).

Plus the FIX-4 class-3 route repro (the panel's exp_e4e): a manifest-less tree's
identity is relpath-pure — renaming the scan-root DIRECTORY must not rekey.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.config import WardlineConfig  # noqa: E402
from wardline.rust.analyzer import RustAnalyzer  # noqa: E402

_TRUSTED = "/// @trusted(level=ASSURED)\n"

# One RS-WL-108 (tainted program) + one RS-WL-112 (tainted arg on a `sh -c` line),
# in separate fns so each rule's fingerprint is tracked independently.
_BASE = (
    _TRUSTED
    + "fn prog() {\n"
    + '    let t = std::env::var("X").unwrap();\n'
    + "    Command::new(t).output();\n"
    + "}\n"
    + _TRUSTED
    + "fn shell() {\n"
    + '    let t = std::env::var("X").unwrap();\n'
    + '    Command::new("sh").arg("-c").arg(t).output();\n'
    + "}\n"
)


def _fingerprints(source: str) -> dict[str, str]:
    findings = RustAnalyzer().analyze_source(source, module="demo.m", path="src/m.rs")
    out = {f.rule_id: f.fingerprint for f in findings if f.rule_id.startswith("RS-WL-")}
    assert set(out) == {"RS-WL-108", "RS-WL-112"}, f"fixture must fire both rules, got {sorted(out)}"
    return out


def test_comment_at_top_of_file_keeps_both_fingerprints() -> None:
    # Shifts every absolute line AND every pre-order NodeId in the file; both fold
    # entity-relative, so the join key must not churn (the panel's critical repro).
    base = _fingerprints(_BASE)
    shifted = _fingerprints("// release notes header\n\n" + _BASE)
    assert base == shifted


def test_comment_directly_above_the_function_keeps_both_fingerprints() -> None:
    base = _fingerprints(_BASE)
    shifted = _fingerprints(_BASE.replace(_TRUSTED + "fn prog", "// reviewed 2026-06-10\n" + _TRUSTED + "fn prog"))
    assert base == shifted


def test_unrelated_sibling_fn_added_above_keeps_both_fingerprints() -> None:
    # A whole sibling item above shifts NodeIds by MANY (not one) — the delta, not
    # the absolute index, is what must be stable.
    base = _fingerprints(_BASE)
    shifted = _fingerprints("fn helper() -> i32 {\n    1 + 2\n}\n" + _BASE)
    assert base == shifted


def test_statement_inserted_inside_the_fn_above_the_trigger_changes_fingerprint() -> None:
    # The accepted entity-relative limitation (mirrors the Python contract): an edit
    # INSIDE the entity above the trigger moves its relative offset -> rekey.
    base = _fingerprints(_BASE)
    mutated = _fingerprints(_BASE.replace("fn prog() {\n", "fn prog() {\n    let _pad = 0;\n"))
    assert base["RS-WL-108"] != mutated["RS-WL-108"]


def test_two_same_line_triggers_keep_distinct_fingerprints() -> None:
    # The discriminator's original purpose survives the rekey: identical
    # (rule, path, qualname, relative line) twins split on the relative NodeId.
    src = (
        _TRUSTED
        + "fn f() {\n"
        + '    let t = std::env::var("X").unwrap();\n'
        + "    Command::new(t).output(); Command::new(t).spawn();\n"
        + "}\n"
    )
    findings = RustAnalyzer().analyze_source(src, module="demo.m", path="src/m.rs")
    fps = [f.fingerprint for f in findings if f.rule_id == "RS-WL-108"]
    assert len(fps) == 2 and len(set(fps)) == 2


def test_display_taint_path_keeps_absolute_lines() -> None:
    # properties["taint_path"] is the DISPLAY surface — human-readable, absolute lines
    # exactly as before the rekey. Only the fingerprint discriminator went relative.
    findings = RustAnalyzer().analyze_source(_BASE, module="demo.m", path="src/m.rs")
    by_rule = {f.rule_id: f for f in findings if f.rule_id.startswith("RS-WL-")}
    assert by_rule["RS-WL-108"].properties["taint_path"] == "EXTERNAL_RAW->Command::new(program)@L4->exec@L4"
    assert by_rule["RS-WL-112"].properties["taint_path"] == "EXTERNAL_RAW->arg->'sh -c'->exec@L9"


# --- FIX 4: class-3 (no crate root) identity is relpath-pure -----------------


def _scan_fingerprints(root: Path) -> dict[str, tuple[str, str]]:
    files = sorted(root.rglob("*.rs"))
    findings = RustAnalyzer().analyze(files, WardlineConfig(), root=root)
    return {f.rule_id: (f.qualname or "", f.fingerprint) for f in findings if f.rule_id.startswith("RS-WL-")}


def test_class3_fingerprints_survive_a_scan_root_directory_rename(tmp_path: Path) -> None:
    # The panel's exp_e4e repro: same content, two scan-root directory NAMES. A
    # manifest-less (class-3) tree's crate segment is the CONSTANT "crate", so the
    # qualname/fingerprint must be byte-identical across the rename.
    src = _TRUSTED + 'fn run() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n'
    for name in ("alpha", "beta"):
        d = tmp_path / name / "bin"
        d.mkdir(parents=True)
        (d / "app.rs").write_text(src, encoding="utf-8")

    alpha = _scan_fingerprints(tmp_path / "alpha")
    beta = _scan_fingerprints(tmp_path / "beta")
    assert alpha["RS-WL-108"] == beta["RS-WL-108"]
    # And the route is the decided class-3 shape: constant crate segment + #out branding.
    assert alpha["RS-WL-108"][0] == "crate.#out.bin.app.run"
