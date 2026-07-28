"""CLAUDE.md -> AGENTS.md redirect routing, and the conservative removal path.

Cites weft-6a1fdb0192 (C-20). A project whose CLAUDE.md is merely an @-import of
AGENTS.md keeps ONE source of agent context; wardline maintains its block in
AGENTS.md alone and migrates any legacy CLAUDE.md block out.

Semantics are ported from the normative legis implementation
(``src/legis/install.py``, commit 4255cf4), so the behaviour these tests pin is
deliberately identical across the federation — including the one accepted
limitation (a markdown-fenced ``@AGENTS.md`` example still triggers).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.install.block import (
    claude_md_redirects_to_agents_md,
    inject_block,
    inject_block_for_project,
    instruction_targets,
    remove_block,
    render_block,
)
from wardline.install.doctor import CheckResult, check_install, repair_install

# A co-resident sibling tool's managed block (filigree), used to assert wardline
# never deletes, truncates, or spans across a foreign block (weft C-4).
_FOREIGN = "<!-- filigree:instructions:v3.0:abcd1234 -->\nfiligree body — DO NOT TOUCH\n<!-- /filigree:instructions -->"
_OPEN = "<!-- wardline:instructions:v1:deadbeef -->"
_CLOSE = "<!-- /wardline:instructions -->"

_REDIRECT = "# Project\n\nAll agent context lives in AGENTS.md.\n\n@AGENTS.md\n"


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    ["@AGENTS.md", "@./AGENTS.md", "@agents.md", "@AGENTS.MD", "  @AGENTS.md  "],
)
def test_redirect_spellings_detected(tmp_path: Path, line: str) -> None:
    _write(tmp_path / "CLAUDE.md", f"# Project\n\n{line}\n")
    assert claude_md_redirects_to_agents_md(tmp_path) is True


@pytest.mark.parametrize(
    "line",
    [
        "See @AGENTS.md for details",  # not *solely* an import
        "@AGENTS.md.bak",  # a different file
        "@/AGENTS.md",  # absolute path names a different location
        "@AGENTS.markdown",
        "AGENTS.md",  # no @-import at all
    ],
)
def test_non_redirect_lines_do_not_trigger(tmp_path: Path, line: str) -> None:
    _write(tmp_path / "CLAUDE.md", f"# Project\n\n{line}\n")
    assert claude_md_redirects_to_agents_md(tmp_path) is False


def test_redirect_quoted_inside_a_foreign_block_does_not_trigger(tmp_path: Path) -> None:
    """A sibling's block documenting `@AGENTS.md` is not this project's redirect.

    Managed blocks are masked before scanning, so text a block merely *quotes*
    can never be read as free-standing project prose.
    """
    quoted = (
        "<!-- filigree:instructions:v3.0:abcd1234 -->\n"
        "Example: put\n@AGENTS.md\nin CLAUDE.md.\n"
        "<!-- /filigree:instructions -->\n"
    )
    _write(tmp_path / "CLAUDE.md", f"# Project\n\n{quoted}")
    assert claude_md_redirects_to_agents_md(tmp_path) is False


def test_redirect_quoted_inside_our_own_block_does_not_trigger(tmp_path: Path) -> None:
    """Own-namespace blocks are masked too — we must not self-trigger."""
    _write(tmp_path / "CLAUDE.md", f"# Project\n\n{_OPEN}\nsee @AGENTS.md\n{_CLOSE}\n")
    assert claude_md_redirects_to_agents_md(tmp_path) is False


def test_unclosed_managed_block_masks_to_eof(tmp_path: Path) -> None:
    """We cannot prove where an unclosed block ends, so nothing past it is prose."""
    _write(tmp_path / "CLAUDE.md", f"# Project\n\n{_OPEN}\nbody\n\n@AGENTS.md\n")
    assert claude_md_redirects_to_agents_md(tmp_path) is False


def test_fenced_markdown_example_still_triggers_known_limitation(tmp_path: Path) -> None:
    """Accepted as spec, matching the sibling implementations.

    Masking covers *managed blocks* only, not plain markdown fences, so a
    documented `@AGENTS.md` example inside a ``` fence reads as a redirect.
    Uniform federation behaviour beats a wardline-only refinement; this test
    pins the limitation so a future divergence is a deliberate decision.
    """
    _write(tmp_path / "CLAUDE.md", "# Project\n\nTo redirect, write:\n\n```\n@AGENTS.md\n```\n")
    assert claude_md_redirects_to_agents_md(tmp_path) is True


# ---------------------------------------------------------------------------
# Fail-safe: anything unreadable is NO redirect (dual-write unchanged)
# ---------------------------------------------------------------------------


def test_absent_claude_md_is_no_redirect(tmp_path: Path) -> None:
    assert claude_md_redirects_to_agents_md(tmp_path) is False
    assert instruction_targets(tmp_path) == (["CLAUDE.md", "AGENTS.md"], [])


def test_symlinked_claude_md_is_no_redirect(tmp_path: Path) -> None:
    """wardline's path guard *raises* where legis's returns an error object.

    If that raise escaped, a symlinked CLAUDE.md would propagate an exception
    instead of failing safe to no-redirect, and `wardline install` would abort.
    """
    outside = _write(tmp_path / "outside.md", _REDIRECT)
    (tmp_path / "CLAUDE.md").symlink_to(outside)
    assert claude_md_redirects_to_agents_md(tmp_path) is False


def test_non_utf8_claude_md_is_no_redirect(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_bytes(b"# Project\n\n\xff\xfe@AGENTS.md\n")
    assert claude_md_redirects_to_agents_md(tmp_path) is False


def test_directory_named_claude_md_is_no_redirect(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").mkdir()
    assert claude_md_redirects_to_agents_md(tmp_path) is False


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def test_redirect_writes_block_to_agents_md_only(tmp_path: Path) -> None:
    _write(tmp_path / "CLAUDE.md", _REDIRECT)
    assert instruction_targets(tmp_path) == (["AGENTS.md"], ["CLAUDE.md"])

    inject_block_for_project(tmp_path)

    assert "wardline:instructions:" in (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert "wardline:instructions:" not in (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")


def test_redirect_creates_absent_agents_md(tmp_path: Path) -> None:
    _write(tmp_path / "CLAUDE.md", _REDIRECT)
    assert not (tmp_path / "AGENTS.md").exists()

    inject_block_for_project(tmp_path)

    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8").strip() == render_block()


def test_legacy_claude_md_block_migrates_out(tmp_path: Path) -> None:
    claude = tmp_path / "CLAUDE.md"
    _write(claude, _REDIRECT)
    inject_block(claude)  # a legacy block from before the redirect existed
    assert "wardline:instructions:" in claude.read_text(encoding="utf-8")

    inject_block_for_project(tmp_path)

    text = claude.read_text(encoding="utf-8")
    assert "wardline:instructions:" not in text
    assert "@AGENTS.md" in text, "the redirect line itself must survive migration"
    assert "wardline:instructions:" in (tmp_path / "AGENTS.md").read_text(encoding="utf-8")


def test_migration_preserves_foreign_blocks_and_the_redirect_line(tmp_path: Path) -> None:
    claude = tmp_path / "CLAUDE.md"
    _write(claude, f"# Project\n\n@AGENTS.md\n\n{_FOREIGN}\n")
    inject_block(claude)

    inject_block_for_project(tmp_path)

    text = claude.read_text(encoding="utf-8")
    assert _FOREIGN in text, "a co-resident sibling's block must never be touched"
    assert "@AGENTS.md" in text
    assert "wardline:instructions:" not in text


def test_no_redirect_leaves_dual_write_unchanged(tmp_path: Path) -> None:
    _write(tmp_path / "CLAUDE.md", "# Project\n\nNo redirect here.\n")

    inject_block_for_project(tmp_path)

    assert "wardline:instructions:" in (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert "wardline:instructions:" in (tmp_path / "AGENTS.md").read_text(encoding="utf-8")


def test_redirect_routing_is_idempotent_and_byte_stable(tmp_path: Path) -> None:
    claude = tmp_path / "CLAUDE.md"
    _write(claude, _REDIRECT)
    inject_block(claude)

    inject_block_for_project(tmp_path)
    first = (claude.read_bytes(), (tmp_path / "AGENTS.md").read_bytes())

    for _ in range(3):
        inject_block_for_project(tmp_path)
        assert (claude.read_bytes(), (tmp_path / "AGENTS.md").read_bytes()) == first


def test_elspeth_style_redirect_is_detected(tmp_path: Path) -> None:
    """The real-world exemplar: prose paragraph then a bare @AGENTS.md line."""
    _write(
        tmp_path / "CLAUDE.md",
        "# ELSPETH\n\n"
        "All shared agent context for this repository lives in AGENTS.md — the single\n"
        "source of truth for Claude Code, Codex, and any other agent.\n\n"
        "@AGENTS.md\n",
    )
    assert claude_md_redirects_to_agents_md(tmp_path) is True


# ---------------------------------------------------------------------------
# CLI opt-outs must skip work, never erase it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("claude_md", [True, False])
@pytest.mark.parametrize("agents_md", [True, False])
def test_flag_combinations_without_a_redirect_write_exactly_what_is_opted_in(
    tmp_path: Path, claude_md: bool, agents_md: bool
) -> None:
    """Without a redirect the flags keep their pre-C-20 meaning: skip that file.

    Pins all four combinations so the routing rewrite cannot silently change a
    non-redirect opt-out, and asserts the migration path stays dormant — with no
    redirect there is nothing to migrate, whatever the flags say.
    """
    _write(tmp_path / "CLAUDE.md", "# Project\n\nNo redirect.\n")

    inject_block_for_project(tmp_path, claude_md=claude_md, agents_md=agents_md)

    assert ("wardline:instructions:" in (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")) is claude_md
    assert (tmp_path / "AGENTS.md").exists() is agents_md


def test_both_opt_outs_under_a_redirect_do_nothing_at_all(tmp_path: Path) -> None:
    claude = tmp_path / "CLAUDE.md"
    _write(claude, _REDIRECT)
    before = claude.read_bytes()

    assert inject_block_for_project(tmp_path, claude_md=False, agents_md=False) == []

    assert claude.read_bytes() == before
    assert not (tmp_path / "AGENTS.md").exists()


def test_no_agents_md_under_redirect_does_not_strand_the_project(tmp_path: Path) -> None:
    """The write that replaces the migrated block never ran, so do not migrate.

    Without this gate the block would be deleted from CLAUDE.md while nothing
    wrote it to AGENTS.md — an opt-out that destroys guidance.
    """
    claude = tmp_path / "CLAUDE.md"
    _write(claude, _REDIRECT)
    inject_block(claude)

    results = inject_block_for_project(tmp_path, agents_md=False)

    assert results == []
    assert "wardline:instructions:" in claude.read_text(encoding="utf-8")
    assert not (tmp_path / "AGENTS.md").exists()


def test_no_claude_md_under_redirect_suppresses_migration(tmp_path: Path) -> None:
    """ "Skip the CLAUDE.md instruction block" plainly means: do not touch that file."""
    claude = tmp_path / "CLAUDE.md"
    _write(claude, _REDIRECT)
    inject_block(claude)

    inject_block_for_project(tmp_path, claude_md=False)

    assert "wardline:instructions:" in claude.read_text(encoding="utf-8")
    assert "wardline:instructions:" in (tmp_path / "AGENTS.md").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Removal is more conservative than injection
# ---------------------------------------------------------------------------


def test_remove_block_on_absent_file_is_a_success_noop(tmp_path: Path) -> None:
    ok, message = remove_block(tmp_path / "CLAUDE.md")
    assert ok is True
    assert "no wardline block" in message


def test_remove_block_with_no_own_block_is_a_success_noop(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"# Project\n\n{_FOREIGN}\n")
    before = f.read_bytes()

    ok, message = remove_block(f)

    assert ok is True
    assert "no wardline block" in message
    assert f.read_bytes() == before


def test_remove_block_refuses_split_brain(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"{_OPEN}\nfirst\n{_CLOSE}\n\n{_OPEN}\nsecond\n{_CLOSE}\n")
    before = f.read_bytes()

    ok, message = remove_block(f)

    assert ok is False
    assert "split brain" in message
    assert f.read_bytes() == before, "a refusal must delete nothing"


def test_remove_block_refuses_unclosed_own_block(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"# Project\n\n{_OPEN}\nbody with no close\n\ntrailing user text\n")
    before = f.read_bytes()

    ok, message = remove_block(f)

    assert ok is False
    assert "unclosed" in message
    assert f.read_bytes() == before


def test_remove_block_refuses_close_beyond_a_foreign_fence(tmp_path: Path) -> None:
    """A naive open..close cut here would swallow the sibling's block."""
    f = _write(tmp_path / "CLAUDE.md", f"{_OPEN}\nbody\n\n{_FOREIGN}\n\n{_CLOSE}\n")
    before = f.read_bytes()

    ok, message = remove_block(f)

    assert ok is False
    assert f.read_bytes() == before
    assert _FOREIGN in f.read_text(encoding="utf-8")


def test_remove_block_ignores_own_marker_shielded_by_unclosed_foreign(tmp_path: Path) -> None:
    """An own marker we cannot prove is ours is not ours."""
    f = _write(tmp_path / "CLAUDE.md", f"<!-- filigree:instructions:v3:aa -->\nsibling\n\n{_OPEN}\nbody\n{_CLOSE}\n")
    before = f.read_bytes()

    ok, message = remove_block(f)

    assert ok is True
    assert "no wardline block" in message
    assert f.read_bytes() == before


def test_remove_block_unlinks_a_file_holding_only_our_block(tmp_path: Path) -> None:
    """The symmetric inverse of inject_block's create-on-missing."""
    f = tmp_path / "CLAUDE.md"
    inject_block(f)

    ok, message = remove_block(f)

    assert ok is True
    assert not f.exists()
    assert "held nothing but" in message


def test_remove_block_preserves_surrounding_content(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", "# Project\n\nBefore.\n")
    inject_block(f)
    _write(f, f.read_text(encoding="utf-8") + "\nAfter.\n")

    ok, _ = remove_block(f)

    text = f.read_text(encoding="utf-8")
    assert ok is True
    assert "Before." in text
    assert "After." in text
    assert "wardline:instructions:" not in text
    assert "\n\n\n" not in text, "the seam should collapse to a single blank line"


def test_remove_block_rejects_a_symlinked_target(tmp_path: Path) -> None:
    outside = _write(tmp_path / "outside.md", "outside\n")
    target = tmp_path / "CLAUDE.md"
    target.symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        remove_block(target)

    assert outside.read_text(encoding="utf-8") == "outside\n"


# ---------------------------------------------------------------------------
# doctor: three states for CLAUDE.md, and a repair that migrates
# ---------------------------------------------------------------------------


def _claude_row(root: Path) -> CheckResult:
    return next(check for check in check_install(root) if check.name == "CLAUDE.md")


def test_doctor_reports_absent_block_healthy_under_redirect(tmp_path: Path) -> None:
    """Absence-in-CLAUDE.md is healthy when CLAUDE.md redirects to AGENTS.md.

    Reporting "missing" would send `--repair` to re-inject a block the project
    deliberately does not want.
    """
    _write(tmp_path / "CLAUDE.md", _REDIRECT)
    inject_block_for_project(tmp_path)

    row = _claude_row(tmp_path)

    assert row.ok is True
    assert "redirects to AGENTS.md" in row.message, "the row must say why, not vanish"


def test_doctor_reports_stale_block_under_redirect_as_unhealthy(tmp_path: Path) -> None:
    claude = tmp_path / "CLAUDE.md"
    _write(claude, _REDIRECT)
    inject_block(claude)

    row = _claude_row(tmp_path)

    assert row.ok is False
    assert "migrate" in row.message


def test_doctor_without_redirect_keeps_current_states(tmp_path: Path) -> None:
    _write(tmp_path / "CLAUDE.md", "# Project\n\nNo redirect.\n")
    assert _claude_row(tmp_path) == CheckResult("CLAUDE.md", False, "missing")

    inject_block(tmp_path / "CLAUDE.md")
    assert _claude_row(tmp_path) == CheckResult("CLAUDE.md", True, "configured")


def test_doctor_repair_migrates_rather_than_reinjects(tmp_path: Path) -> None:
    claude = tmp_path / "CLAUDE.md"
    _write(claude, _REDIRECT)
    inject_block(claude)

    repair_install(tmp_path)

    assert "wardline:instructions:" not in claude.read_text(encoding="utf-8")
    assert "wardline:instructions:" in (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert _claude_row(tmp_path).ok is True


def test_doctor_repair_surfaces_a_conservative_refusal(tmp_path: Path) -> None:
    """A no-op refusal must never be reported as "repaired" — that is a false all-clear."""
    _write(tmp_path / "CLAUDE.md", f"{_REDIRECT}\n{_OPEN}\nfirst\n{_CLOSE}\n\n{_OPEN}\nsecond\n{_CLOSE}\n")

    statuses = repair_install(tmp_path)

    assert statuses["CLAUDE.md"].startswith("refused:")
    assert "split brain" in statuses["CLAUDE.md"]
