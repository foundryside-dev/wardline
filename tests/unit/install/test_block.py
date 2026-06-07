import logging
from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.install.block import _atomic_write_text, inject_block, render_block

# A co-resident sibling tool's managed block (filigree), used to assert
# wardline's writer never deletes, truncates, or spans across a foreign block
# (weft C-4 multi-owner managed-block contract).
_FOREIGN = "<!-- filigree:instructions:v3.0:abcd1234 -->\nfiligree body — DO NOT TOUCH\n<!-- /filigree:instructions -->"
_OPEN = "<!-- wardline:instructions:v1:deadbeef -->"
_CLOSE = "<!-- /wardline:instructions -->"


def test_render_block_is_fenced_and_mentions_the_gate() -> None:
    block = render_block()
    assert block.startswith("<!-- wardline:instructions:v")
    assert block.rstrip().endswith("<!-- /wardline:instructions -->")
    assert "wardline scan" in block
    assert "wardline-gate" in block


def test_inject_into_absent_file_creates_it(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    assert inject_block(f) == "created"
    assert f.read_text(encoding="utf-8").count("wardline:instructions:v") == 1


def test_inject_rejects_symlinked_agents_file(tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("outside\n", encoding="utf-8")
    target = tmp_path / "AGENTS.md"
    target.symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        inject_block(target)

    assert outside.read_text(encoding="utf-8") == "outside\n"


def test_inject_appends_when_no_fence_present(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    f.write_text("# My project\n\nExisting content.\n", encoding="utf-8")
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert "Existing content." in text
    assert "wardline:instructions" in text


def test_reinject_same_version_is_unchanged(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    inject_block(f)
    before = f.read_text(encoding="utf-8")
    assert inject_block(f) == "unchanged"
    assert f.read_text(encoding="utf-8") == before


def test_inject_replaces_a_stale_fenced_block(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    f.write_text(
        "intro\n\n<!-- wardline:instructions:v0:deadbeef -->\nOLD BODY\n<!-- /wardline:instructions -->\n\noutro\n",
        encoding="utf-8",
    )
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert "OLD BODY" not in text
    assert "intro" in text and "outro" in text
    assert text.count("wardline:instructions:v") == 1


def test_inject_appends_when_file_has_no_trailing_newline(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    f.write_text("no trailing newline", encoding="utf-8")  # no final \n
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert text.startswith("no trailing newline\n")
    assert text.count("wardline:instructions:v") == 1


def test_inject_collapses_multiple_existing_blocks(tmp_path: Path) -> None:
    block = render_block()
    f = tmp_path / "CLAUDE.md"
    # Two current blocks already present (e.g. a botched prior write).
    f.write_text(f"head\n\n{block}\n\nmid\n\n{block}\n\ntail\n", encoding="utf-8")
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert text.count("wardline:instructions:v") == 1
    assert "head" in text and "tail" in text


def test_inject_is_idempotent_after_collapse(tmp_path: Path) -> None:
    block = render_block()
    f = tmp_path / "CLAUDE.md"
    f.write_text(f"{block}\n\n{block}\n", encoding="utf-8")
    inject_block(f)  # collapses to one
    assert inject_block(f) == "unchanged"  # now converged


# ---------------------------------------------------------------------------
# C-4 multi-owner managed-block contract
# ---------------------------------------------------------------------------


def test_foreign_block_between_own_head_and_own_trailing_is_preserved(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """(c)+(e): a foreign block sandwiched between an own head and an own trailing
    duplicate survives, AND the trailing own duplicate (beyond the foreign block)
    is preserved + surfaced, not deleted."""
    block = render_block()
    # Stale head block (old hash) so a real rewrite is exercised; the trailing
    # block is current and sits BEYOND the foreign fence.
    stale = f"{_OPEN}\nOLD BODY\n{_CLOSE}"
    f = tmp_path / "CLAUDE.md"
    f.write_text(
        f"head\n\n{stale}\n\n{_FOREIGN}\n\n{block}\n\ntail\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    # Stale head body is gone (replaced in place).
    assert "OLD BODY" not in text
    # Foreign block survives intact.
    assert _FOREIGN in text
    assert "filigree body — DO NOT TOUCH" in text
    # Surrounding user text survives.
    assert "head" in text and "tail" in text
    # The own duplicate beyond the foreign block is preserved (foreign-safety >
    # own-dedup), so there are still two own blocks — NOT collapsed to one.
    assert text.count("wardline:instructions:v") == 2
    # ...and it is surfaced.
    assert any("duplicate" in r.message for r in caplog.records)


def test_unclosed_own_then_foreign_then_complete_own_preserves_foreign(
    tmp_path: Path,
) -> None:
    """(c): an unclosed own open before a foreign block, followed by a complete
    own block, must not let the rewrite span across the foreign block."""
    block = render_block()
    f = tmp_path / "CLAUDE.md"
    # Orphan own open (no close), then foreign, then a complete own block.
    f.write_text(
        f"intro\n\n{_OPEN}\nORPHAN BODY\n\n{_FOREIGN}\n\n{block}\n",
        encoding="utf-8",
    )
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    # Foreign block survives.
    assert _FOREIGN in text
    assert "filigree body — DO NOT TOUCH" in text
    # A valid fresh wardline block is present at the front (orphan recovered).
    assert text.lstrip().startswith("intro")
    assert _CLOSE in text
    # Two own blocks remain: the recovered front block + the complete one beyond
    # the foreign fence. We do NOT assert count == 1 — that would contradict
    # foreign-safety (the trailing block sits beyond the foreign block).
    assert text.count("wardline:instructions:v") == 2


def test_two_call_orphan_open_plus_foreign_keeps_foreign(tmp_path: Path) -> None:
    """(c): the reachable 2-call sequence — orphan own open + foreign, then inject
    twice — must keep the foreign block across both calls."""
    f = tmp_path / "CLAUDE.md"
    f.write_text(f"{_OPEN}\nORPHAN BODY\n\n{_FOREIGN}\n", encoding="utf-8")
    # Call 1: append path manufactures a later own close.
    inject_block(f)
    assert _FOREIGN in f.read_text(encoding="utf-8")
    # Call 2: must not swallow the foreign block now that a later close exists.
    inject_block(f)
    text = f.read_text(encoding="utf-8")
    assert _FOREIGN in text
    assert "filigree body — DO NOT TOUCH" in text


def test_uppercase_foreign_namespace_registers_as_boundary(tmp_path: Path) -> None:
    """(h): an uppercase-namespaced sibling fence must register as a foreign
    boundary (case-insensitive namespace match)."""
    block = render_block()
    upper_foreign = "<!-- FILIGREE:instructions:v3.0:abcd1234 -->\nFILIGREE BODY\n<!-- /FILIGREE:instructions -->"
    f = tmp_path / "CLAUDE.md"
    f.write_text(
        f"{_OPEN}\nORPHAN BODY\n\n{upper_foreign}\n\n{block}\n",
        encoding="utf-8",
    )
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert upper_foreign in text
    assert "FILIGREE BODY" in text


def test_append_on_unclosed_own_with_trailing_text_preserves_all(
    tmp_path: Path,
) -> None:
    """(d): an own open with no close marker, followed by user text, must append a
    fresh block and preserve all existing text verbatim (no recovery-to-EOF that
    would delete the trailing user text)."""
    f = tmp_path / "CLAUDE.md"
    original = f"intro\n\n{_OPEN}\nORPHAN BODY\n\nIMPORTANT USER TEXT\n"
    f.write_text(original, encoding="utf-8")
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    # Every byte of the original is preserved (append-on-missing-end).
    assert original in text
    assert "IMPORTANT USER TEXT" in text
    assert "ORPHAN BODY" in text
    # A fresh, well-formed block was appended.
    assert _CLOSE in text


def test_append_on_unclosed_own_no_trailing_text(tmp_path: Path) -> None:
    """(d): an own open with no close marker and nothing after it still appends a
    fresh block, preserving the orphan."""
    f = tmp_path / "CLAUDE.md"
    original = f"intro\n\n{_OPEN}\nORPHAN BODY\n"
    f.write_text(original, encoding="utf-8")
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert original in text
    assert "ORPHAN BODY" in text
    assert _CLOSE in text


def test_atomic_write_refuses_empty_content(tmp_path: Path) -> None:
    """(g): the atomic writer refuses empty / whitespace-only content rather than
    truncating an existing populated file."""
    f = tmp_path / "CLAUDE.md"
    f.write_text("PRECIOUS CONTENT\n", encoding="utf-8")
    with pytest.raises(WardlineError, match="empty"):
        _atomic_write_text(f, "")
    with pytest.raises(WardlineError, match="empty"):
        _atomic_write_text(f, "   \n\t ")
    # File untouched.
    assert f.read_text(encoding="utf-8") == "PRECIOUS CONTENT\n"


def test_atomic_write_preserves_existing_file_mode(tmp_path: Path) -> None:
    """(g): the atomic writer preserves the destination's permission bits."""
    f = tmp_path / "CLAUDE.md"
    f.write_text("old\n", encoding="utf-8")
    f.chmod(0o640)
    _atomic_write_text(f, "new content\n")
    assert f.read_text(encoding="utf-8") == "new content\n"
    assert (f.stat().st_mode & 0o777) == 0o640


def test_foreign_block_before_own_is_preserved(tmp_path: Path) -> None:
    """(f): a foreign block before the own block is never reordered/relocated and
    a stale own block is still replaced in place."""
    f = tmp_path / "CLAUDE.md"
    f.write_text(
        f"{_FOREIGN}\n\n{_OPEN}\nOLD BODY\n{_CLOSE}\n",
        encoding="utf-8",
    )
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert _FOREIGN in text
    assert "OLD BODY" not in text
    # Foreign block stays first; own block replaced in place.
    assert text.index("filigree body") < text.index("wardline:instructions:v")
    assert text.count("wardline:instructions:v") == 1


def test_own_marker_shielded_in_unclosed_foreign_converges(tmp_path: Path) -> None:
    """(d)+idempotency: a wardline open marker shielded inside an UNCLOSED foreign
    block is not claimable (we must not invent the foreign close), so the first
    inject appends a fresh block. Repeated injects must then CONVERGE rather than
    append a new copy every run (unbounded growth under repeated hook calls)."""
    f = tmp_path / "CLAUDE.md"
    # Unclosed filigree fence with a wardline open quoted inside it.
    f.write_text(
        f"<!-- filigree:instructions:v1:aaaa -->\nexample: {_OPEN}\nsome text\n",
        encoding="utf-8",
    )
    assert inject_block(f) == "updated"  # appends a fresh block
    after_first = f.read_text(encoding="utf-8")
    # The (malformed) foreign marker and quoted text are preserved verbatim.
    assert "<!-- filigree:instructions:v1:aaaa -->" in after_first
    assert "some text" in after_first
    # Second and third runs converge — no unbounded growth.
    assert inject_block(f) == "unchanged"
    assert f.read_text(encoding="utf-8") == after_first
    assert inject_block(f) == "unchanged"
    assert f.read_text(encoding="utf-8") == after_first
