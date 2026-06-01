from pathlib import Path

from wardline.install.block import inject_block, render_block


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
