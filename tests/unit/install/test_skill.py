from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.install.skill import install_skill


def test_install_skill_creates_both_targets(tmp_path: Path) -> None:
    results = install_skill(tmp_path)
    assert results == {".claude": "created", ".agents": "created"}
    for base in (".claude", ".agents"):
        skill = tmp_path / base / "skills" / "wardline-gate" / "SKILL.md"
        assert skill.is_file()
        guidance = skill.read_text(encoding="utf-8")
        assert "name: wardline-gate" in guidance
        assert "`scan_job_start`" in guidance
        sheet_path = skill.parent / "references" / "mcp-safe-scans.md"
        assert sheet_path.is_file()
        sheet = sheet_path.read_text(encoding="utf-8")
        assert "`strict_defaults` is **false by default**" in sheet
        assert "`summary_only` and `max_findings` bound the response" in sheet


def test_reinstall_overwrites(tmp_path: Path) -> None:
    install_skill(tmp_path)
    stale = tmp_path / ".claude" / "skills" / "wardline-gate" / "SKILL.md"
    stale.write_text("STALE", encoding="utf-8")
    results = install_skill(tmp_path)
    assert results[".claude"] == "overwritten"
    assert results[".agents"] == "overwritten"
    assert "name: wardline-gate" in stale.read_text(encoding="utf-8")


def test_install_skill_rejects_symlinked_parent_escape(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside_skill = outside / "skills" / "wardline-gate"
    outside_skill.mkdir(parents=True)
    sentinel = outside_skill / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    (root / ".claude").symlink_to(outside, target_is_directory=True)

    with pytest.raises(WardlineError, match="escapes project root"):
        install_skill(root)

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert not (outside_skill / "SKILL.md").exists()


def test_install_skill_rejects_symlinked_skill_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside-skill"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    skills = tmp_path / ".claude" / "skills"
    skills.mkdir(parents=True)
    (skills / "wardline-gate").symlink_to(outside, target_is_directory=True)

    with pytest.raises(WardlineError, match="symlink"):
        install_skill(tmp_path)

    assert sentinel.read_text(encoding="utf-8") == "keep"
