from pathlib import Path

from wardline.install.skill import install_skill


def test_install_skill_creates_both_targets(tmp_path: Path) -> None:
    results = install_skill(tmp_path)
    assert results == {".claude": "created", ".agents": "created"}
    for base in (".claude", ".agents"):
        skill = tmp_path / base / "skills" / "wardline-gate" / "SKILL.md"
        assert skill.is_file()
        assert "name: wardline-gate" in skill.read_text(encoding="utf-8")


def test_reinstall_overwrites(tmp_path: Path) -> None:
    install_skill(tmp_path)
    stale = tmp_path / ".claude" / "skills" / "wardline-gate" / "SKILL.md"
    stale.write_text("STALE", encoding="utf-8")
    results = install_skill(tmp_path)
    assert results[".claude"] == "overwritten"
    assert results[".agents"] == "overwritten"
    assert "name: wardline-gate" in stale.read_text(encoding="utf-8")
