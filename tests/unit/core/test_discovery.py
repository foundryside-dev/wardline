from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.discovery import discover

FIXTURE = Path(__file__).parents[2] / "fixtures" / "sample_project"


def test_discovers_python_files_under_source_roots() -> None:
    cfg = WardlineConfig(source_roots=("src",))
    files = discover(FIXTURE, cfg)
    names = sorted(p.name for p in files)
    assert names == ["__init__.py", "mod.py"]


def test_respects_exclude_globs() -> None:
    cfg = WardlineConfig(source_roots=("src",), exclude=("*/mod.py",))
    files = discover(FIXTURE, cfg)
    assert all(p.name != "mod.py" for p in files)


def test_skips_pycache_and_warns_on_missing_root() -> None:
    cfg = WardlineConfig(source_roots=("does_not_exist",))
    import pytest

    with pytest.warns(UserWarning, match="source root does not exist"):
        files = discover(FIXTURE, cfg)
    assert files == []


def test_confine_excludes_symlink_escaping_root(tmp_path: Path) -> None:
    # Out-of-root target the symlink points at.
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("SECRET = 1\n")

    root = tmp_path / "root"
    src = root / "src"
    src.mkdir(parents=True)
    real = src / "real.py"
    real.write_text("x = 1\n")
    # A *.py symlink inside a legitimate source_root pointing outside the root.
    (src / "evil.py").symlink_to(secret)

    cfg = WardlineConfig(source_roots=("src",))
    files = discover(root, cfg, confine_to_root=True)

    resolved = {p.resolve() for p in files}
    assert secret.resolve() not in resolved
    assert real.resolve() in resolved
    assert all(p.name != "evil.py" for p in files)


def test_no_confine_keeps_symlink_escape_cli_behavior(tmp_path: Path) -> None:
    # With confine_to_root=False (the released CLI default), behavior is
    # unchanged: the escaping symlink is still discovered.
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("SECRET = 1\n")

    root = tmp_path / "root"
    src = root / "src"
    src.mkdir(parents=True)
    (src / "evil.py").symlink_to(secret)

    cfg = WardlineConfig(source_roots=("src",))
    files = discover(root, cfg)  # confine_to_root defaults to False

    assert any(p.name == "evil.py" for p in files)
