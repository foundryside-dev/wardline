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
