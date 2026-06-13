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


def test_prunes_tool_cache_directories_before_discovery(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    cache = tmp_path / ".uv-cache" / "archive" / "pkg"
    cache.mkdir(parents=True)
    (cache / "cached.py").write_text("y = 2\n", encoding="utf-8")

    files = discover(tmp_path, WardlineConfig(source_roots=(".",)))

    assert [p.relative_to(tmp_path).as_posix() for p in files] == ["src/app.py"]


def test_skip_dirs_are_relative_to_source_root_not_absolute_parents(tmp_path: Path) -> None:
    root = tmp_path / ".venv" / "proj"
    root.mkdir(parents=True)
    (root / "m.py").write_text("x = 1\n", encoding="utf-8")

    files = discover(root, WardlineConfig(source_roots=(".",)))

    assert [p.name for p in files] == ["m.py"]


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


def test_discover_rust_suffix(tmp_path: Path) -> None:
    # The suffix parameter routes discovery to a different language's files: a
    # `.rs` sweep finds `a.rs`, never `a.py`; `target/` (cargo build output) is
    # skipped; and the default (no `suffixes`) call is byte-unchanged Python-only.
    root = tmp_path / "root"
    src = root / "src"
    src.mkdir(parents=True)
    (src / "a.rs").write_text("fn main() {}\n", encoding="utf-8")
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    built = src / "target"
    built.mkdir()
    (built / "built.rs").write_text("fn x() {}\n", encoding="utf-8")

    cfg = WardlineConfig(source_roots=("src",))

    rust_files = discover(root, cfg, suffixes=frozenset({".rs"}))
    assert sorted(p.name for p in rust_files) == ["a.rs"]  # a.rs only; not a.py, not target/

    default_files = discover(root, cfg)  # default suffixes -> Python only
    assert sorted(p.name for p in default_files) == ["a.py"]


def test_target_dir_is_not_skipped_for_python(tmp_path: Path) -> None:
    # `target` is a cargo build dir, skipped only in `.rs` mode. It is a perfectly
    # legitimate Python package name, so a default `.py` scan must NOT silently
    # drop code under `target/` — that would be exactly the under-scan wardline
    # surfaces loudly everywhere else. (Pins the suffix-gate; the identity oracle
    # does not discriminate global-vs-gated since no fixture has a `target/` dir.)
    root = tmp_path / "root"
    pkg = root / "src" / "target"
    pkg.mkdir(parents=True)
    (pkg / "m.py").write_text("y = 2\n", encoding="utf-8")

    cfg = WardlineConfig(source_roots=("src",))
    files = discover(root, cfg)
    assert [p.name for p in files] == ["m.py"]


def test_discover_rust_symlink_confined(tmp_path: Path) -> None:
    # The THREAT-001 confinement invariant holds for `.rs` discovery too: a `.rs`
    # file-symlink inside a legitimate source_root pointing OUTSIDE the root is
    # skipped with WLN-ENGINE-FILE-SKIPPED under confine_to_root, never read.
    import pytest

    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.rs"
    secret.write_text("const SECRET: u8 = 1;\n")

    root = tmp_path / "root"
    src = root / "src"
    src.mkdir(parents=True)
    real = src / "real.rs"
    real.write_text("fn main() {}\n")
    (src / "evil.rs").symlink_to(secret)

    cfg = WardlineConfig(source_roots=("src",))
    with pytest.warns(UserWarning, match="WLN-ENGINE-FILE-SKIPPED"):
        files = discover(root, cfg, confine_to_root=True, suffixes=frozenset({".rs"}))

    resolved = {p.resolve() for p in files}
    assert secret.resolve() not in resolved
    assert real.resolve() in resolved
    assert all(p.name != "evil.rs" for p in files)


def test_no_confine_keeps_low_level_symlink_escape_behavior(tmp_path: Path) -> None:
    # With the low-level discovery opt-out, behavior is unchanged: the escaping
    # symlink is still discovered.
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
