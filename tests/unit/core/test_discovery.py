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


def test_repo_gitignore_cannot_hide_source_from_discovery(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("pkg/\nsrc/generated/\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "hidden.py").write_text("y = 2\n", encoding="utf-8")
    generated = tmp_path / "src" / "generated"
    generated.mkdir(parents=True)
    (generated / "handler.py").write_text("z = 3\n", encoding="utf-8")

    files = discover(tmp_path, WardlineConfig(source_roots=(".",)))

    rel = sorted(p.relative_to(tmp_path).as_posix() for p in files)
    assert rel == ["app.py", "pkg/hidden.py", "src/generated/handler.py"]


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


def test_respect_gitignore_prunes_dir_when_explicitly_enabled(tmp_path: Path) -> None:
    # .gitignore is repository-controlled and is not the default scan boundary, but
    # trusted callers may still opt into Git-like pruning for bulk third-party trees.
    (tmp_path / ".gitignore").write_text("third_party/\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    vendored = tmp_path / "third_party" / "huge" / "deep"
    vendored.mkdir(parents=True)
    (vendored / "lib.py").write_text("y = 2\n", encoding="utf-8")

    files = discover(tmp_path, WardlineConfig(source_roots=(".",)), respect_gitignore=True)

    rel = [p.relative_to(tmp_path).as_posix() for p in files]
    assert rel == ["app.py"]
    assert all("third_party" not in p for p in rel)


def test_gitignored_walk_does_not_descend_ignored_dir(tmp_path: Path, monkeypatch) -> None:
    # When the trusted opt-in is enabled, pruning must happen DURING the walk
    # (dirnames[:] in place), so os.walk never enters the ignored subtree.
    import wardline.core.discovery as discovery_mod

    (tmp_path / ".gitignore").write_text(".venv-vendor/\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    ignored = tmp_path / ".venv-vendor" / "pkg"
    ignored.mkdir(parents=True)
    (ignored / "dep.py").write_text("y = 2\n", encoding="utf-8")

    walked: list[str] = []
    real_walk = discovery_mod.os.walk

    def spy_walk(top, *args, **kwargs):
        for dirpath, dirnames, filenames in real_walk(top, *args, **kwargs):
            walked.append(Path(dirpath).name)
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(discovery_mod.os, "walk", spy_walk)
    discover(tmp_path, WardlineConfig(source_roots=(".",)), respect_gitignore=True)

    assert ".venv-vendor" not in walked
    assert "pkg" not in walked


def test_negated_gitignore_pattern_keeps_dir(tmp_path: Path) -> None:
    # Last-match-wins with negation, at a path with no EXCLUDED parent: a dir matched
    # by a glob and then re-admitted by a later `!` rule is still scanned. (Git cannot
    # re-include a child of an excluded parent; that limitation is pinned in the
    # gitignore-matcher unit test, verified against real `git check-ignore`.)
    (tmp_path / ".gitignore").write_text("build*/\n!build-keep/\n", encoding="utf-8")
    keep = tmp_path / "build-keep"
    drop = tmp_path / "build-out"
    keep.mkdir()
    drop.mkdir()
    (keep / "k.py").write_text("x = 1\n", encoding="utf-8")
    (drop / "d.py").write_text("y = 2\n", encoding="utf-8")

    files = discover(tmp_path, WardlineConfig(source_roots=(".",)), respect_gitignore=True)

    rel = [p.relative_to(tmp_path).as_posix() for p in files]
    assert rel == ["build-keep/k.py"]


def test_expanded_floor_prunes_build_dist_eggs(tmp_path: Path) -> None:
    # The default skip floor now also fences build/, dist/, .eggs/ and *.egg-info/
    # WITHOUT any .gitignore — these bloat a project-root scan.
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
    for noisy in ("build", "dist", ".eggs", "mypkg.egg-info"):
        d = tmp_path / noisy
        d.mkdir()
        (d / "junk.py").write_text("y = 2\n", encoding="utf-8")

    files = discover(tmp_path, WardlineConfig(source_roots=(".",)))

    assert [p.relative_to(tmp_path).as_posix() for p in files] == ["real.py"]


def test_build_and_dist_package_names_under_source_root_are_scanned(tmp_path: Path) -> None:
    root = tmp_path / "root"
    src = root / "src"
    pkg_build = src / "build"
    pkg_dist = src / "dist"
    pkg_build.mkdir(parents=True)
    pkg_dist.mkdir()
    (pkg_build / "api.py").write_text("x = 1\n", encoding="utf-8")
    (pkg_dist / "artifact.py").write_text("y = 2\n", encoding="utf-8")

    files = discover(root, WardlineConfig(source_roots=("src",)))

    rel = sorted(p.relative_to(root).as_posix() for p in files)
    assert rel == ["src/build/api.py", "src/dist/artifact.py"]


def test_nested_gitignore_layers(tmp_path: Path) -> None:
    # A .gitignore in a subdirectory is layered in as the walk descends (git's nested
    # ignore semantics), pruning only within its own subtree.
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / ".gitignore").write_text("generated/\n", encoding="utf-8")
    (tmp_path / "pkg" / "real.py").write_text("x = 1\n", encoding="utf-8")
    gen = tmp_path / "pkg" / "generated"
    gen.mkdir()
    (gen / "g.py").write_text("y = 2\n", encoding="utf-8")
    # A sibling top-level "generated" is NOT ignored — the rule is scoped to pkg/.
    other = tmp_path / "generated"
    other.mkdir()
    (other / "o.py").write_text("z = 3\n", encoding="utf-8")

    files = discover(tmp_path, WardlineConfig(source_roots=(".",)), respect_gitignore=True)

    rel = sorted(p.relative_to(tmp_path).as_posix() for p in files)
    assert rel == ["generated/o.py", "pkg/real.py"]


def test_nested_anchored_gitignore_pattern_is_relative_to_its_own_directory(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / ".gitignore").write_text("/generated/\n", encoding="utf-8")
    (tmp_path / "pkg" / "real.py").write_text("x = 1\n", encoding="utf-8")
    nested = tmp_path / "pkg" / "generated"
    nested.mkdir()
    (nested / "skip.py").write_text("y = 2\n", encoding="utf-8")
    sibling = tmp_path / "generated"
    sibling.mkdir()
    (sibling / "keep.py").write_text("z = 3\n", encoding="utf-8")

    files = discover(tmp_path, WardlineConfig(source_roots=(".",)), respect_gitignore=True)

    rel = sorted(p.relative_to(tmp_path).as_posix() for p in files)
    assert rel == ["generated/keep.py", "pkg/real.py"]


def test_gitignore_does_not_prune_outside_root(tmp_path: Path) -> None:
    # The gitignore base is the scan ROOT. A source_root that resolves outside the
    # root (no confinement) has no gitignore context applied — discovery stays the
    # explicit walk, never silently importing an unrelated tree's ignore rules.
    root = tmp_path / "root"
    root.mkdir()
    (root / ".gitignore").write_text("data/\n", encoding="utf-8")
    sibling = tmp_path / "sibling"
    data = sibling / "data"
    data.mkdir(parents=True)
    (data / "keep.py").write_text("x = 1\n", encoding="utf-8")

    cfg = WardlineConfig(source_roots=("../sibling",))
    files = discover(root, cfg, respect_gitignore=True)

    # The root's `data/` rule must not reach into the out-of-root sibling tree.
    rel = sorted(p.name for p in files)
    assert rel == ["keep.py"]


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
