import os
from pathlib import Path

import pytest

from wardline.core import safe_paths
from wardline.core.confinement import SourceRootConfinement
from wardline.core.errors import WardlineError


def _reader():
    reader = getattr(safe_paths, "read_source_bytes", None)
    assert callable(reader), "shared confined source reader is not implemented"
    return reader


def test_read_source_bytes_reads_stable_regular_file(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    source.write_bytes(b"value = 1\n")

    content = _reader()(
        source,
        root=tmp_path,
        source_root_confinement=SourceRootConfinement.PROJECT_ROOT,
    )

    assert content == b"value = 1\n"


def test_read_source_bytes_allows_regular_outside_file_only_in_legacy_mode(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside = True\n")

    with pytest.raises((OSError, WardlineError)):
        _reader()(outside, root=root, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)

    assert (
        _reader()(
            outside,
            root=root,
            source_root_confinement=SourceRootConfinement.LEGACY_ALLOW_ESCAPE,
        )
        == b"outside = True\n"
    )


def test_read_source_bytes_rejects_swap_between_lstat_and_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.py"
    source.write_bytes(b"safe = True\n")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_bytes(b"outside = True\n")
    real_open = os.open
    swapped = False

    def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):  # noqa: ANN001
        nonlocal swapped
        if (Path(path) == source or (path == source.name and dir_fd is not None)) and not swapped:
            source.unlink()
            source.symlink_to(outside)
            swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_then_open)

    with pytest.raises((OSError, WardlineError)):
        _reader()(source, root=tmp_path, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)

    assert swapped is True


def test_read_source_bytes_rejects_path_swap_after_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.py"
    source.write_bytes(b"safe = True\n")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_bytes(b"outside = True\n")
    real_fstat = os.fstat
    swapped = False

    def swap_after_fstat(fd: int):
        nonlocal swapped
        opened = real_fstat(fd)
        if not swapped:
            source.unlink()
            source.symlink_to(outside)
            swapped = True
        return opened

    monkeypatch.setattr(os, "fstat", swap_after_fstat)

    with pytest.raises((OSError, WardlineError)):
        _reader()(source, root=tmp_path, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)

    assert swapped is True


def test_read_source_bytes_rejects_ancestor_swap_at_component_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    parent = root / "pkg" / "nested"
    parent.mkdir(parents=True)
    source = parent / "source.py"
    source.write_bytes(b"safe = True\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.py").write_bytes(b"outside = True\n")
    parked = root / "pkg" / "nested-safe"
    real_resolve = Path.resolve
    real_open = os.open
    swapped = False

    def swap_parent() -> None:
        nonlocal swapped
        parent.rename(parked)
        parent.symlink_to(outside, target_is_directory=True)
        swapped = True

    def hooked_resolve(path: Path, strict: bool = False) -> Path:
        resolved = real_resolve(path, strict=strict)
        if path == source and not swapped:
            swap_parent()
        return resolved

    def hooked_open(path, flags, mode=0o777, *, dir_fd=None):  # noqa: ANN001
        if path == "nested" and not swapped:
            swap_parent()
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(Path, "resolve", hooked_resolve)
    monkeypatch.setattr(os, "open", hooked_open)

    with pytest.raises((OSError, WardlineError)):
        _reader()(source, root=root, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)

    assert swapped is True


def test_read_source_bytes_rejects_project_root_ancestor_swap_after_root_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ancestor = tmp_path / "container"
    root = ancestor / "project"
    source = root / "pkg" / "source.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"safe = True\n")
    outside_ancestor = tmp_path / "outside-container"
    outside_source = outside_ancestor / "project" / "pkg" / "source.py"
    outside_source.parent.mkdir(parents=True)
    outside_source.write_bytes(b"outside = True\n")
    parked = tmp_path / "container-safe"
    real_resolve = Path.resolve
    swapped = False

    def swap_after_root_resolution(path: Path, strict: bool = False) -> Path:
        nonlocal swapped
        resolved = real_resolve(path, strict=strict)
        if path == root and not swapped:
            ancestor.rename(parked)
            ancestor.symlink_to(outside_ancestor, target_is_directory=True)
            swapped = True
        return resolved

    monkeypatch.setattr(Path, "resolve", swap_after_root_resolution)

    with pytest.raises((OSError, WardlineError)):
        _reader()(source, root=root, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)

    assert swapped is True


@pytest.mark.parametrize("missing_capability", ["no_nofollow", "no_directory", "no_dir_fd"])
def test_read_source_bytes_secure_mode_fails_closed_without_openat_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_capability: str
) -> None:
    source = tmp_path / "source.py"
    source.write_bytes(b"safe = True\n")
    if missing_capability == "no_nofollow":
        monkeypatch.delattr(os, "O_NOFOLLOW")
    elif missing_capability == "no_directory":
        monkeypatch.delattr(os, "O_DIRECTORY")
    else:
        monkeypatch.setattr(safe_paths, "_OPENAT_SUPPORTED", False)

    with pytest.raises((OSError, WardlineError)):
        _reader()(source, root=tmp_path, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)


def test_read_source_bytes_reads_stable_nested_regular_file(tmp_path: Path) -> None:
    source = tmp_path / "pkg" / "nested" / "source.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"nested = True\n")
    assert (
        _reader()(source, root=tmp_path, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)
        == b"nested = True\n"
    )


def test_read_source_bytes_rejects_nonregular_final_component(tmp_path: Path) -> None:
    directory = tmp_path / "source.py"
    directory.mkdir()
    with pytest.raises((OSError, WardlineError)):
        _reader()(directory, root=tmp_path, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)


def test_read_source_bytes_closes_all_traversal_fds_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parent = tmp_path / "pkg"
    parent.mkdir()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-dir"
    outside.mkdir()
    (outside / "source.py").write_bytes(b"outside = True\n")
    (parent / "nested").symlink_to(outside, target_is_directory=True)
    source = parent / "nested" / "source.py"
    real_open = os.open
    real_close = os.close
    live_fds: set[int] = set()

    def track_open(path, flags, mode=0o777, *, dir_fd=None):  # noqa: ANN001
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        live_fds.add(fd)
        return fd

    def track_close(fd: int) -> None:
        live_fds.discard(fd)
        real_close(fd)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "close", track_close)

    with pytest.raises((OSError, WardlineError)):
        _reader()(source, root=tmp_path, source_root_confinement=SourceRootConfinement.PROJECT_ROOT)

    assert live_fds == set()
