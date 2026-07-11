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
        if Path(path) == source and not swapped:
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
