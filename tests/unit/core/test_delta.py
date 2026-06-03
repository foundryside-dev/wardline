from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wardline.core.delta import get_affected_entities, get_changed_files_since
from wardline.core.errors import WardlineError
from wardline.core.finding import Location
from wardline.scanner.index import Entity


@patch("subprocess.run")
def test_get_changed_files_since_success(mock_run) -> None:
    # 1. Mock git rev-parse --show-toplevel
    mock_rev_parse = MagicMock()
    mock_rev_parse.stdout = "/git/root\n"
    # 2. Mock git diff --name-only
    mock_diff = MagicMock()
    mock_diff.stdout = "src/foo.py\nsrc/bar.py\n"
    # 3. Mock git ls-files
    mock_ls_files = MagicMock()
    mock_ls_files.stdout = "src/baz.py\n"

    mock_run.side_effect = [mock_rev_parse, mock_diff, mock_ls_files]

    # Cwd root is a subdirectory of git root
    root = Path("/git/root/src")
    res = get_changed_files_since("HEAD~1", root)

    assert res == {"foo.py", "bar.py", "baz.py"}


@patch("subprocess.run")
def test_get_changed_files_since_not_git_repo(mock_run) -> None:
    # Fail on first call (git rev-parse)
    mock_run.side_effect = FileNotFoundError()

    with pytest.raises(WardlineError, match="Failed to find Git repository"):
        get_changed_files_since("HEAD", Path("/tmp"))


@patch("subprocess.run")
def test_get_changed_files_since_invalid_ref(mock_run) -> None:
    mock_rev_parse = MagicMock()
    mock_rev_parse.stdout = "/git/root\n"

    # git diff returns error status
    import subprocess

    mock_run.side_effect = [
        mock_rev_parse,
        subprocess.CalledProcessError(1, "git diff", stderr="fatal: bad revision 'badref'"),
    ]

    with pytest.raises(WardlineError, match="Git diff failed for ref 'badref'"):
        get_changed_files_since("badref", Path("/git/root"))


def _entity(qualname: str, path: str) -> Entity:
    return Entity(
        qualname=qualname,
        kind="function",
        node=None,  # type: ignore
        location=Location(path=path, line_start=1),
    )


def test_get_affected_entities_propagation() -> None:
    # a.py contains `foo`
    # b.py contains `bar` (calls `foo`)
    # c.py contains `baz` (calls `bar`)
    # d.py contains `qux` (unrelated)
    entities = {
        "m.foo": _entity("m.foo", "a.py"),
        "m.bar": _entity("m.bar", "b.py"),
        "m.baz": _entity("m.baz", "c.py"),
        "m.qux": _entity("m.qux", "d.py"),
    }
    project_edges = {
        "m.bar": frozenset({"m.foo"}),
        "m.baz": frozenset({"m.bar"}),
        "m.qux": frozenset({"m.unrelated"}),
    }

    # Case 1: callee `a.py` changed -> foo changed -> affects foo, bar, baz
    changed_files = {"a.py"}
    affected = get_affected_entities(changed_files, entities, project_edges)
    assert affected == {"m.foo", "m.bar", "m.baz"}

    # Case 2: intermediary `b.py` changed -> affects bar, baz (foo is untouched callee)
    changed_files = {"b.py"}
    affected = get_affected_entities(changed_files, entities, project_edges)
    assert affected == {"m.bar", "m.baz"}

    # Case 3: caller `c.py` changed -> baz changed -> only affects baz
    changed_files = {"c.py"}
    affected = get_affected_entities(changed_files, entities, project_edges)
    assert affected == {"m.baz"}

    # Case 4: unrelated `d.py` changed -> affects qux
    changed_files = {"d.py"}
    affected = get_affected_entities(changed_files, entities, project_edges)
    assert affected == {"m.qux"}

    # Case 5: nothing changed
    changed_files = set()
    affected = get_affected_entities(changed_files, entities, project_edges)
    assert affected == set()
