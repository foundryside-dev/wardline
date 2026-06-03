from __future__ import annotations

import textwrap
from unittest.mock import MagicMock, patch

import pytest

from wardline.core.errors import WardlineError
from wardline.core.finding import Kind, SuppressionState
from wardline.core.run import run_scan


def test_delta_scan_transitive_propagation(tmp_path) -> None:
    # 1. Create files in tmp_path
    callee_src = """
    from wardline.decorators import external_boundary
    @external_boundary
    def read_raw(p):
        return p
    """
    caller_src = """
    from callee import read_raw
    from wardline.decorators import trusted
    @trusted(level='ASSURED')
    def f(p):
        return read_raw(p)
    """
    unrelated_src = """
    from wardline.decorators import external_boundary, trusted
    @external_boundary
    def read_raw_unrelated(p):
        return p
    @trusted(level='ASSURED')
    def h(p):
        return read_raw_unrelated(p)
    """

    (tmp_path / "callee.py").write_text(textwrap.dedent(callee_src), encoding="utf-8")
    (tmp_path / "caller.py").write_text(textwrap.dedent(caller_src), encoding="utf-8")
    (tmp_path / "unrelated.py").write_text(textwrap.dedent(unrelated_src), encoding="utf-8")

    # 2. Mock subprocess.run to simulate git repository where only callee.py changed
    with patch("subprocess.run") as mock_run:
        mock_rev_parse = MagicMock()
        mock_rev_parse.stdout = f"{tmp_path.resolve()}\n"

        mock_diff = MagicMock()
        mock_diff.stdout = "callee.py\n"

        mock_ls_files = MagicMock()
        mock_ls_files.stdout = ""

        mock_run.side_effect = [mock_rev_parse, mock_diff, mock_ls_files]

        result = run_scan(tmp_path, new_since="HEAD~1")

    # 3. Check findings:
    # caller.py/f is active because callee.py changed and f calls callee.read_raw (transitively affected)
    # unrelated.py/h is baselined because it is unchanged and unaffected
    findings = result.findings
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    assert len(defects) == 2

    # Map by qualname
    by_qn = {f.qualname: f for f in defects}
    assert "caller.f" in by_qn
    assert "unrelated.h" in by_qn

    assert by_qn["caller.f"].suppressed is SuppressionState.ACTIVE
    assert by_qn["unrelated.h"].suppressed is SuppressionState.BASELINED
    assert by_qn["unrelated.h"].suppression_reason == "delta: unchanged since HEAD~1"


def test_delta_scan_invalid_ref(tmp_path) -> None:
    # Set up basic file to scan
    (tmp_path / "callee.py").write_text("def f(): pass", encoding="utf-8")

    with patch("subprocess.run") as mock_run:
        mock_rev_parse = MagicMock()
        mock_rev_parse.stdout = f"{tmp_path.resolve()}\n"

        import subprocess

        mock_run.side_effect = [
            mock_rev_parse,
            subprocess.CalledProcessError(1, "git diff", stderr="fatal: bad revision"),
        ]

        with pytest.raises(WardlineError, match="Git diff failed for ref 'badref'"):
            run_scan(tmp_path, new_since="badref")
