# tests/unit/install/test_doctor_pack_grants.py
"""Doctor must judge a pack-declaring project by its .mcp.json-recorded grants
(wardline-7a76f6c5a0 follow-up): without this, doctor reports two FALSE errors
against a working gate — `mcp.registration` (canonicaliser drops the grant
flags, so the entry "differs") and `wardline.config` (config re-derived without
the operator's grants) — while `doctor --repair` would strip the flags and
silently return the gate to inert.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from wardline.install.doctor import _check_config, _check_project_mcp


def _granted_project(tmp_path: Path, *, grant: bool) -> Path:
    proj = tmp_path / "proj"
    (proj / "scripts").mkdir(parents=True)
    (proj / "scripts" / "doctorpack.py").write_text("config = {}\n", encoding="utf-8")
    (proj / "weft.toml").write_text(
        '[wardline]\nsource_roots = ["."]\npacks = ["scripts.doctorpack"]\n', encoding="utf-8"
    )
    args = ["mcp", "--root", "."]
    if grant:
        args += ["--trust-pack", "scripts.doctorpack", "--allow-custom-packs"]
    (proj / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"wardline": {"type": "stdio", "command": "/bin/wardline", "args": args}}}),
        encoding="utf-8",
    )
    return proj


def _forget_pack_modules() -> None:
    sys.modules.pop("scripts.doctorpack", None)
    sys.modules.pop("scripts", None)


def test_config_check_honors_mcp_entry_grants(tmp_path: Path) -> None:
    proj = _granted_project(tmp_path, grant=True)
    try:
        check = _check_config(proj, fixed=False)
    finally:
        _forget_pack_modules()
    assert check.status == "ok", check.message


def test_config_check_still_fails_closed_without_grants(tmp_path: Path) -> None:
    proj = _granted_project(tmp_path, grant=False)
    try:
        check = _check_config(proj, fixed=False)
    finally:
        _forget_pack_modules()
    assert check.status == "error"
    assert "not trusted" in (check.message or "")


def test_project_mcp_check_accepts_grant_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    proj = _granted_project(tmp_path, grant=True)
    check = _check_project_mcp(proj)
    assert check.ok, check.message


def test_project_mcp_check_names_divergence_not_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A present-but-noncanonical entry is a different failure than an absent one;
    # "missing wardline server" for a visibly present entry sent the operator
    # chasing the wrong problem.
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"wardline": {"type": "stdio", "command": "/bin/wardline", "args": ["mcp", "--bogus"]}}}
        ),
        encoding="utf-8",
    )
    check = _check_project_mcp(proj)
    assert not check.ok
    assert "differs" in (check.message or "")
