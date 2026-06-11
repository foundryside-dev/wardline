"""A3 (wardline-d8cc650ab9): the `rekey` MCP twin.

Probe-by-default (read-only: report match/orphans/collisions, write NOTHING);
`apply` / `resume` / `rollback` are explicit, mutually exclusive, WRITE-gated args.
Shares the CLI's core implementation (core.rekey) — no second migration path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")
pytest.importorskip("blake3", reason="run_scan needs wardline[loomweave]")

from wardline.core import paths  # noqa: E402
from wardline.core.baseline import load_baseline  # noqa: E402
from wardline.core.fingerprint_v0 import compute_finding_fingerprint_v0  # noqa: E402
from wardline.core.rekey import load_journal, snapshot_dir, write_journal  # noqa: E402
from wardline.core.run import run_scan  # noqa: E402
from wardline.mcp.server import WardlineMCPServer, _rekey  # noqa: E402
from wardline.mcp.tooling import ToolError  # noqa: E402

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return raw(p)\n"
)


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return project


def _seed_wlfp1_baseline(project: Path, *, extra_fps: tuple[str, ...] = ()):
    leak = next(f for f in run_scan(project).findings if f.rule_id == "PY-WL-101")
    old_fp = compute_finding_fingerprint_v0(
        rule_id=leak.rule_id,
        path=leak.location.path,
        line_start=leak.location.line_start,
        qualname=leak.qualname,
        taint_path=leak.taint_path_v0,
    )
    entries = [{"fingerprint": old_fp, "rule_id": leak.rule_id, "path": leak.location.path, "message": leak.message}]
    entries += [{"fingerprint": fp, "rule_id": "PY-WL-101", "path": "gone.py", "message": "x"} for fp in extra_fps]
    bp = paths.baseline_path(project)
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_text(
        yaml.safe_dump({"fingerprint_scheme": "wlfp1", "version": 1, "entries": entries}),
        encoding="utf-8",
    )
    return leak, old_fp


def test_rekey_defaults_to_read_only_probe(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _seed_wlfp1_baseline(project)
    result = _rekey({}, project)
    assert result["mode"] == "probe"
    assert result["matched"] == 1
    assert result["orphaned"] == []
    assert result["clean"] is True
    # Writes NOTHING: no snapshot, no journal, store untouched (still wlfp1).
    assert not paths.migration_journal_path(project).exists()
    assert not snapshot_dir(project).exists()
    assert "wlfp1" in paths.baseline_path(project).read_text(encoding="utf-8")


def test_rekey_probe_reports_orphans_with_cause(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _seed_wlfp1_baseline(project, extra_fps=("deadbeef" * 8,))
    result = _rekey({}, project)
    assert result["clean"] is False
    assert result["orphaned"] == ["deadbeef" * 8]
    assert result["per_store"] == {"baseline.yaml": 1}
    assert "moved" in result["orphan_cause"]


def test_rekey_apply_migrates_and_reports_journal(tmp_path: Path) -> None:
    project = _project(tmp_path)
    leak, old_fp = _seed_wlfp1_baseline(project)
    assert leak.fingerprint != old_fp
    result = _rekey({"apply": True}, project)
    assert result["mode"] == "apply"
    assert result["complete"] is True
    legs = {leg["name"]: leg for leg in result["legs"]}
    assert legs["baseline"]["done"] is True
    assert legs["baseline"]["carried_count"] == 1
    assert load_baseline(paths.baseline_path(project)).fingerprints == frozenset({leak.fingerprint})
    assert (snapshot_dir(project) / "baseline.yaml").is_file()


def test_rekey_resume_finishes_without_rescan(tmp_path: Path) -> None:
    project = _project(tmp_path)
    leak, _old = _seed_wlfp1_baseline(project)
    _rekey({"apply": True}, project)
    # Revert the baseline leg to pending, corrupt the live store, delete the source —
    # resume must re-carry from the snapshot and NEVER re-scan.
    jpath = paths.migration_journal_path(project)
    journal = load_journal(jpath)
    journal.leg("baseline").done = False
    write_journal(jpath, journal, root=project)
    paths.baseline_path(project).write_text(
        yaml.safe_dump({"fingerprint_scheme": "wlfp2", "version": 1, "entries": []}), encoding="utf-8"
    )
    (project / "svc.py").unlink()
    result = _rekey({"resume": True}, project)
    assert result["mode"] == "resume"
    assert result["complete"] is True
    assert load_baseline(paths.baseline_path(project)).fingerprints == frozenset({leak.fingerprint})


def test_rekey_rollback_restores_stores(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _leak, old_fp = _seed_wlfp1_baseline(project)
    before = paths.baseline_path(project).read_bytes()
    _rekey({"apply": True}, project)
    result = _rekey({"rollback": True}, project)
    assert result["mode"] == "rollback"
    assert "baseline.yaml" in result["restored"]
    assert "not reversed" in result["note"].lower()
    assert paths.baseline_path(project).read_bytes() == before
    assert not paths.migration_journal_path(project).exists()


def test_rekey_modes_are_mutually_exclusive(tmp_path: Path) -> None:
    project = _project(tmp_path)
    with pytest.raises(ToolError, match="mutually exclusive"):
        _rekey({"apply": True, "rollback": True}, project)


def _tool_call(server: WardlineMCPServer, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    assert "error" not in resp, resp
    return resp["result"]


def test_rekey_apply_denied_by_no_write_policy(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _seed_wlfp1_baseline(project)
    server = WardlineMCPServer(root=project, allow_write=False)
    for arg in ("apply", "resume", "rollback"):
        result = _tool_call(server, "rekey", {arg: True})
        assert result["isError"] is True, arg
        assert "write" in result["content"][0]["text"].lower()
    # The default read-only probe stays allowed under the same policy.
    ok = _tool_call(server, "rekey")
    assert "isError" not in ok


def test_rekey_apply_with_filigree_url_denied_by_no_network_policy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    project = _project(tmp_path)
    _seed_wlfp1_baseline(project)
    server = WardlineMCPServer(root=project, filigree_url="http://127.0.0.1:9/weft", allow_network=False)
    result = _tool_call(server, "rekey", {"apply": True})
    assert result["isError"] is True
    assert "network" in result["content"][0]["text"].lower()
