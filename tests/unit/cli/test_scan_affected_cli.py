"""Phase 7 — ``wardline scan --affected`` through the Click CLI.

Drives the real ``scan`` command over a tmp project tree, mirroring
``tests/unit/cli/test_scan_rust.py``. Covers:

* ``--affected <fixture-file>`` scopes the analysis to the affected entity's file;
* ``--affected -`` (stdin) via ``CliRunner().invoke(..., input=...)``;
* an empty ``--affected -`` payload falls back to a full scan (INV-3);
* a malformed payload exits 2 (spec §7);
* ``--affected`` + ``--new-since`` together exits 2 (mutual exclusion);
* ``--format sarif`` carries the scope block at ``runs[0].properties.wardline_delta_scope``;
* a delta CLI Filigree emit forces ``mark_unseen=False`` (INV-5).
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.scan import scan

# A trusted boundary returning an external-tainted value: PY-WL-101 ERROR defect.
# Mirrors ``_LEAKY`` in tests/unit/core/test_run_affected.py.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _two_file_proj(tmp_path: Path) -> Path:
    """A project with two leaky modules, ``good.py`` + ``evil.py``, each carrying a
    PY-WL-101 ERROR on its ``leaky`` entity."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "good.py").write_text(_LEAKY, encoding="utf-8")
    (proj / "evil.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _worklist_file(tmp_path: Path, *locators: str) -> Path:
    """Write a bare warpline entity-list JSON fixture and return its path."""
    payload = [{"locator": loc} for loc in locators]
    fixture = tmp_path / "worklist.json"
    fixture.write_text(json.dumps(payload), encoding="utf-8")
    return fixture


def test_affected_file_scopes_analysis(tmp_path: Path) -> None:
    """``--affected <file>`` naming only ``good.leaky`` analyzes one of two files and
    reports a delta scope block; the stderr scope line names delta mode."""
    proj = _two_file_proj(tmp_path)
    worklist = _worklist_file(tmp_path, "python:function:good.leaky")
    out = proj / "findings.agent-summary.json"

    result = CliRunner().invoke(
        scan,
        [str(proj), "--affected", str(worklist), "--format", "agent-summary", "--output", str(out)],
    )

    assert result.exit_code == 0
    summary = json.loads(out.read_text())
    assert summary["scope"]["mode"] == "delta"
    assert summary["scope"]["files_discovered"] == 2
    assert summary["scope"]["files_analyzed"] == 1
    assert "scope: delta" in result.stderr


def test_affected_stdin_dash_scopes(tmp_path: Path) -> None:
    """``--affected -`` reads the entity list from stdin (Click's stdin, not sys.stdin);
    a valid list → delta mode with a non-null analyzed count."""
    proj = _two_file_proj(tmp_path)
    out = proj / "findings.agent-summary.json"
    payload = json.dumps([{"locator": "python:function:good.leaky"}])

    result = CliRunner().invoke(
        scan,
        [str(proj), "--affected", "-", "--format", "agent-summary", "--output", str(out)],
        input=payload,
    )

    assert result.exit_code == 0
    summary = json.loads(out.read_text())
    assert summary["scope"]["mode"] == "delta"
    assert summary["scope"]["files_analyzed"] == 1


def test_affected_stdin_empty_falls_back_to_full(tmp_path: Path) -> None:
    """An empty ``--affected -`` payload (``[]``) is NOT an error — it falls back to a full
    scan (INV-3), declared as full-fallback / gate-of-record."""
    proj = _two_file_proj(tmp_path)
    out = proj / "findings.agent-summary.json"

    result = CliRunner().invoke(
        scan,
        [str(proj), "--affected", "-", "--format", "agent-summary", "--output", str(out)],
        input="[]",
    )

    assert result.exit_code == 0
    summary = json.loads(out.read_text())
    assert summary["scope"]["mode"] == "full-fallback"
    assert summary["scope"]["gate_authority"] == "gate-of-record"
    assert summary["scope"]["files_analyzed"] == summary["scope"]["files_discovered"] == 2


def test_affected_malformed_payload_exits_2(tmp_path: Path) -> None:
    """A structurally malformed payload (not valid JSON / not an object|array) → the shared
    SystemExit(2) path (spec §7 malformed scope → exit 2)."""
    proj = _two_file_proj(tmp_path)

    result = CliRunner().invoke(
        scan,
        [str(proj), "--affected", "-"],
        input="this is not json",
    )

    assert result.exit_code == 2


def test_affected_stdin_over_cap_exits_2(tmp_path: Path) -> None:
    """A VALID-JSON ``--affected -`` stdin payload that exceeds the byte cap is rejected
    BEFORE an unbounded read + parse (DoS guard, §7) → the shared SystemExit(2) path."""
    from wardline.core.delta_scope import _MAX_PAYLOAD_BYTES

    proj = _two_file_proj(tmp_path)
    big_locator = "python:function:" + ("x" * (_MAX_PAYLOAD_BYTES + 1))
    payload = json.dumps([{"locator": big_locator}])
    assert len(payload.encode("utf-8")) > _MAX_PAYLOAD_BYTES

    result = CliRunner().invoke(
        scan,
        [str(proj), "--affected", "-"],
        input=payload,
    )

    assert result.exit_code == 2


def test_affected_with_new_since_exits_2(tmp_path: Path) -> None:
    """``--affected`` and ``--new-since`` are mutually exclusive → exit 2."""
    proj = _two_file_proj(tmp_path)
    worklist = _worklist_file(tmp_path, "python:function:good.leaky")

    result = CliRunner().invoke(
        scan,
        [str(proj), "--affected", str(worklist), "--new-since", "origin/main"],
    )

    assert result.exit_code == 2
    assert "mutually exclusive" in result.stderr


def test_affected_with_fail_on_exits_2(tmp_path: Path) -> None:
    """``--affected`` (advisory delta) cannot drive ``--fail-on`` (the gate of record).

    A delta scan analyzes only the scoped subset of the tree, so a green gate would be
    unearned (an ERROR in an unanalyzed file would never be seen). The combination is
    rejected at the surface → exit 2, pointing the user at ``--new-since`` (the
    authoritative change-scoped gate) or a full scan."""
    proj = _two_file_proj(tmp_path)
    worklist = _worklist_file(tmp_path, "python:function:good.leaky")

    result = CliRunner().invoke(
        scan,
        [str(proj), "--affected", str(worklist), "--fail-on", "ERROR"],
    )

    assert result.exit_code == 2
    assert "--fail-on" in result.stderr
    assert "--new-since" in result.stderr


def test_affected_sarif_carries_scope_run_properties(tmp_path: Path) -> None:
    """``--format sarif`` threads the scope block into ``runs[0].properties.
    wardline_delta_scope`` (the SARIF run-properties channel)."""
    proj = _two_file_proj(tmp_path)
    worklist = _worklist_file(tmp_path, "python:function:good.leaky")
    out = proj / "findings.sarif"

    result = CliRunner().invoke(
        scan,
        [str(proj), "--affected", str(worklist), "--format", "sarif", "--output", str(out)],
    )

    assert result.exit_code == 0
    sarif = json.loads(out.read_text())
    props = sarif["runs"][0]["properties"]["wardline_delta_scope"]
    assert props["mode"] == "delta"
    assert props["files_analyzed"] == 1
    assert "boundary_caveat" in props


def test_full_scan_sarif_has_no_scope_properties(tmp_path: Path) -> None:
    """INV-1: a full scan (no ``--affected``) emits no ``runs[0].properties`` scope key."""
    proj = _two_file_proj(tmp_path)
    out = proj / "findings.sarif"

    result = CliRunner().invoke(
        scan,
        [str(proj), "--format", "sarif", "--output", str(out)],
    )

    assert result.exit_code == 0
    sarif = json.loads(out.read_text())
    assert "properties" not in sarif["runs"][0]
    assert "scope:" not in result.stderr


def test_delta_emit_forces_mark_unseen_false(tmp_path: Path, monkeypatch) -> None:
    """INV-5: a delta CLI Filigree emit builds the request body with ``mark_unseen=False``
    so out-of-scope findings (absent from the FILTERED findings list but present in the
    FULL scanned_paths) are never read as fixed and closed."""
    captured: dict[str, object] = {}

    class _RecordingEmitter:
        def __init__(self, url: str, **kwargs: object) -> None:
            captured["url"] = url

        def emit(self, findings, *, scanned_paths=(), language=None, mark_unseen=None):  # type: ignore[no-untyped-def]
            captured["mark_unseen"] = mark_unseen
            from wardline.core.filigree_emit import EmitResult

            return EmitResult(reachable=True, created=len(list(findings)), token_sent=False, url=str(captured["url"]))

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _RecordingEmitter)
    monkeypatch.setattr("wardline.filigree.config.load_filigree_token", lambda root: None)

    proj = _two_file_proj(tmp_path)
    worklist = _worklist_file(tmp_path, "python:function:good.leaky")
    out = proj / "findings.jsonl"

    result = CliRunner().invoke(
        scan,
        [
            str(proj),
            "--affected",
            str(worklist),
            "--filigree-url",
            "http://example.invalid/api/scan-results",
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == 0
    assert captured["mark_unseen"] is False


def test_full_scan_emit_uses_auto_mark_unseen(tmp_path: Path, monkeypatch) -> None:
    """The companion: a FULL scan emit passes ``mark_unseen=None`` (auto) so reconciliation
    proceeds normally — the delta guard above is specific to delta mode."""
    captured: dict[str, object] = {}

    class _RecordingEmitter:
        def __init__(self, url: str, **kwargs: object) -> None:
            captured["url"] = url

        def emit(self, findings, *, scanned_paths=(), language=None, mark_unseen=None):  # type: ignore[no-untyped-def]
            captured["mark_unseen"] = mark_unseen
            from wardline.core.filigree_emit import EmitResult

            return EmitResult(reachable=True, created=len(list(findings)), token_sent=False, url=str(captured["url"]))

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _RecordingEmitter)
    monkeypatch.setattr("wardline.filigree.config.load_filigree_token", lambda root: None)

    proj = _two_file_proj(tmp_path)
    out = proj / "findings.jsonl"

    result = CliRunner().invoke(
        scan,
        [
            str(proj),
            "--filigree-url",
            "http://example.invalid/api/scan-results",
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == 0
    assert captured["mark_unseen"] is None
