"""MCP `scan` legis-artifact attachment (`_attach_legis_artifact`).

The MCP scan path has its own dirty/signed status projection distinct from core
`build_legis_artifact`: it reads `allow_dirty` from the args and computes
`status["signed"] = key present and not dirty`. These tests pin that projection —
the core/CLI layers are covered in test_legis_artifact.py / test_cli.py.

Every test `delenv`s the ambient key first: an inherited WARDLINE_LEGIS_ARTIFACT_KEY
would otherwise provision signing where a test means "no key".
"""

from __future__ import annotations

import subprocess

from wardline.core.legis import LEGIS_ARTIFACT_KEY_ENV
from wardline.mcp.server import _scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _git(repo, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _committed_repo(tmp_path):
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "svc.py").write_text(_LEAKY, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


def test_legis_not_attached_unless_requested(tmp_path, monkeypatch) -> None:
    # No key provisioned and no legis_artifact arg -> the response is byte-unchanged.
    monkeypatch.delenv(LEGIS_ARTIFACT_KEY_ENV, raising=False)
    repo = _committed_repo(tmp_path)
    out = _scan({}, repo, None, None)
    assert "legis_artifact" not in out
    assert "legis_artifact_status" not in out


def test_legis_artifact_unsigned_when_no_key(tmp_path, monkeypatch) -> None:
    # legis_artifact:true with no key -> attach an unsigned artifact (legis optional-verify).
    monkeypatch.delenv(LEGIS_ARTIFACT_KEY_ENV, raising=False)
    repo = _committed_repo(tmp_path)
    out = _scan({"legis_artifact": True}, repo, None, None)
    assert "legis_artifact" in out
    status = out["legis_artifact_status"]
    assert status["configured"] is True
    assert status["signed"] is False
    assert "artifact_signature" not in out["legis_artifact"]


def test_legis_suppressed_under_summary_only_even_with_key(tmp_path, monkeypatch) -> None:
    # Dogfood-4 B6: summary_only promises the smallest gate payload, but a
    # provisioned key auto-attached a ~56KB artifact into it (blew the MCP token
    # cap). With a key and summary_only:true the artifact must stay off.
    monkeypatch.setenv(LEGIS_ARTIFACT_KEY_ENV, "testsecret")
    repo = _committed_repo(tmp_path)
    out = _scan({"summary_only": True}, repo, None, None)
    assert "legis_artifact" not in out
    assert "legis_artifact_status" not in out


def test_legis_explicit_opt_in_wins_over_summary_only(tmp_path, monkeypatch) -> None:
    # The caller who asks for both gets both: explicit legis_artifact:true still
    # attaches under summary_only.
    monkeypatch.setenv(LEGIS_ARTIFACT_KEY_ENV, "testsecret")
    repo = _committed_repo(tmp_path)
    out = _scan({"summary_only": True, "legis_artifact": True}, repo, None, None)
    assert "legis_artifact" in out
    assert out["legis_artifact_status"]["signed"] is True


def test_legis_clean_tree_with_key_is_signed(tmp_path, monkeypatch) -> None:
    # The positive arm of `signed = key and not dirty`: a key present on a CLEAN tree signs.
    monkeypatch.setenv(LEGIS_ARTIFACT_KEY_ENV, "testsecret")
    repo = _committed_repo(tmp_path)
    out = _scan({}, repo, None, None)  # a provisioned key activates the block without the arg
    status = out["legis_artifact_status"]
    assert status["signed"] is True
    assert status.get("dirty") is False
    assert out["legis_artifact"]["artifact_signature"].startswith("hmac-sha256:")


def test_legis_dirty_tree_with_key_reports_unsigned_with_loud_reason(tmp_path, monkeypatch) -> None:
    # The MCP-only projection arm that matters: a dirty tree is NOT signed even with a key
    # present (false-provenance guard) -> signed:false, dirty:true, and a loud reason
    # (agent-first parity with the CLI's "never gate CI on it" warning).
    monkeypatch.setenv(LEGIS_ARTIFACT_KEY_ENV, "testsecret")
    repo = _committed_repo(tmp_path)
    (repo / "svc.py").write_text(_LEAKY + "\n# dirty\n", encoding="utf-8")
    out = _scan({"allow_dirty": True}, repo, None, None)
    status = out["legis_artifact_status"]
    assert status["signed"] is False  # despite the key — the dirty arm forces it
    assert status["dirty"] is True
    assert status["reason"] is not None and "UNSIGNED" in status["reason"]
    assert "never gate CI" in status["reason"]
    assert out["legis_artifact"]["dirty"] is True
    assert "artifact_signature" not in out["legis_artifact"]


def test_legis_dirty_tree_with_key_no_allow_dirty_refuses_softly(tmp_path, monkeypatch) -> None:
    # Key present + dirty tree + NO allow_dirty -> signing refused, fail-soft: no postable
    # artifact, status carries the refusal reason, the scan itself still succeeds.
    monkeypatch.setenv(LEGIS_ARTIFACT_KEY_ENV, "testsecret")
    repo = _committed_repo(tmp_path)
    (repo / "svc.py").write_text(_LEAKY + "\n# dirty\n", encoding="utf-8")
    out = _scan({}, repo, None, None)
    status = out["legis_artifact_status"]
    assert status["signed"] is False
    assert status["reason"] is not None
    assert "legis_artifact" not in out  # no postable artifact on a refusal
    assert out["summary"]["total"] >= 1  # scan unaffected
