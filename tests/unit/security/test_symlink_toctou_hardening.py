"""Security regressions for the 2026-06-15 symlink/TOCTOU review pass (PR #40).

An untrusted checkout (wardline scans agent-supplied code) must not be able to use a
planted symlink or a forged state file to make wardline follow a link off-box, clobber
an arbitrary user-writable file, disclose an outside file into the project, or signal an
unrelated process group. Each test drives one site found by the Codex review bot.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from wardline.core import paths, rekey, scan_jobs
from wardline.core.errors import WardlineError
from wardline.install.doctor import _filigree_token_candidates, _rewrite_env_token

# --- config.py: server-mode scope spoof via a symlinked store ------------------------


def test_server_scope_refuses_symlinked_store(tmp_path: Path, monkeypatch) -> None:
    import wardline.core.config as cfg

    victim = tmp_path / "victim"
    (victim / ".weft" / "filigree").mkdir(parents=True)
    attacker = tmp_path / "attacker"
    (attacker / ".weft").mkdir(parents=True)
    # attacker's store is a SYMLINK to victim's registered store
    (attacker / ".weft" / "filigree").symlink_to(victim / ".weft" / "filigree")
    reg = tmp_path / "server.json"
    reg.write_text(
        json.dumps({"port": 8749, "projects": {str((victim / ".weft" / "filigree").resolve()): {"prefix": "victim"}}})
    )
    monkeypatch.setattr(cfg, "_filigree_server_config_path", lambda: reg)

    # the spoofing checkout must NOT inherit victim's scoped URL...
    assert cfg.filigree_server_scoped_url(attacker) is None
    # ...while the legitimate (real-dir) project still resolves its own scope.
    assert cfg._filigree_server_scope(victim) == (8749, "victim")


# --- doctor.py: auth-repair must not write through a symlinked .env -------------------


def test_rewrite_env_refuses_symlinked_dotenv(tmp_path: Path) -> None:
    outside = tmp_path / "victim_secret.txt"
    outside.write_text("KEEP\n", encoding="utf-8")
    env = tmp_path / "proj" / ".env"
    env.parent.mkdir()
    env.symlink_to(outside)
    with pytest.raises(WardlineError, match="symlink"):
        _rewrite_env_token(env, "TOKEN")
    assert outside.read_text(encoding="utf-8") == "KEEP\n"  # target untouched
    assert "WEFT_FEDERATION_TOKEN" not in outside.read_text(encoding="utf-8")


# --- rekey.py: snapshot must not copy a symlinked store's target ----------------------


def test_snapshot_skips_symlinked_store(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    outside = tmp_path / "secret.txt"
    outside.write_text("TOP SECRET\n", encoding="utf-8")
    (state / "baseline.yaml").symlink_to(outside)  # planted symlink store
    (state / "waivers.yaml").write_text("version: 2\nwaivers: []\n", encoding="utf-8")

    present = rekey.snapshot_stores(root)
    snap = rekey.snapshot_dir(root)
    assert "baseline.yaml" not in present  # symlinked store is not snapshot-eligible
    assert not (snap / "baseline.yaml").exists()
    assert (snap / "waivers.yaml").exists()  # the real store still snapshots
    # the outside secret was never disclosed into the project snapshot
    assert all(p.read_text(encoding="utf-8") != "TOP SECRET\n" for p in snap.glob("*") if p.is_file())


# --- rekey.py: journal write must not follow a pre-planted <journal>.tmp symlink ------


def test_write_journal_refuses_symlinked_tmp(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    jpath = paths.migration_journal_path(root)
    jpath.parent.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "journal_victim.txt"
    victim.write_text("KEEP\n", encoding="utf-8")
    Path(str(jpath) + ".tmp").symlink_to(victim)
    journal = rekey.Journal(
        schema_version=1,
        fingerprint_scheme_from="wlfp1",
        fingerprint_scheme_to="wlfp2",
        snapshot_prescheme=True,
        remap={},
        collisions=(),
        legs=(),
    )
    with pytest.raises(WardlineError, match="symlink"):
        rekey.write_journal(jpath, journal, root=root)
    assert victim.read_text(encoding="utf-8") == "KEEP\n"  # target untouched


# --- scan_jobs.py: cancel must not killpg a forged/stale PID --------------------------


def test_cancel_does_not_signal_forged_pid(tmp_path: Path) -> None:
    # An innocent same-user process group, NOT a wardline worker.
    victim = subprocess.Popen(["sleep", "30"], start_new_session=True)  # noqa: S603, S607
    try:
        root = tmp_path / "proj"
        job_id = uuid.uuid4().hex
        jd = scan_jobs.job_dir(root, job_id)
        jd.mkdir(parents=True)
        # forged status.json naming the victim's pid as the "worker"
        (jd / "status.json").write_text(json.dumps({"status": "running", "pid": victim.pid}), encoding="utf-8")

        result = scan_jobs.cancel_scan_job(root, job_id)
        time.sleep(0.4)
        assert result["status"] == "cancelled"  # job is marked cancelled...
        assert victim.poll() is None  # ...but the innocent process group was NOT signaled
    finally:
        victim.terminate()
        victim.wait()


def test_repair_token_candidates_skip_symlinked_project_mint(tmp_path: Path, monkeypatch) -> None:
    # doctor --repair probes local token candidates by SENDING them to a service. The
    # project store is repo-controlled in an untrusted checkout; a symlinked mint would
    # exfil its target's bytes as a Bearer. The symlinked project mint must be skipped.
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "nohome")
    root = tmp_path / "proj"
    mint = root / ".weft" / "filigree"
    mint.mkdir(parents=True)
    (tmp_path / "outside_secret").write_text("EXFIL-TOKEN\n", encoding="utf-8")
    (mint / "federation_token").symlink_to(tmp_path / "outside_secret")
    assert _filigree_token_candidates(root) == []  # symlinked mint contributes nothing
    # a real regular mint is still a candidate
    (mint / "federation_token").unlink()
    (mint / "federation_token").write_text("GOOD\n", encoding="utf-8")
    assert _filigree_token_candidates(root) == ["GOOD"]


def test_explicit_agent_summary_output_refuses_symlink(tmp_path: Path) -> None:
    # `scan --format agent-summary -o <path>` must not follow a repo-controlled symlink at
    # the chosen filename and clobber an arbitrary target (the default + JSONL/SARIF paths
    # already use the no-follow writer).
    from click.testing import CliRunner

    from wardline.cli.main import cli

    project = tmp_path / "proj"
    project.mkdir()
    (project / "svc.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    victim = tmp_path / "victim.json"
    victim.write_text("KEEP\n", encoding="utf-8")
    out = tmp_path / "out.json"
    out.symlink_to(victim)
    result = CliRunner().invoke(cli, ["scan", str(project), "--format", "agent-summary", "--output", str(out)])
    assert result.exit_code == 2  # refused at the boundary
    assert "symlink" in result.output
    assert victim.read_text(encoding="utf-8") == "KEEP\n"  # target untouched


def test_pid_is_scan_job_worker_rejects_non_worker_group_leader() -> None:
    # A genuine group-leader that is NOT our worker (cmdline mismatch) is rejected.
    victim = subprocess.Popen(["sleep", "30"], start_new_session=True)  # noqa: S603, S607
    try:
        assert os.getpgid(victim.pid) == victim.pid  # it IS a group leader
        assert scan_jobs._pid_is_scan_job_worker(victim.pid, "anyjob") is False
    finally:
        victim.terminate()
        victim.wait()
