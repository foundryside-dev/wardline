import json
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.core.filigree_emit import EmitResult
from wardline.core.scan_jobs import DEFAULT_SCAN_JOB_TIMEOUT_SECONDS

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _write(project: Path, name: str, src: str) -> Path:
    path = project / name
    path.write_text(src, encoding="utf-8")
    return path


def _write_job_status(project: Path, job_id: str, payload: dict[str, object]) -> None:
    job_dir = project / ".weft" / "wardline" / "jobs" / job_id
    job_dir.mkdir(parents=True)
    (job_dir / "status.json").write_text(json.dumps(payload), encoding="utf-8")


def _base_job(job_id: str) -> dict[str, object]:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "job_id": job_id,
        "status": "running",
        "phase": "scanning",
        "pid": 12345,
        "progress": {"steps_completed": 1, "steps_total": 4},
        "created_at": now,
        "updated_at": now,
        "heartbeat": now,
        "request": {},
        "artifacts": {},
        "failure_kind": None,
        "error": None,
    }


def test_scan_job_start_foreground_completes_and_status_is_pollable(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    _write(project, "svc.py", "def ok():\n    return 1\n")

    result = CliRunner().invoke(cli, ["scan-job", "start", str(project), "--foreground"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "completed"
    assert payload["phase"] == "complete"
    assert payload["progress"]["steps_completed"] == payload["progress"]["steps_total"] == 4
    assert payload["heartbeat"]
    assert Path(payload["artifacts"]["findings"]).exists()

    status = CliRunner().invoke(cli, ["scan-job", "status", payload["job_id"], "--path", str(project)])
    assert status.exit_code == 0, status.output
    assert json.loads(status.output)["job_id"] == payload["job_id"]


def test_scan_job_gate_failure_is_terminal_gate_status(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    _write(project, "svc.py", _LEAKY)

    result = CliRunner().invoke(cli, ["scan-job", "start", str(project), "--fail-on", "ERROR", "--foreground"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "failed"
    assert payload["failure_kind"] == "gate"
    assert payload["gate"]["verdict"] == "FAILED"
    assert Path(payload["artifacts"]["findings"]).exists()


def test_scan_job_enrichment_failure_keeps_scan_artifact(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    _write(project, "svc.py", "def ok():\n    return 1\n")

    class _UnavailableEmitter:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def emit(self, findings: object, *, scanned_paths: object = ()) -> EmitResult:
            return EmitResult(reachable=False, url="http://x/api/weft/scan-results")

    monkeypatch.setattr("wardline.core.scan_jobs.FiligreeEmitter", _UnavailableEmitter)

    result = CliRunner().invoke(
        cli,
        [
            "scan-job",
            "start",
            str(project),
            "--filigree-url",
            "http://x/api/weft/scan-results",
            "--foreground",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "completed_with_enrichment_failure"
    assert payload["failure_kind"] == "enrichment"
    assert payload["filigree_emit"]["disabled_reason"] == "filigree unreachable at http://x/api/weft/scan-results"
    assert Path(payload["artifacts"]["findings"]).exists()


def test_scan_job_status_marks_dead_worker_failed(tmp_path: Path, monkeypatch) -> None:
    job_id = "a" * 32
    project = tmp_path / "proj"
    project.mkdir()
    _write_job_status(project, job_id, _base_job(job_id))
    monkeypatch.setattr("wardline.core.scan_jobs._pid_alive", lambda pid: False)

    result = CliRunner().invoke(cli, ["scan-job", "status", job_id, "--path", str(project)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "failed"
    assert payload["failure_kind"] == "stale_worker"
    assert "12345" in payload["error"]

    persisted = json.loads((project / ".weft" / "wardline" / "jobs" / job_id / "status.json").read_text())
    assert persisted["status"] == "failed"
    assert persisted["failure_kind"] == "stale_worker"


def test_scan_job_agent_summary_artifact_matches_terminal_status(tmp_path: Path, monkeypatch) -> None:
    # Honesty: the agent-summary ARTIFACT must carry the same gate (honoring
    # fail_on_unanalyzed) and filigree_emit block as the terminal job status — not an
    # unanalyzed-blind, pre-enrichment `configured: false` snapshot.
    project = tmp_path / "proj"
    project.mkdir()
    _write(project, "ok.py", "def ok():\n    return 1\n")
    _write(project, "broken.py", "def f(:\n")  # parse error -> an unanalyzed file

    class _OkEmitter:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def emit(self, findings: object, *, scanned_paths: object = ()) -> EmitResult:
            return EmitResult(reachable=True, created=1, url="http://x/api/weft/scan-results")

    monkeypatch.setattr("wardline.core.scan_jobs.FiligreeEmitter", _OkEmitter)

    result = CliRunner().invoke(
        cli,
        [
            "scan-job",
            "start",
            str(project),
            "--format",
            "agent-summary",
            "--fail-on-unanalyzed",
            "--filigree-url",
            "http://x/api/weft/scan-results",
            "--foreground",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    artifact = json.loads(Path(payload["artifacts"]["findings"]).read_text())

    # the ARTIFACT gate honors fail_on_unanalyzed (tripped on the unanalyzed file),
    # matching the terminal status — not the unanalyzed-blind snapshot it used to write.
    assert artifact["summary"]["unanalyzed"] == 1
    assert artifact["gate"]["tripped"] is True == payload["gate"]["tripped"]
    assert "fail_on_unanalyzed" in artifact["gate"]["reason"]
    # integrations.filigree_emit reflects the REAL emit (configured + reachable), not configured:false
    emit_block = artifact["integrations"]["filigree_emit"]
    assert emit_block["configured"] is True
    assert emit_block["reachable"] is True


def test_scan_job_cancel_signals_process_group_and_persists_terminal_status(tmp_path: Path, monkeypatch) -> None:
    job_id = "b" * 32
    project = tmp_path / "proj"
    project.mkdir()
    _write_job_status(project, job_id, _base_job(job_id))
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr("wardline.core.scan_jobs._pid_alive", lambda pid: True)
    # Treat the recorded pid as a validated worker for this path; the rejection of a
    # forged/non-worker pid is covered by
    # tests/unit/security/test_symlink_toctou_hardening.py::test_cancel_does_not_signal_forged_pid.
    monkeypatch.setattr("wardline.core.scan_jobs._pid_is_scan_job_worker", lambda pid, job_id: True)
    monkeypatch.setattr("wardline.core.scan_jobs.os.killpg", lambda pid, sig: sent.append((pid, sig)))

    result = CliRunner().invoke(cli, ["scan-job", "cancel", job_id, "--path", str(project)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "cancelled"
    assert payload["phase"] == "cancelled"
    assert payload["failure_kind"] == "cancelled"
    assert sent == [(12345, signal.SIGTERM)]

    persisted = json.loads((project / ".weft" / "wardline" / "jobs" / job_id / "status.json").read_text())
    assert persisted["status"] == "cancelled"


def test_scan_job_timeout_is_terminal_timeout_status(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    _write(project, "svc.py", "def ok():\n    return 1\n")

    def slow_scan(*args: object, **kwargs: object) -> object:
        time.sleep(0.2)
        raise AssertionError("timeout should interrupt run_scan before it returns")

    monkeypatch.setattr("wardline.core.scan_jobs.run_scan", slow_scan)

    result = CliRunner().invoke(cli, ["scan-job", "start", str(project), "--timeout", "0.01", "--foreground"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "failed"
    assert payload["failure_kind"] == "timeout"
    assert "timed out" in payload["error"]


def test_scan_job_start_applies_default_timeout(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    _write(project, "svc.py", "def ok():\n    return 1\n")

    result = CliRunner().invoke(cli, ["scan-job", "start", str(project), "--foreground"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "completed"
    assert payload["request"]["timeout_seconds"] == DEFAULT_SCAN_JOB_TIMEOUT_SECONDS


def test_scan_job_start_allows_timeout_opt_out(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    _write(project, "svc.py", "def ok():\n    return 1\n")

    result = CliRunner().invoke(cli, ["scan-job", "start", str(project), "--timeout", "0", "--foreground"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "completed"
    assert payload["request"]["timeout_seconds"] == 0.0


def test_scan_job_start_redacts_filigree_url_in_stdout_request(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    secret_url = "https://user:secret@filigree.example/api/p/demo/weft/scan-results?token=abc#frag"
    redacted_url = "https://<redacted>@filigree.example/api/p/demo/weft/scan-results"
    captured_requests: list[dict[str, object]] = []

    def fake_start_scan_job(root: Path, request: dict[str, object], *, foreground: bool = False) -> dict[str, object]:
        captured_requests.append(dict(request))
        payload = _base_job("c" * 32)
        payload["request"] = dict(request)
        return payload

    monkeypatch.setattr("wardline.cli.scan_job.start_scan_job", fake_start_scan_job)

    result = CliRunner().invoke(cli, ["scan-job", "start", str(project), "--filigree-url", secret_url])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert captured_requests[0]["filigree_url"] == secret_url
    assert payload["request"]["filigree_url"] == redacted_url
    assert "user:secret" not in result.output
    assert "token=abc" not in result.output
    assert "#frag" not in result.output


def test_scan_job_status_redacts_filigree_url_in_stdout_request(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    secret_url = "https://user:secret@filigree.example/api/p/demo/weft/scan-results?token=abc#frag"
    redacted_url = "https://<redacted>@filigree.example/api/p/demo/weft/scan-results"

    def fake_read_scan_job_status(root: Path, job_id: str) -> dict[str, object]:
        payload = _base_job(job_id)
        payload["request"] = {"filigree_url": secret_url}
        return payload

    monkeypatch.setattr("wardline.cli.scan_job.read_scan_job_status", fake_read_scan_job_status)

    result = CliRunner().invoke(cli, ["scan-job", "status", "d" * 32, "--path", str(project)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["request"]["filigree_url"] == redacted_url
    assert "user:secret" not in result.output
    assert "token=abc" not in result.output
    assert "#frag" not in result.output


def test_scan_job_cancel_redacts_filigree_url_in_stdout_request(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    secret_url = "https://user:secret@filigree.example/api/p/demo/weft/scan-results?token=abc#frag"
    redacted_url = "https://<redacted>@filigree.example/api/p/demo/weft/scan-results"

    def fake_cancel_scan_job(root: Path, job_id: str) -> dict[str, object]:
        payload = _base_job(job_id)
        payload["status"] = "cancelled"
        payload["request"] = {"filigree_url": secret_url}
        return payload

    monkeypatch.setattr("wardline.cli.scan_job.cancel_scan_job", fake_cancel_scan_job)

    result = CliRunner().invoke(cli, ["scan-job", "cancel", "e" * 32, "--path", str(project)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["request"]["filigree_url"] == redacted_url
    assert "user:secret" not in result.output
    assert "token=abc" not in result.output
    assert "#frag" not in result.output


def test_scan_job_background_worker_does_not_run_from_untrusted_root(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    _write(project, "svc.py", "def ok():\n    return 1\n")

    calls: list[dict[str, object]] = []

    class _FakePopen:
        pid = 4321

        def __init__(self, args: list[str], **kwargs: object) -> None:
            calls.append({"args": args, **kwargs})

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)

    result = CliRunner().invoke(cli, ["scan-job", "start", str(project)])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    call = calls[0]
    assert call["args"] == [
        sys.executable,
        "-m",
        "wardline.cli.scan_job_worker",
        str(project.resolve()),
        json.loads(result.output)["job_id"],
    ]
    worker_cwd = call["cwd"]
    assert isinstance(worker_cwd, Path)
    assert worker_cwd != project.resolve()
    assert (worker_cwd / "wardline").is_dir()
