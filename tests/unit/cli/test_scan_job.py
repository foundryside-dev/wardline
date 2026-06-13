import json
import signal
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


def test_scan_job_cancel_signals_process_group_and_persists_terminal_status(tmp_path: Path, monkeypatch) -> None:
    job_id = "b" * 32
    project = tmp_path / "proj"
    project.mkdir()
    _write_job_status(project, job_id, _base_job(job_id))
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr("wardline.core.scan_jobs._pid_alive", lambda pid: True)
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
