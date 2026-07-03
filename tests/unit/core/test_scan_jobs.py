"""Unit tests for core/scan_jobs: on-disk redaction of the Filigree URL and the
monotonic (terminal-wins) status.json write discipline."""

import json
import subprocess
from pathlib import Path
from typing import Any

import wardline.core.scan_jobs as scan_jobs
from wardline.core.filigree_emit import EmitResult
from wardline.core.scan_jobs import (
    _SCAN_JOB_FILIGREE_URL_ENV,
    _write_status,
    read_scan_job_status,
    run_scan_job_worker,
    start_scan_job,
    status_path,
)

_SECRET_URL = "https://user:secret@filigree.example/api/p/demo/weft/scan-results?token=abc#frag"
_REDACTED_URL = "https://<redacted>@filigree.example/api/p/demo/weft/scan-results"


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "svc.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    return project


class _CapturingEmitter:
    urls: list[str] = []

    def __init__(self, url: str, *args: object, **kwargs: object) -> None:
        type(self).urls.append(url)

    def emit(self, findings: object, *, scanned_paths: object = ()) -> EmitResult:
        return EmitResult(reachable=True, created=0, url="https://filigree.example/api/weft/scan-results")


# --- Finding: request.json/status.json must never persist the raw (credential-bearing)
# --- Filigree URL; the worker gets the live URL out-of-band. ---------------------------


def test_foreground_job_persists_only_redacted_url_but_emits_to_live_url(tmp_path: Path, monkeypatch) -> None:
    project = _project(tmp_path)
    _CapturingEmitter.urls = []
    monkeypatch.setattr(scan_jobs, "FiligreeEmitter", _CapturingEmitter)
    monkeypatch.delenv(_SCAN_JOB_FILIGREE_URL_ENV, raising=False)

    status = start_scan_job(project, {"filigree_url": _SECRET_URL}, foreground=True)

    assert status["status"] == "completed"
    # the emitter received the caller's exact live URL (credentials + query intact)
    assert _CapturingEmitter.urls == [_SECRET_URL]
    # ...but neither on-disk job file carries it
    job_id = str(status["job_id"])
    job_dir = project / ".weft" / "wardline" / "jobs" / job_id
    request_text = (job_dir / "request.json").read_text(encoding="utf-8")
    status_text = (job_dir / "status.json").read_text(encoding="utf-8")
    for text in (request_text, status_text):
        assert "user:secret" not in text
        assert "token=abc" not in text
        assert "#frag" not in text
    assert json.loads(request_text)["filigree_url"] == _REDACTED_URL
    assert json.loads(status_text)["request"]["filigree_url"] == _REDACTED_URL


def test_background_job_hands_live_url_to_worker_via_environment(tmp_path: Path, monkeypatch) -> None:
    project = _project(tmp_path)
    calls: list[dict[str, Any]] = []

    class _FakePopen:
        pid = 4321

        def __init__(self, args: list[str], **kwargs: object) -> None:
            calls.append({"args": args, **kwargs})

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)

    status = start_scan_job(project, {"filigree_url": _SECRET_URL})

    assert len(calls) == 1
    env = calls[0]["env"]
    assert isinstance(env, dict)
    assert env[_SCAN_JOB_FILIGREE_URL_ENV] == _SECRET_URL
    job_id = str(status["job_id"])
    job_dir = project / ".weft" / "wardline" / "jobs" / job_id
    for name in ("request.json", "status.json"):
        text = (job_dir / name).read_text(encoding="utf-8")
        assert "user:secret" not in text
        assert "token=abc" not in text


def test_background_job_without_filigree_url_inherits_environment(tmp_path: Path, monkeypatch) -> None:
    project = _project(tmp_path)
    calls: list[dict[str, Any]] = []

    class _FakePopen:
        pid = 4321

        def __init__(self, args: list[str], **kwargs: object) -> None:
            calls.append({"args": args, **kwargs})

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)

    start_scan_job(project, {})

    assert calls[0]["env"] is None  # plain inheritance; no handoff var injected


def test_worker_recovers_live_url_from_handoff_environment(tmp_path: Path, monkeypatch) -> None:
    project = _project(tmp_path)
    calls: list[dict[str, Any]] = []

    class _FakePopen:
        pid = 4321

        def __init__(self, args: list[str], **kwargs: object) -> None:
            calls.append({"args": args, **kwargs})

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    status = start_scan_job(project, {"filigree_url": _SECRET_URL})
    job_id = str(status["job_id"])

    _CapturingEmitter.urls = []
    monkeypatch.setattr(scan_jobs, "FiligreeEmitter", _CapturingEmitter)
    # the fake pid recorded by start must read as alive while the worker runs in-process
    monkeypatch.setattr(scan_jobs, "_pid_alive", lambda pid: True)
    # simulate the spawned worker: the handoff env var is present in its process env
    monkeypatch.setenv(_SCAN_JOB_FILIGREE_URL_ENV, _SECRET_URL)
    run_scan_job_worker(project, job_id)

    assert _CapturingEmitter.urls == [_SECRET_URL]
    assert read_scan_job_status(project, job_id)["status"] == "completed"


def test_worker_re_resolves_url_from_env_when_no_handoff(tmp_path: Path, monkeypatch) -> None:
    project = _project(tmp_path)
    calls: list[dict[str, Any]] = []

    class _FakePopen:
        pid = 4321

        def __init__(self, args: list[str], **kwargs: object) -> None:
            calls.append({"args": args, **kwargs})

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    status = start_scan_job(project, {"filigree_url": "https://filigree.example/api/weft/scan-results"})
    job_id = str(status["job_id"])

    _CapturingEmitter.urls = []
    monkeypatch.setattr(scan_jobs, "FiligreeEmitter", _CapturingEmitter)
    monkeypatch.setattr(scan_jobs, "_pid_alive", lambda pid: True)
    monkeypatch.delenv(_SCAN_JOB_FILIGREE_URL_ENV, raising=False)
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "https://resolved.example/api/weft/scan-results")
    run_scan_job_worker(project, job_id)

    assert _CapturingEmitter.urls == ["https://resolved.example/api/weft/scan-results"]


def test_worker_signals_enrichment_failure_when_live_url_unrecoverable(tmp_path: Path, monkeypatch) -> None:
    # An emit was configured but the live URL is gone (no handoff, nothing to
    # re-resolve): the job must SIGNAL (completed_with_enrichment_failure), never
    # silently skip the configured enrichment.
    project = _project(tmp_path)
    calls: list[dict[str, Any]] = []

    class _FakePopen:
        pid = 4321

        def __init__(self, args: list[str], **kwargs: object) -> None:
            calls.append({"args": args, **kwargs})

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    status = start_scan_job(project, {"filigree_url": _SECRET_URL})
    job_id = str(status["job_id"])

    monkeypatch.setattr(scan_jobs, "_pid_alive", lambda pid: True)
    monkeypatch.delenv(_SCAN_JOB_FILIGREE_URL_ENV, raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr(scan_jobs, "resolve_filigree_url", lambda *a, **k: None)
    run_scan_job_worker(project, job_id)

    payload = read_scan_job_status(project, job_id)
    assert payload["status"] == "completed_with_enrichment_failure"
    assert payload["failure_kind"] == "enrichment"
    assert "unreachable" in str(payload["filigree_emit"]["disabled_reason"])
    # the signal itself never echoes the credential-bearing URL
    assert "user:secret" not in json.dumps(payload)


# --- Finding: parent/worker status.json lost-update race — terminal statuses are
# --- monotonic (first terminal write wins; stale writers cannot regress them). --------


def _terminal_completed(job_id: str) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "status": "completed",
        "phase": "complete",
        "progress": {"steps_completed": 4, "steps_total": 4},
        "request": {},
        "artifacts": {"findings": "findings.jsonl"},
        "failure_kind": None,
        "error": None,
    }


def test_write_status_refuses_to_regress_terminal_status(tmp_path: Path) -> None:
    project = _project(tmp_path)
    job_id = "a" * 32
    path = status_path(project, job_id)
    path.parent.mkdir(parents=True)
    _write_status(project, job_id, _terminal_completed(job_id))

    stale = {"job_id": job_id, "status": "running", "phase": "starting", "pid": 999}
    returned = _write_status(project, job_id, stale)

    assert returned["status"] == "completed"
    assert returned["artifacts"] == {"findings": "findings.jsonl"}
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["status"] == "completed"
    assert persisted["artifacts"] == {"findings": "findings.jsonl"}


def test_write_status_refuses_conflicting_terminal_overwrite(tmp_path: Path) -> None:
    # First terminal write wins: a racing "cancelled"/"failed" cannot replace "completed".
    project = _project(tmp_path)
    job_id = "b" * 32
    path = status_path(project, job_id)
    path.parent.mkdir(parents=True)
    _write_status(project, job_id, _terminal_completed(job_id))

    for regression in ("cancelled", "failed"):
        stale = dict(_terminal_completed(job_id))
        stale["status"] = regression
        returned = _write_status(project, job_id, stale)
        assert returned["status"] == "completed"

    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "completed"


def test_write_status_allows_same_terminal_rewrite(tmp_path: Path) -> None:
    project = _project(tmp_path)
    job_id = "c" * 32
    path = status_path(project, job_id)
    path.parent.mkdir(parents=True)
    _write_status(project, job_id, _terminal_completed(job_id))

    updated = _terminal_completed(job_id)
    updated["summary"] = {"total": 0}
    _write_status(project, job_id, updated)

    assert json.loads(path.read_text(encoding="utf-8"))["summary"] == {"total": 0}


def test_fast_worker_completion_survives_parent_handoff_write(tmp_path: Path, monkeypatch) -> None:
    # Deterministic reproduction of the race: the worker runs to COMPLETION before the
    # parent's post-Popen "running"/"starting" write lands. The parent's stale write must
    # not regress the terminal status (which would later read as failed/stale_worker once
    # the exited worker's pid is seen dead).
    project = _project(tmp_path)

    class _InlineWorkerPopen:
        pid = 987654  # a pid that is certainly not a live process of ours

        def __init__(self, args: list[str], **kwargs: object) -> None:
            # args: [python, -m, module, root, job_id] — run the worker synchronously,
            # so its terminal write lands BEFORE the parent's handoff write.
            run_scan_job_worker(Path(args[3]), args[4])

    monkeypatch.setattr(subprocess, "Popen", _InlineWorkerPopen)

    status = start_scan_job(project, {})

    assert status["status"] == "completed"
    job_id = str(status["job_id"])
    persisted = json.loads(status_path(project, job_id).read_text(encoding="utf-8"))
    assert persisted["status"] == "completed"
    assert "findings" in persisted["artifacts"]
    # a later poll must still see the completed terminal status, not failed/stale_worker
    polled = read_scan_job_status(project, job_id)
    assert polled["status"] == "completed"
    assert polled["failure_kind"] is None
