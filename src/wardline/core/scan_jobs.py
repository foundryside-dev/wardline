"""File-backed Wardline scan jobs.

The job surface is intentionally local and daemon-free: ``start`` writes a stable
handle under ``.weft/wardline/jobs/`` and a worker process updates status JSON as it
moves through scan, artifact write, optional enrichment, and gate evaluation.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wardline.core.agent_summary import build_agent_summary
from wardline.core.emit import JsonlSink
from wardline.core.errors import WardlineError
from wardline.core.filigree_emit import (
    EmitResult,
    FiligreeEmitter,
    filigree_destination,
    filigree_disabled_reason,
)
from wardline.core.finding import Severity
from wardline.core.run import baseline_migration_hint, gate_decision, run_scan
from wardline.core.safe_paths import safe_project_path, safe_write_text
from wardline.core.sarif import SarifSink

_JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_JOB_STEPS_TOTAL = 4
_HEARTBEAT_INTERVAL_SECONDS = 5.0
_STALE_AFTER_SECONDS = 30.0
DEFAULT_SCAN_JOB_TIMEOUT_SECONDS = 30 * 60
_TERMINAL_STATUSES = {"completed", "completed_with_enrichment_failure", "failed", "cancelled"}


class _ScanJobTimeout(WardlineError):
    """Internal terminal error for scan-job timeouts."""


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def jobs_dir(root: Path) -> Path:
    return safe_project_path(root, root / ".weft" / "wardline" / "jobs", label="wardline jobs")


def job_dir(root: Path, job_id: str) -> Path:
    if not _JOB_ID_RE.fullmatch(job_id):
        raise WardlineError(f"invalid scan job id: {job_id!r}")
    return safe_project_path(root, jobs_dir(root) / job_id, label="wardline scan job")


def status_path(root: Path, job_id: str) -> Path:
    return job_dir(root, job_id) / "status.json"


def request_path(root: Path, job_id: str) -> Path:
    return job_dir(root, job_id) / "request.json"


def read_scan_job_status(root: Path, job_id: str) -> dict[str, Any]:
    root = root.resolve()
    path = status_path(root, job_id)
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WardlineError(f"scan job {job_id} not found under {root}") from exc
    if not isinstance(parsed, dict):
        raise WardlineError(f"scan job {job_id} status is malformed")
    return _refresh_liveness(root, job_id, parsed)


def cancel_scan_job(root: Path, job_id: str) -> dict[str, Any]:
    """Cancel a non-terminal scan job and persist the terminal status."""
    root = root.resolve()
    status = read_scan_job_status(root, job_id)
    if str(status.get("status")) in _TERMINAL_STATUSES:
        return status
    pid = _status_pid(status)
    if pid is not None and _pid_alive(pid):
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            raise WardlineError(f"scan job {job_id} worker could not be cancelled: permission denied") from exc
    status.update(
        {
            "status": "cancelled",
            "phase": "cancelled",
            "failure_kind": "cancelled",
            "error": "cancelled by operator",
        }
    )
    return _write_status(root, job_id, status)


def _write_status(root: Path, job_id: str, status: dict[str, Any]) -> dict[str, Any]:
    timestamp = _now()
    status.setdefault("created_at", timestamp)
    status["updated_at"] = timestamp
    status["heartbeat"] = timestamp
    safe_write_text(root, status_path(root, job_id), json.dumps(status, indent=2, sort_keys=True) + "\n")
    return status


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _status_pid(status: dict[str, Any]) -> int | None:
    pid = status.get("pid")
    if isinstance(pid, int) and pid > 0:
        return pid
    return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _refresh_liveness(root: Path, job_id: str, status: dict[str, Any]) -> dict[str, Any]:
    if str(status.get("status")) in _TERMINAL_STATUSES:
        return status
    pid = _status_pid(status)
    if pid is not None and not _pid_alive(pid):
        status.update(
            {
                "status": "failed",
                "phase": "failed",
                "failure_kind": "stale_worker",
                "error": f"scan job worker pid {pid} is no longer running",
            }
        )
        return _write_status(root, job_id, status)
    heartbeat = _parse_timestamp(status.get("heartbeat"))
    if str(status.get("status")) in {"running", "running_stale"} and heartbeat is not None:
        stale_for = (datetime.now(UTC) - heartbeat).total_seconds()
        if stale_for > _STALE_AFTER_SECONDS:
            status["status"] = "running_stale"
            status["stale_for_seconds"] = int(stale_for)
            status.setdefault("warning", "scan job heartbeat is stale; worker may still be running")
            return status
    status.pop("stale_for_seconds", None)
    if status.get("status") == "running_stale":
        status["status"] = "running"
    return status


def _start_heartbeat(
    root: Path,
    job_id: str,
    status: dict[str, Any],
    lock: threading.Lock,
    stop: threading.Event,
) -> threading.Thread:
    def beat() -> None:
        while not stop.wait(_HEARTBEAT_INTERVAL_SECONDS):
            with lock:
                if str(status.get("status")) in _TERMINAL_STATUSES:
                    return
                progress = dict(status.get("progress") if isinstance(status.get("progress"), dict) else {})
                progress.setdefault("message", "scan still running")
                status["progress"] = progress
                try:
                    _write_status(root, job_id, status)
                except OSError:
                    return

    thread = threading.Thread(target=beat, name=f"wardline-scan-job-{job_id[:8]}-heartbeat", daemon=True)
    thread.start()
    return thread


def _progress(step: int, **extra: object) -> dict[str, object]:
    data: dict[str, object] = {"steps_completed": step, "steps_total": _JOB_STEPS_TOTAL}
    data.update(extra)
    return data


def _base_status(job_id: str, request: dict[str, Any]) -> dict[str, Any]:
    timestamp = _now()
    return {
        "job_id": job_id,
        "status": "queued",
        "phase": "queued",
        "progress": _progress(0),
        "created_at": timestamp,
        "updated_at": timestamp,
        "heartbeat": timestamp,
        "request": request,
        "artifacts": {},
        "failure_kind": None,
        "error": None,
    }


def _normalize_request(request: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(request)
    timeout_seconds = normalized.get("timeout_seconds")
    if timeout_seconds is None:
        normalized["timeout_seconds"] = DEFAULT_SCAN_JOB_TIMEOUT_SECONDS
    return normalized


def _filigree_status(result: EmitResult | None) -> dict[str, object]:
    if result is None:
        return {
            "configured": False,
            "reachable": None,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "warnings": [],
            "disabled_reason": "not configured",
            "destination": filigree_destination(None),
        }
    return {
        "configured": True,
        "reachable": result.reachable,
        "created": result.created,
        "updated": result.updated,
        "failed": result.failed,
        "warnings": list(result.warnings),
        "disabled_reason": filigree_disabled_reason(
            reachable=result.reachable,
            status=result.status,
            token_sent=result.token_sent,
            url=result.url,
        ),
        "destination": filigree_destination(result.url),
    }


def _write_scan_artifact(root: Path, output: Path, fmt: str, result: Any, fail_on: str | None) -> None:
    sink_root = root if output.is_relative_to(root.resolve()) else None
    if fmt == "sarif":
        SarifSink(output, root=sink_root).write(result.findings, result.context)
        return
    if fmt == "agent-summary":
        decision = gate_decision(result, Severity(fail_on)) if fail_on is not None else gate_decision(result, None)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(build_agent_summary(result, decision).to_dict(), sort_keys=True) + "\n")
        return
    JsonlSink(output, root=sink_root).write(result.findings)


def start_scan_job(root: Path, request: dict[str, Any], *, foreground: bool = False) -> dict[str, Any]:
    root = root.resolve()
    request = _normalize_request(request)
    job_id = uuid.uuid4().hex
    directory = job_dir(root, job_id)
    directory.mkdir(parents=True, exist_ok=True)
    status = _base_status(job_id, request)
    _write_status(root, job_id, status)
    safe_write_text(root, request_path(root, job_id), json.dumps(request, indent=2, sort_keys=True) + "\n")
    if foreground:
        run_scan_job_worker(root, job_id)
        return read_scan_job_status(root, job_id)

    stdout_path = directory / "stdout.log"
    stderr_path = directory / "stderr.log"
    with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
        proc = subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "wardline.cli.scan_job_worker", str(root), job_id],
            cwd=root,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
    status["status"] = "running"
    status["phase"] = "starting"
    status["pid"] = proc.pid
    status["artifacts"] = {"stdout": str(stdout_path), "stderr": str(stderr_path)}
    return _write_status(root, job_id, status)


def run_scan_job_worker(root: Path, job_id: str) -> None:
    root = root.resolve()
    request_file = request_path(root, job_id)
    request = json.loads(request_file.read_text(encoding="utf-8"))
    if not isinstance(request, dict):
        raise WardlineError(f"scan job {job_id} request is malformed")
    status = read_scan_job_status(root, job_id)
    status.setdefault("pid", os.getpid())
    default_output = job_dir(root, job_id) / _default_output_name(str(request.get("format", "jsonl")))
    output = Path(str(request.get("output") or default_output))
    if not output.is_absolute():
        output = root / output
    artifacts = dict(status.get("artifacts") if isinstance(status.get("artifacts"), dict) else {})
    artifacts["findings"] = str(output)
    lock = threading.Lock()
    heartbeat_stop = threading.Event()
    heartbeat_thread: threading.Thread | None = None
    previous_alarm: tuple[int, Any] | None = None

    def progress_update(event: dict[str, Any]) -> None:
        with lock:
            phase = event.get("phase")
            if isinstance(phase, str):
                status["phase"] = phase
            progress = dict(status.get("progress") if isinstance(status.get("progress"), dict) else {})
            progress.update(event)
            progress.setdefault("steps_completed", 1)
            progress.setdefault("steps_total", _JOB_STEPS_TOTAL)
            status["progress"] = progress
            _write_status(root, job_id, status)

    def timeout_handler(signum: int, frame: object) -> None:
        timeout_seconds = request.get("timeout_seconds")
        raise _ScanJobTimeout(f"scan job timed out after {timeout_seconds} seconds")

    try:
        status.update({"status": "running", "phase": "scanning", "progress": _progress(1), "artifacts": artifacts})
        with lock:
            _write_status(root, job_id, status)
        heartbeat_thread = _start_heartbeat(root, job_id, status, lock, heartbeat_stop)
        timeout_seconds = request.get("timeout_seconds")
        if isinstance(timeout_seconds, int | float) and timeout_seconds > 0:
            previous_alarm = (signal.SIGALRM, signal.getsignal(signal.SIGALRM))
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.setitimer(signal.ITIMER_REAL, float(timeout_seconds))
        result = run_scan(
            root,
            config_path=Path(str(request["config"])) if request.get("config") else None,
            cache_dir=Path(str(request["cache_dir"])) if request.get("cache_dir") else None,
            new_since=str(request["new_since"]) if request.get("new_since") else None,
            trust_local_packs=bool(request.get("trust_local_packs", False)),
            trusted_packs=tuple(str(p) for p in request.get("trusted_packs", ())),
            strict_defaults=bool(request.get("strict_defaults", False)),
            trust_suppressions=bool(request.get("trust_suppressions", False)),
            lang=str(request.get("lang", "python")),
            progress_callback=progress_update,
        )
        if previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(previous_alarm[0], previous_alarm[1])
            previous_alarm = None
        heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1.0)
        status.update(
            {
                "phase": "writing_artifact",
                "progress": _progress(2, files_scanned=result.files_scanned, findings=result.summary.total),
            }
        )
        with lock:
            _write_status(root, job_id, status)
        fmt = str(request.get("format", "jsonl"))
        _write_scan_artifact(root, output, fmt, result, str(request["fail_on"]) if request.get("fail_on") else None)

        emit_result: EmitResult | None = None
        if request.get("filigree_url") and not request.get("local_only"):
            from wardline.filigree.config import load_filigree_token

            status.update({"phase": "emitting_filigree", "progress": _progress(3)})
            with lock:
                _write_status(root, job_id, status)
            explicit_cap = request.get("filigree_max_findings_per_request")
            max_findings = int(explicit_cap) if explicit_cap is not None else None
            emit_result = FiligreeEmitter(
                str(request["filigree_url"]),
                token=load_filigree_token(root),
                max_findings_per_request=max_findings,
                protocol_errors_loud=False,
            ).emit(result.findings, scanned_paths=result.scanned_paths)

        fail_on = str(request["fail_on"]) if request.get("fail_on") else None
        decision = gate_decision(
            result,
            Severity(fail_on) if fail_on is not None else None,
            fail_on_unanalyzed=bool(request.get("fail_on_unanalyzed", False)),
        )
        filigree_block = _filigree_status(emit_result)
        enrichment_failed = emit_result is not None and (not emit_result.reachable or emit_result.failed > 0)
        terminal = "completed"
        failure_kind = None
        error = None
        if decision.tripped:
            terminal = "failed"
            failure_kind = "gate"
            error = decision.reason
        elif enrichment_failed:
            terminal = "completed_with_enrichment_failure"
            failure_kind = "enrichment"
            error = filigree_block["disabled_reason"] or f"{emit_result.failed} Filigree finding(s) failed"
        status.update(
            {
                "status": terminal,
                "phase": "complete",
                "progress": _progress(4, files_scanned=result.files_scanned, findings=result.summary.total),
                "failure_kind": failure_kind,
                "error": error,
                "artifacts": artifacts,
                "summary": {
                    "total": result.summary.total,
                    "active": result.summary.active,
                    "baselined": result.summary.baselined,
                    "waived": result.summary.waived,
                    "judged": result.summary.judged,
                    "informational": result.summary.informational,
                    "unanalyzed": result.summary.unanalyzed,
                },
                "gate": {
                    "tripped": decision.tripped,
                    "fail_on": decision.fail_on,
                    "fail_on_unanalyzed": decision.fail_on_unanalyzed,
                    "exit_class": decision.exit_class,
                    "verdict": decision.verdict,
                    "reason": decision.reason,
                    "evaluated": decision.evaluated,
                    "migration_hint": baseline_migration_hint(
                        result,
                        decision,
                        root=root,
                        new_since=request.get("new_since"),
                    ),
                },
                "filigree_emit": filigree_block,
            }
        )
        with lock:
            _write_status(root, job_id, status)
    except _ScanJobTimeout as exc:
        heartbeat_stop.set()
        if previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(previous_alarm[0], previous_alarm[1])
            previous_alarm = None
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1.0)
        status.update(
            {
                "status": "failed",
                "phase": "failed",
                "progress": _progress(4),
                "failure_kind": "timeout",
                "error": str(exc),
                "artifacts": artifacts,
            }
        )
        with lock:
            _write_status(root, job_id, status)
    except WardlineError as exc:
        heartbeat_stop.set()
        if previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(previous_alarm[0], previous_alarm[1])
            previous_alarm = None
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1.0)
        status.update(
            {
                "status": "failed",
                "phase": "failed",
                "progress": _progress(4),
                "failure_kind": "scan",
                "error": str(exc),
                "artifacts": artifacts,
            }
        )
        with lock:
            _write_status(root, job_id, status)
    finally:
        heartbeat_stop.set()
        if previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(previous_alarm[0], previous_alarm[1])


def _default_output_name(fmt: str) -> str:
    if fmt == "sarif":
        return "findings.sarif"
    if fmt == "agent-summary":
        return "findings.agent-summary.json"
    return "findings.jsonl"
