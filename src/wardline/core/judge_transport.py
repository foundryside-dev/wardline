from __future__ import annotations

import os
import re
import signal
import subprocess
import tempfile
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import IO

from wardline.core.errors import JudgeConfigurationError
from wardline.core.judge_types import JudgeTransport

_CODEX_PREFLIGHT_TIMEOUT_SECONDS = 10
_DIAGNOSTIC_CHAR_LIMIT = 1_000
_PREFLIGHT_STDOUT_BYTE_LIMIT = 256 * 1024
_PREFLIGHT_STDERR_BYTE_LIMIT = 64 * 1024
_PROCESS_TERMINATION_GRACE_SECONDS = 2.0

CODEX_REQUIRED_EXEC_FLAGS = frozenset(
    {
        "--config",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--sandbox",
        "--model",
        "--output-schema",
        "--json",
        "--color",
        "--cd",
    }
)
CODEX_DISABLED_FEATURES = frozenset(
    {
        "apps",
        "browser_use",
        "computer_use",
        "goals",
        "hooks",
        "image_generation",
        "memories",
        "multi_agent",
        "personality",
        "plugins",
        "plugin_sharing",
        "remote_plugin",
        "shell_snapshot",
        "shell_tool",
        "skill_mcp_dependency_install",
        "unified_exec",
        "workspace_dependencies",
    }
)

_CHILD_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TERM",
        "TMPDIR",
        "CODEX_HOME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
)
_EXEC_FLAG_RE = re.compile(r"(?<!\S)(--[a-z0-9][a-z0-9-]*)(?=[=,\s]|$)")
_VERSION_RE = re.compile(r"^codex(?:-cli)?\s+\d", re.IGNORECASE)
_AUTHENTICATED_RE = re.compile(r"^\s*logged in(?:\s|$)", re.IGNORECASE | re.MULTILINE)


class CodexUnavailableReason(StrEnum):
    AVAILABLE = "available"
    BINARY_MISSING = "binary_missing"
    INCOMPATIBLE = "incompatible"
    UNAUTHENTICATED = "unauthenticated"


@dataclass(frozen=True, slots=True)
class CodexAvailability:
    reason: CodexUnavailableReason
    detail: str
    version: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, CodexUnavailableReason):
            raise TypeError("reason must be a CodexUnavailableReason")

    @classmethod
    def available(cls, version: str) -> CodexAvailability:
        return cls(CodexUnavailableReason.AVAILABLE, "authenticated", version)

    @property
    def is_available(self) -> bool:
        return self.reason is CodexUnavailableReason.AVAILABLE


Probe = Callable[[], CodexAvailability]
Runner = Callable[..., subprocess.CompletedProcess[str]]


class _PreflightOutputOverflow(Exception):
    pass


class _PreflightDecodeFailure(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_decode_error: bool = False
    stderr_decode_error: bool = False


@dataclass(slots=True)
class _BoundedCapture:
    limit: int
    data: bytearray
    truncated: bool = False
    read_failed: bool = False

    @classmethod
    def create(cls, limit: int) -> _BoundedCapture:
        if limit <= 0:
            raise ValueError("process output limit must be positive")
        return cls(limit=limit, data=bytearray())

    def add(self, chunk: bytes) -> None:
        remaining = self.limit - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])
        if len(chunk) > remaining:
            self.truncated = True


def _drain_stream(stream: IO[bytes], capture: _BoundedCapture) -> None:
    try:
        while chunk := stream.read(64 * 1024):
            capture.add(chunk)
    except (OSError, ValueError):
        capture.read_failed = True


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    posix: bool,
    grace_seconds: float = _PROCESS_TERMINATION_GRACE_SECONDS,
) -> None:
    """Terminate, escalate, and reap the isolated Codex process tree."""
    if posix:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    else:
        with suppress(ProcessLookupError):
            process.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
    leader_reaped = False
    try:
        process.wait(timeout=grace_seconds)
        leader_reaped = True
    except subprocess.TimeoutExpired:
        pass
    if posix:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    else:
        try:
            subprocess.run(  # noqa: S603,S607 - Windows process-tree teardown
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=grace_seconds,
                check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            with suppress(ProcessLookupError):
                process.kill()
    if not leader_reaped:
        process.wait()


def _run_bounded_process(
    args: list[str],
    *,
    input_text: str | None,
    timeout: float,
    env: Mapping[str, str],
    cwd: Path | None,
    stdout_limit: int,
    stderr_limit: int,
) -> _BoundedProcessResult:
    """Run one isolated child while draining both output pipes into byte caps."""
    stdout_capture = _BoundedCapture.create(stdout_limit)
    stderr_capture = _BoundedCapture.create(stderr_limit)
    prompt_file: IO[bytes] | int
    with tempfile.TemporaryFile(mode="w+b") as stdin_file:
        if input_text is None:
            prompt_file = subprocess.DEVNULL
        else:
            stdin_file.write(input_text.encode("utf-8"))
            stdin_file.seek(0)
            prompt_file = stdin_file

        is_posix = os.name == "posix"
        process = subprocess.Popen(  # noqa: S603 - fixed executable contract at callers
            args,
            stdin=prompt_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            cwd=str(cwd) if cwd is not None else None,
            start_new_session=is_posix,
            creationflags=(
                0
                if is_posix
                else getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            ),
        )
        assert process.stdout is not None and process.stderr is not None
        stdout_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout_capture),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_capture),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process, posix=is_posix)
            raise subprocess.TimeoutExpired(args, timeout) from None
        finally:
            stdout_thread.join(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
            stderr_thread.join(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
            if stdout_thread.is_alive():
                process.stdout.close()
                stdout_thread.join(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
            if stderr_thread.is_alive():
                process.stderr.close()
                stderr_thread.join(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)

    if stdout_capture.read_failed or stderr_capture.read_failed:
        raise OSError("bounded subprocess output drain failed")
    def _decode(data: bytearray) -> tuple[str, bool]:
        try:
            return bytes(data).decode("utf-8", errors="strict"), False
        except UnicodeDecodeError:
            return "", True

    stdout, stdout_decode_error = _decode(stdout_capture.data)
    stderr, stderr_decode_error = _decode(stderr_capture.data)
    return _BoundedProcessResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_capture.truncated,
        stderr_truncated=stderr_capture.truncated,
        stdout_decode_error=stdout_decode_error,
        stderr_decode_error=stderr_decode_error,
    )


def _truncate_completed_output(
    completed: subprocess.CompletedProcess[str],
) -> _BoundedProcessResult:
    def _cap(text: str, limit: int) -> tuple[str, bool]:
        raw = text.encode("utf-8")
        return raw[:limit].decode("utf-8", errors="ignore"), len(raw) > limit

    stdout, stdout_truncated = _cap(completed.stdout or "", _PREFLIGHT_STDOUT_BYTE_LIMIT)
    stderr, stderr_truncated = _cap(completed.stderr or "", _PREFLIGHT_STDERR_BYTE_LIMIT)
    return _BoundedProcessResult(
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )


def codex_child_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the minimal environment shared by Codex preflight and execution."""
    environ = os.environ if source is None else source
    child = {
        key: value for key, value in environ.items() if value and (key in _CHILD_ENV_KEYS or key.startswith("LC_"))
    }
    child["NO_COLOR"] = "1"
    return child


def _first_nonempty_line(*streams: str) -> str | None:
    for stream in streams:
        for line in stream.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped[:_DIAGNOSTIC_CHAR_LIMIT]
    return None


def _incompatible(detail: str, version: str | None) -> CodexAvailability:
    return CodexAvailability(
        reason=CodexUnavailableReason.INCOMPATIBLE,
        detail=detail[:_DIAGNOSTIC_CHAR_LIMIT],
        version=version,
    )


def probe_codex_cli(*, runner: Runner | None = None) -> CodexAvailability:
    """Probe sealed-exec capabilities and authentication without invoking a model."""
    child_env = codex_child_env()
    current_command: list[str] = ["codex", "--version"]
    version: str | None = None

    def _run(args: list[str]) -> _BoundedProcessResult:
        nonlocal current_command
        current_command = args
        if runner is None:
            result = _run_bounded_process(
                args,
                input_text=None,
                timeout=_CODEX_PREFLIGHT_TIMEOUT_SECONDS,
                env=child_env,
                cwd=None,
                stdout_limit=_PREFLIGHT_STDOUT_BYTE_LIMIT,
                stderr_limit=_PREFLIGHT_STDERR_BYTE_LIMIT,
            )
        else:
            result = _truncate_completed_output(
                runner(
                    args,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=_CODEX_PREFLIGHT_TIMEOUT_SECONDS,
                    env=child_env,
                )
            )
        if result.stdout_truncated or result.stderr_truncated:
            raise _PreflightOutputOverflow
        if result.stdout_decode_error or result.stderr_decode_error:
            raise _PreflightDecodeFailure
        return result

    try:
        version_result = _run(["codex", "--version"])
        if version_result.returncode != 0:
            return _incompatible(
                "`codex --version` failed; install or upgrade Codex CLI",
                None,
            )
        version = _first_nonempty_line(version_result.stdout, version_result.stderr)
        if version is None or _VERSION_RE.search(version) is None:
            return _incompatible(
                "`codex --version` did not identify a compatible Codex CLI",
                None,
            )

        help_result = _run(["codex", "exec", "--help"])
        if help_result.returncode != 0:
            return _incompatible(
                "`codex exec --help` failed; upgrade Codex CLI",
                version,
            )
        advertised_flags = frozenset(_EXEC_FLAG_RE.findall(help_result.stdout + "\n" + help_result.stderr))
        missing_flags = sorted(CODEX_REQUIRED_EXEC_FLAGS - advertised_flags)
        if missing_flags:
            return _incompatible(
                "Codex CLI is missing required exec capability: " + ", ".join(missing_flags),
                version,
            )

        features_result = _run(["codex", "features", "list"])
        if features_result.returncode != 0:
            return _incompatible(
                "`codex features list` failed; upgrade Codex CLI",
                version,
            )
        advertised_features = frozenset(
            parts[0]
            for line in (features_result.stdout + "\n" + features_result.stderr).splitlines()
            if (parts := line.split())
        )
        missing_features = sorted(CODEX_DISABLED_FEATURES - advertised_features)
        if missing_features:
            return _incompatible(
                "Codex CLI is missing required feature controls: " + ", ".join(missing_features),
                version,
            )

        login_result = _run(["codex", "login", "status"])
    except _PreflightOutputOverflow:
        return _incompatible(
            "Codex CLI preflight exceeded the bounded output limit",
            version,
        )
    except _PreflightDecodeFailure:
        return _incompatible(
            "Codex CLI preflight emitted invalid UTF-8 output",
            version,
        )
    except FileNotFoundError:
        return CodexAvailability(
            reason=CodexUnavailableReason.BINARY_MISSING,
            detail="Codex CLI executable was not found; install Codex CLI",
            version=None,
        )
    except subprocess.TimeoutExpired:
        command = " ".join(current_command)
        raise JudgeConfigurationError(
            f"Codex CLI preflight timed out while running `{command}`; retry or inspect the local Codex installation"
        ) from None
    except OSError:
        command = " ".join(current_command)
        raise JudgeConfigurationError(
            f"Codex CLI preflight could not run `{command}` due to an OS error; "
            "inspect the local installation and permissions"
        ) from None

    login_output = login_result.stdout + "\n" + login_result.stderr
    if login_result.returncode != 0 or _AUTHENTICATED_RE.search(login_output) is None:
        return CodexAvailability(
            reason=CodexUnavailableReason.UNAUTHENTICATED,
            detail="Codex CLI is not authenticated; run `codex login` and retry",
            version=version,
        )
    return CodexAvailability.available(version)


def resolve_judge_transport(
    requested: JudgeTransport,
    *,
    probe: Probe = probe_codex_cli,
) -> JudgeTransport:
    """Resolve one requested transport to a concrete provider exactly once."""
    if not isinstance(requested, JudgeTransport):
        raise TypeError("requested must be a JudgeTransport")
    if requested is JudgeTransport.OPENROUTER:
        return requested
    availability = probe()
    if availability.is_available:
        return JudgeTransport.CODEX_CLI
    if requested is JudgeTransport.AUTO:
        return JudgeTransport.OPENROUTER
    raise JudgeConfigurationError(
        f"Codex CLI transport is unavailable ({availability.reason.value}): {availability.detail}"
    )
