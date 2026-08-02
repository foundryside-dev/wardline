from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import IO, cast

from wardline.core.errors import JudgeConfigurationError, JudgeTransportError
from wardline.core.judge_types import JudgeTransport

_CODEX_PREFLIGHT_TIMEOUT_SECONDS = 10
_DIAGNOSTIC_CHAR_LIMIT = 1_000
_PREFLIGHT_STDOUT_BYTE_LIMIT = 256 * 1024
_PREFLIGHT_STDERR_BYTE_LIMIT = 64 * 1024
_CODEX_AUTH_BYTE_LIMIT = 1024 * 1024
CODEX_AUTH_EXPIRY_MARGIN_SECONDS = 300.0
_CODEX_INERT_REFRESH_TOKEN = "WARDLINE_INVALID_REFRESH_TOKEN_DO_NOT_USE"
_PROCESS_TERMINATION_GRACE_SECONDS = 2.0
_PROCESS_DRAIN_GRACE_SECONDS = 0.05
CODEX_CLI_TIMEOUT_SECONDS = 600.0

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
_LOCALE_ENV_KEYS = frozenset(
    {
        "LC_ADDRESS",
        "LC_ALL",
        "LC_COLLATE",
        "LC_CTYPE",
        "LC_IDENTIFICATION",
        "LC_MEASUREMENT",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NAME",
        "LC_NUMERIC",
        "LC_PAPER",
        "LC_TELEPHONE",
        "LC_TIME",
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
    AUTH_UNPROJECTABLE = "auth_unprojectable"


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


def _fallback_kill_and_reap(
    process: subprocess.Popen[bytes],
    *,
    posix: bool,
) -> None:
    """Make bounded independent kill/reap attempts after normal teardown fails."""
    deadline = time.monotonic() + _PROCESS_TERMINATION_GRACE_SECONDS
    if posix:
        with suppress(BaseException):
            os.killpg(process.pid, signal.SIGKILL)
    with suppress(BaseException):
        process.kill()
    for _attempt in range(2):
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
            break
        except BaseException:
            pass


def _finalize_bounded_process(
    process: subprocess.Popen[bytes],
    *,
    posix: bool,
    terminate_tree: bool,
    started_threads: tuple[threading.Thread, ...],
    stdout_thread: threading.Thread | None,
    stderr_thread: threading.Thread | None,
) -> None:
    """Terminate when required, reap readers, and close both capture pipes."""
    cleanup_failed = False
    if terminate_tree:
        try:
            _terminate_process_tree(process, posix=posix)
        except BaseException:
            cleanup_failed = True
            with suppress(BaseException):
                _fallback_kill_and_reap(process, posix=posix)

    reader_deadline = time.monotonic() + _PROCESS_TERMINATION_GRACE_SECONDS
    for thread in started_threads:
        try:
            thread.join(timeout=max(0.0, reader_deadline - time.monotonic()))
        except BaseException:
            cleanup_failed = True

    for stream, stream_thread in (
        (process.stdout, stdout_thread),
        (process.stderr, stderr_thread),
    ):
        alive = False
        if stream_thread in started_threads:
            try:
                assert stream_thread is not None
                alive = stream_thread.is_alive()
            except BaseException:
                cleanup_failed = True
                alive = True
        if alive:
            cleanup_failed = True
            continue
        if stream is not None:
            try:
                stream.close()
            except BaseException:
                cleanup_failed = True

    if cleanup_failed:
        raise OSError("bounded subprocess process-tree cleanup failed") from None


def _windows_taskkill_context(
    system_directory: Path,
) -> tuple[str, str, dict[str, str]]:
    """Derive an absolute cleanup command and environment from a trusted OS path."""
    if not system_directory.is_absolute():
        raise OSError("Windows system directory must be absolute")
    system_root = system_directory.parent
    executable = system_directory / "taskkill.exe"
    cleanup_env = {
        "SystemRoot": str(system_root),
        "WINDIR": str(system_root),
        "PATH": str(system_directory),
    }
    return str(executable), str(system_directory), cleanup_env


def _resolve_windows_taskkill() -> tuple[str, str, dict[str, str]]:
    """Resolve System32 through the native Windows API, never process environment."""
    if os.name != "nt":
        raise OSError("native Windows system-directory lookup is unavailable")
    import ctypes

    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("native Windows system-directory lookup is unavailable")
    kernel32 = win_dll("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_system_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32_768)
    length = get_system_directory(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise OSError("native Windows system-directory lookup failed")
    return _windows_taskkill_context(Path(buffer.value))


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    posix: bool,
    grace_seconds: float = _PROCESS_TERMINATION_GRACE_SECONDS,
) -> None:
    """Terminate the isolated tree and reap its leader within one deadline."""
    if grace_seconds <= 0:
        raise ValueError("process-tree grace period must be positive")
    deadline = time.monotonic() + grace_seconds

    def _remaining() -> float:
        return max(0.0, deadline - time.monotonic())

    def _wait_leader(limit: float) -> bool:
        try:
            process.wait(timeout=max(0.0, min(limit, _remaining())))
            return True
        except subprocess.TimeoutExpired:
            return False

    if posix:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    else:
        with suppress(OSError):
            process.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
    leader_reaped = _wait_leader(grace_seconds / 2)

    if posix:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        if not leader_reaped:
            leader_reaped = _wait_leader(_remaining())
        if not leader_reaped:
            with suppress(ProcessLookupError):
                process.kill()
            leader_reaped = _wait_leader(_remaining())
        if not leader_reaped:
            raise OSError("bounded POSIX process-tree cleanup failed")
        return

    taskkill_succeeded = False
    try:
        taskkill_executable, taskkill_cwd, taskkill_env = _resolve_windows_taskkill()
        taskkill = subprocess.run(  # noqa: S603,S607 - Windows process-tree teardown
            [taskkill_executable, "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(_remaining(), 0.001),
            check=False,
            cwd=taskkill_cwd,
            env=taskkill_env,
        )
        taskkill_succeeded = taskkill.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        taskkill_succeeded = False

    if not taskkill_succeeded:
        with suppress(ProcessLookupError):
            process.kill()
        if not leader_reaped:
            _wait_leader(_remaining())
        raise OSError("bounded Windows process-tree cleanup failed")

    if not leader_reaped:
        leader_reaped = _wait_leader(_remaining())
    if not leader_reaped:
        with suppress(ProcessLookupError):
            process.kill()
        leader_reaped = _wait_leader(_remaining())
    if not leader_reaped:
        raise OSError("bounded Windows process-tree cleanup failed")


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
    if timeout <= 0:
        raise ValueError("process timeout must be positive")
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
            creationflags=(0 if is_posix else getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)),
        )
        stdout_thread: threading.Thread | None = None
        stderr_thread: threading.Thread | None = None
        started_threads: list[threading.Thread] = []
        cleanup_attempted = False
        try:
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
            started_threads.append(stdout_thread)
            stderr_thread.start()
            started_threads.append(stderr_thread)
            timed_out = False
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = -1

            if not timed_out and not is_posix:
                drain_deadline = time.monotonic() + _PROCESS_DRAIN_GRACE_SECONDS
                for thread in started_threads:
                    thread.join(timeout=max(0.0, drain_deadline - time.monotonic()))

            terminate_tree = timed_out or is_posix or any(thread.is_alive() for thread in started_threads)
            cleanup_attempted = True
            _finalize_bounded_process(
                process,
                posix=is_posix,
                terminate_tree=terminate_tree,
                started_threads=tuple(started_threads),
                stdout_thread=stdout_thread,
                stderr_thread=stderr_thread,
            )
            if timed_out:
                raise subprocess.TimeoutExpired(args, timeout) from None
        except BaseException:
            if not cleanup_attempted:
                cleanup_attempted = True
                try:
                    _finalize_bounded_process(
                        process,
                        posix=is_posix,
                        terminate_tree=True,
                        started_threads=tuple(started_threads),
                        stdout_thread=stdout_thread,
                        stderr_thread=stderr_thread,
                    )
                except OSError:
                    raise OSError("bounded subprocess process-tree cleanup failed") from None
            raise

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
        key: value for key, value in environ.items() if value and (key in _CHILD_ENV_KEYS or key in _LOCALE_ENV_KEYS)
    }
    child["NO_COLOR"] = "1"
    return child


def _ambient_codex_auth_path(source: Mapping[str, str] | None = None) -> Path:
    environ = os.environ if source is None else source
    configured_codex_home = environ.get("CODEX_HOME")
    if configured_codex_home:
        codex_home = Path(configured_codex_home)
    else:
        configured_home = environ.get("HOME")
        if configured_home:
            codex_home = Path(configured_home) / ".codex"
        elif source is None:
            codex_home = Path.home() / ".codex"
        else:
            raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    if not codex_home.is_absolute():
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    return codex_home / "auth.json"


def codex_auth_projection_supported() -> bool:
    """Return whether Wardline can privately stage and scrub Codex file auth."""
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    required_functions = (
        "close",
        "fchmod",
        "fstat",
        "fsync",
        "ftruncate",
        "lseek",
        "open",
        "rmdir",
        "stat",
        "unlink",
        "write",
    )
    if os.name != "posix" or not all(hasattr(os, name) for name in (*required_flags, *required_functions)):
        return False
    dir_fd_functions = (os.open, os.rmdir, os.stat, os.unlink)
    return all(function in os.supports_dir_fd for function in dir_fd_functions) and (
        os.stat in os.supports_follow_symlinks
    )


def _strict_auth_json_object(payload: bytes) -> dict[str, object]:
    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def _constant(_value: str) -> object:
        raise ValueError

    def _finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError
        return parsed

    try:
        decoded = payload.decode("utf-8", errors="strict")
        parsed: object = json.loads(
            decoded,
            object_pairs_hook=_object,
            parse_constant=_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely") from None
    if not isinstance(parsed, dict) or not all(isinstance(key, str) for key in parsed):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    return cast(dict[str, object], parsed)


def _decode_jwt_payload(token: object) -> dict[str, object]:
    if not isinstance(token, str) or not token:
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    try:
        segments = token.encode("ascii").split(b".")
    except UnicodeEncodeError:
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely") from None
    if len(segments) != 3 or any(not segment for segment in segments):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")

    decoded_segments: list[bytes] = []
    try:
        for segment in segments:
            padding = b"=" * (-len(segment) % 4)
            decoded_segments.append(
                base64.b64decode(
                    segment + padding,
                    altchars=b"-_",
                    validate=True,
                )
            )
    except (ValueError, TypeError):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely") from None
    if not decoded_segments[2]:
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    _strict_auth_json_object(decoded_segments[0])
    return _strict_auth_json_object(decoded_segments[1])


def _project_codex_auth(
    payload: bytes,
    *,
    minimum_remaining_seconds: float,
) -> bytes:
    if not math.isfinite(minimum_remaining_seconds) or minimum_remaining_seconds < 0:
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    auth = _strict_auth_json_object(payload)
    if auth.get("auth_mode") != "chatgpt" or auth.get("OPENAI_API_KEY") is not None:
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    tokens = auth.get("tokens")
    if not isinstance(tokens, dict):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    required: dict[str, str] = {}
    for key in ("id_token", "access_token", "refresh_token", "account_id"):
        value = tokens.get(key)
        if not isinstance(value, str) or not value:
            raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
        required[key] = value

    _decode_jwt_payload(required["id_token"])
    access_claims = _decode_jwt_payload(required["access_token"])
    expires_at = access_claims.get("exp")
    if type(expires_at) is not int:
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    auth_claims = access_claims.get("https://api.openai.com/auth")
    if not isinstance(auth_claims, dict):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    claimed_account = auth_claims.get("chatgpt_account_id")
    if (
        not isinstance(claimed_account, str)
        or not claimed_account
        or not hmac.compare_digest(claimed_account, required["account_id"])
    ):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")

    now = time.time()
    if not math.isfinite(now) or expires_at <= now + minimum_remaining_seconds:
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    try:
        refreshed_at = datetime.fromtimestamp(now, UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely") from None
    projection = {
        "OPENAI_API_KEY": None,
        "auth_mode": "chatgpt",
        "last_refresh": refreshed_at,
        "tokens": {
            "access_token": required["access_token"],
            "account_id": required["account_id"],
            "id_token": required["id_token"],
            "refresh_token": _CODEX_INERT_REFRESH_TOKEN,
        },
    }
    return json.dumps(
        projection,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _auth_file_snapshot(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_bounded_codex_auth(source_path: Path) -> bytes:
    try:
        before = source_path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise OSError
        if stat.S_IMODE(before.st_mode) & 0o077:
            raise OSError
        if before.st_size <= 0 or before.st_size > _CODEX_AUTH_BYTE_LIMIT:
            raise OSError
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source_path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise OSError
            if _auth_file_snapshot(before) != _auth_file_snapshot(opened):
                raise OSError
            chunks: list[bytes] = []
            remaining = _CODEX_AUTH_BYTE_LIMIT + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            if _auth_file_snapshot(opened) != _auth_file_snapshot(after):
                raise OSError
            if not payload or len(payload) > _CODEX_AUTH_BYTE_LIMIT or len(payload) != opened.st_size:
                raise OSError
            return payload
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely") from None


def stage_codex_execution_auth(
    destination_codex_home: Path,
    *,
    source: Mapping[str, str] | None = None,
    minimum_remaining_seconds: float = (CODEX_CLI_TIMEOUT_SECONDS + CODEX_AUTH_EXPIRY_MARGIN_SECONDS),
) -> str:
    """Project stateless ChatGPT auth into one private ephemeral Codex home."""
    if not codex_auth_projection_supported():
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    payload = _project_codex_auth(
        _read_bounded_codex_auth(_ambient_codex_auth_path(source)),
        minimum_remaining_seconds=minimum_remaining_seconds,
    )
    expected_digest = hashlib.sha256(payload).hexdigest()
    try:
        destination_codex_home.mkdir(mode=0o700)
        os.chmod(destination_codex_home, 0o700)
        destination = destination_codex_home / "auth.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(destination, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(destination, 0o600)
    except (OSError, ValueError):
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely") from None
    return expected_digest


def verify_codex_execution_auth(
    destination_codex_home: Path,
    *,
    expected_digest: str,
) -> None:
    """Fail if the ephemeral runner altered its stateless auth projection."""
    payload = _read_bounded_codex_auth(destination_codex_home / "auth.json")
    actual_digest = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise JudgeTransportError("Codex CLI authentication material changed during execution")


def validate_codex_auth_projection(
    *,
    source: Mapping[str, str] | None = None,
    minimum_remaining_seconds: float = (CODEX_CLI_TIMEOUT_SECONDS + CODEX_AUTH_EXPIRY_MARGIN_SECONDS),
) -> None:
    """Validate that ambient ChatGPT file auth is safe for stateless projection."""
    if not codex_auth_projection_supported():
        raise JudgeTransportError("Codex CLI authentication material could not be staged safely")
    _project_codex_auth(
        _read_bounded_codex_auth(_ambient_codex_auth_path(source)),
        minimum_remaining_seconds=minimum_remaining_seconds,
    )


def codex_execution_env(
    *,
    home: Path,
    codex_home: Path,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the sealed execution environment with no ambient state roots."""
    if not home.is_absolute() or not codex_home.is_absolute():
        raise ValueError("Codex execution homes must be absolute")
    child = codex_child_env(source)
    child["HOME"] = str(home)
    child["CODEX_HOME"] = str(codex_home)
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
    operator_env = dict(os.environ)
    child_env = codex_child_env(operator_env)
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
    try:
        validate_codex_auth_projection(source=operator_env)
    except JudgeTransportError:
        if not codex_auth_projection_supported():
            detail = "Codex CLI file-auth projection is unsupported on this platform; select OpenRouter instead"
        else:
            detail = "Codex CLI ChatGPT authentication cannot be projected safely; run `codex login` and retry"
        return CodexAvailability(
            reason=CodexUnavailableReason.AUTH_UNPROJECTABLE,
            detail=detail,
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
