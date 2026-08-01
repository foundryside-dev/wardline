from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from wardline.core.errors import JudgeConfigurationError
from wardline.core.judge_types import JudgeTransport

_CODEX_PREFLIGHT_TIMEOUT_SECONDS = 10
_DIAGNOSTIC_CHAR_LIMIT = 1_000

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

    @classmethod
    def available(cls, version: str) -> CodexAvailability:
        return cls(CodexUnavailableReason.AVAILABLE, "authenticated", version)

    @property
    def is_available(self) -> bool:
        return self.reason is CodexUnavailableReason.AVAILABLE


Probe = Callable[[], CodexAvailability]
Runner = Callable[..., subprocess.CompletedProcess[str]]


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
    run = subprocess.run if runner is None else runner
    child_env = codex_child_env()
    current_command: list[str] = ["codex", "--version"]

    def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
        nonlocal current_command
        current_command = args
        return run(
            args,
            text=True,
            capture_output=True,
            check=False,
            timeout=_CODEX_PREFLIGHT_TIMEOUT_SECONDS,
            env=child_env,
        )

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
    except FileNotFoundError:
        return CodexAvailability(
            reason=CodexUnavailableReason.BINARY_MISSING,
            detail="Codex CLI executable was not found; install Codex CLI",
            version=None,
        )
    except subprocess.TimeoutExpired as exc:
        command = " ".join(current_command)
        raise JudgeConfigurationError(
            f"Codex CLI preflight timed out while running `{command}`; retry or inspect the local Codex installation"
        ) from exc
    except OSError as exc:
        command = " ".join(current_command)
        raise JudgeConfigurationError(
            f"Codex CLI preflight could not run `{command}` due to an OS error; "
            "inspect the local installation and permissions"
        ) from exc

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
