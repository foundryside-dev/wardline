from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from wardline.core.errors import JudgeConfigurationError
from wardline.core.judge_transport import (
    CODEX_DISABLED_FEATURES,
    CODEX_REQUIRED_EXEC_FLAGS,
    CodexAvailability,
    CodexUnavailableReason,
    codex_child_env,
    probe_codex_cli,
    resolve_judge_transport,
)
from wardline.core.judge_types import (
    CODEX_JUDGE_REASONING_EFFORT,
    CONCRETE_JUDGE_TRANSPORTS,
    DEFAULT_CODEX_JUDGE_MODEL,
    DEFAULT_OPENROUTER_JUDGE_MODEL,
    CodexToolScope,
    JudgeTransport,
)

_EXPECTED_REQUIRED_FLAGS = frozenset(
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
_EXPECTED_DISABLED_FEATURES = frozenset(
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


def _completed(
    returncode: int = 0,
    *,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def _help_text(flags: frozenset[str] = _EXPECTED_REQUIRED_FLAGS) -> str:
    return "\n".join(f"  {flag} <VALUE>" for flag in sorted(flags))


def _features_text(features: frozenset[str] = _EXPECTED_DISABLED_FEATURES) -> str:
    return "\n".join(f"{feature}\tstable\tfalse" for feature in sorted(features))


class _RecordingRunner:
    def __init__(self, results: Sequence[subprocess.CompletedProcess[str] | BaseException]) -> None:
        self._results = list(results)
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(args), dict(kwargs)))
        if not self._results:
            raise AssertionError(f"unexpected subprocess call: {args}")
        result = self._results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return subprocess.CompletedProcess(
            args,
            result.returncode,
            result.stdout,
            result.stderr,
        )


def _successful_runner(
    *,
    version: str = "codex-cli 0.146.0",
    help_text: str | None = None,
    features_text: str | None = None,
    login_stdout: str = "Logged in with ChatGPT",
    login_stderr: str = "",
    login_returncode: int = 0,
) -> _RecordingRunner:
    return _RecordingRunner(
        [
            _completed(stdout=version + "\n"),
            _completed(stdout=_help_text() if help_text is None else help_text),
            _completed(stdout=_features_text() if features_text is None else features_text),
            _completed(login_returncode, stdout=login_stdout, stderr=login_stderr),
        ]
    )


def test_judge_transport_values_are_closed_and_ordered() -> None:
    assert [transport.value for transport in JudgeTransport] == [
        "auto",
        "codex-cli",
        "openrouter",
    ]
    assert frozenset({JudgeTransport.CODEX_CLI, JudgeTransport.OPENROUTER}) == CONCRETE_JUDGE_TRANSPORTS


def test_transport_model_defaults_use_separate_namespaces() -> None:
    assert DEFAULT_CODEX_JUDGE_MODEL == "gpt-5.6-sol"
    assert DEFAULT_OPENROUTER_JUDGE_MODEL == "anthropic/claude-opus-4-8"
    assert CODEX_JUDGE_REASONING_EFFORT == "high"


def test_codex_tool_scope_uses_absolute_root_and_positive_default(tmp_path: Path) -> None:
    root = tmp_path.resolve()

    scope = CodexToolScope(root=root)

    assert scope.root == root
    assert scope.max_calls == 24


def test_codex_tool_scope_rejects_relative_root() -> None:
    with pytest.raises(ValueError, match="absolute"):
        CodexToolScope(root=Path("relative/repository"))


@pytest.mark.parametrize("max_calls", [0, -1])
def test_codex_tool_scope_rejects_nonpositive_call_budget(tmp_path: Path, max_calls: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        CodexToolScope(root=tmp_path.resolve(), max_calls=max_calls)


def test_codex_probe_vocabulary_is_exact() -> None:
    assert CODEX_REQUIRED_EXEC_FLAGS == _EXPECTED_REQUIRED_FLAGS
    assert CODEX_DISABLED_FEATURES == _EXPECTED_DISABLED_FEATURES
    assert [reason.value for reason in CodexUnavailableReason] == [
        "available",
        "binary_missing",
        "incompatible",
        "unauthenticated",
    ]

    availability = CodexAvailability.available("codex-cli 0.146.0")

    assert availability == CodexAvailability(
        reason=CodexUnavailableReason.AVAILABLE,
        detail="authenticated",
        version="codex-cli 0.146.0",
    )
    assert availability.is_available is True


@pytest.mark.parametrize("reason", [item.value for item in CodexUnavailableReason])
def test_codex_availability_rejects_raw_string_reason(reason: str) -> None:
    with pytest.raises(TypeError, match="CodexUnavailableReason"):
        CodexAvailability(
            reason=reason,  # type: ignore[arg-type]
            detail="must not become fallback-eligible",
            version=None,
        )


def test_auto_prefers_available_codex_and_probes_once() -> None:
    calls = 0

    def _probe() -> CodexAvailability:
        nonlocal calls
        calls += 1
        return CodexAvailability.available("codex-cli 0.146.0")

    selected = resolve_judge_transport(JudgeTransport.AUTO, probe=_probe)

    assert selected is JudgeTransport.CODEX_CLI
    assert calls == 1


@pytest.mark.parametrize(
    "reason",
    [
        CodexUnavailableReason.BINARY_MISSING,
        CodexUnavailableReason.INCOMPATIBLE,
        CodexUnavailableReason.UNAUTHENTICATED,
    ],
)
def test_auto_falls_back_only_for_typed_unavailability(reason: CodexUnavailableReason) -> None:
    unavailable = CodexAvailability(reason=reason, detail="operator remediation", version=None)

    selected = resolve_judge_transport(JudgeTransport.AUTO, probe=lambda: unavailable)

    assert selected is JudgeTransport.OPENROUTER


@pytest.mark.parametrize(
    ("reason", "detail"),
    [
        (CodexUnavailableReason.BINARY_MISSING, "install Codex CLI"),
        (CodexUnavailableReason.INCOMPATIBLE, "upgrade Codex CLI"),
        (CodexUnavailableReason.UNAUTHENTICATED, "run codex login"),
    ],
)
def test_explicit_codex_unavailable_fails_without_fallback(
    reason: CodexUnavailableReason,
    detail: str,
) -> None:
    unavailable = CodexAvailability(reason=reason, detail=detail, version=None)

    with pytest.raises(JudgeConfigurationError) as exc_info:
        resolve_judge_transport(JudgeTransport.CODEX_CLI, probe=lambda: unavailable)

    message = str(exc_info.value)
    assert reason.value in message
    assert detail in message


def test_explicit_openrouter_never_probes_codex() -> None:
    def _unexpected_probe() -> CodexAvailability:
        raise AssertionError("probe must not run")

    selected = resolve_judge_transport(JudgeTransport.OPENROUTER, probe=_unexpected_probe)

    assert selected is JudgeTransport.OPENROUTER


@pytest.mark.parametrize("requested", [item.value for item in JudgeTransport])
def test_selector_rejects_raw_string_transport_before_probing(requested: str) -> None:
    def _unexpected_probe() -> CodexAvailability:
        raise AssertionError("untyped transport must fail before probing")

    with pytest.raises(TypeError, match="JudgeTransport"):
        resolve_judge_transport(
            requested,  # type: ignore[arg-type]
            probe=_unexpected_probe,
        )


def test_codex_child_env_is_an_exact_nonempty_allowlist() -> None:
    allowed = {
        "PATH": "/bin",
        "HOME": "/home/operator",
        "USER": "operator",
        "LOGNAME": "operator",
        "SHELL": "/bin/sh",
        "LANG": "en_AU.UTF-8",
        "TERM": "xterm-256color",
        "TMPDIR": "/tmp/operator",
        "CODEX_HOME": "/home/operator/.codex",
        "SSL_CERT_FILE": "/etc/ssl/cert.pem",
        "SSL_CERT_DIR": "/etc/ssl/certs",
        "LC_ALL": "en_AU.UTF-8",
        "LC_MESSAGES": "C",
    }
    source = {
        **allowed,
        "LC_EMPTY": "",
        "PATH_EMPTY_DECOY": "/secret",
        "WARDLINE_OPENROUTER_API_KEY": "sk-or-secret",
        "OPENROUTER_API_KEY": "sk-or-secret",
        "OPENAI_API_KEY": "sk-secret",
        "ANTHROPIC_API_KEY": "ant-secret",
        "AWS_ACCESS_KEY_ID": "cloud-secret",
        "AWS_SECRET_ACCESS_KEY": "cloud-secret",
        "GOOGLE_APPLICATION_CREDENTIALS": "/secret/cloud.json",
        "HTTP_PROXY": "http://credential@proxy",
        "HTTPS_PROXY": "http://credential@proxy",
        "ALL_PROXY": "socks://credential@proxy",
        "NO_PROXY": "internal.example",
        "UNRELATED_APPLICATION_SETTING": "secret",
    }

    child = codex_child_env(source)

    assert child == {**allowed, "NO_COLOR": "1"}


def test_probe_runs_exact_non_model_commands_with_one_bounded_environment() -> None:
    runner = _successful_runner(login_stdout="", login_stderr="Logged in with ChatGPT")
    expected_env = codex_child_env(os.environ)

    availability = probe_codex_cli(runner=runner)

    assert availability == CodexAvailability.available("codex-cli 0.146.0")
    assert [args for args, _kwargs in runner.calls] == [
        ["codex", "--version"],
        ["codex", "exec", "--help"],
        ["codex", "features", "list"],
        ["codex", "login", "status"],
    ]
    for _args, kwargs in runner.calls:
        assert kwargs == {
            "text": True,
            "capture_output": True,
            "check": False,
            "timeout": 10,
            "env": expected_env,
        }


def test_probe_binary_missing_is_typed_and_does_not_echo_os_detail() -> None:
    secret = "sensitive executable lookup path"
    runner = _RecordingRunner([FileNotFoundError(secret)])

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.BINARY_MISSING
    assert availability.version is None
    assert secret not in availability.detail
    assert len(runner.calls) == 1


@pytest.mark.parametrize(
    "version_result",
    [
        _completed(1, stdout="provider-secret", stderr="provider-secret"),
        _completed(0, stdout="", stderr=""),
    ],
)
def test_probe_broken_version_is_typed_incompatible(
    version_result: subprocess.CompletedProcess[str],
) -> None:
    runner = _RecordingRunner([version_result])

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert availability.version is None
    assert "provider-secret" not in availability.detail
    assert len(availability.detail) <= 1000
    assert len(runner.calls) == 1


def test_probe_nonzero_exec_help_is_typed_incompatible() -> None:
    runner = _RecordingRunner(
        [
            _completed(stdout="codex-cli 0.146.0"),
            _completed(2, stdout="provider-secret", stderr="provider-secret"),
        ]
    )

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert availability.version == "codex-cli 0.146.0"
    assert "provider-secret" not in availability.detail


@pytest.mark.parametrize("missing", sorted(_EXPECTED_REQUIRED_FLAGS))
def test_probe_requires_every_exec_flag_as_an_exact_token(missing: str) -> None:
    runner = _successful_runner(help_text=_help_text(_EXPECTED_REQUIRED_FLAGS - {missing}))

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert availability.version == "codex-cli 0.146.0"
    assert missing in availability.detail
    assert len(runner.calls) == 2


@pytest.mark.parametrize(
    ("missing", "decoy"),
    [("--model", "--model-extra"), ("--json", "--jsonl")],
)
def test_probe_does_not_accept_exec_flag_substrings(missing: str, decoy: str) -> None:
    help_text = _help_text(_EXPECTED_REQUIRED_FLAGS - {missing}) + f"\n  {decoy}"
    runner = _successful_runner(help_text=help_text)

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert missing in availability.detail


def test_probe_nonzero_feature_listing_is_typed_incompatible() -> None:
    runner = _RecordingRunner(
        [
            _completed(stdout="codex-cli 0.146.0"),
            _completed(stdout=_help_text()),
            _completed(2, stdout="provider-secret", stderr="provider-secret"),
        ]
    )

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert availability.version == "codex-cli 0.146.0"
    assert "provider-secret" not in availability.detail


@pytest.mark.parametrize("missing", sorted(_EXPECTED_DISABLED_FEATURES))
def test_probe_requires_every_disabled_feature_as_an_exact_first_column(missing: str) -> None:
    runner = _successful_runner(features_text=_features_text(_EXPECTED_DISABLED_FEATURES - {missing}))

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert availability.version == "codex-cli 0.146.0"
    assert missing in availability.detail
    assert len(runner.calls) == 3


def test_probe_does_not_accept_feature_name_substrings_or_descriptions() -> None:
    features = _features_text(_EXPECTED_DISABLED_FEATURES - {"apps"})
    features += "\napps_extra\tstable\tfalse\ndecoy\tstable\tapps"
    runner = _successful_runner(features_text=features)

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert "apps" in availability.detail


@pytest.mark.parametrize(
    ("login_returncode", "login_stdout", "login_stderr"),
    [
        (1, "Logged in with ChatGPT", ""),
        (0, "Not logged in", ""),
        (0, "authentication state unknown", ""),
    ],
)
def test_probe_requires_successful_positive_login_marker(
    login_returncode: int,
    login_stdout: str,
    login_stderr: str,
) -> None:
    runner = _successful_runner(
        login_returncode=login_returncode,
        login_stdout=login_stdout,
        login_stderr=login_stderr,
    )

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.UNAUTHENTICATED
    assert availability.version == "codex-cli 0.146.0"
    assert "codex login" in availability.detail
    assert len(availability.detail) <= 1000


@pytest.mark.parametrize(
    ("login_stdout", "login_stderr"),
    [("Logged in with ChatGPT", ""), ("", "Logged in with ChatGPT")],
)
def test_probe_accepts_login_marker_on_stdout_or_stderr_and_preserves_version(
    login_stdout: str,
    login_stderr: str,
) -> None:
    runner = _successful_runner(login_stdout=login_stdout, login_stderr=login_stderr)

    availability = probe_codex_cli(runner=runner)

    assert availability == CodexAvailability.available("codex-cli 0.146.0")


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.TimeoutExpired(
            ["codex", "--version"],
            10,
            output="secret-provider-output",
            stderr="secret-provider-error",
        ),
        OSError("secret executable path and environment"),
    ],
)
def test_probe_timeout_or_unexpected_os_error_is_not_fallback_eligible(
    failure: BaseException,
) -> None:
    runner = _RecordingRunner([failure])

    with pytest.raises(JudgeConfigurationError) as exc_info:
        probe_codex_cli(runner=runner)

    message = str(exc_info.value)
    assert len(message) <= 1000
    assert "secret" not in message


def test_probe_resolves_default_runner_inside_function(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _successful_runner()

    def _patched_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return runner(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", _patched_run)

    availability = probe_codex_cli(runner=None)

    assert availability.is_available
    assert len(runner.calls) == 4
