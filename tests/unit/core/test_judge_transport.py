from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from wardline.core.errors import JudgeConfigurationError
from wardline.core.judge_transport import (
    CODEX_DISABLED_FEATURES,
    CODEX_REQUIRED_EXEC_FLAGS,
    CodexAvailability,
    CodexUnavailableReason,
    _BoundedProcessResult,
    _run_bounded_process,
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

_FAKE_ACCOUNT_ID = "fake-account-id"
_AUTH_EXPIRY_MARGIN_SECONDS = 300


def _fake_jwt(claims: dict[str, object]) -> str:
    def _part(value: dict[str, object]) -> str:
        encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")

    return f"{_part({'alg': 'none'})}.{_part(claims)}.fake-signature"


def _jwt_with_raw_payload(payload: bytes) -> str:
    return _jwt_with_raw_parts(b'{"alg":"none"}', payload)


def _jwt_with_raw_parts(header_payload: bytes, claims_payload: bytes) -> str:
    header = base64.urlsafe_b64encode(header_payload).decode("ascii").rstrip("=")
    encoded_payload = base64.urlsafe_b64encode(claims_payload).decode("ascii").rstrip("=")
    return f"{header}.{encoded_payload}.fake-signature"


def _fake_auth_bytes(
    *,
    exp: object = 4_000_000_000,
    api_key: object = None,
    auth_mode: object = "chatgpt",
) -> bytes:
    return json.dumps(
        {
            "auth_mode": auth_mode,
            "OPENAI_API_KEY": api_key,
            "tokens": {
                "id_token": _fake_jwt({"sub": "fake-user"}),
                "access_token": _fake_jwt(
                    {
                        "exp": exp,
                        "https://api.openai.com/auth": {
                            "chatgpt_account_id": _FAKE_ACCOUNT_ID,
                        },
                    }
                ),
                "refresh_token": "REAL_REFRESH_TOKEN_SENTINEL",
                "account_id": _FAKE_ACCOUNT_ID,
            },
            "last_refresh": "2000-01-01T00:00:00+00:00",
        },
        separators=(",", ":"),
    ).encode("utf-8")


@pytest.fixture(autouse=True)
def _use_fake_codex_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    codex_home = tmp_path / "fixture-codex-home"
    codex_home.mkdir()
    auth_path = codex_home / "auth.json"
    auth_path.write_bytes(_fake_auth_bytes())
    auth_path.chmod(0o600)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))


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
        "auth_unprojectable",
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


def test_auth_unprojectable_is_fallback_eligible_but_explicit_codex_fails() -> None:
    reason = getattr(CodexUnavailableReason, "AUTH_UNPROJECTABLE", None)
    assert reason is not None
    unavailable = CodexAvailability(
        reason=reason,
        detail="run codex login",
        version="codex-cli 0.146.0",
    )

    assert resolve_judge_transport(JudgeTransport.AUTO, probe=lambda: unavailable) is JudgeTransport.OPENROUTER
    with pytest.raises(JudgeConfigurationError, match="auth_unprojectable"):
        resolve_judge_transport(JudgeTransport.CODEX_CLI, probe=lambda: unavailable)


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
        "LC_SECRET": "ENV_SENTINEL",
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


def test_injected_probe_runner_output_is_bounded_before_capability_parsing() -> None:
    runner = _RecordingRunner([_completed(stdout="codex-cli 0.146.0\n" + "x" * 300_000)])

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert "output limit" in availability.detail
    assert len(runner.calls) == 1


def test_default_preflight_process_runner_bounds_both_output_streams() -> None:
    result = _run_bounded_process(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "sys.stdout.buffer.write(b'o' * 20000); sys.stdout.flush(); "
                "sys.stderr.buffer.write(b'e' * 20000); sys.stderr.flush()"
            ),
        ],
        input_text=None,
        timeout=10,
        env=codex_child_env(),
        cwd=None,
        stdout_limit=4096,
        stderr_limit=4096,
    )

    assert result.returncode == 0
    assert len(result.stdout.encode("utf-8")) <= 4096
    assert len(result.stderr.encode("utf-8")) <= 4096
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True


def test_probe_treats_invalid_utf8_as_incompatible_without_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import wardline.core.judge_transport as transport_module

    def _invalid(*_args: object, **_kwargs: object) -> _BoundedProcessResult:
        return _BoundedProcessResult(
            returncode=0,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_decode_error=True,
        )

    monkeypatch.setattr(transport_module, "_run_bounded_process", _invalid)

    availability = probe_codex_cli()

    assert availability.reason is CodexUnavailableReason.INCOMPATIBLE
    assert "UTF-8" in availability.detail


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
    "unsafe_auth",
    ["missing-file", "near-expiry", "non-chatgpt", "private-acl-unsupported"],
)
def test_probe_requires_safely_projectable_chatgpt_file_auth(
    monkeypatch: pytest.MonkeyPatch,
    unsafe_auth: str,
) -> None:
    import wardline.core.judge_transport as transport_module

    auth_path = Path(os.environ["CODEX_HOME"]) / "auth.json"
    if unsafe_auth == "missing-file":
        auth_path.unlink()
        monkeypatch.setenv("CODEX_ACCESS_TOKEN", "EXTERNAL_TOKEN_SENTINEL")
    elif unsafe_auth == "near-expiry":
        monkeypatch.setattr(transport_module.time, "time", lambda: 1_000)
        auth_path.write_bytes(
            _fake_auth_bytes(
                exp=1_000 + 600 + _AUTH_EXPIRY_MARGIN_SECONDS,
            )
        )
        auth_path.chmod(0o600)
    elif unsafe_auth == "non-chatgpt":
        auth_path.write_bytes(
            _fake_auth_bytes(
                api_key="API_KEY_SENTINEL",
                auth_mode="api-key",
            )
        )
        auth_path.chmod(0o600)
    else:
        monkeypatch.setattr(
            transport_module,
            "codex_auth_projection_supported",
            lambda: False,
        )
    runner = _successful_runner()

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.AUTH_UNPROJECTABLE
    assert availability.version == "codex-cli 0.146.0"
    assert len(runner.calls) == 4
    assert "EXTERNAL_TOKEN_SENTINEL" not in availability.detail
    assert "API_KEY_SENTINEL" not in availability.detail
    assert _FAKE_ACCOUNT_ID not in availability.detail
    assert len(availability.detail) <= 1_000
    if unsafe_auth == "private-acl-unsupported":
        assert "unsupported on this platform" in availability.detail
        assert "OpenRouter" in availability.detail
        assert "codex login" not in availability.detail


@pytest.mark.parametrize(
    "nested_location",
    [
        "auth-document",
        "access-jwt-header",
        "access-jwt-payload",
        "id-jwt-payload",
    ],
)
def test_probe_maps_recursively_nested_auth_to_typed_unavailability(
    nested_location: str,
) -> None:
    nested_value = b"[" * 10_000 + b"0" + b"]" * 10_000
    auth_path = Path(os.environ["CODEX_HOME"]) / "auth.json"
    if nested_location == "auth-document":
        payload = _fake_auth_bytes()[:-1] + b',"nested":' + nested_value + b"}"
    else:
        parsed = json.loads(_fake_auth_bytes())
        access_payload = b'{"exp":4000000000,"https://api.openai.com/auth":{"chatgpt_account_id":"fake-account-id"}}'
        if nested_location == "access-jwt-header":
            nested_header = b'{"alg":"none","nested":' + nested_value + b"}"
            parsed["tokens"]["access_token"] = _jwt_with_raw_parts(nested_header, access_payload)
        elif nested_location == "access-jwt-payload":
            nested_access_payload = access_payload[:-1] + b',"nested":' + nested_value + b"}"
            parsed["tokens"]["access_token"] = _jwt_with_raw_payload(nested_access_payload)
        else:
            nested_id_payload = b'{"sub":"fake-user","nested":' + nested_value + b"}"
            parsed["tokens"]["id_token"] = _jwt_with_raw_payload(nested_id_payload)
        payload = json.dumps(parsed, separators=(",", ":")).encode("utf-8")
    auth_path.write_bytes(payload)
    auth_path.chmod(0o600)
    runner = _successful_runner()

    availability = probe_codex_cli(runner=runner)

    assert availability.reason is CodexUnavailableReason.AUTH_UNPROJECTABLE
    assert availability.version == "codex-cli 0.146.0"
    assert resolve_judge_transport(JudgeTransport.AUTO, probe=lambda: availability) is JudgeTransport.OPENROUTER
    with pytest.raises(JudgeConfigurationError, match="auth_unprojectable"):
        resolve_judge_transport(JudgeTransport.CODEX_CLI, probe=lambda: availability)
    assert len(runner.calls) == 4


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
    import wardline.core.judge_transport as transport_module

    runner = _successful_runner()

    def _patched_run(args: list[str], **kwargs: object):  # type: ignore[no-untyped-def]
        completed = runner(
            args,
            text=True,
            capture_output=True,
            check=False,
            timeout=kwargs["timeout"],
            env=kwargs["env"],
        )
        return _BoundedProcessResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            stdout_truncated=False,
            stderr_truncated=False,
        )

    monkeypatch.setattr(transport_module, "_run_bounded_process", _patched_run)

    availability = probe_codex_cli(runner=None)

    assert availability.is_available
    assert len(runner.calls) == 4
