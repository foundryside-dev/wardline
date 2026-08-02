from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import wardline.mcp.codex_judge_tools as tools_module
from wardline.core.judge_types import CodexToolScope
from wardline.mcp.codex_judge_tools import (
    _MAX_FILE_BYTES,
    _MAX_FILE_RESULTS,
    _MAX_PATH_CHARS,
    _MAX_PATTERN_CHARS,
    _MAX_READ_LINES,
    _MAX_RESULT_CHARS,
    _MAX_SCANNED_FILES,
    _MAX_TOTAL_SCANNED_BYTES,
    _MAX_WALK_DEPTH,
    _MAX_WALK_ENTRIES,
    _SENSITIVE_ENVIRONMENT_NAMES,
    _Accounting,
    _assert_keyless_environment,
    _BudgetStop,
    _Context,
    _directory_entries,
    _glob_files,
    _grep_files,
    _read_file,
    _safe_text,
    create_server,
    main,
)
from wardline.mcp.protocol import PROTOCOL_VERSION, JsonRpcServer


def _ctx(root: Path, *, max_calls: int = 24) -> _Context:
    return _Context(CodexToolScope(root=root.resolve(), max_calls=max_calls))


def _close_context(context: _Context) -> None:
    close = getattr(context, "close", None)
    if close is not None:
        close()


def _json(value: str) -> dict[str, object]:
    parsed = json.loads(value)
    assert isinstance(parsed, dict)
    return parsed


def _handshake(server: JsonRpcServer) -> None:
    initialized = server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
        }
    )
    assert initialized is not None and "result" in initialized
    assert server.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) is None


def _tool_call(
    server: JsonRpcServer,
    name: object,
    arguments: object,
    *,
    request_id: int = 1,
) -> dict[str, object]:
    response = server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    return response


def test_fixed_limits_are_exact() -> None:
    assert _MAX_READ_LINES == 400
    assert _MAX_RESULT_CHARS == 50_000
    assert _MAX_FILE_RESULTS == 500
    assert _MAX_SCANNED_FILES == 20_000
    assert _MAX_FILE_BYTES == 2 * 1024 * 1024
    assert _MAX_TOTAL_SCANNED_BYTES == 64 * 1024 * 1024
    assert _MAX_WALK_ENTRIES == 50_000
    assert _MAX_WALK_DEPTH == 32
    assert _MAX_PATH_CHARS == 4096
    assert _MAX_PATTERN_CHARS == 512


def test_read_file_is_line_and_character_bounded(tmp_path: Path) -> None:
    path = tmp_path / "safe.py"
    path.write_text("".join(f"line {index}\n" for index in range(600)), encoding="utf-8")

    result = _read_file(
        _ctx(tmp_path),
        {"file_path": "safe.py", "start_line": 3, "line_count": 400},
    )

    assert result.startswith("3: line 2")
    assert "402: line 401" in result
    assert "403: line 402" not in result
    assert len(result) <= 50_000


def test_read_file_defaults_to_first_line_and_numbers_one_based(tmp_path: Path) -> None:
    (tmp_path / "safe.txt").write_text("alpha\nbeta\n", encoding="utf-8")

    assert _read_file(_ctx(tmp_path), {"file_path": "safe.txt"}) == "1: alpha\n2: beta"


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"file_path": ""},
        {"file_path": 7},
        {"file_path": "safe.py", "start_line": 0},
        {"file_path": "safe.py", "start_line": True},
        {"file_path": "safe.py", "line_count": 0},
        {"file_path": "safe.py", "line_count": 401},
        {"file_path": "safe.py", "extra": True},
    ],
)
def test_read_file_runtime_validation_rejects_malformed_arguments(tmp_path: Path, arguments: dict[str, object]) -> None:
    (tmp_path / "safe.py").write_text("safe", encoding="utf-8")

    with pytest.raises(ValueError):
        _read_file(_ctx(tmp_path), arguments)


@pytest.mark.parametrize(
    "file_path",
    [
        "/etc/passwd",
        "../outside.txt",
        "nested/../../outside.txt",
        "C:\\Windows\\system.ini",
        "safe.py\x00ignored",
        "x" * (_MAX_PATH_CHARS + 1),
    ],
)
def test_read_file_rejects_non_relative_or_overlong_paths(tmp_path: Path, file_path: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": file_path})

    assert str(tmp_path.resolve()) not in str(exc_info.value)


def test_read_file_rejects_missing_directory_and_fifo_without_host_path(
    tmp_path: Path,
) -> None:
    (tmp_path / "directory").mkdir()
    candidates = ["missing.txt", "directory"]
    if hasattr(os, "mkfifo"):
        os.mkfifo(tmp_path / "named-pipe")
        candidates.append("named-pipe")

    for candidate in candidates:
        with pytest.raises(ValueError) as exc_info:
            _read_file(_ctx(tmp_path), {"file_path": candidate})
        assert str(tmp_path.resolve()) not in str(exc_info.value)


def test_read_file_rejects_root_and_file_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret", encoding="utf-8")
    (root / "escape.txt").symlink_to(outside)

    with pytest.raises(ValueError):
        _read_file(_ctx(root), {"file_path": "."})
    with pytest.raises(ValueError) as exc_info:
        _read_file(_ctx(root), {"file_path": "escape.txt"})
    assert "outside secret" not in str(exc_info.value)
    assert str(outside) not in str(exc_info.value)


def test_walkers_never_follow_directory_symlink_escape_or_loop(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("needle", encoding="utf-8")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "loop").symlink_to(root, target_is_directory=True)
    (root / "safe.py").write_text("needle", encoding="utf-8")

    globbed = _json(_glob_files(_ctx(root), {"pattern": "*.py"}))
    grepped = _json(
        _grep_files(
            _ctx(root),
            {"pattern": "needle", "output_mode": "files_with_matches"},
        )
    )

    assert globbed["files"] == ["safe.py"]
    assert grepped["files"] == ["safe.py"]
    assert str(root.resolve()) not in json.dumps([globbed, grepped])
    assert str(outside.resolve()) not in json.dumps([globbed, grepped])


def test_pinned_root_survives_configured_root_ancestor_swap_for_direct_read(
    tmp_path: Path,
) -> None:
    configured_parent = tmp_path / "configured"
    root = configured_parent / "repo"
    root.mkdir(parents=True)
    (root / "target.txt").write_text("INSIDE_BYTES", encoding="utf-8")
    outside_parent = tmp_path / "outside"
    outside_root = outside_parent / "repo"
    outside_root.mkdir(parents=True)
    (outside_root / "target.txt").write_text("OUTSIDE_BYTES", encoding="utf-8")
    context = _ctx(root)

    try:
        configured_parent.rename(tmp_path / "parked")
        configured_parent.symlink_to(outside_parent, target_is_directory=True)

        assert _read_file(context, {"file_path": "target.txt"}) == "1: INSIDE_BYTES"
    finally:
        _close_context(context)


def test_pinned_root_survives_configured_root_ancestor_swap_for_walkers(
    tmp_path: Path,
) -> None:
    configured_parent = tmp_path / "configured"
    root = configured_parent / "repo"
    root.mkdir(parents=True)
    (root / "target.txt").write_text("INSIDE_BYTES", encoding="utf-8")
    outside_parent = tmp_path / "outside"
    outside_root = outside_parent / "repo"
    outside_root.mkdir(parents=True)
    (outside_root / "target.txt").write_text("OUTSIDE_BYTES", encoding="utf-8")
    context = _ctx(root)

    try:
        configured_parent.rename(tmp_path / "parked")
        configured_parent.symlink_to(outside_parent, target_is_directory=True)

        outside = _json(_grep_files(context, {"pattern": "OUTSIDE_BYTES", "output_mode": "files_with_matches"}))
        inside = _json(_grep_files(context, {"pattern": "INSIDE_BYTES", "output_mode": "files_with_matches"}))
    finally:
        _close_context(context)

    assert outside["files"] == []
    assert inside["files"] == ["target.txt"]


def test_context_close_is_idempotent_and_invalidates_retained_root_fd(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    root_fd = context.root_fd

    context.close()
    context.close()

    with pytest.raises(OSError):
        os.fstat(root_fd)
    with pytest.raises(ValueError, match="closed"):
        _glob_files(context, {"pattern": "*"})


@pytest.mark.parametrize(
    "missing",
    ["dir_fd_open", "fd_scandir", "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"],
)
def test_context_refuses_missing_secure_open_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    if missing == "dir_fd_open":
        monkeypatch.setattr(tools_module.os, "supports_dir_fd", set())
    elif missing == "fd_scandir":
        monkeypatch.setattr(tools_module.os, "supports_fd", set())
    else:
        monkeypatch.delattr(tools_module.os, missing)

    with pytest.raises(RuntimeError, match="secure repository access unavailable") as exc_info:
        _ctx(tmp_path)

    assert str(tmp_path) not in str(exc_info.value)


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".ENV.local",
        ".npmrc",
        "nested/.NPMRC",
        ".netrc",
        "nested/.NETRC",
        ".git-credentials",
        "nested/.GIT-CREDENTIALS",
        ".docker/config.json",
        "nested/.DOCKER/Config.JSON",
        "settings.xml",
        "nested/SETTINGS.XML",
        "NuGet.Config",
        "nested/NUGET.CONFIG",
        "gradle.properties",
        "nested/GRADLE.PROPERTIES",
        ".yarnrc.yml",
        "nested/.YARNRC.YML",
        "pip.conf",
        "nested/PIP.CONF",
        ".cursorrules",
        "AGENTS.md",
        "agents.OVERRIDE.md",
        "CLAUDE.md",
        "Gemini.MD",
        "copilot-instructions.md",
        ".codex/config.toml",
        ".agents/skills/example.md",
        ".CLAUDE/settings.json",
        ".Cursor/rules.md",
        ".Git/config",
        ".github/instructions/review.instructions.md",
        "nested/AGENTS.md",
    ],
)
def test_instruction_and_credential_paths_are_denied_case_insensitively(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("do not expose", encoding="utf-8")

    with pytest.raises(ValueError, match="denied") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": name})

    assert "do not expose" not in str(exc_info.value)
    assert str(tmp_path.resolve()) not in str(exc_info.value)


def test_denied_paths_are_absent_from_glob_and_grep(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text("needle", encoding="utf-8")
    (tmp_path / ".env").write_text("needle=secret", encoding="utf-8")
    for name in [
        ".npmrc",
        ".netrc",
        ".git-credentials",
        ".docker/config.json",
        "settings.xml",
        "nuget.config",
        "gradle.properties",
        ".yarnrc.yml",
        "pip.conf",
    ]:
        denied = tmp_path / name
        denied.parent.mkdir(parents=True, exist_ok=True)
        denied.write_text("needle=secret", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "AGENTS.md").write_text("needle", encoding="utf-8")
    instructions = tmp_path / ".github" / "instructions"
    instructions.mkdir(parents=True)
    (instructions / "review.instructions.md").write_text("needle", encoding="utf-8")

    globbed = _json(_glob_files(_ctx(tmp_path), {"pattern": "*"}))
    grepped = _json(
        _grep_files(
            _ctx(tmp_path),
            {"pattern": "needle", "output_mode": "files_with_matches"},
        )
    )

    assert globbed["files"] == ["safe.py"]
    assert grepped["files"] == ["safe.py"]


def test_noncredential_config_basenames_remain_visible(tmp_path: Path) -> None:
    filenames = ["settings.json", "nuget.json", "gradle.toml", ".yarnrc", "pip.ini"]
    for filename in filenames:
        (tmp_path / filename).write_text("needle", encoding="utf-8")

    globbed = _json(_glob_files(_ctx(tmp_path), {"pattern": "*"}))
    grepped = _json(
        _grep_files(
            _ctx(tmp_path),
            {"pattern": "needle", "output_mode": "files_with_matches"},
        )
    )

    assert globbed["files"] == sorted(filenames)
    assert grepped["files"] == sorted(filenames)


def test_safe_text_accepts_exact_file_cap_and_rejects_sparse_overflow(tmp_path: Path) -> None:
    exact = tmp_path / "exact.txt"
    exact.write_bytes(b"a" * _MAX_FILE_BYTES)
    oversized = tmp_path / "oversized.txt"
    with oversized.open("wb") as handle:
        handle.truncate(_MAX_FILE_BYTES + 1)

    assert len(_safe_text(_ctx(tmp_path), exact)) == _MAX_FILE_BYTES
    with pytest.raises(ValueError, match="size"):
        _safe_text(_ctx(tmp_path), oversized)


def test_safe_text_rejects_file_that_grows_between_stat_and_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "growing.txt"
    target.write_bytes(b"a" * _MAX_FILE_BYTES)
    context = _ctx(tmp_path)
    real_open = tools_module.os.open
    grown = False

    def _grow_then_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal grown
        if not grown:
            grown = True
            target.write_bytes(b"a" * (_MAX_FILE_BYTES + 1))
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(tools_module.os, "open", _grow_then_open)

    try:
        with pytest.raises(ValueError, match="size"):
            _safe_text(context, target)
    finally:
        _close_context(context)


def test_safe_text_growth_charges_detection_byte_and_scanned_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "growing.txt"
    target.write_bytes(b"1234")
    accounting = _Accounting()
    monkeypatch.setattr(tools_module, "_MAX_TOTAL_SCANNED_BYTES", 4)
    real_read = tools_module.os.read
    grown = False

    def _grow_then_read(descriptor: int, size: int) -> bytes:
        nonlocal grown
        if not grown:
            grown = True
            target.write_bytes(b"12345")
        return real_read(descriptor, size)

    monkeypatch.setattr(tools_module.os, "read", _grow_then_read)

    with pytest.raises(_BudgetStop):
        _safe_text(_ctx(tmp_path), target, accounting)

    assert accounting.scanned_files == 1
    assert accounting.scanned_bytes == 5
    assert accounting.truncated is True


@pytest.mark.parametrize(
    "data",
    [b"safe\x00binary", b"\xff\xfe\xfa"],
)
def test_safe_text_rejects_binary_and_invalid_utf8(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "candidate.bin"
    path.write_bytes(data)

    with pytest.raises(ValueError, match="text"):
        _safe_text(_ctx(tmp_path), path)


@pytest.mark.parametrize(
    ("pattern_name", "content"),
    [
        (
            "pem_private_key",
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
        ),
        ("authorization_bearer", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"),
        ("provider_token", "token = sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789"),
        ("credential_assignment", 'password = "correct-horse-battery-staple-2026"'),
        ("credential_assignment", 'client_secret: "abcdefghijklmnopqrstuvwxyz0123456789"'),
        ("credential_assignment", 'api_key = "abcdefghijklmnopqrstuvwxyz0123456789"'),
    ],
)
def test_secret_patterns_are_named_without_echoing_matching_bytes(
    tmp_path: Path, pattern_name: str, content: str
) -> None:
    path = tmp_path / "candidate.py"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "candidate.py"})

    message = str(exc_info.value)
    assert pattern_name in message
    assert content not in message
    assert str(path) not in message


@pytest.mark.parametrize(
    "content",
    [
        "Authorization: Bearer <YOUR_TOKEN_HERE>",
        "Authorization: Bearer example-example-example-example",
        "token = sk-test-abcdefghijklmnopqrstuvwxyz0123456789",
        "OPENAI_API_KEY = 'sk-placeholder-abcdefghijklmnopqrstuvwxyz'",
        'password = "REDACTED"',
        'secret = "dummy-value-for-tests"',
        'api_key = "fake-example-key"',
    ],
)
def test_obvious_placeholder_and_test_credentials_remain_readable(tmp_path: Path, content: str) -> None:
    path = tmp_path / "security_fixture.py"
    path.write_text(content, encoding="utf-8")

    result = _read_file(_ctx(tmp_path), {"file_path": "security_fixture.py"})

    assert content in result


@pytest.mark.parametrize(
    "content",
    [
        'aws_access_key_id = "AKIA1234567890ABCDEF"',
        'token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
        'token = "github_pat_abcdefghijklmnopqrstuvwxyz_0123456789"',
        'google_key = "AIzaSyabcdefghijklmnopqrstuvwxyz012345"',
    ],
)
def test_common_cloud_and_provider_tokens_are_denied_without_value_echo(tmp_path: Path, content: str) -> None:
    path = tmp_path / "provider.txt"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="provider_token") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "provider.txt"})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    "content",
    [
        'aws_access_key_id = "AKIATESTPLACEHOLDER1"',
        'token = "ghp_test_placeholder_abcdefghijklmnopqrstuvwxyz"',
        'token = "github_pat_test_placeholder_abcdefghijklmnopqrstuvwxyz"',
        'google_key = "AIzaTestPlaceholderabcdefghijklmnopqrstuvwxyz"',
    ],
)
def test_common_provider_placeholder_tokens_remain_readable(tmp_path: Path, content: str) -> None:
    path = tmp_path / "provider-fixture.txt"
    path.write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "provider-fixture.txt"})


@pytest.mark.parametrize(
    ("pattern_name", "content"),
    [
        (
            "authorization_bearer",
            "Authorization: Bearer production-contest-example-fake-token-123456",
        ),
        ("provider_token", 'token = "sk-live-contest-example-fake-1234567890"'),
        ("provider_token", 'token = "ghp_productiontestexamplefake1234567890"'),
        ("credential_assignment", 'password = "productiontestexamplefakevalue"'),
    ],
)
def test_placeholder_words_embedded_in_real_credentials_do_not_exempt_them(
    tmp_path: Path, pattern_name: str, content: str
) -> None:
    path = tmp_path / "real-credential.txt"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=pattern_name) as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "real-credential.txt"})

    assert content not in str(exc_info.value)


def test_quoted_credential_literal_with_spaces_is_denied(tmp_path: Path) -> None:
    content = 'password = "correct horse battery staple"'
    (tmp_path / "credential.txt").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "credential.txt"})

    assert content not in str(exc_info.value)


def test_secret_wrapper_around_literal_credential_is_denied(tmp_path: Path) -> None:
    content = 'secret = SecretStr("production literal secret value")'
    (tmp_path / "credential.py").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "credential.py"})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    ("content", "literal"),
    [
        (
            '{"password": "correct-horse-battery-staple-2026"}',
            "correct-horse-battery-staple-2026",
        ),
        (
            'database_password = "correct-horse-battery-staple-2026"',
            "correct-horse-battery-staple-2026",
        ),
        (
            'AWS_SECRET_ACCESS_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD"',
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD",
        ),
    ],
)
def test_labelled_credential_literals_are_denied_without_value_echo(tmp_path: Path, content: str, literal: str) -> None:
    path = tmp_path / "credential-literal.txt"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "credential-literal.txt"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        'password_policy = "minimum length 12"',
        'password_field = "password"',
        'token_endpoint = "https://identity.example/oauth/token"',
        'api_key_header = "X-API-Key"',
        '{"password_label": "Account password"}',
        "api_key = self.settings.api_key",
        "token = credentials.token",
        "password = DEFAULT_PASSWORD",
    ],
)
def test_credential_metadata_and_bare_source_references_remain_readable(tmp_path: Path, content: str) -> None:
    path = tmp_path / "credential-metadata.py"
    path.write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "credential-metadata.py"})


def test_source_reference_suffix_vocabulary_is_exact() -> None:
    expected = frozenset(
        {
            ".c",
            ".cc",
            ".cpp",
            ".cs",
            ".go",
            ".h",
            ".hpp",
            ".java",
            ".js",
            ".jsx",
            ".kt",
            ".kts",
            ".mjs",
            ".php",
            ".py",
            ".pyi",
            ".rb",
            ".rs",
            ".scala",
            ".swift",
            ".ts",
            ".tsx",
        }
    )
    assert expected == tools_module._SOURCE_REFERENCE_SUFFIXES


@pytest.mark.parametrize(
    ("filename", "content", "literal"),
    [
        ("config.yaml", "password: hunter2.secret", "hunter2.secret"),
        ("config.yml", "api_key: PROD_SECRET_2026", "PROD_SECRET_2026"),
    ],
)
def test_yaml_credential_literals_are_denied_without_value_echo(
    tmp_path: Path, filename: str, content: str, literal: str
) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    ("content", "literal"),
    [
        ('password: config["production_password"]', 'config["production_password"]'),
        ('token: request.headers.get("Authorization")', 'request.headers.get("Authorization")'),
        ("secret: SecretStr(config.api_key)", "SecretStr(config.api_key)"),
        ('api_key: os.environ["OPENAI_API_KEY"]', 'os.environ["OPENAI_API_KEY"]'),
    ],
)
def test_yaml_complex_credential_scalars_are_denied_without_value_echo(
    tmp_path: Path, content: str, literal: str
) -> None:
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        'password = config["production_password"]',
        'token = request.headers.get("Authorization")',
        "secret = SecretStr(config.api_key)",
        'api_key = os.environ["OPENAI_API_KEY"]',
    ],
)
def test_supported_source_files_keep_complex_references_readable(tmp_path: Path, content: str) -> None:
    (tmp_path / "configuration.py").write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "configuration.py"})


@pytest.mark.parametrize(
    "content",
    [
        "password: REDACTED",
        "token: dummy-value-for-tests",
        "secret: placeholder-value",
        "api_key: sk-test-abcdefghijklmnopqrstuvwxyz0123456789",
        'password_policy: "minimum length 12"',
        'password_field: "password"',
        'token_endpoint: "https://identity.example/oauth/token"',
        'api_key_header: "X-API-Key"',
    ],
)
def test_yaml_placeholders_and_credential_metadata_remain_readable(tmp_path: Path, content: str) -> None:
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("config.json", '{"password": "placeholder-password", "user": "alice"}'),
        ("config.yaml", "password: ${DATABASE_PASSWORD}"),
        ("config.yaml", "api_key: ${OPENAI_API_KEY}"),
        ("config.yaml", "token: null"),
        ("config.yaml", "secret: false"),
        ("config.yaml", "password: none"),
        ("config.yaml", "token: true"),
        ("config.yaml", "secret: ~"),
        ("notes.txt", "The password: must be at least twelve characters."),
    ],
)
def test_structured_safe_scalars_and_prose_remain_readable(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


def test_flow_map_later_credential_is_denied_without_value_echo(tmp_path: Path) -> None:
    content = '{password: "placeholder-password", api_key: correct horse battery staple}'
    literal = "correct horse battery staple"
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("config.json", '{"password": null, "user": "alice"}'),
        ("config.yaml", "password: ${DATABASE_PASSWORD:-changeme}"),
        ("config.yaml", "password: ${DATABASE_PASSWORD-changeme}"),
        ("config.yaml", "password: ${DATABASE_PASSWORD:-null}"),
        ("notes.txt", "The password: contains uppercase characters."),
    ],
)
def test_composed_safe_scalars_and_prose_remain_readable(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    "content",
    [
        "password: ${DATABASE_PASSWORD:-production-secret-value}",
        "password: ${database_password}",
        "password: ${DATABASE_PASSWORD:?required}",
    ],
)
def test_arbitrary_credential_substitutions_are_denied_without_value_echo(tmp_path: Path, content: str) -> None:
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    "content",
    [
        "const api_key = settings.api_key",
        "export const api_key = settings.api_key;",
    ],
)
def test_supported_source_declaration_reference_remains_readable(tmp_path: Path, content: str) -> None:
    (tmp_path / "configuration.ts").write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "configuration.ts"})


@pytest.mark.parametrize(
    ("pattern_name", "content", "literal"),
    [
        (
            "authorization_bearer",
            "Authorization: Bearer example-example-example-example\n"
            "Authorization: Bearer production-bearer-secret-abcdefghijklmnopqrstuvwxyz",
            "production-bearer-secret-abcdefghijklmnopqrstuvwxyz",
        ),
        (
            "provider_token",
            "token = sk-test-abcdefghijklmnopqrstuvwxyz0123456789\n"
            "token = sk-live-abcdefghijklmnopqrstuvwxyz0123456789",
            "sk-live-abcdefghijklmnopqrstuvwxyz0123456789",
        ),
    ],
)
def test_later_real_global_token_is_denied_without_value_echo(
    tmp_path: Path, pattern_name: str, content: str, literal: str
) -> None:
    (tmp_path / "credentials.txt").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=pattern_name) as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "credentials.txt"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        'password = os.getenv("PASSWORD", "correct horse battery staple")',
        'api_key = settings.api_key or "correct horse battery staple"',
        'client_secret = config.client_secret + "correct horse battery staple"',
    ],
)
def test_source_reference_with_appended_literal_is_denied_without_value_echo(tmp_path: Path, content: str) -> None:
    (tmp_path / "configuration.py").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "configuration.py"})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configure.sh", 'export PASSWORD="correct horse battery staple"'),
        ("configuration.ts", 'export const api_key = "correct horse battery staple";'),
        ("configuration.rs", 'let mut password = "correct horse battery staple";'),
        ("Configuration.java", 'private String password = "correct horse battery staple";'),
        ("Configuration.cs", 'private string password = "correct horse battery staple";'),
        ("configuration.cpp", 'std::string password = "correct horse battery staple";'),
        ("Configuration.kt", 'private val password = "correct horse battery staple"'),
        ("configuration.php", '$this->password = "correct horse battery staple";'),
        ("configuration.rb", '@password = "correct horse battery staple"'),
        ("Dockerfile", 'ENV PASSWORD="correct horse battery staple"'),
    ],
)
def test_language_declaration_literal_is_denied_without_value_echo(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("config.yaml", "password: changeme#actual-production-secret"),
        ("configuration.py", 'password = "placeholder-password", "correct horse battery staple"'),
    ],
)
def test_credential_scalar_delimiters_do_not_truncate_real_literal(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


def test_separated_yaml_comment_after_placeholder_remains_readable(tmp_path: Path) -> None:
    content = "password: changeme # replace outside production"
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.py", "api_key: str"),
        ("configuration.py", "password: SecretStr | None = None"),
        ("configuration.ts", "token: string;"),
        ("schema.json", '{"properties":{"password":{"type":"string"}}}'),
    ],
)
def test_secret_free_type_declaration_and_schema_remain_readable(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.py", 'api_key: str = "correct horse battery staple"'),
        ("configuration.py", 'password: SecretStr | None = "correct horse battery staple"'),
        ("configuration.ts", 'token: string = "correct horse battery staple";'),
        (
            "schema.json",
            '{"properties":{"password":{"type":"string","default":"correct horse battery staple"}}}',
        ),
    ],
)
def test_typed_declaration_and_schema_literal_is_denied_without_value_echo(
    tmp_path: Path, filename: str, content: str
) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    "safe_prefix",
    ["null", "placeholder-password", "${DATABASE_PASSWORD}"],
)
def test_truncated_credential_scalar_is_denied_without_value_echo(tmp_path: Path, safe_prefix: str) -> None:
    literal = "correct horse battery staple"
    content = f"password: {safe_prefix}{' ' * 600}{literal}"
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "label",
    ["accessToken", "databasePassword", "secretAccessKey", "apiKey", "clientSecret"],
)
def test_camel_case_credential_label_literal_is_denied_without_value_echo(tmp_path: Path, label: str) -> None:
    literal = "correct horse battery staple"
    content = f'{label}: "{literal}"'
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    assert literal not in str(exc_info.value)
    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.ts", 'export const api_key: string = "correct horse battery staple";'),
        ("configuration.rs", 'let mut password: String = "correct horse battery staple";'),
        ("Configuration.kt", 'private val password: String = "correct horse battery staple"'),
        ("configuration.php", 'private string $password = "correct horse battery staple";'),
        ("Configuration.swift", 'private let password: String = "correct horse battery staple"'),
        ("Configuration.scala", 'private val password: String = "correct horse battery staple"'),
        ("configuration.go", 'var password string = "correct horse battery staple"'),
        ("constants.go", 'const apiKey string = "correct horse battery staple"'),
        ("Configuration.cs", 'private string? password = "correct horse battery staple";'),
        ("Dockerfile", 'ENV PASSWORD "correct horse battery staple"'),
        ("Dockerfile", 'ARG PASSWORD="correct horse battery staple"'),
    ],
)
def test_format_specific_typed_declaration_literal_is_denied_without_echo(
    tmp_path: Path, filename: str, content: str
) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    "content",
    ["ENV PASSWORD=changeme", "ENV PASSWORD changeme", "ARG PASSWORD=changeme"],
)
def test_docker_placeholder_declaration_remains_readable(tmp_path: Path, content: str) -> None:
    (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "Dockerfile"})


@pytest.mark.parametrize("filename", ["config.ini", "config.cfg", "config.conf", "application.properties"])
def test_hash_is_value_data_in_non_comment_format(tmp_path: Path, filename: str) -> None:
    content = "password = changeme #actual-production-secret"
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    "content",
    [
        '{\n  "password": null,\n  "user": "alice"\n}',
        '{\n  "apiKey": "placeholder-value",\n  "user": "alice"\n}',
    ],
)
def test_pretty_json_safe_credential_scalar_remains_readable(tmp_path: Path, content: str) -> None:
    (tmp_path / "config.json").write_text(content, encoding="utf-8")

    result = _read_file(_ctx(tmp_path), {"file_path": "config.json"})

    assert all(line in result for line in content.splitlines())


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.py", 'api_key: str = os.environ["OPENAI_API_KEY"]'),
        ("configuration.py", "password: SecretStr | None = None"),
        ("configuration.ts", "token: string = settings.token;"),
        ("configuration.ts", "token: string | null;"),
        ("configuration.ts", "token?: string | null;"),
    ],
)
def test_typed_safe_reference_or_annotation_remains_readable(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.py", 'api_key: str = "correct horse battery staple"'),
        ("configuration.ts", 'token: string = "correct horse battery staple";'),
    ],
)
def test_typed_literal_default_remains_denied_without_echo(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


def test_json_schema_harmless_credential_constraints_remain_readable(tmp_path: Path) -> None:
    content = json.dumps(
        {
            "properties": {
                "password": {
                    "type": "string",
                    "title": "Password",
                    "description": "Account credential",
                    "format": "password",
                    "minLength": 12,
                    "maxLength": 128,
                    "pattern": "[A-Z]",
                }
            }
        },
        indent=2,
    )
    (tmp_path / "schema.json").write_text(content, encoding="utf-8")

    result = _read_file(_ctx(tmp_path), {"file_path": "schema.json"})

    assert all(line in result for line in content.splitlines())


@pytest.mark.parametrize("keyword", ["default", "const", "examples", "enum"])
def test_json_schema_literal_credential_keywords_are_denied_without_echo(tmp_path: Path, keyword: str) -> None:
    literal = "correct horse battery staple"
    value: object = [literal] if keyword in {"examples", "enum"} else literal
    content = json.dumps({"properties": {"password": {"type": "string", keyword: value}}})
    (tmp_path / "schema.json").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "schema.json"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.py", 'password = config.get("PASSWORD")'),
        ("Configuration.java", "password = config.getPassword()"),
        ("configuration.php", "password = $config->password"),
        ("configuration.rb", 'password = ENV.fetch("PASSWORD")'),
        ("configuration.rb", 'password = ENV["PASSWORD"]'),
        ("configuration.ts", 'password = process.env["PASSWORD"]'),
        ("configuration.js", "password = process.env.PASSWORD"),
    ],
)
def test_suffix_specific_source_reference_remains_readable(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.py", 'password = config.get("PASSWORD") or "correct horse battery staple"'),
        ("Configuration.java", 'password = config.getPassword() + "correct horse battery staple"'),
        ("configuration.php", 'password = $config->password ?: "correct horse battery staple"'),
        ("configuration.rb", 'password = ENV.fetch("PASSWORD") || "correct horse battery staple"'),
        ("configuration.ts", 'password = process.env.PASSWORD || "correct horse battery staple"'),
    ],
)
def test_suffix_specific_source_reference_with_fallback_is_denied_without_echo(
    tmp_path: Path, filename: str, content: str
) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.py", "password = None# optional credential"),
        ("config.toml", 'password = "placeholder-password"# fixture value'),
        ("config.yaml", "password: changeme # fixture value"),
        ("configure.sh", "export PASSWORD=changeme # fixture value"),
    ],
)
def test_format_specific_hash_comment_after_safe_scalar_remains_readable(
    tmp_path: Path, filename: str, content: str
) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("config.yaml", "password: changeme#actual-production-secret"),
        ("configure.sh", "export PASSWORD=changeme#actual-production-secret"),
        ("config.ini", "password = changeme #actual-production-secret"),
        ("config.cfg", "password = changeme #actual-production-secret"),
        ("config.conf", "password = changeme #actual-production-secret"),
        ("application.properties", "password = changeme #actual-production-secret"),
    ],
)
def test_hash_without_format_valid_comment_boundary_is_denied_without_echo(
    tmp_path: Path, filename: str, content: str
) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize("label", ["refreshToken", "authToken"])
def test_additional_camel_case_credential_label_is_denied_without_echo(tmp_path: Path, label: str) -> None:
    literal = "correct horse battery staple"
    content = f'{label}: "{literal}"'
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        'passwordPolicy: "minimum length 12"',
        'tokenEndpoint: "https://identity.example/oauth/token"',
    ],
)
def test_camel_case_credential_metadata_remains_readable(tmp_path: Path, content: str) -> None:
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.ts", 'export const api_key: SecretString = "correct horse battery staple";'),
        ("configuration.ts", 'private readonly password: string = "correct horse battery staple";'),
        ("configuration.cpp", 'const char *password = "correct horse battery staple";'),
        ("Configuration.java", 'var password = "correct horse battery staple";'),
        ("configuration.php", 'private ?string $password = "correct horse battery staple";'),
        ("configuration.rs", 'let mut password: String = "correct horse battery staple";'),
        ("Configuration.kt", 'private val password: String = "correct horse battery staple"'),
        ("Configuration.swift", 'private let password: String = "correct horse battery staple"'),
        ("Configuration.scala", 'private val password: String = "correct horse battery staple"'),
        ("configuration.go", 'var password string = "correct horse battery staple"'),
    ],
)
def test_final_language_declaration_literal_is_denied_without_echo(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("configuration.ts", "export const api_key: SecretString = settings.api_key;"),
        ("configuration.ts", 'private readonly password: string = process.env["PASSWORD"];'),
        ("configuration.cpp", 'const char *password = std::getenv("PASSWORD");'),
        ("Configuration.java", "var password = settings.getPassword();"),
        ("configuration.php", "private ?string $password = $config->password;"),
        ("configuration.rs", "let mut password: String = DEFAULT_PASSWORD;"),
        ("Configuration.kt", "private val password: String = settings.password"),
        ("Configuration.swift", 'private let password: String = ProcessInfo.processInfo.environment["PASSWORD"]'),
        ("Configuration.scala", "private val password: String = settings.password"),
        ("configuration.go", 'var password string = os.Getenv("PASSWORD")'),
    ],
)
def test_final_language_declaration_reference_remains_readable(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    "content",
    [
        '#!/bin/sh\nexport PASSWORD="correct horse battery staple"',
        '#!/usr/bin/env bash\nexport PASSWORD="correct horse battery staple"',
        '#!/usr/bin/env -S zsh -eu\nexport PASSWORD="correct horse battery staple"',
    ],
)
def test_extensionless_shell_shebang_literal_is_denied_without_echo(tmp_path: Path, content: str) -> None:
    (tmp_path / "configure").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "configure"})

    assert content not in str(exc_info.value)


@pytest.mark.parametrize(
    "content",
    [
        "#!/bin/bash\nexport PASSWORD=changeme",
        "#!/usr/bin/env zsh\nexport PASSWORD=${DATABASE_PASSWORD}",
    ],
)
def test_extensionless_shell_shebang_safe_rhs_remains_readable(tmp_path: Path, content: str) -> None:
    (tmp_path / "configure").write_text(content, encoding="utf-8")

    result = _read_file(_ctx(tmp_path), {"file_path": "configure"})

    assert all(line in result for line in content.splitlines())


def test_extensionless_non_shell_shebang_does_not_enable_shell_declarations(tmp_path: Path) -> None:
    content = '#!/usr/bin/env python3\nexport PASSWORD="correct horse battery staple"'
    (tmp_path / "configure").write_text(content, encoding="utf-8")

    result = _read_file(_ctx(tmp_path), {"file_path": "configure"})

    assert all(line in result for line in content.splitlines())


@pytest.mark.parametrize("delimiter", [":", "="])
def test_json_schema_descriptive_credential_literal_is_denied_without_echo(tmp_path: Path, delimiter: str) -> None:
    literal = "correct horse battery staple"
    description = f"Production password{delimiter} {literal}"
    content = json.dumps({"properties": {"password": {"type": "string", "description": description}}})
    (tmp_path / "schema.json").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "schema.json"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("Configuration.java", "password = settings.getPassword()"),
        ("configuration.c", 'password = std::getenv("PASSWORD")'),
        ("configuration.cpp", 'password = std::getenv("PASSWORD")'),
        ("configuration.go", 'password = os.Getenv("PASSWORD")'),
        ("Configuration.swift", 'password = ProcessInfo.processInfo.environment["PASSWORD"]'),
    ],
)
def test_final_suffix_specific_source_reference_remains_readable(tmp_path: Path, filename: str, content: str) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("Configuration.java", 'password = settings.getPassword() + "correct horse battery staple"'),
        ("configuration.c", 'password = std::getenv("PASSWORD") + "correct horse battery staple"'),
        ("configuration.go", 'password = os.Getenv("PASSWORD") + "correct horse battery staple"'),
        (
            "Configuration.swift",
            'password = ProcessInfo.processInfo.environment["PASSWORD"] ?? "correct horse battery staple"',
        ),
    ],
)
def test_final_suffix_specific_reference_with_literal_is_denied_without_echo(
    tmp_path: Path, filename: str, content: str
) -> None:
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    assert content not in str(exc_info.value)


def test_multiline_yaml_flow_safe_scalars_remain_readable(tmp_path: Path) -> None:
    content = (
        "{\n  password: null,\n  token: false,\n  api_key: ${DATABASE_PASSWORD},\n"
        "  client_secret: placeholder-value,\n  user: alice\n}"
    )
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    result = _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    assert all(line in result for line in content.splitlines())


def test_multiline_yaml_flow_later_literal_is_denied_without_echo(tmp_path: Path) -> None:
    literal = "correct horse battery staple"
    content = f'{{\n  password: null,\n  token: false,\n  api_key: "{literal}"\n}}'
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        "{password: null,real-secret}",
        "password: null,,",
        "password: null,real-secret,",
        "password: null, appended text",
    ],
)
def test_yaml_safe_prefix_comma_with_extra_content_is_denied_without_echo(tmp_path: Path, content: str) -> None:
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    assert content not in str(exc_info.value)


def test_quoted_brace_does_not_create_yaml_flow_context(tmp_path: Path) -> None:
    content = 'note: "{"\npassword: null,'
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment"):
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})


def test_column_zero_yaml_comment_brace_does_not_create_flow_context(tmp_path: Path) -> None:
    literal = "correct-horse-battery-staple"
    content = f"# {{\npassword: null,{literal}"
    assert yaml.safe_load(content) == {"password": f"null,{literal}"}
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        "note: |\n  {\npassword: null,correct-horse-battery-staple",
        "note: >\n  {\npassword: null,correct-horse-battery-staple",
        "  note: |\n    {\n  password: null,correct-horse-battery-staple",
        "  note: >\n    {\n  password: null,correct-horse-battery-staple",
    ],
)
def test_yaml_block_scalar_brace_does_not_create_flow_context(tmp_path: Path, content: str) -> None:
    literal = "correct-horse-battery-staple"
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, dict)
    assert parsed["password"] == f"null,{literal}"
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        "- note: |\n    harmless\n  password: null,real-secret",
        "- note: |\n    {\n  password: null,real-secret",
        "items:\n  - note: |\n      harmless\n    password: null,real-secret",
        "items:\n  - note: |\n      {\n    password: null,real-secret",
    ],
)
def test_yaml_sequence_block_scalar_sibling_credential_is_denied_without_echo(tmp_path: Path, content: str) -> None:
    literal = "real-secret"
    parsed = yaml.safe_load(content)
    if isinstance(parsed, list):
        assert parsed[0]["password"] == f"null,{literal}"
    else:
        assert isinstance(parsed, dict)
        assert parsed["items"][0]["password"] == f"null,{literal}"
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        "note: !!str |\n  {\npassword: null,real-secret",
        "note: &body |\n  {\npassword: null,real-secret",
        '"note#body": |\n  {\npassword: null,real-secret',
    ],
)
def test_yaml_decorated_block_header_brace_does_not_create_flow_context(tmp_path: Path, content: str) -> None:
    literal = "real-secret"
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, dict)
    assert parsed["password"] == f"null,{literal}"
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


def test_yaml_plain_key_embedded_hash_block_header_does_not_create_flow_context(tmp_path: Path) -> None:
    literal = "real-secret"
    content = f"note#body: |\n  {{\npassword: null,{literal}"
    assert yaml.safe_load(content) == {"note#body": "{\n", "password": f"null,{literal}"}
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        "- |\n  {\n- password: null,real-secret",
        "- >2-\n  {\n- password: null,real-secret",
        "|\n  {\n---\npassword: null,real-secret",
        ">\n  {\n---\npassword: null,real-secret",
        "!!str |\n  {\n---\npassword: null,real-secret",
        "- &body |\n  {\n- password: null,real-secret",
        "---\n- !!str >\n  {\n- password: null,real-secret\n...\n---\nstatus: ok",
    ],
)
def test_yaml_direct_block_scalar_header_brace_does_not_create_flow_context(tmp_path: Path, content: str) -> None:
    literal = "real-secret"
    parsed = list(yaml.safe_load_all(content))
    assert literal in json.dumps(parsed)
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        "note: foo{bar\npassword: null,real-secret",
        "note: literal-{\npassword: null,real-secret",
    ],
)
def test_yaml_plain_scalar_adjacent_brace_does_not_create_flow_context(tmp_path: Path, content: str) -> None:
    literal = "real-secret"
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, dict)
    assert parsed["password"] == f"null,{literal}"
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


def test_yaml_plain_scalar_whitespace_adjacent_brace_does_not_create_flow_context(tmp_path: Path) -> None:
    literal = "real-secret"
    content = f"note: foo {{bar\npassword: null,{literal}"
    assert yaml.safe_load(content) == {"note": "foo {bar", "password": f"null,{literal}"}
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        "? note\n: |\n  {\npassword: null,real-secret",
        "? |\n  {\n: value\npassword: null,real-secret",
    ],
)
def test_yaml_explicit_mapping_block_scalar_does_not_create_flow_context(tmp_path: Path, content: str) -> None:
    literal = "real-secret"
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, dict)
    assert parsed["password"] == f"null,{literal}"
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "content",
    [
        "items: [{\n  password: null,\n  token: false\n}]",
        "items: [{name: first},{\n  password: null,\n  token: false\n}]",
    ],
)
def test_yaml_structural_adjacent_brace_flow_safe_scalars_remain_readable(tmp_path: Path, content: str) -> None:
    assert yaml.safe_load(content) is not None
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    result = _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    assert all(line in result for line in content.splitlines())


@pytest.mark.parametrize(
    "content",
    [
        "items: [{\n  password: null,\n  token: real-secret\n}]",
        "items: [{name: first},{\n  password: null,\n  token: real-secret\n}]",
    ],
)
def test_yaml_structural_adjacent_brace_flow_literal_is_denied_without_echo(tmp_path: Path, content: str) -> None:
    literal = "real-secret"
    assert literal in json.dumps(yaml.safe_load(content))
    (tmp_path / "config.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "config.yaml"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    ("field", "prose"),
    [
        ("description", "Password: must be at least 12 characters"),
        ("title", "Password: Account credential"),
        ("pattern", "^token:[A-F0-9]{32}$"),
    ],
)
def test_json_schema_bounded_credential_prose_remains_readable(tmp_path: Path, field: str, prose: str) -> None:
    content = json.dumps({"properties": {"password": {"type": "string", field: prose}}})
    (tmp_path / "schema.json").write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "schema.json"})


@pytest.mark.parametrize("field", ["description", "title", "pattern"])
@pytest.mark.parametrize(
    "clause",
    [
        "password: placeholder-password, token: correct horse battery staple",
        "password=placeholder-password; token=correct horse battery staple",
    ],
)
def test_json_schema_multiple_credential_clauses_are_all_denied_without_echo(
    tmp_path: Path, field: str, clause: str
) -> None:
    literal = "correct horse battery staple"
    content = json.dumps({"properties": {"password": {"type": "string", field: clause}}})
    (tmp_path / "schema.json").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": "schema.json"})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    ("filename", "reference"),
    [
        ("configuration.c", 'getenv("PASSWORD")'),
        ("configuration.cc", 'getenv("PASSWORD")'),
        ("configuration.cc", 'std::getenv("PASSWORD")'),
        ("configuration.cpp", 'getenv("PASSWORD")'),
        ("configuration.cpp", 'std::getenv("PASSWORD")'),
        ("configuration.h", 'getenv("PASSWORD")'),
        ("configuration.h", 'std::getenv("PASSWORD")'),
        ("configuration.hpp", 'getenv("PASSWORD")'),
        ("configuration.hpp", 'std::getenv("PASSWORD")'),
        ("Configuration.swift", 'ProcessInfo.processInfo.environment["PASSWORD"]!'),
    ],
)
def test_final_native_source_reference_forms_remain_readable(tmp_path: Path, filename: str, reference: str) -> None:
    content = f"password = {reference}"
    (tmp_path / filename).write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    ("filename", "reference", "operator"),
    [
        ("configuration.c", 'getenv("PASSWORD")', "+"),
        ("configuration.cpp", 'getenv("PASSWORD")', "+"),
        ("configuration.hpp", 'std::getenv("PASSWORD")', "+"),
        ("Configuration.swift", 'ProcessInfo.processInfo.environment["PASSWORD"]!', "??"),
    ],
)
def test_final_native_source_reference_with_appended_literal_is_denied_without_echo(
    tmp_path: Path, filename: str, reference: str, operator: str
) -> None:
    literal = "correct horse battery staple"
    content = f'password = {reference} {operator} "{literal}"'
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment") as exc_info:
        _read_file(_ctx(tmp_path), {"file_path": filename})

    message = str(exc_info.value)
    assert literal not in message
    assert content not in message


@pytest.mark.parametrize(
    "filename",
    ["config.json", "config.toml", "config.sh", "config.data", "config"],
)
def test_bare_source_reference_forms_are_not_exempt_in_non_source_files(tmp_path: Path, filename: str) -> None:
    content = "password = DEFAULT_PASSWORD"
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="credential_assignment"):
        _read_file(_ctx(tmp_path), {"file_path": filename})


@pytest.mark.parametrize(
    "content",
    [
        'api_key = os.environ["OPENAI_API_KEY"]',
        'password = os.getenv("PASSWORD")',
        'token = request.headers.get("Authorization")',
        "password = settings.database_password",
        "secret = SecretStr(config.api_key)",
        'client_secret = config["client_secret"]',
    ],
)
def test_credential_source_expressions_remain_readable(tmp_path: Path, content: str) -> None:
    path = tmp_path / "configuration.py"
    path.write_text(content, encoding="utf-8")

    assert content in _read_file(_ctx(tmp_path), {"file_path": "configuration.py"})


def test_grep_is_literal_and_never_returns_matching_content(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("literal a.* marker", encoding="utf-8")
    (tmp_path / "b.py").write_text("literal abc marker", encoding="utf-8")

    result = _json(
        _grep_files(
            _ctx(tmp_path),
            {"pattern": "a.*", "glob": "*.py", "output_mode": "files_with_matches"},
        )
    )

    assert result["files"] == ["a.py"]
    assert "literal" not in json.dumps(result)
    assert set(result) == {
        "files",
        "truncated",
        "scanned_files",
        "scanned_bytes",
        "visited_entries",
    }


def test_grep_count_mode_counts_files_not_occurrences(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("needle needle", encoding="utf-8")
    (tmp_path / "b.py").write_text("needle", encoding="utf-8")

    result = _json(
        _grep_files(
            _ctx(tmp_path),
            {"pattern": "needle", "output_mode": "count"},
        )
    )

    assert result["count"] == 2
    assert "files" not in result


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"pattern": ""},
        {"pattern": 4},
        {"pattern": "x" * (_MAX_PATTERN_CHARS + 1)},
        {"pattern": "x", "glob": "../*.py"},
        {"pattern": "x", "glob": "/tmp/*.py"},
        {"pattern": "x", "glob": "x" * (_MAX_PATTERN_CHARS + 1)},
        {"pattern": "x", "output_mode": "content"},
        {"pattern": "x", "extra": True},
    ],
)
def test_grep_runtime_validation_rejects_malformed_arguments(tmp_path: Path, arguments: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _grep_files(_ctx(tmp_path), arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"pattern": ""},
        {"pattern": 4},
        {"pattern": "../*.py"},
        {"pattern": "/tmp/*.py"},
        {"pattern": "x" * (_MAX_PATTERN_CHARS + 1)},
        {"pattern": "*.py", "extra": True},
    ],
)
def test_glob_runtime_validation_rejects_malformed_arguments(tmp_path: Path, arguments: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _glob_files(_ctx(tmp_path), arguments)


def test_glob_returns_canonical_accounted_json_and_safe_files_only(tmp_path: Path) -> None:
    (tmp_path / "z.py").write_text("z", encoding="utf-8")
    (tmp_path / "a.py").write_text("a", encoding="utf-8")
    (tmp_path / "note.txt").write_text("note", encoding="utf-8")

    raw = _glob_files(_ctx(tmp_path), {"pattern": "*.py"})
    result = _json(raw)

    assert raw == json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    assert result["files"] == ["a.py", "z.py"]
    assert result["truncated"] is False
    assert result["scanned_files"] == 2
    assert result["scanned_bytes"] == 2
    assert result["visited_entries"] == 3


def test_secret_content_is_absent_from_glob_and_grep(tmp_path: Path) -> None:
    secret = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    (tmp_path / "secret.py").write_text(secret, encoding="utf-8")
    (tmp_path / "safe.py").write_text("needle", encoding="utf-8")

    globbed = _json(_glob_files(_ctx(tmp_path), {"pattern": "*.py"}))
    grepped = _json(
        _grep_files(
            _ctx(tmp_path),
            {"pattern": "needle", "output_mode": "files_with_matches"},
        )
    )

    assert globbed["files"] == ["safe.py"]
    assert grepped["files"] == ["safe.py"]
    assert secret not in json.dumps([globbed, grepped])


def test_file_result_cap_is_stable_sorted_and_truncated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools_module, "_MAX_FILE_RESULTS", 2)
    for name in ["z.py", "b.py", "a.py"]:
        (tmp_path / name).write_text("safe", encoding="utf-8")

    result = _json(_glob_files(_ctx(tmp_path), {"pattern": "*.py"}))

    assert result["files"] == ["a.py", "b.py"]
    assert result["truncated"] is True


def test_scanned_file_cap_stops_before_reading_more(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools_module, "_MAX_SCANNED_FILES", 1)
    (tmp_path / "a.py").write_text("safe", encoding="utf-8")
    (tmp_path / "b.py").write_text("safe", encoding="utf-8")

    result = _json(_glob_files(_ctx(tmp_path), {"pattern": "*.py"}))

    assert result["files"] == ["a.py"]
    assert result["scanned_files"] == 1
    assert result["truncated"] is True


def test_cumulative_actual_byte_cap_stops_before_next_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools_module, "_MAX_TOTAL_SCANNED_BYTES", 5)
    (tmp_path / "a.py").write_text("1234", encoding="utf-8")
    (tmp_path / "b.py").write_text("5678", encoding="utf-8")

    result = _json(_glob_files(_ctx(tmp_path), {"pattern": "*.py"}))

    assert result["files"] == ["a.py"]
    assert result["scanned_bytes"] == 4
    assert result["truncated"] is True


def test_visited_entry_cap_counts_denied_and_nonregular_before_filtering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tools_module, "_MAX_WALK_ENTRIES", 2)
    (tmp_path / ".env").write_text("denied", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text("denied", encoding="utf-8")
    (tmp_path / "directory").mkdir()

    result = _json(_glob_files(_ctx(tmp_path), {"pattern": "*"}))

    assert result["files"] == []
    assert result["visited_entries"] == 2
    assert result["truncated"] is True


def test_directory_enumeration_never_reads_beyond_remaining_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tools_module, "_MAX_WALK_ENTRIES", 2)
    context = _ctx(tmp_path)
    directory_fd = os.dup(context.root_fd)
    pulls = 0

    class _FakeEntry:
        def __init__(self, name: str) -> None:
            self.name = name

        def is_symlink(self) -> bool:
            return False

        def is_dir(self, *, follow_symlinks: bool = True) -> bool:
            return False

        def is_file(self, *, follow_symlinks: bool = True) -> bool:
            return True

    class _FakeScandir:
        def __init__(self) -> None:
            self._names = iter(["z.py", "a.py", "y.py", "b.py", "x.py"])

        def __enter__(self) -> _FakeScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> _FakeScandir:
            return self

        def __next__(self) -> _FakeEntry:
            nonlocal pulls
            pulls += 1
            return _FakeEntry(next(self._names))

    monkeypatch.setattr(tools_module.os, "scandir", lambda _path: _FakeScandir())
    accounting = _Accounting()
    try:
        entries = _directory_entries(directory_fd, accounting)
    finally:
        os.close(directory_fd)
        _close_context(context)

    assert [entry.name for entry in entries] == ["a.py", "z.py"]
    assert pulls == 2
    assert accounting.visited_entries == 2
    assert accounting.truncated is True


def test_recursive_walk_charges_each_scandir_pull_once_globally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tools_module, "_MAX_WALK_ENTRIES", 3)
    for directory_name in ("a", "b"):
        directory = tmp_path / directory_name
        directory.mkdir()
        (directory / "one.txt").write_text("safe", encoding="utf-8")
        (directory / "two.txt").write_text("safe", encoding="utf-8")
    real_scandir = tools_module.os.scandir
    context = _ctx(tmp_path)
    pulls = 0

    class _CountingScandir:
        def __init__(self, source: int | Path) -> None:
            self._inner = real_scandir(source)

        def __enter__(self) -> _CountingScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            self._inner.close()

        def __iter__(self) -> _CountingScandir:
            return self

        def __next__(self) -> os.DirEntry[str]:
            nonlocal pulls
            entry = next(self._inner)
            pulls += 1
            return entry

    monkeypatch.setattr(tools_module.os, "scandir", lambda source: _CountingScandir(source))
    try:
        result = _json(_glob_files(context, {"pattern": "*"}))
    finally:
        _close_context(context)

    assert pulls == 3
    assert result["visited_entries"] == 3
    assert result["truncated"] is True


def test_ancestor_swap_to_outside_symlink_never_reads_outside_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    ancestor = root / "ancestor"
    ancestor.mkdir(parents=True)
    (ancestor / "target.txt").write_text("inside bytes", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_content = "outside bytes were read"
    (outside / "target.txt").write_text(outside_content, encoding="utf-8")
    parked = root / "parked"
    context = _ctx(root)
    real_open = tools_module.os.open
    swapped = False

    def _swap_then_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        raw = str(path)
        if not swapped and (raw == "ancestor" or raw.endswith("/ancestor/target.txt")):
            swapped = True
            ancestor.rename(parked)
            ancestor.symlink_to(outside, target_is_directory=True)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(tools_module.os, "open", _swap_then_open)

    try:
        with pytest.raises(ValueError) as exc_info:
            _read_file(context, {"file_path": "ancestor/target.txt"})
    finally:
        _close_context(context)

    assert outside_content not in str(exc_info.value)


def test_walk_depth_cap_is_bounded_and_marks_truncated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools_module, "_MAX_WALK_DEPTH", 1)
    deep = tmp_path / "one" / "two"
    deep.mkdir(parents=True)
    (deep / "deep.py").write_text("safe", encoding="utf-8")

    result = _json(_glob_files(_ctx(tmp_path), {"pattern": "*"}))

    assert result["files"] == []
    assert result["truncated"] is True


def test_result_character_cap_stops_before_oversized_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools_module, "_MAX_RESULT_CHARS", 150)
    for index in range(10):
        (tmp_path / f"long-name-{index:02d}.py").write_text("safe", encoding="utf-8")

    raw = _glob_files(_ctx(tmp_path), {"pattern": "*.py"})
    result = _json(raw)

    assert len(raw) <= 150
    assert result["truncated"] is True
    files = result["files"]
    assert isinstance(files, list)
    assert files == sorted(files)


def test_server_requires_handshake_and_advertises_exact_sealed_surface(tmp_path: Path) -> None:
    server = create_server(CodexToolScope(root=tmp_path.resolve()))
    before = server.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert before is not None and "error" in before

    _handshake(server)
    listing = server.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert listing is not None
    result = listing["result"]
    assert result is not None
    advertised = result["tools"]
    assert [tool["name"] for tool in advertised] == [
        "read_file",
        "grep_files",
        "glob_files",
    ]
    assert server.capabilities == {"tools": {"listChanged": False}}
    for tool in advertised:
        assert tool["inputSchema"]["additionalProperties"] is False
        assert tool["annotations"] == {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    read_schema = advertised[0]["inputSchema"]
    assert read_schema["properties"]["file_path"]["maxLength"] == _MAX_PATH_CHARS
    assert read_schema["properties"]["line_count"]["maximum"] == _MAX_READ_LINES
    assert advertised[1]["inputSchema"]["properties"]["pattern"]["maxLength"] == _MAX_PATTERN_CHARS
    assert advertised[2]["inputSchema"]["properties"]["pattern"]["maxLength"] == _MAX_PATTERN_CHARS


def test_server_success_and_failure_results_are_one_text_block_and_budgeted(
    tmp_path: Path,
) -> None:
    (tmp_path / "safe.py").write_text("safe", encoding="utf-8")
    server = create_server(CodexToolScope(root=tmp_path.resolve(), max_calls=1))
    _handshake(server)

    first = _tool_call(server, "glob_files", {"pattern": "*.py"}, request_id=1)
    second = _tool_call(server, "glob_files", {"pattern": "*.py"}, request_id=2)

    first_result = first["result"]
    second_result = second["result"]
    assert first_result == {"content": [{"type": "text", "text": first_result["content"][0]["text"]}]}
    assert second_result["isError"] is True
    assert len(second_result["content"]) == 1
    assert second_result["content"][0]["type"] == "text"
    assert "budget" in second_result["content"][0]["text"]


def test_stdio_server_closes_its_retained_root_context(tmp_path: Path) -> None:
    server = create_server(CodexToolScope(root=tmp_path.resolve()))
    context = server._context
    root_fd = context.root_fd

    server.run_stdio(stdin=io.StringIO(""), stdout=io.StringIO())

    with pytest.raises(OSError):
        os.fstat(root_fd)


def test_server_unknown_and_malformed_calls_are_iserror_and_consume_budget(tmp_path: Path) -> None:
    server = create_server(CodexToolScope(root=tmp_path.resolve(), max_calls=2))
    _handshake(server)

    unknown = _tool_call(server, "unknown", {}, request_id=1)
    malformed = _tool_call(server, "read_file", [], request_id=2)
    exhausted = _tool_call(server, "glob_files", {"pattern": "*"}, request_id=3)

    for response in (unknown, malformed, exhausted):
        result = response["result"]
        assert result["isError"] is True
        assert len(result["content"]) == 1
    assert "unknown tool" in unknown["result"]["content"][0]["text"]
    assert "arguments" in malformed["result"]["content"][0]["text"]
    assert "budget" in exhausted["result"]["content"][0]["text"]


def test_server_runtime_validation_does_not_depend_on_jsonschema(tmp_path: Path) -> None:
    server = create_server(CodexToolScope(root=tmp_path.resolve()))
    _handshake(server)

    response = _tool_call(
        server,
        "read_file",
        {"file_path": "safe.py", "line_count": "400"},
    )

    assert response["result"]["isError"] is True
    assert "arguments" in response["result"]["content"][0]["text"]


def test_sensitive_environment_check_names_keys_not_values() -> None:
    secret = "super-secret-value"

    with pytest.raises(RuntimeError) as exc_info:
        _assert_keyless_environment(
            {
                "OPENAI_API_KEY": secret,
                "WARDLINE_OPENROUTER_API_KEY": secret,
                "SAFE": secret,
            }
        )

    message = str(exc_info.value)
    assert "OPENAI_API_KEY" in message
    assert "WARDLINE_OPENROUTER_API_KEY" in message
    assert "SAFE" not in message
    assert secret not in message


def test_sensitive_environment_vocabulary_is_exact() -> None:
    expected = frozenset(
        {
            "WARDLINE_OPENROUTER_API_KEY",
            "OPENROUTER_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "WEFT_FEDERATION_TOKEN",
            "LEGIS_ARTIFACT_KEY",
        }
    )
    assert expected == _SENSITIVE_ENVIRONMENT_NAMES


@pytest.mark.parametrize("name", sorted(_SENSITIVE_ENVIRONMENT_NAMES))
def test_every_sensitive_environment_key_is_rejected_even_when_empty(name: str) -> None:
    with pytest.raises(RuntimeError, match=name):
        _assert_keyless_environment({name: ""})


def test_main_refuses_sensitive_environment_before_server_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-never-cross")
    monkeypatch.setattr(
        tools_module,
        "create_server",
        lambda _scope: (_ for _ in ()).throw(AssertionError("server must not start")),
    )

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        main(["--root", str(tmp_path), "--max-calls", "2"])


def test_main_validates_root_and_enters_stdio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    captured: list[CodexToolScope] = []

    class _FakeServer:
        def __init__(self, scope: CodexToolScope) -> None:
            self.scope = scope

        def run_stdio(self) -> None:
            captured.append(self.scope)

    def _create(candidate: CodexToolScope) -> _FakeServer:
        return _FakeServer(candidate)

    monkeypatch.setattr(tools_module, "create_server", _create)

    assert main(["--root", str(tmp_path), "--max-calls", "7"]) == 0
    assert captured == [CodexToolScope(root=tmp_path.resolve(), max_calls=7)]


def test_main_rejects_missing_root_or_nonpositive_budget(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--root", str(tmp_path / "missing"), "--max-calls", "1"])
    with pytest.raises(SystemExit):
        main(["--root", str(tmp_path), "--max-calls", "0"])


def test_module_help_exits_without_starting_stdio() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wardline.mcp.codex_judge_tools", "--help"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--root" in result.stdout
    assert "--max-calls" in result.stdout
