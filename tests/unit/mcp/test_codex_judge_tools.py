from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

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


@pytest.mark.parametrize(
    "content",
    [
        'api_key = os.environ["OPENAI_API_KEY"]',
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
