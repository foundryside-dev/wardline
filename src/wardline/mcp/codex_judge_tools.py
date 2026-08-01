"""Sealed, read-only repository tools for the Codex judge transport.

The server deliberately exposes a much smaller surface than Wardline's normal
MCP server.  It accepts only repository-relative paths, never follows symlinks,
filters instruction and credential files, and returns bounded text-only results.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, NoReturn, TextIO, TypeGuard

from wardline._version import __version__
from wardline.core.judge_types import CodexToolScope
from wardline.mcp.protocol import JsonRpcServer

_MAX_READ_LINES = 400
_MAX_RESULT_CHARS = 50_000
_MAX_FILE_RESULTS = 500
_MAX_SCANNED_FILES = 20_000
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_SCANNED_BYTES = 64 * 1024 * 1024
_MAX_WALK_ENTRIES = 50_000
_MAX_WALK_DEPTH = 32
_MAX_PATH_CHARS = 4096
_MAX_PATTERN_CHARS = 512
_ROOT_RELATIVE = PurePosixPath(".")

_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

_DENIED_FILE_NAMES = frozenset(
    {
        ".cursorrules",
        "agents.md",
        "agents.override.md",
        "claude.md",
        "gemini.md",
        "copilot-instructions.md",
    }
)
_DENIED_DIRECTORY_NAMES = frozenset({".agents", ".claude", ".codex", ".cursor", ".git"})
_SENSITIVE_ENVIRONMENT_NAMES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "LEGIS_ARTIFACT_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "WARDLINE_OPENROUTER_API_KEY",
        "WEFT_FEDERATION_TOKEN",
    }
)

_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_AUTHORIZATION_BEARER_RE = re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._~+/=-]{20,})")
_PROVIDER_TOKEN_RE = re.compile(
    r"\b((?:(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}"
    r"|AKIA[A-Z0-9]{16}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AIza[A-Za-z0-9_-]{20,}))\b"
)
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?imx)(?<![A-Za-z0-9_])[\"']?"
    r"(?:[A-Za-z0-9]+[._-])*"
    r"(?:secret[._-]access[._-]key|api[._-]?key|client[._-]?secret|password|passwd|secret|token)"
    r"(?:[._-][A-Za-z0-9]+)*[\"']?(?![A-Za-z0-9_])"
    r"\s*[:=]\s*(?:"
    r"\"(?P<double>[^\"\r\n]{8,})\""
    r"|'(?P<single>[^'\r\n]{8,})'"
    r"|(?:secretstr|secretbytes|secretvalue|secret)\(\s*"
    r"(?:\"(?P<wrapped_double>[^\"\r\n]{8,})\"|'(?P<wrapped_single>[^'\r\n]{8,})')\s*\)"
    r"|(?P<bare>[A-Za-z0-9][A-Za-z0-9._~+/=-]{7,})(?![A-Za-z0-9._~+/=(\[]))"
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:<?your(?:[-_][a-z0-9]+)*(?:_here)?>?"
    r"|(?:placeholder|example|dummy|redacted|fake|test|changeme)(?:$|[-_].*)"
    r"|(?:sk|pk|rk)-(?:placeholder|example|dummy|redacted|fake|test|changeme)(?:$|[-_].*)"
    r"|ghp_(?:placeholder|example|dummy|redacted|fake|test|changeme)(?:$|[_-].*)"
    r"|github_pat_(?:placeholder|example|dummy|redacted|fake|test|changeme)(?:$|[_-].*)"
    r"|AIza(?:Placeholder|Example|Dummy|Redacted|Fake|Test|Changeme)[A-Za-z0-9_-]*"
    r"|AKIA(?:PLACEHOLDER|EXAMPLE|DUMMY|REDACTED|FAKE|TEST|CHANGEME)[A-Z0-9]*)$"
)
_SOURCE_REFERENCE_RE = re.compile(
    r"(?i)^(?:(?:os\.)?environ(?:\[|\.get\()|(?:os\.)?getenv\("
    r"|request(?:\.|\[)|settings(?:\.|\[)|config(?:\.|\[))"
)


class _BudgetStop(Exception):
    """Internal signal that a repository traversal reached a hard limit."""


@dataclass(slots=True)
class _Accounting:
    scanned_files: int = 0
    scanned_bytes: int = 0
    visited_entries: int = 0
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _WalkEntry:
    name: str
    is_symlink: bool
    is_directory: bool
    is_file: bool


@dataclass(slots=True)
class _Context:
    scope: CodexToolScope
    calls: int = 0
    _root_fd: int = field(init=False, default=-1, repr=False)

    def __post_init__(self) -> None:
        _require_secure_open_capabilities()
        self._root_fd = _pin_repository_root(self.scope.root)

    @property
    def root_fd(self) -> int:
        if self._root_fd < 0:
            raise ValueError("repository context is closed")
        return self._root_fd

    def duplicate_root_fd(self) -> int:
        try:
            return os.dup(self.root_fd)
        except OSError:
            _fail("repository context is closed")

    def close(self) -> None:
        descriptor = self._root_fd
        self._root_fd = -1
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)

    def __enter__(self) -> _Context:
        _ = self.root_fd
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def consume_call(self) -> None:
        self.calls += 1
        if self.calls > self.scope.max_calls:
            raise ValueError("tool call budget exhausted")


def _require_secure_open_capabilities() -> None:
    available = (
        os.open in os.supports_dir_fd
        and os.scandir in os.supports_fd
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NONBLOCK")
    )
    if not available:
        raise RuntimeError("secure repository access unavailable on this platform")


def _directory_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW | os.O_DIRECTORY


def _pin_repository_root(root: Path) -> int:
    descriptor = -1
    try:
        descriptor = os.open(os.sep, _directory_flags())
        for component in root.parts[1:]:
            next_descriptor = os.open(component, _directory_flags(), dir_fd=descriptor)
            previous_descriptor = descriptor
            descriptor = next_descriptor
            os.close(previous_descriptor)
        return descriptor
    except OSError as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise RuntimeError("secure repository root unavailable") from exc


class _CodexJudgeServer(JsonRpcServer):
    def __init__(self, context: _Context) -> None:
        self._context = context
        super().__init__(
            server_name="wardline-codex-judge-tools",
            server_version=__version__,
            require_handshake=True,
        )

    def close(self) -> None:
        self._context.close()

    def run_stdio(self, *, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        try:
            super().run_stdio(stdin=stdin, stdout=stdout)
        finally:
            self.close()

    def __del__(self) -> None:
        self.close()


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _is_plain_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_object(arguments: object, *, allowed: set[str]) -> dict[str, object]:
    if not isinstance(arguments, dict):
        _fail("invalid tool arguments")
    if not all(isinstance(key, str) for key in arguments):
        _fail("invalid tool arguments")
    typed = arguments
    if not set(typed).issubset(allowed):
        _fail("invalid tool arguments")
    return typed


def _validate_relative(value: object, *, limit: int, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
        _fail(f"invalid {label}")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or ".." in posix.parts or ".." in windows.parts:
        _fail(f"invalid {label}")
    return value


def _is_denied_relative(relative: PurePosixPath) -> bool:
    parts = tuple(part.casefold() for part in relative.parts if part not in ("", "."))
    if not parts:
        return False
    if any(part in _DENIED_DIRECTORY_NAMES for part in parts):
        return True
    name = parts[-1]
    if name == ".env" or name.startswith(".env.") or name in _DENIED_FILE_NAMES:
        return True
    if len(parts) >= 3 and parts[-3:-1] == (".github", "instructions"):
        return name.endswith(".instructions.md")
    return False


def _relative_to_root(context: _Context, path: Path) -> PurePosixPath:
    try:
        relative = path.relative_to(context.scope.root)
    except ValueError:
        _fail("path escapes repository root")
    return PurePosixPath(relative.as_posix())


def _resolve_file(context: _Context, raw_path: object) -> Path:
    value = _validate_relative(raw_path, limit=_MAX_PATH_CHARS, label="file path")
    relative = PurePosixPath(value)
    if not relative.parts or relative == PurePosixPath("."):
        _fail("file path must identify a regular file")
    if _is_denied_relative(relative):
        _fail("file path denied")
    return context.scope.root.joinpath(*relative.parts)


def _placeholder(value: str) -> bool:
    return _PLACEHOLDER_RE.fullmatch(value.strip()) is not None


def _source_reference(value: str) -> bool:
    return _SOURCE_REFERENCE_RE.match(value.strip()) is not None


def _secret_pattern(text: str) -> str | None:
    if _PEM_PRIVATE_KEY_RE.search(text):
        return "pem_private_key"
    bearer = _AUTHORIZATION_BEARER_RE.search(text)
    if bearer is not None and not _placeholder(bearer.group(1)):
        return "authorization_bearer"
    provider = _PROVIDER_TOKEN_RE.search(text)
    if provider is not None and not _placeholder(provider.group(1)):
        return "provider_token"
    for credential in _CREDENTIAL_ASSIGNMENT_RE.finditer(text):
        quoted = (
            credential.group("double")
            or credential.group("single")
            or credential.group("wrapped_double")
            or credential.group("wrapped_single")
        )
        value = quoted or credential.group("bare")
        if value is None or _placeholder(value):
            continue
        if quoted is None and _source_reference(value):
            continue
        return "credential_assignment"
    return None


def _open_anchored_file(context: _Context, path: Path) -> int:
    """Open ``path`` component-by-component beneath a held repository root."""
    relative = _relative_to_root(context, path)
    parts = relative.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        _fail("file path must identify a regular file")
    if _is_denied_relative(relative):
        _fail("file path denied")

    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_fd = context.duplicate_root_fd()
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, _directory_flags(), dir_fd=directory_fd)
            previous_fd = directory_fd
            directory_fd = next_fd
            os.close(previous_fd)
        return os.open(parts[-1], file_flags, dir_fd=directory_fd)
    except ValueError:
        raise
    except OSError:
        _fail("file is unavailable")
    finally:
        if directory_fd >= 0:
            with suppress(OSError):
                os.close(directory_fd)


def _open_anchored_directory(context: _Context, relative: PurePosixPath) -> int:
    descriptor = context.duplicate_root_fd()
    try:
        for component in relative.parts:
            if component in ("", "."):
                continue
            if component == "..":
                _fail("path escapes repository root")
            next_descriptor = os.open(component, _directory_flags(), dir_fd=descriptor)
            previous_descriptor = descriptor
            descriptor = next_descriptor
            os.close(previous_descriptor)
    except ValueError:
        with suppress(OSError):
            os.close(descriptor)
        raise
    except OSError:
        with suppress(OSError):
            os.close(descriptor)
        _fail("directory is unavailable")
    return descriptor


def _safe_text(
    context: _Context,
    path: Path,
    accounting: _Accounting | None = None,
) -> str:
    """Read one regular, in-root file with race-aware size and content checks."""
    if accounting is not None:
        if accounting.scanned_files >= _MAX_SCANNED_FILES:
            accounting.truncated = True
            raise _BudgetStop
        remaining = _MAX_TOTAL_SCANNED_BYTES - accounting.scanned_bytes
        if remaining <= 0:
            accounting.truncated = True
            raise _BudgetStop
    else:
        remaining = _MAX_FILE_BYTES

    descriptor = _open_anchored_file(context, path)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            _fail("file path must identify a regular file")
        if opened.st_size > _MAX_FILE_BYTES:
            _fail("file exceeds size limit")
        if accounting is not None and opened.st_size > remaining:
            accounting.truncated = True
            raise _BudgetStop

        read_limit = min(_MAX_FILE_BYTES, remaining) + 1
        chunks: list[bytes] = []
        received = 0
        while received < read_limit:
            chunk = os.read(descriptor, min(64 * 1024, read_limit - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(descriptor)

    if accounting is not None:
        accounting.scanned_files += 1
        accounting.scanned_bytes += len(data)
        if len(data) > remaining:
            accounting.truncated = True
            raise _BudgetStop
    if len(data) > _MAX_FILE_BYTES:
        _fail("file exceeds size limit")
    if b"\x00" in data:
        _fail("file is not safe UTF-8 text")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _fail("file is not safe UTF-8 text")
    pattern = _secret_pattern(text)
    if pattern is not None:
        _fail(f"file content denied by secret pattern: {pattern}")
    return text


def _read_file(context: _Context, arguments: object) -> str:
    values = _require_object(arguments, allowed={"file_path", "start_line", "line_count"})
    if "file_path" not in values:
        _fail("invalid tool arguments")
    start_line = values.get("start_line", 1)
    line_count = values.get("line_count", _MAX_READ_LINES)
    if not _is_plain_int(start_line) or start_line < 1:
        _fail("invalid tool arguments")
    if not _is_plain_int(line_count) or not 1 <= line_count <= _MAX_READ_LINES:
        _fail("invalid tool arguments")
    path = _resolve_file(context, values["file_path"])
    text = _safe_text(context, path)
    lines = text.splitlines()
    first = start_line - 1
    selected = lines[first : first + line_count]
    rendered = "\n".join(f"{first + offset + 1}: {line}" for offset, line in enumerate(selected))
    return rendered[:_MAX_RESULT_CHARS]


def _validate_pattern(value: object, *, label: str) -> str:
    return _validate_relative(value, limit=_MAX_PATTERN_CHARS, label=label)


def _directory_entries(directory_fd: int, accounting: _Accounting) -> list[_WalkEntry]:
    remaining = _MAX_WALK_ENTRIES - accounting.visited_entries
    if remaining <= 0:
        accounting.truncated = True
        raise _BudgetStop
    entries: list[_WalkEntry] = []
    try:
        with os.scandir(directory_fd) as iterator:
            for _index in range(remaining):
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                accounting.visited_entries += 1
                try:
                    entries.append(
                        _WalkEntry(
                            name=entry.name,
                            is_symlink=entry.is_symlink(),
                            is_directory=entry.is_dir(follow_symlinks=False),
                            is_file=entry.is_file(follow_symlinks=False),
                        )
                    )
                except OSError:
                    entries.append(
                        _WalkEntry(
                            name=entry.name,
                            is_symlink=False,
                            is_directory=False,
                            is_file=False,
                        )
                    )
            if len(entries) == remaining:
                accounting.truncated = True
    except OSError:
        return []
    return sorted(entries, key=lambda item: item.name)


def _walk_files(
    context: _Context,
    accounting: _Accounting,
    directory: PurePosixPath | None = None,
    depth: int = 0,
) -> Sequence[tuple[PurePosixPath, Path]]:
    if directory is None:
        directory = _ROOT_RELATIVE
    found: list[tuple[PurePosixPath, Path]] = []
    try:
        directory_fd = _open_anchored_directory(context, directory)
    except ValueError:
        if directory == _ROOT_RELATIVE:
            raise
        return found
    try:
        entries = _directory_entries(directory_fd, accounting)
    except _BudgetStop:
        return found
    finally:
        os.close(directory_fd)
    for entry in entries:
        relative = PurePosixPath(entry.name) if directory == _ROOT_RELATIVE else directory / entry.name
        if _is_denied_relative(relative):
            continue
        if entry.is_symlink:
            continue
        if entry.is_directory:
            if depth >= _MAX_WALK_DEPTH:
                accounting.truncated = True
            else:
                found.extend(_walk_files(context, accounting, relative, depth + 1))
            if accounting.visited_entries >= _MAX_WALK_ENTRIES:
                break
        elif entry.is_file:
            path = context.scope.root.joinpath(*relative.parts)
            found.append((relative, path))
    return found


def _canonical_result(payload: dict[str, object]) -> str:
    rendered = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    files = payload.get("files")
    if not isinstance(files, list):
        return rendered[:_MAX_RESULT_CHARS]
    while len(rendered) > _MAX_RESULT_CHARS and files:
        files.pop()
        payload["truncated"] = True
        rendered = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(rendered) > _MAX_RESULT_CHARS:
        _fail("result metadata exceeds character limit")
    return rendered


def _result_payload(accounting: _Accounting, files: list[str]) -> dict[str, object]:
    return {
        "files": files,
        "truncated": accounting.truncated,
        "scanned_files": accounting.scanned_files,
        "scanned_bytes": accounting.scanned_bytes,
        "visited_entries": accounting.visited_entries,
    }


def _glob_files(context: _Context, arguments: object) -> str:
    values = _require_object(arguments, allowed={"pattern"})
    if "pattern" not in values:
        _fail("invalid tool arguments")
    pattern = _validate_pattern(values["pattern"], label="glob pattern")
    accounting = _Accounting()
    matches: list[str] = []
    for relative, path in _walk_files(context, accounting):
        relative_text = relative.as_posix()
        if not fnmatch.fnmatchcase(relative_text, pattern):
            continue
        try:
            _safe_text(context, path, accounting)
        except _BudgetStop:
            break
        except ValueError:
            continue
        if len(matches) >= _MAX_FILE_RESULTS:
            accounting.truncated = True
            break
        matches.append(relative_text)
    matches.sort()
    return _canonical_result(_result_payload(accounting, matches))


def _grep_files(context: _Context, arguments: object) -> str:
    values = _require_object(arguments, allowed={"pattern", "glob", "output_mode"})
    if "pattern" not in values:
        _fail("invalid tool arguments")
    pattern = values["pattern"]
    if not isinstance(pattern, str) or not pattern or len(pattern) > _MAX_PATTERN_CHARS or "\x00" in pattern:
        _fail("invalid grep pattern")
    glob_pattern = _validate_pattern(values.get("glob", "*"), label="glob pattern")
    output_mode = values.get("output_mode", "files_with_matches")
    if output_mode not in ("files_with_matches", "count"):
        _fail("invalid tool arguments")

    accounting = _Accounting()
    matches: list[str] = []
    count = 0
    for relative, path in _walk_files(context, accounting):
        relative_text = relative.as_posix()
        if not fnmatch.fnmatchcase(relative_text, glob_pattern):
            continue
        try:
            text = _safe_text(context, path, accounting)
        except _BudgetStop:
            break
        except ValueError:
            continue
        if pattern not in text:
            continue
        count += 1
        if output_mode == "files_with_matches":
            if len(matches) >= _MAX_FILE_RESULTS:
                accounting.truncated = True
                break
            matches.append(relative_text)

    if output_mode == "count":
        return _canonical_result(
            {
                "count": count,
                "truncated": accounting.truncated,
                "scanned_files": accounting.scanned_files,
                "scanned_bytes": accounting.scanned_bytes,
                "visited_entries": accounting.visited_entries,
            }
        )
    matches.sort()
    return _canonical_result(_result_payload(accounting, matches))


def _tool_definitions() -> list[dict[str, object]]:
    return [
        {
            "name": "read_file",
            "description": "Read a bounded range of lines from a safe repository text file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "minLength": 1, "maxLength": _MAX_PATH_CHARS},
                    "start_line": {"type": "integer", "minimum": 1},
                    "line_count": {"type": "integer", "minimum": 1, "maximum": _MAX_READ_LINES},
                },
                "required": ["file_path"],
                "additionalProperties": False,
            },
            "annotations": dict(_ANNOTATIONS),
        },
        {
            "name": "grep_files",
            "description": "Find safe repository files containing a literal string.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": _MAX_PATTERN_CHARS,
                    },
                    "glob": {"type": "string", "minLength": 1, "maxLength": _MAX_PATTERN_CHARS},
                    "output_mode": {
                        "type": "string",
                        "enum": ["files_with_matches", "count"],
                    },
                },
                "required": ["pattern"],
                "additionalProperties": False,
            },
            "annotations": dict(_ANNOTATIONS),
        },
        {
            "name": "glob_files",
            "description": "List safe repository text files matching a bounded glob.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": _MAX_PATTERN_CHARS,
                    }
                },
                "required": ["pattern"],
                "additionalProperties": False,
            },
            "annotations": dict(_ANNOTATIONS),
        },
    ]


def _text_result(text: str, *, error: bool = False) -> dict[str, object]:
    result: dict[str, object] = {"content": [{"type": "text", "text": text}]}
    if error:
        result["isError"] = True
    return result


def create_server(scope: CodexToolScope) -> JsonRpcServer:
    context = _Context(scope)
    server = _CodexJudgeServer(context)
    server.capabilities = {"tools": {"listChanged": False}}
    tools = _tool_definitions()

    def _list_tools(_params: dict[str, Any]) -> dict[str, object]:
        return {"tools": tools}

    def _call_tool(params: dict[str, Any]) -> dict[str, object]:
        try:
            context.consume_call()
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or name not in {"read_file", "grep_files", "glob_files"}:
                _fail("unknown tool")
            if not isinstance(arguments, dict):
                _fail("invalid tool arguments")
            if name == "read_file":
                value = _read_file(context, arguments)
            elif name == "grep_files":
                value = _grep_files(context, arguments)
            else:
                value = _glob_files(context, arguments)
            return _text_result(value)
        except ValueError as exc:
            return _text_result(str(exc), error=True)
        except Exception:  # noqa: BLE001 - never disclose host details through MCP errors
            return _text_result("tool failed safely", error=True)

    server.register("tools/list", _list_tools)
    server.register("tools/call", _call_tool)
    return server


def _assert_keyless_environment(source: Mapping[str, str] | None = None) -> None:
    environment = os.environ if source is None else source
    present = sorted(name for name in _SENSITIVE_ENVIRONMENT_NAMES if name in environment)
    if present:
        raise RuntimeError(f"sensitive environment keys are present: {', '.join(present)}")


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _repository_root(value: str) -> Path:
    try:
        root = Path(value).resolve(strict=True)
    except OSError as exc:
        raise argparse.ArgumentTypeError("root must be an existing directory") from exc
    if not root.is_dir():
        raise argparse.ArgumentTypeError("root must be an existing directory")
    return root


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=_repository_root)
    parser.add_argument("--max-calls", required=True, type=_positive_integer)
    parsed = parser.parse_args(argv)
    _assert_keyless_environment()
    scope = CodexToolScope(root=parsed.root, max_calls=parsed.max_calls)
    create_server(scope).run_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
