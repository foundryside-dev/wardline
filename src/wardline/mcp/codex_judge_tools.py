"""Sealed, read-only repository tools for the Codex judge transport.

The server deliberately exposes a much smaller surface than Wardline's normal
MCP server.  It accepts only repository-relative paths, never follows symlinks,
filters instruction and credential files, and returns bounded text-only results.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import io
import json
import os
import re
import stat
import tokenize
import tomllib
from collections.abc import Iterator, Mapping, Sequence
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
_MAX_SHEBANG_CHARS = 256
_ROOT_RELATIVE = PurePosixPath(".")
_SOURCE_REFERENCE_SUFFIXES = frozenset(
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
_DENIED_CREDENTIAL_FILE_NAMES = frozenset(
    {
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".yarnrc.yml",
        "gradle.properties",
        "nuget.config",
        "pip.conf",
        "settings.xml",
    }
)
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
_CREDENTIAL_LABEL_PATTERN = (
    r"(?<![A-Za-z0-9_])[\"']?"
    r"(?:[A-Za-z0-9]+[._-])*"
    r"(?:secret[._-]access[._-]key|api[._-]?key|client[._-]?secret|password|passwd|secret|token"
    r"|accessToken|authToken|databasePassword|refreshToken|secretAccessKey|apiKey|clientSecret)"
    r"[\"']?(?![A-Za-z0-9_])"
)
_CREDENTIAL_KEY_RE = re.compile(
    rf"(?imx)(?:^[ \t]*(?:-[ \t]+)?|(?P<flow>(?<!\$\{{)(?<=[{{,]))[ \t]*"
    rf"){_CREDENTIAL_LABEL_PATTERN}[ \t]*(?P<delimiter>[:=])"
)
_SEMICOLON_CREDENTIAL_KEY_RE = re.compile(rf"(?imx)(?<=;)[ \t]*{_CREDENTIAL_LABEL_PATTERN}[ \t]*(?P<delimiter>[:=])")
_RAW_CREDENTIAL_KEY_SUFFIXES = frozenset({".yaml", ".yml"})
_PYTHON_LEXICAL_SUFFIXES = frozenset({".py", ".pyi"})
_SEMICOLON_STATEMENT_SUFFIXES = frozenset({".py", ".pyi"})
_DECLARATION_PATTERNS = {
    ".bash": (r"export[ \t]+", r""),
    ".c": (r"(?:(?:static|extern|const)[ \t]+)*(?:char[ \t]*\*|char[ \t]+)[ \t]*", r""),
    ".cc": (
        r"(?:(?:static|extern|const|constexpr)[ \t]+)*(?:(?:std::)?string[ \t]+|char[ \t]*\*[ \t]*)",
        r"",
    ),
    ".cpp": (
        r"(?:(?:static|extern|const|constexpr)[ \t]+)*(?:(?:std::)?string[ \t]+|char[ \t]*\*[ \t]*)",
        r"",
    ),
    ".cs": (
        r"(?:(?:public|protected|private|internal|static|readonly|const)[ \t]+)*"
        r"(?:string\??|char\[\]|byte\[\])[ \t]+",
        r"",
    ),
    ".go": (r"(?:const|var)[ \t]+", r"(?:[ \t]+[A-Za-z_][A-Za-z0-9_.\[\]*]*)?"),
    ".h": (
        r"(?:(?:static|extern|const|constexpr)[ \t]+)*(?:(?:std::)?string[ \t]+|char[ \t]*\*[ \t]*)",
        r"",
    ),
    ".hpp": (
        r"(?:(?:static|extern|const|constexpr)[ \t]+)*(?:(?:std::)?string[ \t]+|char[ \t]*\*[ \t]*)",
        r"",
    ),
    ".java": (
        r"(?:(?:public|protected|private|static|final|volatile|transient)[ \t]+)*"
        r"(?:String|var|char\[\]|byte\[\])[ \t]+",
        r"",
    ),
    ".js": (r"(?:export[ \t]+)?(?:const|let|var)[ \t]+", r"(?:[ \t]*:[ \t]*string)?"),
    ".jsx": (r"(?:export[ \t]+)?(?:const|let|var)[ \t]+", r"(?:[ \t]*:[ \t]*string)?"),
    ".kt": (
        r"(?:(?:public|protected|private|internal|lateinit|const)[ \t]+)*(?:val|var)[ \t]+",
        r"(?:[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_.<>?, \t]{0,128})?",
    ),
    ".kts": (
        r"(?:(?:public|protected|private|internal|lateinit|const)[ \t]+)*(?:val|var)[ \t]+",
        r"(?:[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_.<>?, \t]{0,128})?",
    ),
    ".mjs": (r"(?:export[ \t]+)?(?:const|let|var)[ \t]+", r"(?:[ \t]*:[ \t]*string)?"),
    ".php": (
        r"(?:(?:public|protected|private|static|readonly)[ \t]+)*(?:\?(?:string|array|mixed)[ \t]+"
        r"|(?:string|array|mixed)\??[ \t]+)?"
        r"(?:\$this->|\$)",
        r"",
    ),
    ".rb": (r"(?:@@?|\$)", r""),
    ".rs": (
        r"(?:pub(?:\([^\r\n)]{1,64}\))?[ \t]+)?(?:static|const|let)(?:[ \t]+mut)?[ \t]+",
        r"(?:[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_:<>, &'\[\]]{0,128})?",
    ),
    ".scala": (
        r"(?:(?:private|protected|final|lazy)[ \t]+)*(?:val|var)[ \t]+",
        r"(?:[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_.<>?, \t]{0,128})?",
    ),
    ".sh": (r"export[ \t]+", r""),
    ".swift": (
        r"(?:(?:private|fileprivate|internal|public|open|static|class|lazy)[ \t]+)*(?:let|var)[ \t]+",
        r"(?:[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_.<>?!, \t]{0,128})?",
    ),
    ".ts": (
        r"(?:(?:export[ \t]+)?(?:const|let|var)[ \t]+"
        r"|(?:(?:public|private|protected|static|readonly|declare|abstract)[ \t]+)+)",
        r"(?:[ \t]*:[ \t]*[A-Za-z_$][A-Za-z0-9_$.[\]<>| &, \t]{0,127})?",
    ),
    ".tsx": (
        r"(?:(?:export[ \t]+)?(?:const|let|var)[ \t]+"
        r"|(?:(?:public|private|protected|static|readonly|declare|abstract)[ \t]+)+)",
        r"(?:[ \t]*:[ \t]*[A-Za-z_$][A-Za-z0-9_$.[\]<>| &, \t]{0,127})?",
    ),
    ".zsh": (r"export[ \t]+", r""),
}
_CREDENTIAL_DECLARATION_RES = {
    suffix: re.compile(rf"(?imx)^[ \t]*{prefix}{_CREDENTIAL_LABEL_PATTERN}{post_key}[ \t]*(?P<delimiter>=)")
    for suffix, (prefix, post_key) in _DECLARATION_PATTERNS.items()
}
_DOCKERFILE_EQUALS_CREDENTIAL_RE = re.compile(
    rf"(?imx)^[ \t]*(?:ENV|ARG)[ \t]+{_CREDENTIAL_LABEL_PATTERN}[ \t]*(?P<delimiter>=)"
)
_DOCKERFILE_LEGACY_ENV_RE = re.compile(
    rf"(?imx)^[ \t]*ENV[ \t]+{_CREDENTIAL_LABEL_PATTERN}(?P<delimiter>[ \t]+)(?![ \t]*=)"
)
_SAFE_CREDENTIAL_SENTINEL_RE = re.compile(r"(?i)^(?:null|none|true|false|~)$")
_CREDENTIAL_SUBSTITUTION_RE = re.compile(
    r"^\$\{[A-Z_][A-Z0-9_]{0,127}(?:(?P<operator>:-|-)(?P<default>[^{}]{1,128}))?\}$"
)
_SECRET_WRAPPER_RE = re.compile(
    rf"(?is)^(?:secretstr|secretbytes|secretvalue|secret)[ \t]*\("
    rf"(?P<argument>[^\r\n]{{0,{_MAX_PATTERN_CHARS}}})\)$"
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
_REFERENCE_STRING_PATTERN = r'(?:"(?:\\.|[^"\\\r\n])*"|\'(?:\\.|[^\'\\\r\n])*\')'
_REFERENCE_IDENTIFIER_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*"
_PYTHON_SOURCE_REFERENCE_RE = re.compile(
    rf"(?ix)^(?:"
    rf"(?:os\.)?environ[ \t]*\[[ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\]"
    rf"|(?:os\.)?environ\.get[ \t]*\([ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\)"
    rf"|(?:os\.)?getenv[ \t]*\([ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\)"
    rf"|(?:self\.)?(?:request|settings|config|credentials)"
    rf"(?:"
    rf"(?:\.{_REFERENCE_IDENTIFIER_PATTERN}|[ \t]*\[[ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\])+"
    rf"|(?:\.{_REFERENCE_IDENTIFIER_PATTERN}|[ \t]*\[[ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\])*"
    rf"\.get[ \t]*\([ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\)"
    rf")"
    rf")$"
)
_JAVA_SOURCE_REFERENCE_RE = re.compile(
    r"(?i)^(?:config|settings)\.get(?:Password|Passwd|ApiKey|ClientSecret|Secret|Token)\(\)$"
)
_C_SOURCE_REFERENCE_RE = re.compile(rf"^(?:std::)?getenv[ \t]*\([ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\)$")
_GO_SOURCE_REFERENCE_RE = re.compile(rf"^os\.Getenv[ \t]*\([ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\)$")
_PHP_SOURCE_REFERENCE_RE = re.compile(r"(?i)^\$config->(?:password|passwd|apiKey|clientSecret|secret|token)$")
_RUBY_SOURCE_REFERENCE_RE = re.compile(
    rf"^ENV(?:\.fetch[ \t]*\([ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\)"
    rf"|[ \t]*\[[ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\])$"
)
_JAVASCRIPT_SOURCE_REFERENCE_RE = re.compile(
    rf"^process\.env(?:\.[A-Z_][A-Z0-9_]*|[ \t]*\[[ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\])$"
)
_SWIFT_SOURCE_REFERENCE_RE = re.compile(
    rf"^ProcessInfo\.processInfo\.environment[ \t]*\[[ \t]*{_REFERENCE_STRING_PATTERN}[ \t]*\]!?$"
)
_DOTTED_REFERENCE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
_CONSTANT_REFERENCE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PYTHON_CREDENTIAL_ANNOTATION_RE = re.compile(
    r"^(?:str|bytes|SecretStr|SecretBytes)(?:[ \t]*\|[ \t]*None)?"
    r"(?:[ \t]*=[ \t]*(?P<rhs>.+))?$"
)
_TYPESCRIPT_CREDENTIAL_ANNOTATION_RE = re.compile(
    r"^string(?:[ \t]*\|[ \t]*null)?(?:[ \t]*=[ \t]*(?P<rhs>.+))?$", re.IGNORECASE
)
_TYPESCRIPT_OPTIONAL_CREDENTIAL_RE = re.compile(rf"(?imx)^[ \t]*{_CREDENTIAL_LABEL_PATTERN}\?[ \t]*(?P<delimiter>:)")
_HASH_COMMENT_MODES = {
    ".bash": "separated",
    ".py": "adjacent",
    ".pyi": "adjacent",
    ".rb": "adjacent",
    ".sh": "separated",
    ".toml": "adjacent",
    ".yaml": "separated",
    ".yml": "separated",
    ".zsh": "separated",
}
_SHELL_SHEBANG_RE = re.compile(
    r"^#![ \t]*(?:/(?:usr/)?bin/(?:sh|bash|zsh)"
    r"|/usr/bin/env(?:[ \t]+-S)?[ \t]+(?:sh|bash|zsh))(?:[ \t]+[^\r\n]{0,128})?$"
)
_SCHEMA_CREDENTIAL_KEY_RE = re.compile(rf"(?imx){_CREDENTIAL_LABEL_PATTERN}[ \t]*[:=]")
_SAFE_SCHEMA_DESCRIPTION_VALUE_RE = re.compile(
    r"(?i)^must[ \t]+be[ \t]+at[ \t]+least[ \t]+[1-9][0-9]{0,4}[ \t]+characters?$"
)
_SAFE_SCHEMA_TITLE_VALUE_RE = re.compile(r"(?i)^account[ \t]+credential$")
_SAFE_SCHEMA_CREDENTIAL_PATTERN_RE = re.compile(
    r"(?i)^\^(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token):"
    r"\[[A-Za-z0-9-]{1,128}\]\{[1-9][0-9]{0,3}\}\$$"
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


@dataclass(frozen=True, slots=True)
class _ScalarScan:
    value: str
    complete: bool
    terminator: str | None = None


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
    if (
        name == ".env"
        or name.startswith(".env.")
        or name in _DENIED_FILE_NAMES
        or name in _DENIED_CREDENTIAL_FILE_NAMES
    ):
        return True
    if len(parts) >= 2 and parts[-2:] == (".docker", "config.json"):
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


def _source_reference(value: str, source_suffix: str) -> bool:
    candidate = value.strip()
    if source_suffix not in _SOURCE_REFERENCE_SUFFIXES:
        return False
    if candidate.startswith("process.env"):
        return source_suffix in {".js", ".jsx", ".mjs", ".ts", ".tsx"} and (
            _JAVASCRIPT_SOURCE_REFERENCE_RE.fullmatch(candidate) is not None
        )
    if source_suffix in {".py", ".pyi"} and _PYTHON_SOURCE_REFERENCE_RE.fullmatch(candidate) is not None:
        return True
    if source_suffix == ".java" and _JAVA_SOURCE_REFERENCE_RE.fullmatch(candidate) is not None:
        return True
    if source_suffix in {".c", ".cc", ".cpp", ".h", ".hpp"} and (
        _C_SOURCE_REFERENCE_RE.fullmatch(candidate) is not None
    ):
        return True
    if source_suffix == ".go" and _GO_SOURCE_REFERENCE_RE.fullmatch(candidate) is not None:
        return True
    if source_suffix == ".php" and _PHP_SOURCE_REFERENCE_RE.fullmatch(candidate) is not None:
        return True
    if source_suffix == ".rb" and _RUBY_SOURCE_REFERENCE_RE.fullmatch(candidate) is not None:
        return True
    if source_suffix == ".swift" and _SWIFT_SOURCE_REFERENCE_RE.fullmatch(candidate) is not None:
        return True
    return (
        _DOTTED_REFERENCE_RE.fullmatch(candidate) is not None or _CONSTANT_REFERENCE_RE.fullmatch(candidate) is not None
    )


def _exact_quoted_value(candidate: str) -> str | None:
    if len(candidate) < 2 or candidate[0] not in ('"', "'"):
        return None
    quote = candidate[0]
    escaped = False
    for index, character in enumerate(candidate[1:], start=1):
        if character == quote and not escaped:
            if index == len(candidate) - 1:
                return candidate[1:index]
            return None
        escaped = character == "\\" and not escaped
        if character != "\\":
            escaped = False
    return None


def _normalized_credential_scalar(value: str) -> tuple[str, bool]:
    candidate = value.strip()
    quoted = _exact_quoted_value(candidate)
    if quoted is not None:
        return quoted, True
    wrapper = _SECRET_WRAPPER_RE.fullmatch(candidate)
    if wrapper is None:
        return candidate, False
    argument = wrapper.group("argument").strip()
    quoted = _exact_quoted_value(argument)
    return (quoted, True) if quoted is not None else (argument, False)


def _shell_shebang(text: str) -> bool:
    newline = text.find("\n", 0, _MAX_SHEBANG_CHARS + 1)
    if newline < 0:
        if len(text) > _MAX_SHEBANG_CHARS:
            return False
        first_line = text.rstrip("\r")
    else:
        first_line = text[:newline].rstrip("\r")
    return _SHELL_SHEBANG_RE.fullmatch(first_line) is not None


def _hash_comment_mode(source_suffix: str, text: str) -> str:
    if not source_suffix and _shell_shebang(text):
        return "separated"
    return _HASH_COMMENT_MODES.get(source_suffix, "none")


def _starts_hash_comment(text: str, index: int, mode: str) -> bool:
    return mode == "adjacent" or (mode == "separated" and (index == 0 or text[index - 1] in " \t\r\n"))


def _python_ignored_credential_spans(text: str) -> tuple[tuple[int, int], ...] | None:
    if len(text) > _MAX_FILE_BYTES:
        return None
    try:
        ast.parse(text)
    except (MemoryError, OverflowError, RecursionError, SyntaxError, ValueError):
        return None
    line_starts = [0]
    line_starts.extend(match.end() for match in re.finditer("\n", text))

    def offset(position: tuple[int, int]) -> int:
        line, column = position
        if line < 1 or line > len(line_starts):
            return len(text)
        return min(line_starts[line - 1] + column, len(text))

    ignored_token_types = {tokenize.STRING, tokenize.COMMENT}
    fstring_middle = getattr(tokenize, "FSTRING_MIDDLE", None)
    if isinstance(fstring_middle, int):
        ignored_token_types.add(fstring_middle)
    spans: list[tuple[int, int]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type == tokenize.ERRORTOKEN and not token.string.isspace():
                return None
            if token.type in ignored_token_types:
                spans.append((offset(token.start), offset(token.end)))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return None
    return tuple(spans)


def _toml_basic_escape_end(text: str, start: int, *, multiline: bool) -> int | None:
    escape_start = start + 1
    if escape_start >= len(text):
        return None
    escape = text[escape_start]
    if escape in {'"', "\\", "b", "t", "n", "f", "r"}:
        return escape_start + 1
    if escape in {"u", "U"}:
        width = 4 if escape == "u" else 8
        digits = text[escape_start + 1 : escape_start + 1 + width]
        if len(digits) != width or any(character not in "0123456789abcdefABCDEF" for character in digits):
            return None
        codepoint = int(digits, 16)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            return None
        return escape_start + 1 + width
    if multiline and escape in "\r\n":
        if escape == "\r" and (escape_start + 1 >= len(text) or text[escape_start + 1] != "\n"):
            return None
        end = escape_start + (2 if escape == "\r" else 1)
        while end < len(text) and text[end] in " \t\r\n":
            end += 1
        return end
    return None


def _toml_string_end(text: str, start: int, *, quote: str, multiline: bool) -> int | None:
    delimiter_length = 3 if multiline else 1
    index = start + delimiter_length
    while index < len(text):
        character = text[index]
        if multiline:
            if character == quote:
                run_end = index + 1
                while run_end < len(text) and text[run_end] == quote:
                    run_end += 1
                if run_end - index >= 3:
                    return run_end if run_end - index <= 5 else None
                index = run_end
                continue
        elif character == quote:
            return index + 1
        if quote == '"' and character == "\\":
            escape_end = _toml_basic_escape_end(text, index, multiline=multiline)
            if escape_end is None:
                return None
            index = escape_end
            continue
        if character in "\r\n":
            if not multiline or (character == "\r" and (index + 1 >= len(text) or text[index + 1] != "\n")):
                return None
        elif (ord(character) < 0x20 and character != "\t") or ord(character) == 0x7F:
            return None
        index += 1
    return None


def _toml_ignored_credential_spans(text: str) -> tuple[tuple[int, int], ...] | None:
    if len(text) > _MAX_FILE_BYTES:
        return None
    try:
        tomllib.loads(text)
    except (MemoryError, OverflowError, RecursionError, tomllib.TOMLDecodeError, ValueError):
        return None
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        character = text[index]
        if character == "#":
            end = index + 1
            while end < len(text) and text[end] not in "\r\n":
                end += 1
            spans.append((index, end))
            index = end
            continue
        if character in {'"', "'"}:
            multiline = text.startswith(character * 3, index)
            string_end = _toml_string_end(text, index, quote=character, multiline=multiline)
            if string_end is None:
                return None
            spans.append((index, string_end))
            index = string_end
            continue
        index += 1
    return tuple(spans)


def _matches_outside_ignored_spans(
    pattern: re.Pattern[str], text: str, ignored_spans: tuple[tuple[int, int], ...] | None
) -> Iterator[re.Match[str]]:
    span_index = 0
    for match in pattern.finditer(text):
        if ignored_spans is not None:
            while span_index < len(ignored_spans) and ignored_spans[span_index][1] <= match.start():
                span_index += 1
            if span_index < len(ignored_spans):
                span_start, span_end = ignored_spans[span_index]
                if span_start < match.end() <= span_end:
                    continue
        yield match


def _credential_scalar_starts(text: str, *, source_suffix: str, source_name: str) -> Iterator[tuple[int, bool, str]]:
    ignored_spans: tuple[tuple[int, int], ...] | None = None
    if source_suffix in _RAW_CREDENTIAL_KEY_SUFFIXES:
        # YAML block scalars may contain arbitrary unmatched quote or
        # substitution bytes.  Treat structural key matches as raw evidence.
        for credential in _CREDENTIAL_KEY_RE.finditer(text):
            yield credential.end(), credential.group("flow") is not None, credential.group("delimiter")
    elif source_suffix in _PYTHON_LEXICAL_SUFFIXES or source_suffix == ".toml":
        ignored_spans = (
            _python_ignored_credential_spans(text)
            if source_suffix in _PYTHON_LEXICAL_SUFFIXES
            else _toml_ignored_credential_spans(text)
        )
        for credential in _matches_outside_ignored_spans(_CREDENTIAL_KEY_RE, text, ignored_spans):
            yield credential.end(), credential.group("flow") is not None, credential.group("delimiter")
    else:
        cursor = 0
        quote: str | None = None
        escaped = False
        substitution_depth = 0
        in_comment = False
        hash_comment_mode = _hash_comment_mode(source_suffix, text)
        for credential in _CREDENTIAL_KEY_RE.finditer(text):
            index = cursor
            while index < credential.start():
                character = text[index]
                if character in "\r\n":
                    quote = None
                    escaped = False
                    substitution_depth = 0
                    in_comment = False
                    index += 1
                    continue
                if in_comment:
                    index += 1
                    continue
                if substitution_depth:
                    if character == "{":
                        substitution_depth += 1
                    elif character == "}":
                        substitution_depth -= 1
                    index += 1
                    continue
                if quote is not None:
                    if escaped:
                        escaped = False
                    elif character == "\\":
                        escaped = True
                    elif character == quote:
                        quote = None
                    index += 1
                    continue
                if character == "$" and index + 1 < credential.start() and text[index + 1] == "{":
                    substitution_depth = 1
                    index += 2
                    continue
                if character in ('"', "'"):
                    quote = character
                elif character == "#" and _starts_hash_comment(text, index, hash_comment_mode):
                    in_comment = True
                index += 1
            if quote is not None or substitution_depth or in_comment:
                cursor = credential.start()
                continue
            flow_context = source_suffix == ".json" or credential.group("flow") is not None
            yield credential.end(), flow_context, credential.group("delimiter")
            cursor = credential.end()
    if source_suffix in _SEMICOLON_STATEMENT_SUFFIXES:
        for credential in _matches_outside_ignored_spans(_SEMICOLON_CREDENTIAL_KEY_RE, text, ignored_spans):
            yield credential.end(), False, credential.group("delimiter")
    if source_suffix in {".ts", ".tsx"}:
        for credential in _TYPESCRIPT_OPTIONAL_CREDENTIAL_RE.finditer(text):
            yield credential.end(), False, credential.group("delimiter")
    declaration_suffix = ".sh" if not source_suffix and _shell_shebang(text) else source_suffix
    declaration_re = _CREDENTIAL_DECLARATION_RES.get(declaration_suffix)
    if declaration_re is not None:
        for credential in declaration_re.finditer(text):
            yield credential.end(), False, credential.group("delimiter")
    if source_name == "dockerfile" or source_name.startswith("dockerfile."):
        for credential in _DOCKERFILE_EQUALS_CREDENTIAL_RE.finditer(text):
            yield credential.end(), False, credential.group("delimiter")
        for credential in _DOCKERFILE_LEGACY_ENV_RE.finditer(text):
            yield credential.end(), False, "="


def _scan_credential_scalar(
    text: str,
    start: int,
    *,
    flow_context: bool,
    hash_comment_mode: str,
    source_suffix: str,
) -> _ScalarScan:
    limit = min(len(text), start + _MAX_PATTERN_CHARS)
    while start < limit and text[start] in " \t":
        start += 1
    index = start
    quote: str | None = None
    escaped = False
    square_depth = 0
    brace_depth = 0
    parenthesis_depth = 0
    terminated = False
    terminator: str | None = None
    while index < limit:
        character = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in ('"', "'"):
            quote = character
        elif character == "[":
            square_depth += 1
        elif character == "{":
            brace_depth += 1
        elif character == "(":
            parenthesis_depth += 1
        elif character == "]":
            if square_depth:
                square_depth -= 1
            elif not (brace_depth or parenthesis_depth):
                terminated = True
                terminator = character
                break
        elif character == "}":
            if brace_depth:
                brace_depth -= 1
            elif not (square_depth or parenthesis_depth):
                terminated = True
                terminator = character
                break
        elif character == ")":
            if parenthesis_depth:
                parenthesis_depth -= 1
            elif not (square_depth or brace_depth):
                terminated = True
                terminator = character
                break
        elif not (square_depth or brace_depth or parenthesis_depth):
            if character in "\r\n":
                terminated = True
                terminator = character
                break
            if character == "," and flow_context:
                terminated = True
                terminator = character
                break
            if character == "#" and _starts_hash_comment(text, index, hash_comment_mode):
                terminated = True
                terminator = character
                break
        index += 1
    return _ScalarScan(
        value=text[start:index].strip(), complete=terminated or index == len(text), terminator=terminator
    )


def _scan_schema_credential_clause(text: str, start: int) -> _ScalarScan:
    limit = min(len(text), start + _MAX_PATTERN_CHARS)
    while start < limit and text[start] in " \t":
        start += 1
    index = start
    quote: str | None = None
    escaped = False
    square_depth = 0
    brace_depth = 0
    parenthesis_depth = 0
    terminated = False
    while index < limit:
        character = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in ('"', "'"):
            quote = character
        elif character == "[":
            square_depth += 1
        elif character == "{":
            brace_depth += 1
        elif character == "(":
            parenthesis_depth += 1
        elif character == "]" and square_depth:
            square_depth -= 1
        elif character == "}" and brace_depth:
            brace_depth -= 1
        elif character == ")" and parenthesis_depth:
            parenthesis_depth -= 1
        elif not (square_depth or brace_depth or parenthesis_depth) and character in ",;\r\n":
            terminated = True
            break
        index += 1
    return _ScalarScan(value=text[start:index].strip(), complete=terminated or index == len(text))


def _safe_credential_scalar(value: str) -> bool:
    if _placeholder(value) or _SAFE_CREDENTIAL_SENTINEL_RE.fullmatch(value) is not None:
        return True
    substitution = _CREDENTIAL_SUBSTITUTION_RE.fullmatch(value)
    if substitution is None:
        return False
    default = substitution.group("default")
    return default is None or _placeholder(default) or _SAFE_CREDENTIAL_SENTINEL_RE.fullmatch(default) is not None


def _typed_credential_rhs(
    scalar: str, *, source_suffix: str, delimiter: str, flow_context: bool
) -> tuple[bool, str | None]:
    candidate = scalar.strip()
    if delimiter != ":" or flow_context:
        return False, None
    annotation: re.Match[str] | None = None
    if source_suffix in {".py", ".pyi"}:
        annotation = _PYTHON_CREDENTIAL_ANNOTATION_RE.fullmatch(candidate)
    elif source_suffix in {".ts", ".tsx"}:
        annotation = _TYPESCRIPT_CREDENTIAL_ANNOTATION_RE.fullmatch(candidate.removesuffix(";").rstrip())
    if annotation is None:
        return False, None
    rhs = annotation.group("rhs")
    return True, rhs.strip() if rhs is not None else None


def _safe_json_schema_shape(scalar: str, *, source_suffix: str, flow_context: bool) -> bool:
    if source_suffix != ".json" or not flow_context:
        return False
    try:
        schema = json.loads(scalar)
    except (json.JSONDecodeError, RecursionError):
        return False
    if not isinstance(schema, dict) or schema.get("type") != "string":
        return False
    allowed = {"description", "format", "maxLength", "minLength", "pattern", "title", "type"}
    if not set(schema).issubset(allowed):
        return False
    for schema_field in ("description", "format", "pattern", "title"):
        if schema_field in schema and not isinstance(schema[schema_field], str):
            return False
    for schema_field in ("description", "pattern", "title"):
        description = schema.get(schema_field)
        if not isinstance(description, str):
            continue
        if schema_field == "pattern" and _SAFE_SCHEMA_CREDENTIAL_PATTERN_RE.fullmatch(description) is not None:
            continue
        for credential in _SCHEMA_CREDENTIAL_KEY_RE.finditer(description):
            scan = _scan_schema_credential_clause(description, credential.end())
            value, _is_literal = _normalized_credential_scalar(scan.value)
            safe_field_value = (
                schema_field == "description" and _SAFE_SCHEMA_DESCRIPTION_VALUE_RE.fullmatch(value) is not None
            ) or (schema_field == "title" and _SAFE_SCHEMA_TITLE_VALUE_RE.fullmatch(value) is not None)
            if not scan.complete or not value or not (_safe_credential_scalar(value) or safe_field_value):
                return False
    for schema_field in ("maxLength", "minLength"):
        if schema_field in schema and (
            not isinstance(schema[schema_field], int)
            or isinstance(schema[schema_field], bool)
            or schema[schema_field] < 0
        ):
            return False
    return True


def _source_scalar(scalar: str, *, source_suffix: str) -> str:
    if source_suffix in _SOURCE_REFERENCE_SUFFIXES and scalar.endswith(";"):
        return scalar[:-1].rstrip()
    return scalar


def _credential_scalar_denied(
    scalar: str, *, source_suffix: str, allow_safe_value_trailing_comma: bool = False
) -> bool:
    source_scalar = _source_scalar(scalar, source_suffix=source_suffix)
    # This is a value-based exception for an exact safe scalar before a line
    # ending.  It does not authorize or infer YAML flow structure.
    if allow_safe_value_trailing_comma and source_suffix in {".yaml", ".yml"} and source_scalar.endswith(","):
        without_comma = source_scalar[:-1].rstrip()
        if without_comma and not without_comma.endswith(","):
            trailing_value, _is_literal = _normalized_credential_scalar(without_comma)
            if _safe_credential_scalar(trailing_value):
                return False
    value, is_literal = _normalized_credential_scalar(source_scalar)
    if _safe_credential_scalar(value):
        return False
    return is_literal or not _source_reference(value, source_suffix)


def _secret_pattern(text: str, *, source_suffix: str, source_name: str) -> str | None:
    if _PEM_PRIVATE_KEY_RE.search(text):
        return "pem_private_key"
    for bearer in _AUTHORIZATION_BEARER_RE.finditer(text):
        if not _placeholder(bearer.group(1)):
            return "authorization_bearer"
    for provider in _PROVIDER_TOKEN_RE.finditer(text):
        if not _placeholder(provider.group(1)):
            return "provider_token"
    for scalar_start, flow_context, delimiter in _credential_scalar_starts(
        text, source_suffix=source_suffix, source_name=source_name
    ):
        scan = _scan_credential_scalar(
            text,
            scalar_start,
            flow_context=flow_context,
            hash_comment_mode=_hash_comment_mode(source_suffix, text),
            source_suffix=source_suffix,
        )
        if not scan.complete:
            return "credential_assignment"
        scalar = scan.value
        if not scalar:
            continue
        typed, rhs = _typed_credential_rhs(
            scalar, source_suffix=source_suffix, delimiter=delimiter, flow_context=flow_context
        )
        if typed:
            if rhs is None:
                continue
            scalar = rhs
        elif _safe_json_schema_shape(scalar, source_suffix=source_suffix, flow_context=flow_context):
            continue
        if _credential_scalar_denied(
            scalar,
            source_suffix=source_suffix,
            allow_safe_value_trailing_comma=scan.terminator in {"\r", "\n"},
        ):
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
    relative = _relative_to_root(context, path)
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
    pattern = _secret_pattern(
        text,
        source_suffix=relative.suffix.casefold(),
        source_name=relative.name.casefold(),
    )
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
