"""Health checks and repair for Wardline's agent-install artifacts."""

from __future__ import annotations

import ipaddress
import json
import os
import tomllib
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wardline.core.config import _filigree_published_url, load
from wardline.core.errors import ConfigError
from wardline.core.filigree_emit import FiligreeEmitter, Transport, UrllibTransport
from wardline.core.paths import weft_config_path, weft_state_dir
from wardline.core.safe_paths import safe_write_text
from wardline.filigree.config import load_filigree_token
from wardline.install.block import inject_block
from wardline.install.detect import (
    _detect_filigree,
    _detect_loomweave,
    detect_siblings,
)
from wardline.install.mcp_json import (
    _codex_config_path,
    _codex_mcp_entry,
    _desired_local_entry,
    install_codex_mcp,
    merge_mcp_entry,
)
from wardline.install.skill import install_skill
from wardline.loomweave.config import load_loomweave_token


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    message: str


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    id: str
    status: str
    fixed: bool = False
    message: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.id, "status": self.status, "fixed": self.fixed}
        if self.message:
            data["message"] = self.message
        return data


_DEFAULT_CONFIG_EXCLUDES = (
    ".git/**",
    ".venv/**",
    "venv/**",
    ".uv-cache/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    ".tox/**",
    ".nox/**",
    "node_modules/**",
    "telemetry/**",
    "data/**",
)


def _format_toml_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def _default_source_roots(root: Path) -> tuple[str, ...]:
    return ("src",) if (root / "src").is_dir() else (".",)


def _default_weft_config(root: Path) -> str:
    source_roots = _default_source_roots(root)
    return (
        "# Created by `wardline doctor --repair`.\n"
        "# Keep the scan rooted at the project root for stable identity; bound the\n"
        "# analyzed source here so agent gates do not traverse caches or run artifacts.\n"
        "[wardline]\n"
        f"source_roots = {_format_toml_array(source_roots)}\n"
        f"exclude = {_format_toml_array(_DEFAULT_CONFIG_EXCLUDES)}\n"
    )


def _ensure_weft_config(root: Path) -> bool:
    cfg_path = weft_config_path(root)
    if cfg_path.exists():
        return False
    safe_write_text(root, cfg_path, _default_weft_config(root), label="weft.toml")
    return True


def _has_instruction_block(path: Path) -> bool:
    if not path.is_file():
        return False
    return "wardline:instructions:" in path.read_text(encoding="utf-8", errors="replace")


def _has_skill(root: Path, base: str) -> bool:
    return (root / base / "skills" / "wardline-gate" / "SKILL.md").is_file()


def _check_project_mcp(root: Path) -> CheckResult:
    path = root / ".mcp.json"
    if not path.is_file():
        return CheckResult(".mcp.json", False, "missing wardline server")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return CheckResult(".mcp.json", False, "invalid JSON")
    if not isinstance(raw, dict):
        return CheckResult(".mcp.json", False, "must be a JSON object")
    servers = raw.get("mcpServers")
    if not isinstance(servers, dict):
        return CheckResult(".mcp.json", False, "missing mcpServers object")
    entry = servers.get("wardline")
    # An entry carrying operator-pinned --loomweave-url/--filigree-url args is well-formed:
    # compare against the canonical entry augmented with those preserved args (and the
    # live server-mode filigree scope, if any), not the bare canonical entry (which would
    # flag a configured emit target as misconfiguration).
    if entry != _desired_local_entry(entry, root):
        return CheckResult(".mcp.json", False, "missing wardline server")
    return CheckResult(".mcp.json", True, "configured")


def _check_codex_mcp() -> CheckResult:
    path = _codex_config_path()
    if not path.is_file():
        return CheckResult("Codex MCP", False, "missing wardline server")
    try:
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return CheckResult("Codex MCP", False, "invalid TOML")
    servers = parsed.get("mcp_servers")
    entry = servers.get("wardline") if isinstance(servers, dict) else None
    if entry != _codex_mcp_entry():
        return CheckResult("Codex MCP", False, "missing wardline server")
    return CheckResult("Codex MCP", True, "configured")


def _check_bindings(root: Path) -> CheckResult:
    # Detection report only — bindings are no longer persisted to config (the shared
    # weft.toml is operator-owned; live URLs resolve via the published .weft/<sibling>/
    # ephemeral.port rung). Presence of a sibling is informational, never a failure.
    detectors = (("loomweave", _detect_loomweave), ("filigree", _detect_filigree))
    detected = [key for key, detector in detectors if detector(root)[0]]
    if not detected:
        return CheckResult("bindings", True, "no siblings detected")
    return CheckResult("bindings", True, "detected: " + ", ".join(detected))


def _check_config(root: Path, *, fixed: bool) -> DoctorCheck:
    cfg_path = weft_config_path(root)
    # C-9c makes load() silently fall back to defaults on an unparseable shared
    # weft.toml (a sibling's section may be broken). doctor restores the operator
    # signal by distinguishing ABSENT (ok — defaults are intentional) from
    # PRESENT-BUT-BROKEN (error — your policy is silently not applying).
    if not cfg_path.exists():
        return DoctorCheck(
            "wardline.config",
            "error",
            fixed=False,
            message="missing weft.toml; run `wardline doctor --repair` to create a bounded default policy",
        )
    if cfg_path.is_file():
        try:
            parsed = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
            return DoctorCheck("wardline.config", "error", fixed=False, message=f"unparseable weft.toml: {exc}")
        table = parsed.get("wardline")
        if table is not None and not isinstance(table, dict):
            return DoctorCheck(
                "wardline.config", "error", fixed=False, message="[wardline] in weft.toml must be a table"
            )
    try:
        load(cfg_path)
    except ConfigError as exc:
        return DoctorCheck("wardline.config", "error", fixed=False, message=str(exc))
    return DoctorCheck("wardline.config", "ok", fixed=fixed)


def _check_mcp_registration(root: Path, *, before: dict[str, CheckResult]) -> DoctorCheck:
    project = _check_project_mcp(root)
    codex = _check_codex_mcp()
    fixed = any(not before.get(name, CheckResult(name, True, "")).ok for name in (".mcp.json", "Codex MCP")) and (
        project.ok and codex.ok
    )
    if project.ok and codex.ok:
        return DoctorCheck("mcp.registration", "ok", fixed=fixed)
    missing = ", ".join(f"{c.name}: {c.message}" for c in (project, codex) if not c.ok)
    return DoctorCheck("mcp.registration", "error", fixed=False, message=missing)


def _check_marker_package() -> DoctorCheck:
    try:
        decorators = import_module("wardline.decorators")
    except Exception as exc:
        return DoctorCheck("marker_package", "error", message=f"wardline.decorators not importable: {exc}")
    missing = [name for name in ("external_boundary", "trust_boundary", "trusted") if not hasattr(decorators, name)]
    if missing:
        return DoctorCheck("marker_package", "error", message="missing " + ", ".join(missing))
    return DoctorCheck("marker_package", "ok")


def _valid_http_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except Exception:
        return False
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _check_url(root: Path, key: str, *, fixed: bool, effective_url: str | None = None) -> DoctorCheck:
    # Doctor must vouch for the EFFECTIVE config of the process answering it
    # (dogfood-4 B8: it said "not configured" while the same server was launched
    # with --loomweave-url/--filigree-url and using them successfully). Precedence
    # mirrors runtime resolution: the launch flag the caller threads in, then the
    # env var. Each verdict names its provenance so two surfaces can never
    # silently disagree about WHICH config they describe. Live local discovery
    # (.weft/<sibling>/ephemeral.port) is dynamic and not a doctor concern.
    env_key = "WARDLINE_LOOMWEAVE_URL" if key == "loomweave" else "WARDLINE_FILIGREE_URL"
    check_id = f"{key}.url"
    if effective_url:
        if _valid_http_url(effective_url):
            return DoctorCheck(check_id, "ok", fixed=fixed, message=f"from --{key}-url launch flag")
        return DoctorCheck(check_id, "error", fixed=False, message=f"invalid URL (launch flag): {effective_url!r}")
    url = os.environ.get(env_key)
    if not url:
        return DoctorCheck(check_id, "ok", fixed=fixed, message="not configured (no launch flag, no env)")
    if _valid_http_url(url):
        return DoctorCheck(check_id, "ok", fixed=fixed, message=f"from env {env_key}")
    return DoctorCheck(check_id, "error", fixed=False, message=f"invalid URL: {url!r}")


def _check_decorator_grammar() -> DoctorCheck:
    try:
        from wardline.core.registry import REGISTRY
        from wardline.scanner.grammar import BUILTIN_BOUNDARY_TYPES
    except Exception as exc:
        return DoctorCheck("decorator_grammar", "error", message=f"cannot load grammar: {exc}")

    expected = {("wardline.decorators", name) for name in REGISTRY} | {("weft_markers", name) for name in REGISTRY}
    actual = {(bt.module_prefix, bt.canonical_name) for bt in BUILTIN_BOUNDARY_TYPES}
    missing = sorted(expected - actual)
    if missing:
        return DoctorCheck("decorator_grammar", "error", message=f"missing builtin boundary types: {missing}")
    return DoctorCheck("decorator_grammar", "ok")


def _check_scan_output_path(root: Path) -> DoctorCheck:
    output = root / "findings.jsonl"
    if output.exists() and output.is_dir():
        return DoctorCheck("scan.output_path", "error", message=f"{output} is a directory")
    if not root.exists() or not root.is_dir():
        return DoctorCheck("scan.output_path", "error", message=f"{root} is not a directory")
    if not os.access(root, os.W_OK):
        return DoctorCheck("scan.output_path", "error", message=f"{root} is not writable")
    return DoctorCheck("scan.output_path", "ok")


def _check_auth_token(root: Path) -> DoctorCheck:
    try:
        token = load_loomweave_token(root)
    except OSError as exc:
        return DoctorCheck("auth.token", "error", message=f"cannot read auth token wiring: {exc}")
    if token:
        return DoctorCheck("auth.token", "ok")
    return DoctorCheck("auth.token", "ok", message="optional Loomweave token not configured")


def _rewrite_env_token(env_path: Path, value: str) -> None:
    """Surgically pin ``WEFT_FEDERATION_TOKEN=<value>`` in *env_path*. Removes any
    existing ``WEFT_FEDERATION_TOKEN`` or legacy ``WARDLINE_FILIGREE_TOKEN`` line,
    preserves all other lines/order byte-for-byte, creates the file if absent, and
    keeps mode 0600 (the file holds a secret).

    Operates on raw bytes: an unrelated line carrying a non-UTF8 byte (e.g. a sibling
    secret) is preserved verbatim rather than corrupted to U+FFFD on a decode round-trip.
    The file is created with mode 0600 from the outset (``os.open`` with O_CREAT), so the
    secret is never briefly written to a world-readable file; the trailing ``chmod`` still
    tightens an already-existing loose-permission file."""
    drop = (b"WEFT_FEDERATION_TOKEN=", b"WARDLINE_FILIGREE_TOKEN=")
    kept: list[bytes] = []
    if env_path.is_file():
        for raw in env_path.read_bytes().splitlines():
            if raw.strip().startswith(drop):
                continue
            kept.append(raw)
    kept.append(b"WEFT_FEDERATION_TOKEN=" + value.encode("utf-8"))
    payload = b"\n".join(kept) + b"\n"
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(payload)
    env_path.chmod(0o600)


_FILIGREE_URL_ENV = "WARDLINE_FILIGREE_URL"


def _mcp_filigree_url(root: Path) -> str | None:
    """The ``--filigree-url`` value from the wardline server entry in ``.mcp.json``,
    or None. This is the URL the agent's MCP server actually emits to, and the only
    place it is recorded in the common (MCP) setup."""
    path = root / ".mcp.json"
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    try:
        args = raw["mcpServers"]["wardline"]["args"]
        if not isinstance(args, list):
            return None
        idx = args.index("--filigree-url")
        value = args[idx + 1]
    except (KeyError, TypeError, ValueError, IndexError):
        return None
    return value if isinstance(value, str) else None


def _resolve_probe_url(root: Path, flag: str | None) -> str | None:
    """Probe-URL precedence: flag > WARDLINE_FILIGREE_URL env > .mcp.json wardline
    --filigree-url arg > Filigree's published port. None when nothing resolves.

    This mirrors the actual emit path (:func:`core.config.resolve_filigree_url`)
    exactly: a scan auto-discovers a live Filigree daemon from its published
    ``ephemeral.port`` (or the server-mode registry), so a project with a running
    Filigree but no pinned ``--filigree-url`` (the common ethereal/per-project case)
    *does* emit — and *does* need a valid token. The published-port rung is therefore
    included so doctor verifies the credential the scan will really use rather than
    reporting "nothing to verify" and leaving a 401 to surface only at emit time. The
    rung is read-only and the token is sent only to loopback (the ``_is_loopback``
    guard in :func:`_check_filigree_auth`), and a published port implies a daemon that
    bound it, so this still does no speculative network."""
    if flag:
        return flag
    env = os.environ.get(_FILIGREE_URL_ENV)
    if env:
        return env
    return _mcp_filigree_url(root) or _filigree_published_url(root)


def _is_loopback(url: str) -> bool:
    """True when *url*'s host is loopback — the only origins a bearer is probed against.

    Uses strict IP parsing, never a string-prefix test: ``127.attacker.com`` /
    ``127.0.0.1.evil.com`` are registrable hostnames that resolve off-box via DNS, so
    a ``startswith("127.")`` check would send the federation bearer to an attacker. Only
    the literal ``localhost`` and addresses in the 127/8 + ``::1`` loopback ranges pass."""
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _filigree_token_candidates(root: Path) -> list[str]:
    """Locally-readable federation-token mints, in precedence order: the server-mode
    store (~/.config/filigree) then the project store (<root>/.weft/filigree). Returns
    distinct, non-empty values."""
    paths = [
        Path.home() / ".config" / "filigree" / "federation_token",
        root / ".weft" / "filigree" / "federation_token",
    ]
    out: list[str] = []
    for p in paths:
        try:
            value = p.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value and value not in out:
            out.append(value)
    return out


def _repair_filigree_auth(root: Path, url: str, transport: Transport) -> DoctorCheck:
    """A 401/403 was seen. Probe each locally-readable mint; if exactly one is
    accepted, pin it as WEFT_FEDERATION_TOKEN in .env and confirm. Otherwise write
    nothing and report (the daemon likely uses an env override we cannot read)."""
    for candidate in _filigree_token_candidates(root):
        probe = FiligreeEmitter(url, transport=transport, token=candidate).verify_token()
        if probe.reachable and probe.accepted:
            _rewrite_env_token(root / ".env", candidate)
            return DoctorCheck(
                "filigree.auth",
                "ok",
                fixed=True,
                message="wrote WEFT_FEDERATION_TOKEN to .env (was a stale/mismatched token)",
            )
    return DoctorCheck(
        "filigree.auth",
        "error",
        message="no local federation_token matched the daemon — it likely uses a "
        "WEFT_FEDERATION_TOKEN env override; set that same value in .env",
    )


def _check_filigree_auth(
    root: Path,
    *,
    repair: bool,
    filigree_url: str | None = None,
    transport: Transport | None = None,
) -> DoctorCheck:
    """Verify the token wardline would emit is accepted by the configured Filigree
    daemon. Read-only probe; under *repair*, recover the accepted token from local
    mints and pin it in .env. The probe targets only loopback origins."""
    probe_transport = transport if transport is not None else UrllibTransport(timeout=2.0)
    url = _resolve_probe_url(root, filigree_url)
    if url is None:
        return DoctorCheck("filigree.auth", "ok", message="filigree not configured; nothing to verify")
    if not _is_loopback(url):
        return DoctorCheck("filigree.auth", "ok", message="non-loopback filigree; token not probed")
    token = load_filigree_token(root)  # may be None — probe anyway (the daemon may have auth off)
    probe = FiligreeEmitter(url, transport=probe_transport, token=token).verify_token()
    if not probe.reachable:
        return DoctorCheck("filigree.auth", "ok", message="filigree daemon not reachable; token not verified")
    if probe.accepted:
        return DoctorCheck("filigree.auth", "ok")
    # Rejected (401/403): filigree auth is on and our credential is not accepted.
    if repair:
        return _repair_filigree_auth(root, url, probe_transport)
    if token:
        return DoctorCheck(
            "filigree.auth",
            "error",
            message=f"emit token rejected by filigree ({probe.status}); "
            "the configured token is not what the daemon accepts",
        )
    return DoctorCheck(
        "filigree.auth",
        "error",
        message="filigree rejected an unauthenticated emit and no federation token is set; "
        "export WEFT_FEDERATION_TOKEN or add it to .env",
    )


def machine_readable_doctor(
    root: Path,
    *,
    fix: bool = False,
    filigree_url: str | None = None,
    loomweave_url: str | None = None,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Return the shared machine-readable doctor shape, optionally repairing install bindings."""
    before = {check.name: check for check in check_install(root)}
    config_missing_before = not weft_config_path(root).exists()
    bindings_fixed = False
    if fix:
        repair_install(root)
        bindings_fixed = not before.get("bindings", CheckResult("bindings", True, "")).ok
    # Resolve the probe URL AFTER repair: when Filigree runs in server mode, repair
    # (merge_mcp_entry) rewrites a default-shaped/unscoped --filigree-url to the live
    # project scope, so the post-repair value is the URL the agent will actually emit
    # to — and the one whose auth the filigree-auth check should probe. Without fix,
    # repair is a no-op and this is just the recorded emit target.
    probe_url = _resolve_probe_url(root, filigree_url)

    checks: list[DoctorCheck] = []
    checks.append(_check_config(root, fixed=fix and config_missing_before and weft_config_path(root).exists()))
    checks.append(_check_mcp_registration(root, before=before))
    checks.append(_check_marker_package())
    checks.append(_check_url(root, "loomweave", fixed=bindings_fixed, effective_url=loomweave_url))
    checks.append(_check_url(root, "filigree", fixed=bindings_fixed, effective_url=filigree_url))
    checks.append(_check_decorator_grammar())
    checks.append(_check_scan_output_path(root))
    checks.append(_check_auth_token(root))
    checks.append(_check_filigree_auth(root, repair=fix, filigree_url=probe_url, transport=transport))

    next_actions = [f"{check.id}: {check.message}" for check in checks if not check.ok and check.message]
    return {
        "ok": all(check.ok for check in checks),
        "checks": [check.to_dict() for check in checks],
        "next_actions": next_actions,
    }


def check_install(root: Path) -> list[CheckResult]:
    """Return install health checks without mutating the project."""
    return [
        CheckResult("CLAUDE.md", _has_instruction_block(root / "CLAUDE.md"), "configured")
        if _has_instruction_block(root / "CLAUDE.md")
        else CheckResult("CLAUDE.md", False, "missing"),
        CheckResult("AGENTS.md", _has_instruction_block(root / "AGENTS.md"), "configured")
        if _has_instruction_block(root / "AGENTS.md")
        else CheckResult("AGENTS.md", False, "missing"),
        CheckResult(".claude skill", _has_skill(root, ".claude"), "configured")
        if _has_skill(root, ".claude")
        else CheckResult(".claude skill", False, "missing"),
        CheckResult(".agents skill", _has_skill(root, ".agents"), "configured")
        if _has_skill(root, ".agents")
        else CheckResult(".agents skill", False, "missing"),
        _check_project_mcp(root),
        _check_codex_mcp(),
        _check_bindings(root),
    ]


def repair_install(root: Path) -> dict[str, str]:
    """Repair agent-install artifacts and return per-check repair status."""
    statuses: dict[str, str] = {}
    for filename in ("CLAUDE.md", "AGENTS.md"):
        inject_block(root / filename)
        statuses[filename] = "repaired"
    install_skill(root)
    statuses[".claude skill"] = "repaired"
    statuses[".agents skill"] = "repaired"
    merge_mcp_entry(root)
    statuses[".mcp.json"] = "repaired"
    install_codex_mcp(root)
    statuses["Codex MCP"] = "repaired"
    detect_siblings(root)
    statuses["bindings"] = "detected"
    statuses["weft.toml"] = "created" if _ensure_weft_config(root) else "checked"
    # doctor MAY create its OWN state subtree (never a sibling's).
    weft_state_dir(root).mkdir(parents=True, exist_ok=True)
    statuses["state_dir"] = "ensured"
    return statuses
