"""Health checks and repair for Wardline's agent-install artifacts."""

from __future__ import annotations

import ipaddress
import json
import os
import tomllib
import urllib.error
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wardline.core import artifacts as _artifacts
from wardline.core import discovery, paths
from wardline.core.config import ArtifactSettings, _filigree_published_url, filigree_server_scoped_url, load
from wardline.core.errors import ConfigError, WardlineError
from wardline.core.filigree_emit import FiligreeEmitter, Transport, UrllibTransport
from wardline.core.http import WeftHttp
from wardline.core.paths import legacy_sibling_dir, sibling_state_dir, weft_config_path, weft_state_dir
from wardline.core.safe_paths import safe_project_path, safe_read_text_if_regular, safe_write_text
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
    removed: Sequence[str] = ()
    review: Sequence[str] = ()

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.id, "status": self.status, "fixed": self.fixed}
        if self.message:
            data["message"] = self.message
        if self.removed:
            data["removed"] = list(self.removed)
        if self.review:
            data["review"] = list(self.review)
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


_GITIGNORE_HEADER = "# Wardline scan artifacts"


def _artifacts_dir_relname(proj: Path) -> str:
    """The project-root-relative dir name to ignore (always in-tree by construction)."""
    try:
        cfg = load(weft_config_path(proj))
        artifacts_dir_value = cfg.artifacts.dir
    except (ConfigError, OSError):
        artifacts_dir_value = ArtifactSettings().dir
    resolved = paths.artifacts_dir(proj, artifacts_dir_value)
    rel = resolved.relative_to(proj.resolve())
    return rel.as_posix()


_MANAGED_SUFFIXES = ("findings.jsonl", "findings.sarif", "findings.agent-summary.json", "scan.legis.json")


def _is_managed_name(name: str) -> bool:
    return any(_artifacts._managed_artifact_pattern(s).match(name) for s in _MANAGED_SUFFIXES)


def _sweep_stray_artifacts(proj: Path, *, fix: bool) -> DoctorCheck:
    proj = proj.resolve()
    # Both the configured artifacts dir AND the default .wardline are standard dirs:
    # a subdir scan loads config from the scan path (no weft.toml => default .wardline),
    # so it may write to <proj>/.wardline/ even when the project root's weft.toml
    # configures a custom dir. Both locations are tool-owned and must not be swept.
    standard_dirs = {
        paths.artifacts_dir(proj, _artifacts_dir_relname(proj)),
        paths.artifacts_dir(proj, paths.DEFAULT_ARTIFACT_DIR),
    }
    removed: list[str] = []
    review: list[str] = []
    emptied_dirs: list[Path] = []
    # topdown=True (the os.walk default) is REQUIRED: the dirnames[:] prune below
    # (nested-project-root stop + standard-dir skip) is a no-op under topdown=False.
    for dirpath, dirnames, filenames in os.walk(proj, followlinks=False):
        here = Path(dirpath)
        # prune: hard-skip set, .git, the standard artifacts dirs, and nested project roots
        dirnames[:] = [
            d
            for d in dirnames
            if d not in discovery.WALK_SKIP_DIRS
            and (here / d).resolve() not in standard_dirs
            and not paths._has_project_markers(here / d)
        ]
        in_wardline_dir = here.name == ".wardline" and here.resolve() not in standard_dirs
        for fname in filenames:
            fpath = here / fname
            managed = _is_managed_name(fname)  # timestamped: 2026...-findings.jsonl
            bare = fname in _MANAGED_SUFFIXES and not managed  # unstamped: findings.jsonl
            if not managed and not bare:
                continue
            rel = str(fpath.relative_to(proj))
            # ONLY a timestamped (managed) file INSIDE a non-standard .wardline/ dir is
            # auto-deletable; bare-managed, or managed outside .wardline/, is REVIEW.
            if not (managed and in_wardline_dir):
                review.append(rel)
                continue
            if not _artifacts._is_regular_file_no_follow(fpath):
                continue  # symlink / non-regular -> skip
            if not fix:
                removed.append(rel)  # would-remove (no unlink)
                continue
            try:
                safe = safe_project_path(proj, fpath, label=fname)
            except WardlineError:
                continue  # escaping entry -> skip, keep sweeping
            try:
                safe.unlink()
            except OSError:
                continue
            removed.append(rel)
            emptied_dirs.append(here)
    if fix:
        for d in emptied_dirs:
            try:
                if d.resolve() not in standard_dirs and not d.is_symlink():
                    d.rmdir()  # os.rmdir only; ENOTEMPTY guards
            except OSError:
                pass
    # ADVISORY status (must-fix from plan review): stray artifacts are cleanup items, not a
    # health failure, so status stays "ok" and the sweep never flips machine_readable_doctor's
    # all(check.ok) aggregation (which would fail `doctor --fix` / MCP doctor on success).
    msg = f"removed {len(removed)}, review {len(review)}" if fix else f"{len(removed)} removable, review {len(review)}"
    return DoctorCheck(
        "stray_artifacts", "ok", fixed=bool(fix and removed), message=msg, removed=removed, review=review
    )


def _gitignore_present_entries(text: str) -> set[str]:
    out: set[str] = set()
    for raw in text.splitlines():  # handles \n, \r\n, \r
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        out.add(line.rstrip("/"))  # trailing-slash tolerant
    return out


def _check_gitignore(proj: Path, *, fix: bool) -> DoctorCheck:
    gitignore = proj / ".gitignore"
    # Always protect BOTH the configured artifacts dir AND the default .wardline/:
    # a subdir scan may write to .wardline/ even when the project root weft.toml
    # uses a custom dir, so both locations need gitignore coverage.
    dir_entries: set[str] = {
        _artifacts_dir_relname(proj) + "/",
        paths.DEFAULT_ARTIFACT_DIR + "/",
    }
    wanted = sorted(dir_entries) + ["findings.jsonl"]
    existing = safe_read_text_if_regular(proj, gitignore, label=".gitignore") or ""
    present = _gitignore_present_entries(existing)
    missing = [w for w in wanted if w.rstrip("/") not in present]
    if not missing:
        return DoctorCheck("gitignore", "ok", message="present")
    if not fix:
        # ADVISORY: a missing ignore line must NOT make .ok False — that would flip
        # machine_readable_doctor's all(check.ok) and fail `doctor --fix` / MCP doctor.
        # Status stays "ok"; the gap is surfaced in the message.
        return DoctorCheck("gitignore", "ok", message="missing ignore lines: " + ", ".join(missing) + " (run --repair)")
    block = "\n".join([_GITIGNORE_HEADER, *missing]) + "\n"
    if existing and not existing.endswith("\n"):
        block = "\n" + block  # don't concatenate the header onto a no-newline last line
    try:
        safe_write_text(proj, gitignore, existing + block, label=".gitignore")
    except WardlineError:
        # A symlinked/escaping .gitignore is an untrusted-repo surface (spec §8). Report a
        # single check error rather than letting the raise abort the whole doctor run.
        return DoctorCheck("gitignore", "error", message="refused to write through a symlinked .gitignore")
    return DoctorCheck("gitignore", "ok", fixed=True, message="added " + ", ".join(missing))


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
    # signal by flagging BOTH silent-default cases as a repairable error: ABSENT
    # (built-in source_roots=['.'] make project-root scans broad/slow — the scan
    # warns about this; --repair writes a bounded default policy) and
    # PRESENT-BUT-BROKEN (your policy is silently not applying).
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


def _check_url(
    root: Path,
    key: str,
    *,
    fixed: bool,
    effective_url: str | None = None,
    effective_url_source: str | None = None,
) -> DoctorCheck:
    # Doctor must vouch for the EFFECTIVE config of the process answering it
    # (dogfood-4 B8: it said "not configured" while the same server was launched
    # with --loomweave-url/--filigree-url and using them successfully). Precedence
    # mirrors runtime resolution: a caller-threaded effective URL, then the env
    # var. Each verdict names provenance so two surfaces can never silently
    # disagree about WHICH config they describe. When the effective URL was
    # resolved before the server was constructed, the caller must pass its source
    # too so a published-port URL is not mislabeled as a launch flag.
    env_key = "WARDLINE_LOOMWEAVE_URL" if key == "loomweave" else "WARDLINE_FILIGREE_URL"
    check_id = f"{key}.url"
    if effective_url:
        source = effective_url_source or f"--{key}-url launch flag"
        if _valid_http_url(effective_url):
            return DoctorCheck(check_id, "ok", fixed=fixed, message=f"from {source}")
        return DoctorCheck(check_id, "error", fixed=False, message=f"invalid URL ({source}): {effective_url!r}")
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
    tightens an already-existing loose-permission file.

    Refuses a SYMLINKED ``.env``: an ``O_TRUNC`` open on a symlink would follow it and
    clobber an arbitrary user-writable file outside the repo (and reading it would
    disclose that target). We refuse before reading and open the write with O_NOFOLLOW
    (defends the check->open race), raising ``WardlineError`` so doctor reports a refusal
    rather than writing through the link."""
    if env_path.is_symlink():
        raise WardlineError(f"{env_path.name}: refusing to rewrite a symlinked .env")
    drop = (b"WEFT_FEDERATION_TOKEN=", b"WARDLINE_FILIGREE_TOKEN=")
    kept: list[bytes] = []
    if env_path.is_file():
        for raw in env_path.read_bytes().splitlines():
            if raw.strip().startswith(drop):
                continue
            kept.append(raw)
    kept.append(b"WEFT_FEDERATION_TOKEN=" + value.encode("utf-8"))
    payload = b"\n".join(kept) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(env_path, flags, 0o600)
    except OSError as exc:
        if env_path.is_symlink():
            raise WardlineError(f"{env_path.name}: refusing to write through a symlink") from exc
        raise
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


@dataclass(frozen=True, slots=True)
class _ProbeTarget:
    url: str
    source: str
    token_probe_allowed: bool = True


def _resolve_probe_target(root: Path, flag: str | None) -> _ProbeTarget | None:
    """Resolve the Filigree auth-probe target while preserving URL provenance."""
    if flag:
        return _ProbeTarget(flag, "flag")
    env = os.environ.get(_FILIGREE_URL_ENV)
    if env:
        return _ProbeTarget(env, "env")
    mcp = _mcp_filigree_url(root)
    if mcp:
        return _ProbeTarget(mcp, "mcp")
    scoped = filigree_server_scoped_url(root)
    if scoped is not None:
        return _ProbeTarget(scoped, "server-registry")
    published = _filigree_published_url(root)
    if published is not None:
        return _ProbeTarget(published, "project-published-port", token_probe_allowed=False)
    return None


def _resolve_probe_url(root: Path, flag: str | None) -> str | None:
    """Probe-URL precedence: flag > WARDLINE_FILIGREE_URL env > .mcp.json wardline
    --filigree-url arg > Filigree's server registry. None when nothing safe resolves.

    Compatibility wrapper for callers that only need the URL. The auth-probe path
    uses :func:`_resolve_probe_target` so it can distinguish operator-pinned targets
    from repository-owned ``ephemeral.port`` discovery before sending a bearer."""
    target = _resolve_probe_target(root, flag)
    if target is None or not target.token_probe_allowed:
        return None
    return target.url


def _filigree_auth_probe_would_network(root: Path, flag: str | None) -> bool:
    target = _resolve_probe_target(root, flag)
    return bool(target and target.token_probe_allowed and _is_loopback(target.url))


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
    out: list[str] = []
    # Home store: the operator's own config — read normally.
    home_mint = Path.home() / ".config" / "filigree" / "federation_token"
    try:
        candidates = [home_mint.read_text(encoding="utf-8").strip()]
    except OSError:
        candidates = [""]
    # Project store: repo-controlled when wardline scans an untrusted checkout. A symlinked
    # mint here would have its TARGET's bytes read and sent as a Bearer to the probed local
    # service (token exfil). Read it regular-only / no-follow — a symlink is skipped.
    proj = safe_read_text_if_regular(root, root / ".weft" / "filigree" / "federation_token", label="federation_token")
    candidates.append((proj or "").strip())
    for value in candidates:
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
            try:
                _rewrite_env_token(root / ".env", candidate)
            except WardlineError as exc:
                return DoctorCheck("filigree.auth", "error", message=str(exc))
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
    probe_target: _ProbeTarget | None = None,
) -> DoctorCheck:
    """Verify the token wardline would emit is accepted by the configured Filigree
    daemon. Read-only probe; under *repair*, recover the accepted token from local
    mints and pin it in .env. The probe targets only loopback origins."""
    probe_transport = transport if transport is not None else UrllibTransport(timeout=2.0)
    target = probe_target or _resolve_probe_target(root, filigree_url)
    if target is None:
        return DoctorCheck("filigree.auth", "ok", message="filigree not configured; nothing to verify")
    url = target.url
    if not _is_loopback(url):
        return DoctorCheck("filigree.auth", "ok", message="non-loopback filigree; token not probed")
    if not target.token_probe_allowed:
        return DoctorCheck(
            "filigree.auth",
            "ok",
            message="filigree resolved from project published port; token not probed",
        )
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


# Siblings a `wardline scan` DIALS during emission (filigree weft scan-results POST,
# loomweave taint-fact write). Each origin is resolved live from
# .weft/<sibling>/ephemeral.port; we clear ONLY these two — never another tool's file.
_DIALED_SIBLINGS = ("filigree", "loomweave")

# Probe each advertised port at the SAME host the scan dials, so 'reachable per doctor'
# == 'reachable per scan' and we NEVER delete a live server's port file. filigree
# publishes a ``localhost`` origin (``core/config`` self-heals over IPv4/IPv6 — a
# filigree bound to ``::1`` only is reachable there, so a ``127.0.0.1`` probe would
# wrongly call it dead and clear a live advertisement); loomweave publishes
# ``127.0.0.1``. ``localhost`` is a safe superset regardless — ``create_connection``
# walks every getaddrinfo result, so it still reaches a ``127.0.0.1``-only server.
_SIBLING_PROBE_HOST = {"filigree": "localhost", "loomweave": "127.0.0.1"}

# Short reachability deadline for the stale-port probe. Deliberately NOT the federation
# clients' 30s `urlopen` default: doctor must answer fast, and the whole point is to
# catch the port that WOULD make a scan hang. A dead port refuses instantly; a wedged
# one (accepts TCP, never replies) is declared stale after this deadline, not after 30s.
_STALE_PORT_PROBE_TIMEOUT = 2.0


def _port_origin_reachable(url: str, timeout: float) -> bool:
    """True iff *url* yields ANY HTTP response within *timeout* — a live server is
    listening. A 4xx/5xx still proves liveness (``WeftHttp.fetch`` returns an
    ``HttpResult``). A transport failure — connection refused / DNS / read timeout (a
    server that accepts the TCP connection but never answers) — raises ``URLError`` /
    ``OSError`` and reads as not reachable: the advertised instance is gone or wedged."""
    try:
        WeftHttp(timeout=timeout).fetch("GET", url)
    except (urllib.error.URLError, OSError):
        return False
    return True


def _read_port_file(root: Path, port_file: Path) -> int | None:
    """The TCP port published in *port_file*, or None if absent / non-regular (a
    symlink is never followed) / not a valid 1..65535 ASCII integer. Mirrors
    ``core/config._read_published_port``'s parse discipline (ascii-only read, isdigit
    gate, ``int()`` over-cap guard) so detection and the live dial agree on what counts."""
    text = safe_read_text_if_regular(root, port_file, label="ephemeral.port", encoding="ascii")
    if text is None:
        return None
    text = text.strip()
    if not text.isdigit():
        return None
    try:
        port = int(text)
    except ValueError:  # all-digit payload over CPython's int() cap — fail-soft
        return None
    return port if 1 <= port <= 65535 else None


def _check_stale_sibling_ports(
    root: Path,
    *,
    fix: bool,
    probe: Callable[[str], bool] | None = None,
) -> DoctorCheck:
    """Detect — and under *fix*, clear — stale ``.weft/<sibling>/ephemeral.port`` files
    for the siblings a scan dials (filigree, loomweave).

    A sibling's ``ephemeral.port`` advertises 'an instance is listening here NOW'. When
    the owning ``serve`` process has exited or wedged, the file lingers and every
    ``wardline scan`` dials a dead/hung origin — stalling the agent gate up to the 30s
    federation ``urlopen`` timeout per round-trip on an emission that is purely advisory
    (the reported hang). A short reachability probe classifies each advertised port:
    unreachable (connection refused OR no HTTP reply within the deadline) ⇒ stale, and
    ``--repair`` deletes the file so ``resolve_*_url`` falls back to 'no sibling' and the
    scan stops dialing it. A live server (any HTTP status) is never touched.

    ADVISORY (like stray artifacts): a stale port file is a hygiene item, not a health
    failure, so status stays 'ok' and never flips the aggregate doctor verdict. The
    delete is regular-file / no-follow confined: a symlinked ``ephemeral.port`` is read
    as None (regular-only) and never followed or deleted."""
    reach = probe if probe is not None else (lambda url: _port_origin_reachable(url, _STALE_PORT_PROBE_TIMEOUT))
    stale: list[str] = []
    removed: list[str] = []
    for sibling in _DIALED_SIBLINGS:
        host = _SIBLING_PROBE_HOST.get(sibling, "localhost")
        # Prefer the consolidated .weft/<sibling>/ location; tolerate the legacy
        # .<sibling>/ dot-dir, mirroring core/config._read_published_port_with_source.
        for base in (sibling_state_dir(root, sibling), legacy_sibling_dir(root, sibling)):
            port_file = base / "ephemeral.port"
            port = _read_port_file(root, port_file)
            if port is None:
                continue
            if reach(f"http://{host}:{port}/"):
                continue  # a live server answers here — not stale, never touched
            try:
                rel = str(port_file.relative_to(root))
            except ValueError:
                rel = str(port_file)
            stale.append(f"{sibling}:{port}")
            if not fix:
                removed.append(rel)  # would-remove (no unlink)
                continue
            if not _artifacts._is_regular_file_no_follow(port_file):
                continue  # symlink / non-regular -> skip (defends the read->unlink TOCTOU)
            try:
                safe = safe_project_path(root, port_file, label="ephemeral.port")
            except WardlineError:
                continue  # escaping entry -> skip
            try:
                safe.unlink()
            except OSError:
                continue
            removed.append(rel)
    if fix:
        msg = f"cleared {len(removed)} stale ({', '.join(stale)})" if stale else "no stale sibling ports"
    else:
        msg = f"{len(stale)} stale: {', '.join(stale)} (run --repair to clear)" if stale else "no stale sibling ports"
    return DoctorCheck("stale_sibling_ports", "ok", fixed=bool(fix and removed), message=msg, removed=removed)


def machine_readable_doctor(
    root: Path,
    *,
    fix: bool = False,
    filigree_url: str | None = None,
    filigree_url_source: str | None = None,
    loomweave_url: str | None = None,
    loomweave_url_source: str | None = None,
    transport: Transport | None = None,
    port_probe: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """Return the shared machine-readable doctor shape, optionally repairing install bindings."""
    before = {check.name: check for check in check_install(root)}
    config_missing_before = not weft_config_path(root).exists()
    proj = paths.project_root_for(root)  # snapshot BEFORE repair_install plants weft.toml at literal root
    bindings_fixed = False
    if fix:
        repair_install(root)
        bindings_fixed = not before.get("bindings", CheckResult("bindings", True, "")).ok
    # Resolve the probe URL AFTER repair: when Filigree runs in server mode, repair
    # (merge_mcp_entry) rewrites a default-shaped/unscoped --filigree-url to the live
    # project scope, so the post-repair value is the URL the agent will actually emit
    # to — and the one whose auth the filigree-auth check should probe. Without fix,
    # repair is a no-op and this is just the recorded emit target.
    probe_target = _resolve_probe_target(root, filigree_url)

    checks: list[DoctorCheck] = []
    checks.append(_check_config(root, fixed=fix and config_missing_before and weft_config_path(root).exists()))
    checks.append(_check_mcp_registration(root, before=before))
    checks.append(_check_marker_package())
    checks.append(
        _check_url(
            root,
            "loomweave",
            fixed=bindings_fixed,
            effective_url=loomweave_url,
            effective_url_source=loomweave_url_source,
        )
    )
    checks.append(
        _check_url(
            root,
            "filigree",
            fixed=bindings_fixed,
            effective_url=filigree_url,
            effective_url_source=filigree_url_source,
        )
    )
    checks.append(_check_decorator_grammar())
    checks.append(_check_scan_output_path(root))
    checks.append(_check_auth_token(root))
    checks.append(_check_filigree_auth(root, repair=fix, probe_target=probe_target, transport=transport))
    checks.append(_check_gitignore(proj, fix=fix))
    checks.append(_sweep_stray_artifacts(proj, fix=fix))
    checks.append(_check_stale_sibling_ports(proj, fix=fix, probe=port_probe))

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
