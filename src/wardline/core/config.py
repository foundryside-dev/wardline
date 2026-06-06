"""``weft.toml [wardline]`` config loader. Reads TOML via stdlib ``tomllib`` (so the
base package stays zero-dep); validation still uses the `scanner` extra (jsonschema)."""

from __future__ import annotations

import keyword
import os
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wardline.core.config_schema import WARDLINE_SCHEMA
from wardline.core.errors import ConfigError
from wardline.core.optional_deps import require_jsonschema
from wardline.core.paths import (
    legacy_sibling_dir,
    sibling_state_dir,
)


def validate_boundary_exception_name(value: str) -> str:
    parts = value.split(".")
    if not value or not parts or any(not part or not part.isidentifier() or keyword.iskeyword(part) for part in parts):
        raise ConfigError(
            "autofix.boundary_exception must be an identifier or dotted identifier, "
            "for example ValueError or mypkg.ValidationError"
        )
    return value


@dataclass(frozen=True, slots=True)
class WardlineConfig:
    source_roots: tuple[str, ...] = (".",)
    exclude: tuple[str, ...] = ()
    rules_enable: tuple[str, ...] = ("*",)
    rules_severity: Mapping[str, str] = field(default_factory=dict)
    # reserved (declared so the shape is visible; inert in SP0)
    judge: Mapping[str, Any] = field(default_factory=dict)
    packs: tuple[str, ...] = ()
    pack_modules: Mapping[str, Any] = field(default_factory=dict)
    untrusted_sources: tuple[str, ...] = ()
    sanitisers: tuple[str, ...] = ()
    provenance_clash: bool = False
    autofix: Mapping[str, Any] = field(default_factory=dict)

    @property
    def boundary_exception(self) -> str:
        value = self.autofix.get("boundary_exception")
        return validate_boundary_exception_name(value) if isinstance(value, str) else "ValueError"


def _deep_merge(local: dict[str, Any], default: dict[str, Any]) -> dict[str, Any]:
    res = dict(default)
    for k, v in local.items():
        if k in res and isinstance(res[k], dict) and isinstance(v, dict):
            res[k] = _deep_merge(v, res[k])
        elif k in res and isinstance(res[k], list) and isinstance(v, list):
            if k in ("exclude", "source_roots"):
                res[k] = list(dict.fromkeys(res[k] + v))
            else:
                res[k] = res[k] + v
        else:
            res[k] = v
    return res


def _local_module_path_exists(import_root: Path, parts: list[str]) -> bool:
    """Stat-only check: would importing ``parts`` resolve to a file under ``import_root``?

    Pure filesystem inspection — never imports anything. Intermediate components
    of a dotted import must be packages (directories); only the final component
    may be a module file. This is the safe replacement for ``find_spec``, which
    executes parent ``__init__.py`` while resolving a dotted name.
    """
    target = import_root
    for index, part in enumerate(parts):
        module_file = target / f"{part}.py"
        package_dir = target / part
        is_last = index == len(parts) - 1

        if is_last:
            return module_file.is_file() or package_dir.is_dir()
        if not package_dir.is_dir():
            return False
        target = package_dir
    return False


def _is_local_pack(pack_name: str, config_path: Path | None) -> bool:
    """Would ``pack_name`` import from the scanned project directory?

    Determined by pure filesystem inspection so that scanning untrusted
    source/config never executes repository code. Earlier revisions called
    ``importlib.util.find_spec`` here, which imports (and runs) the parent
    package of a dotted name — defeating the guard's own purpose. We refuse
    only genuinely-empty components (which can never name an importable module)
    and let every other name fall through to the stat-only walk: a guard whose
    job is to block local execution must fail *closed*, not skip names that
    ``import_module`` could still load (e.g. hyphenated package directories).
    """
    import sys

    parts = pack_name.split(".")
    if not parts or any(not part for part in parts):
        return False

    roots: list[Path] = []
    if config_path is not None:
        roots.append(config_path.parent.resolve())
    roots.append(Path.cwd().resolve())

    for p_str in sys.path:
        try:
            p_path = Path.cwd().resolve() if not p_str else Path(p_str).resolve()
        except Exception:
            continue

        if "site-packages" in p_path.parts or "dist-packages" in p_path.parts:
            continue

        is_local = False
        for root in roots:
            try:
                if p_path == root or p_path.is_relative_to(root):
                    is_local = True
                    break
            except Exception:
                continue

        if is_local and _local_module_path_exists(p_path, parts):
            return True
    return False


def load(
    path: Path | None,
    *,
    trust_local_packs: bool = False,
    trusted_packs: Iterable[str] = (),
    strict_defaults: bool = False,
) -> WardlineConfig:
    if strict_defaults or path is None or not path.exists():
        return WardlineConfig()
    jsonschema = require_jsonschema("validating weft.toml [wardline]")

    # C-9c (normative): a missing OR malformed shared weft.toml is treated as ABSENT —
    # silent fallback to built-in defaults, never a hard fail. weft.toml is shared
    # across the federation, so a parse error (possibly from another member's section,
    # or a structurally-broken [wardline]) must not crash wardline. A WELL-FORMED
    # [wardline] table with bad keys/values still fails loud below (actionable,
    # wardline-specific config feedback — not a "malformed file").
    try:
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
        return WardlineConfig()
    table = parsed.get("wardline")
    if not isinstance(table, dict):
        return WardlineConfig()
    raw = table

    # Load and merge packs config
    packs = raw.get("packs") or []
    if not isinstance(packs, list):
        raise ConfigError(f"packs key in {path.name} must be a list")

    merged_raw = dict(raw)
    trusted_pack_names = frozenset(trusted_packs)
    pack_modules: dict[str, Any] = {}
    for pack_name in packs:
        if not isinstance(pack_name, str):
            raise ConfigError(f"packs list in {path.name} must contain strings only")
        if pack_name not in trusted_pack_names:
            raise ConfigError(
                f"trust-grammar pack {pack_name!r} is not trusted. Pass --trust-pack {pack_name} to allow importing it."
            )
        if not trust_local_packs and _is_local_pack(pack_name, path):
            raise ConfigError(
                f"loading trust-grammar pack {pack_name!r} from local project directory is disabled "
                f"for security. Use trust_local_packs to override."
            )
        try:
            import importlib

            pkg = importlib.import_module(pack_name)
        except ImportError as exc:
            raise ConfigError(f"failed to load trust-grammar pack {pack_name!r}: {exc}") from exc

        pack_modules[pack_name] = pkg
        pack_config = getattr(pkg, "config", None)
        if pack_config is not None:
            if not isinstance(pack_config, dict):
                raise ConfigError(f"pack {pack_name!r} attribute 'config' must be a dictionary")
            merged_raw = _deep_merge(merged_raw, pack_config)

    autofix_raw = merged_raw.get("autofix") or {}
    if isinstance(autofix_raw, Mapping):
        boundary_exception = autofix_raw.get("boundary_exception")
        if isinstance(boundary_exception, str):
            validate_boundary_exception_name(boundary_exception)

    try:
        jsonschema.validate(merged_raw, WARDLINE_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"invalid {path.name} (after merging packs): {exc.message}") from exc

    autofix = dict(autofix_raw)
    boundary_exception = autofix.get("boundary_exception")
    if isinstance(boundary_exception, str):
        validate_boundary_exception_name(boundary_exception)

    rules = merged_raw.get("rules") or {}
    return WardlineConfig(
        source_roots=tuple(merged_raw.get("source_roots") or (".",)),
        exclude=tuple(merged_raw.get("exclude") or ()),
        rules_enable=tuple(rules.get("enable") or ("*",)),
        rules_severity=dict(rules.get("severity") or {}),
        judge=dict(merged_raw.get("judge") or {}),
        packs=tuple(packs),
        pack_modules=pack_modules,
        untrusted_sources=tuple(merged_raw.get("untrusted_sources") or ()),
        sanitisers=tuple(merged_raw.get("sanitisers") or ()),
        provenance_clash=bool(merged_raw.get("provenance_clash") or False),
        autofix=autofix,
    )


_LOOMWEAVE_URL_ENV = "WARDLINE_LOOMWEAVE_URL"
_FILIGREE_URL_ENV = "WARDLINE_FILIGREE_URL"


def _read_published_port(root: Path, sibling: str) -> int | None:
    """Read a sibling's live ``ephemeral.port``, preferring the consolidated
    ``.weft/<sibling>/`` location and tolerating the legacy ``.<sibling>/`` dot-dir
    during the federation transition window. Returns a valid port or ``None``
    (missing / unreadable / malformed / out-of-range) — fail-soft."""
    for base in (sibling_state_dir(root, sibling), legacy_sibling_dir(root, sibling)):
        try:
            raw = (base / "ephemeral.port").read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            continue
        if raw.isdigit() and 1 <= (port := int(raw)) <= 65535:
            return port
    return None


def _loomweave_published_url(root: Path) -> str | None:
    """Loomweave's live read-API origin from its published ``ephemeral.port``.

    Consumer half of Loomweave **ADR-044** (Read-API Ephemeral Port Publication).
    Loomweave writes its live bound port on a successful loopback bind (atomically;
    removed on clean shutdown; present only while serving). We *read* it — never
    derive or guess a port. Prefers ``.weft/loomweave/ephemeral.port`` and falls
    back to the legacy ``.loomweave/ephemeral.port``. Returns
    ``http://127.0.0.1:<port>`` or ``None``; fail-soft falls through to config.

    The host is loopback by construction: ADR-034's ``allow_non_loopback`` bind
    publishes *no* file, so a port-only value can never under-specify the host.
    """
    port = _read_published_port(root, "loomweave")
    return f"http://127.0.0.1:{port}" if port is not None else None


def _filigree_published_url(root: Path) -> str | None:
    """Filigree's live Weft scan-results URL from its published ``ephemeral.port``.

    Twin of :func:`_loomweave_published_url` (Loomweave **ADR-044**): Filigree
    writes its live bound port on a successful loopback bind. We *read* it — never
    derive or guess. Prefers ``.weft/filigree/ephemeral.port`` and falls back to
    the legacy ``.filigree/ephemeral.port``. Fail-soft on any defect.

    Unlike Loomweave's bare-origin contract, Filigree's URL carries the full Weft
    route, so this returns the route-suffixed
    ``http://localhost:<port>/api/weft/scan-results`` (loopback by construction).
    The ``localhost`` host self-heals transparently over an install-stamped literal
    — Filigree's loopback spelling, distinct from Loomweave's ``127.0.0.1``.
    """
    port = _read_published_port(root, "filigree")
    return f"http://localhost:{port}/api/weft/scan-results" if port is not None else None


def resolve_loomweave_url(
    flag: str | None,
    root: Path,
    config_path: Path | None = None,
    *,
    trust_local_packs: bool = False,
    trusted_packs: Iterable[str] = (),
    strict_defaults: bool = False,
) -> str | None:
    """Loomweave URL by precedence: explicit flag > env var > published port.

    Sibling-endpoint *config keys* are NOT read here: a persisted operator-declared
    endpoint is an instance of the still-pending Weft shared-endpoint fact
    (``weft-a2f4cf95c7``), so wardline does not bake a ``[wardline.loomweave].url``
    key. The published-port rung (ADR-044, preferring ``.weft/loomweave/ephemeral.port``
    and tolerating the legacy ``.loomweave/ephemeral.port``) supplies the zero-config
    local case; a flag or env var is the interim escape hatch for a fixed remote.
    Skipped under ``strict_defaults`` (hermetic, no project-derived discovery).

    ``config_path`` / ``trust_local_packs`` / ``trusted_packs`` are accepted for
    caller-shape compatibility (the same surface ``run_scan`` consumes) and reserved
    for the canonical hub endpoint key once its layout is pinned; they are not read
    today, since no sibling-endpoint config rung exists.
    """
    if flag is not None:
        return flag
    env = os.environ.get(_LOOMWEAVE_URL_ENV)
    if env:
        return env
    if not strict_defaults:
        return _loomweave_published_url(root)
    return None


def resolve_filigree_url(
    flag: str | None,
    root: Path,
    config_path: Path | None = None,
    *,
    trust_local_packs: bool = False,
    trusted_packs: Iterable[str] = (),
    strict_defaults: bool = False,
) -> str | None:
    """Filigree Weft URL by precedence: explicit flag > env var > published port.

    Twin of :func:`resolve_loomweave_url`: no ``[wardline.filigree].url`` config key
    is read (pending the hub shared-endpoint schema ``weft-a2f4cf95c7``). The
    published-port rung (ADR-044 twin, preferring ``.weft/filigree/ephemeral.port``,
    tolerating the legacy ``.filigree/ephemeral.port``) carries the full Weft
    scan-results route; flag/env override. Skipped under ``strict_defaults``.

    ``config_path`` / ``trust_local_packs`` / ``trusted_packs`` are accepted for
    caller-shape compatibility and reserved for the canonical hub endpoint key once
    its layout is pinned; they are not read today.
    """
    if flag is not None:
        return flag
    env = os.environ.get(_FILIGREE_URL_ENV)
    if env:
        return env
    if not strict_defaults:
        return _filigree_published_url(root)
    return None


@dataclass(frozen=True, slots=True)
class JudgeSettings:
    model: str = "anthropic/claude-opus-4-8"
    context_lines: int = 30
    max_findings: int | None = None
    policy_file: str | None = None
    # FALSE_POSITIVE verdicts below this confidence are reported but NOT written to
    # judged.yaml (the conservative prior: don't suppress a real defect on a low-
    # confidence guess). Set to 0.0 to write every FP.
    write_confidence_floor: float = 0.5


def parse_judge_settings(raw: Mapping[str, Any]) -> JudgeSettings:
    """Parse the ``judge:`` config section, fail-loud on bad types.

    ``weft.toml [wardline]`` is project-supplied input. ``judge.policy_file`` is parsed
    here as a string only; loading its contents requires an explicit trusted
    caller flag in the judge runner.
    """

    def _int(key: str, default: int | None) -> int | None:
        if key not in raw or raw[key] is None:
            return default
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"judge.{key} must be an integer, got {type(value).__name__}")
        return value

    def _str(key: str, default: str | None) -> str | None:
        if key not in raw or raw[key] is None:
            return default
        value = raw[key]
        if not isinstance(value, str):
            raise ConfigError(f"judge.{key} must be a string, got {type(value).__name__}")
        return value

    model = _str("model", "anthropic/claude-opus-4-8")
    assert model is not None  # default is non-None
    ctx = _int("context_lines", 30)
    assert ctx is not None
    if ctx < 0:
        raise ConfigError(f"judge.context_lines must be >= 0, got {ctx}")
    max_findings = _int("max_findings", None)
    if max_findings is not None and max_findings <= 0:
        raise ConfigError(f"judge.max_findings must be a positive integer, got {max_findings}")
    floor = raw.get("write_confidence_floor")
    if floor is None:
        floor_val = 0.5
    elif isinstance(floor, bool) or not isinstance(floor, int | float):
        raise ConfigError(f"judge.write_confidence_floor must be a number, got {type(floor).__name__}")
    else:
        floor_val = float(floor)
        if not 0.0 <= floor_val <= 1.0:
            raise ConfigError(f"judge.write_confidence_floor must be 0.0..1.0, got {floor_val}")
    return JudgeSettings(
        model=model,
        context_lines=ctx,
        max_findings=max_findings,
        policy_file=_str("policy_file", None),
        write_confidence_floor=floor_val,
    )
