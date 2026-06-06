"""wardline.yaml loader. Uses the `scanner` extra (pyyaml + jsonschema)."""

from __future__ import annotations

import keyword
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wardline.core.config_schema import WARDLINE_SCHEMA
from wardline.core.errors import ConfigError
from wardline.core.optional_deps import require_jsonschema, require_yaml


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
    baseline: Mapping[str, Any] = field(default_factory=dict)
    waivers: tuple[Mapping[str, Any], ...] = ()
    judge: Mapping[str, Any] = field(default_factory=dict)
    filigree: Mapping[str, Any] = field(default_factory=dict)
    loomweave: Mapping[str, Any] = field(default_factory=dict)
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

    @property
    def loomweave_url(self) -> str | None:
        value = self.loomweave.get("url")
        return value if isinstance(value, str) else None

    @property
    def filigree_url(self) -> str | None:
        value = self.filigree.get("url")
        return value if isinstance(value, str) else None


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
    yaml = require_yaml("loading wardline.yaml")
    jsonschema = require_jsonschema("validating wardline.yaml")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path.name} must be a mapping at top level")

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
        baseline=dict(merged_raw.get("baseline") or {}),
        waivers=tuple(merged_raw.get("waivers") or ()),
        judge=dict(merged_raw.get("judge") or {}),
        filigree=dict(merged_raw.get("filigree") or {}),
        loomweave=dict(merged_raw.get("loomweave") or {}),
        packs=tuple(packs),
        pack_modules=pack_modules,
        untrusted_sources=tuple(merged_raw.get("untrusted_sources") or ()),
        sanitisers=tuple(merged_raw.get("sanitisers") or ()),
        provenance_clash=bool(merged_raw.get("provenance_clash") or False),
        autofix=autofix,
    )


_LOOMWEAVE_URL_ENV = "WARDLINE_LOOMWEAVE_URL"
_FILIGREE_URL_ENV = "WARDLINE_FILIGREE_URL"


def _config_for(
    root: Path,
    config_path: Path | None,
    *,
    trust_local_packs: bool = False,
    trusted_packs: Iterable[str] = (),
    strict_defaults: bool = False,
) -> WardlineConfig:
    return load(
        config_path if config_path is not None else root / "wardline.yaml",
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )


def _loomweave_published_url(root: Path) -> str | None:
    """Read Loomweave's live read-API port from ``<root>/.loomweave/ephemeral.port``.

    Consumer half of Loomweave **ADR-044** (Read-API Ephemeral Port Publication).
    Loomweave writes its live bound port to this file on a successful loopback
    bind (atomically; removed on clean shutdown; present only while serving). We
    *read* it — never derive or guess a port from any band formula. Returns
    ``http://127.0.0.1:<port>`` or ``None`` (missing / unreadable / malformed /
    out-of-range). Fail-soft: any defect falls through to the configured URL.

    The host is loopback by construction: ADR-034's ``allow_non_loopback`` bind
    publishes *no* file, so a port-only value can never under-specify the host.
    """
    port_file = root / ".loomweave" / "ephemeral.port"
    try:
        raw = port_file.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not raw.isdigit():
        return None
    port = int(raw)
    if not (1 <= port <= 65535):
        return None
    return f"http://127.0.0.1:{port}"


def _filigree_published_url(root: Path) -> str | None:
    """Read Filigree's live Weft port from ``<root>/.filigree/ephemeral.port``.

    Twin of :func:`_loomweave_published_url` (Loomweave **ADR-044**, Read-API
    Ephemeral Port Publication): Filigree writes its live bound port to this file
    on a successful loopback bind (same single-ASCII-integer format). We *read*
    it — never derive or guess a port. Fail-soft: any defect (missing /
    unreadable / malformed / out-of-range) falls through to the configured URL.

    Unlike Loomweave's bare-origin contract, Filigree's URL carries the full
    Weft route: ``install/detect.py`` writes ``filigree.url`` as
    ``…/api/weft/scan-results`` and ``core/filigree_issue.py`` derives sibling
    routes (promote, api-base) from it, so this returns the route-suffixed
    ``http://localhost:<port>/api/weft/scan-results`` (loopback by construction).
    The host matches ``install/detect.py``'s writer (``localhost``), so a live
    published port self-heals transparently over the install-stamped literal —
    Filigree's loopback spelling, distinct from Loomweave's ``127.0.0.1``.
    """
    port_file = root / ".filigree" / "ephemeral.port"
    try:
        raw = port_file.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not raw.isdigit():
        return None
    port = int(raw)
    if not (1 <= port <= 65535):
        return None
    return f"http://localhost:{port}/api/weft/scan-results"


def _is_safe_url(url: str | None) -> bool:
    if not url:
        return True
    try:
        from urllib.parse import urlsplit

        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if hostname in ("localhost", "127.0.0.1", "::1"):
            return True
    except Exception:
        pass
    return False


def resolve_loomweave_url(
    flag: str | None,
    root: Path,
    config_path: Path | None = None,
    *,
    trust_local_packs: bool = False,
    trusted_packs: Iterable[str] = (),
    trust_config_urls: bool = False,
    strict_defaults: bool = False,
) -> str | None:
    """Loomweave URL by precedence: explicit flag > env var > published port > wardline.yaml.

    The published ``.loomweave/ephemeral.port`` rung (ADR-044) lets a live serve's
    real port beat a stale/default literal in ``wardline.yaml`` (self-heal), while
    a deliberate flag or env target always wins. Skipped under ``strict_defaults``,
    which asks for hermetic defaults with no project-derived discovery.
    """
    if flag is not None:
        return flag
    env = os.environ.get(_LOOMWEAVE_URL_ENV)
    if env:
        return env
    if not strict_defaults:
        published = _loomweave_published_url(root)
        if published is not None:
            return published
    url = _config_for(
        root,
        config_path,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    ).loomweave_url
    if url and not trust_config_urls and not _is_safe_url(url):
        raise ConfigError(
            f"Loading Loomweave URL {url!r} from project config is disabled by default for security. "
            "Specify the URL via command-line flags, environment variables, or allow local config URLs."
        )
    return url


def resolve_filigree_url(
    flag: str | None,
    root: Path,
    config_path: Path | None = None,
    *,
    trust_local_packs: bool = False,
    trusted_packs: Iterable[str] = (),
    trust_config_urls: bool = False,
    strict_defaults: bool = False,
) -> str | None:
    """Filigree Weft URL by precedence: explicit flag > env var > published port > wardline.yaml.

    The published ``.filigree/ephemeral.port`` rung (ADR-044 twin) lets a live
    dashboard's real port beat a stale/default literal in ``wardline.yaml``
    (self-heal), while a deliberate flag or env target always wins. The published
    value carries the full Weft scan-results route. Skipped under
    ``strict_defaults``, which asks for hermetic defaults with no project-derived
    discovery.
    """
    if flag is not None:
        return flag
    env = os.environ.get(_FILIGREE_URL_ENV)
    if env:
        return env
    if not strict_defaults:
        published = _filigree_published_url(root)
        if published is not None:
            return published
    url = _config_for(
        root,
        config_path,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    ).filigree_url
    if url and not trust_config_urls and not _is_safe_url(url):
        raise ConfigError(
            f"Loading Filigree URL {url!r} from project config is disabled by default for security. "
            "Specify the URL via command-line flags, environment variables, or allow local config URLs."
        )
    return url


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

    ``wardline.yaml`` is project-supplied input. ``judge.policy_file`` is parsed
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
