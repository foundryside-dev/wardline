# src/wardline/core/ruleset.py
"""Effective-scan-policy identity (``ruleset_hash``) — a low-tier, dependency-free home.

``ruleset_hash`` derives a deterministic ``"sha256:<hex>"`` over the *effective scan
policy*: the analyzer version, source scope, excludes, rule enablement/severity,
provenance policy, custom source/sanitiser trust semantics, and trusted-pack
identity/config/grammar. Two scans (or two attestations) sharing a hash were shaped by
the same policy inputs that materially affect taint results.

This module lives BELOW both the taint engine and the attestation layer on purpose. The
engine's project resolver and parse pipeline need the policy hash to key their summary
cache, and the attestation builder needs it for the signed payload — but ``core.attest``
sits ABOVE the engine (it imports ``core.run``, which drives a scan), so the engine must
not reach UP into ``core.attest`` for the hash. Housing ``ruleset_hash`` here lets both
sides import DOWN without an engine→attest layering inversion (formerly masked by a
function-local deferred import in ``scanner.taint.project_resolver``).

Zero-dependency: stdlib only, plus ``wardline._version`` and a TYPE_CHECKING-only
reference to :class:`wardline.core.config.WardlineConfig` (so this module pulls in no
config/engine/attest code at import time).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

from wardline._version import __version__

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig


def _file_sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _module_origin(module: ModuleType) -> Path | None:
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None) or getattr(module, "__file__", None)
    if not isinstance(origin, str) or origin in {"built-in", "frozen"}:
        return None
    return Path(origin)


def _callable_policy_identity(value: Any) -> dict[str, Any]:
    code = getattr(value, "__code__", None)
    code_hash = None
    if code is not None:
        digest = hashlib.sha256()
        digest.update(code.co_code)
        digest.update(repr(code.co_consts).encode("utf-8", "backslashreplace"))
        digest.update(repr(code.co_names).encode("utf-8", "backslashreplace"))
        digest.update(repr(code.co_varnames).encode("utf-8", "backslashreplace"))
        code_hash = digest.hexdigest()
    return {
        "module": getattr(value, "__module__", None),
        "qualname": getattr(value, "__qualname__", getattr(value, "__name__", repr(value))),
        "code_sha256": code_hash,
    }


def _class_policy_identity(value: type) -> dict[str, Any]:
    source_path = None
    try:
        import inspect

        source = inspect.getsourcefile(value)
        source_path = Path(source) if source is not None else None
    except (OSError, TypeError):
        source_path = None
    return {
        "module": getattr(value, "__module__", None),
        "qualname": getattr(value, "__qualname__", value.__name__),
        "rule_id": getattr(value, "rule_id", None),
        "source_sha256": _file_sha256(source_path),
    }


def _jsonable_policy_value(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _jsonable_policy_value(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, tuple | list):
        return [_jsonable_policy_value(v) for v in value]
    if isinstance(value, set | frozenset):
        rendered = [_jsonable_policy_value(v) for v in value]
        return sorted(rendered, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if isinstance(value, type):
        return _class_policy_identity(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _jsonable_policy_value(getattr(value, field.name)) for field in fields(value)}
    if callable(value):
        return _callable_policy_identity(value)
    return repr(value)


def _pack_policy_identity(name: str, module: Any) -> dict[str, Any]:
    if not isinstance(module, ModuleType):
        return {"name": name, "loaded": False, "module_repr": repr(module)}
    origin = _module_origin(module)
    return {
        "name": name,
        "loaded": True,
        "module": getattr(module, "__name__", name),
        "version": getattr(module, "__version__", None),
        "source_sha256": _file_sha256(origin),
        "config": _jsonable_policy_value(getattr(module, "config", None)),
        "grammar": _jsonable_policy_value(getattr(module, "grammar", None)),
    }


def _effective_scan_policy(config: WardlineConfig) -> dict[str, Any]:
    return {
        "schema": "wardline-effective-scan-policy-v1",
        "wardline_version": __version__,
        "source_roots": list(config.source_roots),
        "exclude": list(config.exclude),
        "rules": {
            "enable": sorted(config.rules_enable),
            "severity": {str(k): str(v) for k, v in sorted(config.rules_severity.items())},
        },
        "provenance_clash": config.provenance_clash,
        "untrusted_sources": sorted(config.untrusted_sources),
        "sanitisers": sorted(config.sanitisers),
        "packs": [_pack_policy_identity(name, config.pack_modules.get(name)) for name in config.packs],
    }


def ruleset_hash(config: WardlineConfig) -> str:
    """A deterministic ``"sha256:<hex>"`` over the effective scan policy.

    The signed identity covers the analyzer version, source scope, excludes, rule
    enablement/severity, provenance policy, custom source/sanitiser trust semantics,
    and trusted pack identity/config/grammar. Two attestations with the same hash are
    therefore comparable evidence bundles under the policy inputs that materially shape
    scan results.
    """
    canonical = json.dumps(_effective_scan_policy(config), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
