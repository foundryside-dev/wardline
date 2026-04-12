"""Load and verify BAR policy trees from the published governance docs."""

from __future__ import annotations

import importlib.abc
import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from types import ModuleType

from wardline.bar.models import LoadedBarPolicy, LoadedBarSkillPack

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_POLICY_TREES_ROOT: Path = _REPO_ROOT / "docs" / "governance" / "bar-policy"


class BarPolicyError(Exception):
    """Raised when a BAR policy tree cannot be loaded safely."""


def describe_policy_runtime(policy: LoadedBarPolicy) -> dict[str, object]:
    """Project the loaded policy tree into stable runtime-facing metadata."""
    model_id = _optional_str(policy.model_pin.get("model_id"))
    return {
        "pipeline_name": policy.pipeline_name,
        "policy_version": policy.version,
        "policy_hash": policy.policy_hash,
        "skill_pack": {
            "skill_pack_id": policy.skill_pack.skill_pack_id,
            "skill_pack_version": policy.skill_pack.skill_pack_version,
            "assets": list(policy.skill_pack.assets),
        },
        "model": {
            "provider": provider_name_for_model_id(model_id),
            "model_id": model_id,
            "temperature": policy.model_pin.get("temperature"),
            "top_p": policy.model_pin.get("top_p"),
            "seed": policy.model_pin.get("seed"),
            "max_output_tokens": policy.model_pin.get("max_output_tokens"),
        },
        "guardrails": {
            "timeout_seconds": policy.model_pin.get("timeout_seconds"),
            "max_retries": policy.model_pin.get("max_retries"),
        },
    }


def load_policy_tree(version: str | None = None) -> LoadedBarPolicy:
    """Load the requested BAR policy tree and verify its recorded policy hash."""
    root = _resolve_policy_root(version)
    version_path = root / "version.json"
    version_data = _read_json_object(version_path, label="version.json")

    pipeline_version = _require_str(version_data, "pipeline_version", source=version_path)
    pipeline_name = _require_str(version_data, "pipeline_name", source=version_path)
    expected_policy_hash = _require_str(version_data, "policy_hash", source=version_path)
    policy_hash_algorithm = _require_str(version_data, "policy_hash_algorithm", source=version_path)
    if policy_hash_algorithm != "sha256":
        raise BarPolicyError(
            f"{version_path} declares unsupported policy_hash_algorithm {policy_hash_algorithm!r}"
        )
    if root.name != pipeline_version:
        raise BarPolicyError(
            f"{version_path} declares pipeline_version {pipeline_version!r} "
            f"but lives under {root.name!r}"
        )

    model_pin_path = root / "model-pin.json"
    model_pin = _read_json_object(model_pin_path, label="model-pin.json")
    skill_pack = _load_skill_pack(root)

    aggregation_path = root / "aggregation.py"
    if not aggregation_path.is_file():
        raise BarPolicyError(f"missing BAR aggregation module: {aggregation_path}")

    module_name = _module_name_for_version(pipeline_version)
    aggregation_module = _import_module(aggregation_path, module_name)
    compute_policy_hash = getattr(aggregation_module, "compute_policy_hash", None)
    if not callable(compute_policy_hash):
        raise BarPolicyError(
            f"{aggregation_path} does not define callable compute_policy_hash(policy_tree_root)"
        )

    actual_policy_hash = compute_policy_hash(root)
    if not isinstance(actual_policy_hash, str):
        raise BarPolicyError(
            f"{aggregation_path} returned non-string policy hash {type(actual_policy_hash).__name__}"
        )
    if actual_policy_hash != expected_policy_hash:
        raise BarPolicyError(
            "policy hash mismatch: "
            f"expected {expected_policy_hash}, got {actual_policy_hash} for {root}"
        )

    panel_roles = getattr(aggregation_module, "PANEL_ROLES", None)
    if not isinstance(panel_roles, tuple) or not all(isinstance(role, str) for role in panel_roles):
        raise BarPolicyError(f"{aggregation_path} does not define PANEL_ROLES as tuple[str, ...]")

    return LoadedBarPolicy(
        version=pipeline_version,
        root=root,
        pipeline_name=pipeline_name,
        policy_hash=actual_policy_hash,
        model_pin=model_pin,
        skill_pack=skill_pack,
        aggregation_module=aggregation_module,
        panel_roles=panel_roles,
    )


def _resolve_policy_root(version: str | None) -> Path:
    if version is not None:
        root = _POLICY_TREES_ROOT / version
        if not root.is_dir():
            raise BarPolicyError(f"BAR policy tree not found for version {version!r}: {root}")
        return root

    candidates: list[tuple[str, Path]] = []
    if not _POLICY_TREES_ROOT.is_dir():
        raise BarPolicyError(f"BAR policy tree root does not exist: {_POLICY_TREES_ROOT}")

    for root in sorted(path for path in _POLICY_TREES_ROOT.iterdir() if path.is_dir()):
        version_path = root / "version.json"
        if not version_path.is_file():
            continue
        version_data = _read_json_object(version_path, label="version.json")
        deprecated = version_data.get("deprecated", False)
        superseded_by = version_data.get("superseded_by")
        if deprecated is True or superseded_by not in (None, ""):
            continue
        pipeline_version = _require_str(version_data, "pipeline_version", source=version_path)
        candidates.append((pipeline_version, root))

    if not candidates:
        raise BarPolicyError(f"no active BAR policy tree found under {_POLICY_TREES_ROOT}")
    if len(candidates) > 1:
        candidate_versions = ", ".join(version for version, _root in candidates)
        raise BarPolicyError(f"multiple active BAR policy trees found: {candidate_versions}")
    return candidates[0][1]


def _read_json_object(path: Path, *, label: str) -> dict[str, object]:
    if not path.is_file():
        raise BarPolicyError(f"missing BAR {label}: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BarPolicyError(f"unable to read BAR {label} at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise BarPolicyError(f"BAR {label} at {path} must contain a JSON object")
    return data


def provider_name_for_model_id(model_id: str | None) -> str | None:
    """Infer the provider name from the pinned model identifier."""
    if model_id is None:
        return None
    if model_id.startswith("openrouter/"):
        return "openrouter"
    if model_id.startswith("anthropic/") or model_id.startswith("claude-"):
        return "anthropic"
    if model_id.startswith("openai/") or model_id.startswith("gpt-"):
        return "openai"
    return None


def _load_skill_pack(root: Path) -> LoadedBarSkillPack:
    manifest_path = root / "skill-pack.json"
    manifest = _read_json_object(manifest_path, label="skill-pack.json")
    skill_pack_id = _require_str(manifest, "skill_pack_id", source=manifest_path)
    skill_pack_version = _require_str(manifest, "skill_pack_version", source=manifest_path)
    resolved_root = root.resolve()

    assets_value = manifest.get("assets")
    if not isinstance(assets_value, list) or not assets_value:
        raise BarPolicyError(f"{manifest_path} must define non-empty list field 'assets'")

    assets: list[str] = []
    seen: set[str] = set()
    content_chunks: list[str] = []
    for index, asset_value in enumerate(assets_value, start=1):
        if not isinstance(asset_value, str) or asset_value == "":
            raise BarPolicyError(
                f"{manifest_path} asset #{index} must be a non-empty relative path string"
            )
        if asset_value in seen:
            raise BarPolicyError(f"{manifest_path} contains duplicate skill-pack asset {asset_value!r}")
        asset_path = (root / asset_value).resolve()
        try:
            asset_path.relative_to(resolved_root)
        except ValueError as exc:
            raise BarPolicyError(f"{manifest_path} asset {asset_value!r} escapes policy root") from exc
        if not asset_path.is_file():
            raise BarPolicyError(f"missing BAR skill-pack asset {asset_path}")
        assets.append(asset_value)
        seen.add(asset_value)
        try:
            content_chunks.append(asset_path.read_text(encoding="utf-8").strip())
        except OSError as exc:
            raise BarPolicyError(f"unable to read BAR skill-pack asset {asset_path}: {exc}") from exc

    return LoadedBarSkillPack(
        skill_pack_id=skill_pack_id,
        skill_pack_version=skill_pack_version,
        assets=tuple(assets),
        content="\n\n".join(chunk for chunk in content_chunks if chunk),
    )


def _require_str(data: dict[str, object], key: str, *, source: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or value == "":
        raise BarPolicyError(f"{source} must define non-empty string field {key!r}")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


def _module_name_for_version(version: str) -> str:
    sanitized = "".join(character if character.isalnum() else "_" for character in version)
    return f"wardline_bar_policy_{sanitized}"


def _import_module(module_path: Path, module_name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise BarPolicyError(f"unable to construct import spec for BAR policy module {module_path}")
    module = importlib.util.module_from_spec(spec)
    loader = spec.loader
    try:
        loader.exec_module(module)
    except OSError as exc:
        raise BarPolicyError(f"unable to import BAR policy module {module_path}: {exc}") from exc
    return module
