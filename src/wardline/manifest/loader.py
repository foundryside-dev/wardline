"""YAML manifest loader with alias-bomb protection and schema validation.

Uses a SafeLoader subclass with alias-resolution counting to prevent
YAML bomb denial-of-service. All loading paths (manifest, overlay,
corpus) use this loader.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

import jsonschema
import yaml

from wardline.manifest.models import (
    BoundaryEntry,
    ContractBinding,
    DelegationConfig,
    DelegationGrant,
    DependencyTaintEntry,
    ManifestMetadata,
    ModuleTierEntry,
    OptionalFieldEntry,
    RulesConfig,
    TemporalSeparation,
    TierEntry,
    WardlineManifest,
    WardlineOverlay,
)

_SCHEMA_DIR = Path(__file__).parent / "schemas"

# Expected schema version — compared against document $id
EXPECTED_SCHEMA_VERSION = "1.0"

# File size limit: 1MB
MAX_FILE_SIZE = 1_048_576

# Alias limit defaults
DEFAULT_ALIAS_LIMIT = 1000
HARD_ALIAS_UPPER_BOUND = 10_000


class WardlineYAMLError(yaml.YAMLError):
    """Raised when YAML loading fails due to wardline-specific checks."""


class ManifestLoadError(Exception):
    """Raised when manifest loading fails (file size, schema, version)."""


class ManifestPolicyError(ManifestLoadError):
    """Raised for policy violations that must not be silently skipped.

    Subclass of ManifestLoadError so callers catching the base class
    still see it, but resolve.py can let it propagate while catching
    ordinary ManifestLoadError for I/O-level parse failures.
    """


def make_wardline_loader(
    alias_limit: int = DEFAULT_ALIAS_LIMIT,
) -> type[yaml.SafeLoader]:
    """Create a SafeLoader subclass with alias-resolution counting.

    PyYAML's SafeLoader does not accept constructor kwargs, so we use
    a factory that returns a configured subclass with the limit as a
    class attribute.

    Args:
        alias_limit: Maximum alias resolutions before raising.
            Capped at HARD_ALIAS_UPPER_BOUND to prevent threshold defeat.
    """
    effective_limit = min(alias_limit, HARD_ALIAS_UPPER_BOUND)

    class WardlineSafeLoader(yaml.SafeLoader):
        _alias_limit: int = effective_limit

        def __init__(self, stream: Any) -> None:
            super().__init__(stream)
            self._alias_count: int = 0

        def compose_node(
            self, parent: Any, index: Any
        ) -> yaml.nodes.Node | None:
            if self.check_event(yaml.events.AliasEvent):  # type: ignore[no-untyped-call]
                self._alias_count += 1
                if self._alias_count > self._alias_limit:
                    raise WardlineYAMLError(
                        f"YAML alias limit exceeded ({self._alias_limit}). "
                        f"This may indicate a YAML bomb attack."
                    )
            return super().compose_node(parent, index)

    # Fix the "Norway problem": YAML 1.1 coerces YES/NO/ON/OFF to
    # booleans, silently corrupting taint states and identifiers.
    # Remove the implicit bool resolver and re-add only YAML 1.2
    # strict booleans (true/false).
    import re

    WardlineSafeLoader.yaml_implicit_resolvers = {
        key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
        for key, resolvers in WardlineSafeLoader.yaml_implicit_resolvers.items()
    }
    WardlineSafeLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
        "tag:yaml.org,2002:bool",
        re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
        list("tTfF"),
    )

    return WardlineSafeLoader


def _check_file_size(path: Path) -> None:
    """Raise ManifestLoadError if file exceeds MAX_FILE_SIZE."""
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ManifestLoadError(
            f"File {path} is {size} bytes, exceeding the "
            f"{MAX_FILE_SIZE} byte limit."
        )


def _check_schema_version(data: dict[str, Any], path: Path) -> None:
    """Check $id version against expected scanner version.

    Extracts the version segment from the ``$id`` URL (the path component
    between ``/schemas/`` and the next ``/``) and compares it exactly
    against ``EXPECTED_SCHEMA_VERSION``.  Falls back to substring match
    only when the URL doesn't follow the expected pattern.
    """
    doc_id = data.get("$id", "")
    if not doc_id:
        import logging
        logging.getLogger("wardline").warning(
            "Document %s has no $id — schema version cannot be verified", path
        )
        return

    # Extract version from $id URL: .../schemas/<version>/...
    import re

    m = re.search(r"/schemas/([^/]+)/", doc_id)
    if m:
        doc_version = m.group(1)
        if doc_version != EXPECTED_SCHEMA_VERSION:
            raise ManifestLoadError(
                f"Manifest {path} targets schema version "
                f"'{doc_version}' (from $id '{doc_id}'), this scanner "
                f"bundles version {EXPECTED_SCHEMA_VERSION} — update "
                f"the manifest or upgrade wardline."
            )
    elif EXPECTED_SCHEMA_VERSION not in doc_id:
        # Fallback for non-standard $id formats
        raise ManifestLoadError(
            f"Manifest {path} targets schema version "
            f"'{doc_id}', this scanner bundles version "
            f"{EXPECTED_SCHEMA_VERSION} — update the manifest "
            f"or upgrade wardline."
        )


def _validate_schema(
    data: dict[str, Any], schema_name: str
) -> None:
    """Validate data against a named schema. Raises ManifestLoadError."""
    schema_path = _SCHEMA_DIR / schema_name
    schema = json.loads(schema_path.read_text())
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        raise ManifestLoadError(
            f"Schema validation failed: {e.message}"
        ) from e


def _load_yaml(path: Path, alias_limit: int = DEFAULT_ALIAS_LIMIT) -> Any:
    """Load a YAML file with alias-bomb protection.

    Uses yaml.load() with our SafeLoader subclass — NOT yaml.safe_load()
    which does not accept a Loader parameter.
    """
    _check_file_size(path)
    loader_cls = make_wardline_loader(alias_limit)
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=loader_cls)  # noqa: S506


def load_manifest(
    path: Path,
    alias_limit: int = DEFAULT_ALIAS_LIMIT,
) -> WardlineManifest:
    """Load and validate a wardline root manifest.

    Steps:
    1. File size check (1MB limit)
    2. YAML parse with alias-bomb protection
    3. $id version check
    4. Schema validation
    5. Dataclass construction
    """
    data = _load_yaml(path, alias_limit)
    if not isinstance(data, dict):
        raise ManifestLoadError(
            f"Manifest {path} must be a YAML mapping, got {type(data).__name__}"
        )

    _check_schema_version(data, path)
    _validate_schema(data, "wardline.schema.json")

    # Strip $id before constructing dataclass
    data.pop("$id", None)

    return _build_manifest(data)


def _build_manifest(data: dict[str, Any]) -> WardlineManifest:
    """Construct a WardlineManifest from validated data."""
    tiers = tuple(
        TierEntry(
            id=t["id"],
            tier=t["tier"],
            description=t.get("description", ""),
        )
        for t in data.get("tiers", [])
    )

    module_tiers = tuple(
        ModuleTierEntry(path=m["path"], default_taint=m["default_taint"])
        for m in data.get("module_tiers", [])
    )

    dependency_taint = tuple(
        DependencyTaintEntry(
            package=d["package"],
            function=d["function"],
            returns_taint=d["returns_taint"],
            rationale=d["rationale"],
        )
        for d in data.get("dependency_taint", [])
    )

    raw_delegation = data.get("delegation", {})
    delegation = DelegationConfig(
        default_authority=raw_delegation.get("default_authority", "RELAXED"),
        grants=tuple(
            DelegationGrant(path=g["path"], authority=g["authority"])
            for g in raw_delegation.get("grants", [])
        ),
    )

    raw_rules = data.get("rules", {})
    rules = RulesConfig(
        overrides=tuple(raw_rules.get("overrides", [])),
    )

    raw_meta = data.get("metadata", {})

    # Build TemporalSeparation with conditional validation
    ts_data = raw_meta.get("temporal_separation")
    temporal_separation = None
    if ts_data is not None:
        alt = ts_data["alternative"]
        if alt == "same-actor-with-retrospective":
            if "retrospective_window_days" not in ts_data:
                raise ManifestLoadError(
                    "temporal_separation: retrospective_window_days required "
                    "when alternative is same-actor-with-retrospective"
                )
            if not ts_data.get("rationale"):
                raise ManifestLoadError(
                    "temporal_separation: rationale required "
                    "when alternative is same-actor-with-retrospective"
                )
            temporal_separation = TemporalSeparation(
                alternative=alt,
                retrospective_window_days=ts_data["retrospective_window_days"],
                rationale=ts_data["rationale"],
            )
        elif alt == "enforced":
            if "retrospective_window_days" in ts_data or "rationale" in ts_data:
                raise ManifestLoadError(
                    "temporal_separation: retrospective_window_days and rationale "
                    "must not be present when alternative is enforced"
                )
            temporal_separation = TemporalSeparation(alternative="enforced")

    metadata = ManifestMetadata(
        organisation=raw_meta.get("organisation", ""),
        ratified_by=raw_meta.get("ratified_by"),
        ratification_date=raw_meta.get("ratification_date"),
        review_interval_days=raw_meta.get("review_interval_days"),
        temporal_separation=temporal_separation,
    )

    raw_age_limits = data.get("exception_age_limits", {})
    exception_age_limits = MappingProxyType(raw_age_limits) if raw_age_limits else MappingProxyType({})

    return WardlineManifest(
        governance_profile=data.get("governance_profile", "lite"),
        tiers=tiers,
        rules=rules,
        delegation=delegation,
        module_tiers=module_tiers,
        dependency_taint=dependency_taint,
        metadata=metadata,
        exception_age_limits=exception_age_limits,
    )


def load_overlay(
    path: Path,
    alias_limit: int = DEFAULT_ALIAS_LIMIT,
) -> WardlineOverlay:
    """Load and validate a wardline overlay file."""
    data = _load_yaml(path, alias_limit)
    if not isinstance(data, dict):
        raise ManifestLoadError(
            f"Overlay {path} must be a YAML mapping, got {type(data).__name__}"
        )

    _check_schema_version(data, path)
    _validate_schema(data, "overlay.schema.json")

    data.pop("$id", None)

    return _build_overlay(data)


def reject_skip_promotions(boundaries: Iterable[dict[str, Any]]) -> None:
    """Reject boundaries with to_tier=1 from any from_tier other than 2.

    Raises ``ManifestPolicyError`` on the first invalid boundary found.
    Called by both ``_build_overlay()`` and ``_load_resolved()`` to enforce
    the skip-promotion invariant (§14.1.2) regardless of load path.
    """
    for b in boundaries:
        to_tier = b.get("to_tier")
        if to_tier == 1 and b.get("transition") != "restoration":
            from_tier = b.get("from_tier")
            if from_tier != 2:
                raise ManifestPolicyError(
                    f"Boundary '{b.get('function', '<unknown>')}' declares "
                    f"from_tier={from_tier}, to_tier=1 — skip-promotions to "
                    f"Tier 1 are prohibited. Use composed steps: "
                    f"validation to T2, then T2→T1 construction (§14.1.2)."
                )


def _build_overlay(data: dict[str, Any]) -> WardlineOverlay:
    """Construct a WardlineOverlay from validated data."""
    reject_skip_promotions(data.get("boundaries", []))

    boundaries = tuple(
        BoundaryEntry(
            function=b["function"],
            transition=b["transition"],
            from_tier=b.get("from_tier"),
            to_tier=None if b["transition"] == "restoration" else b.get("to_tier"),
            restored_tier=b.get("restored_tier"),
            provenance=b.get("provenance"),
            validation_scope=b.get("validation_scope"),
        )
        for b in data.get("boundaries", [])
    )

    contract_bindings = tuple(
        ContractBinding(
            contract=cb["contract"],
            functions=tuple(cb["functions"]),
        )
        for cb in data.get("contract_bindings", [])
    )

    return WardlineOverlay(
        overlay_for=data.get("overlay_for", ""),
        boundaries=boundaries,
        rule_overrides=tuple(data.get("rule_overrides", [])),
        optional_fields=tuple(
            OptionalFieldEntry(
                field=entry["field"],
                approved_default=entry["approved_default"],
                rationale=entry["rationale"],
            )
            for entry in data.get("optional_fields", [])
        ),
        contract_bindings=contract_bindings,
    )
