"""Manifest data models — frozen dataclasses for configuration objects.

All manifest models use ``@dataclass(frozen=True)`` because they are
loaded once at scan startup. Mutable manifests risk non-deterministic
behaviour across rules.
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from wardline.core.severity import Exceptionability, GovernancePath, RuleId, Severity
from wardline.core.taints import TaintState

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExceptionEntry:
    """A granted exception to a wardline rule finding."""

    id: str
    rule: RuleId
    taint_state: TaintState
    location: str
    exceptionability: Exceptionability
    severity_at_grant: Severity
    rationale: str
    reviewer: str
    expires: str | None = None
    provenance: str | None = None
    agent_originated: bool | None = None
    ast_fingerprint: str = ""
    recurrence_count: int = 0
    governance_path: GovernancePath = GovernancePath.STANDARD
    last_refreshed_by: str | None = None
    last_refresh_rationale: str | None = None
    last_refreshed_at: str | None = None
    analysis_level: int = 1
    migrated_from: str | None = None
    migrated_by: str | None = None
    elimination_path: str | None = None
    elimination_cost: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rule, RuleId):
            object.__setattr__(self, "rule", RuleId(self.rule))
        if not isinstance(self.taint_state, TaintState):
            object.__setattr__(self, "taint_state", TaintState(self.taint_state))
        if not isinstance(self.exceptionability, Exceptionability):
            object.__setattr__(self, "exceptionability", Exceptionability(self.exceptionability))
        if not isinstance(self.severity_at_grant, Severity):
            object.__setattr__(self, "severity_at_grant", Severity(self.severity_at_grant))


@dataclass(frozen=True)
class FingerprintEntry:
    """Annotation fingerprint for baseline tracking."""

    qualified_name: str
    module: str
    decorators: tuple[str, ...]
    annotation_hash: str
    tier_context: int
    boundary_transition: str | None = None
    last_changed: str | None = None
    artefact_class: str = ""


@dataclass(frozen=True)
class CoverageReport:
    """Annotation coverage statistics."""

    annotated: int
    total: int
    ratio: float
    tier1_annotated: int
    tier1_total: int
    tier1_unannotated: tuple[str, ...] = ()


@dataclass(frozen=True)
class TierEntry:
    """A tier declaration in the manifest."""

    id: str
    tier: int
    description: str = ""


@dataclass(frozen=True)
class ModuleTierEntry:
    """A module-level taint default."""

    path: str
    default_taint: str


@dataclass(frozen=True)
class DependencyTaintEntry:
    """A dependency taint declaration for a third-party function."""

    package: str
    function: str
    returns_taint: TaintState
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.returns_taint, TaintState):
            object.__setattr__(self, "returns_taint", TaintState(self.returns_taint))


@dataclass(frozen=True)
class DelegationGrant:
    """A delegation grant for exception authority."""

    path: str
    authority: str


@dataclass(frozen=True)
class DelegationConfig:
    """Delegation configuration."""

    default_authority: str = "RELAXED"
    grants: tuple[DelegationGrant, ...] = ()


@dataclass(frozen=True)
class RulesConfig:
    """Rules configuration — overrides to the default severity matrix.

    The ``overrides`` tuple contains dicts that are deep-frozen in
    ``__post_init__`` via ``MappingProxyType``, following the same
    pattern as ``ScanContext.function_level_taint_map``.
    """

    overrides: tuple[dict[str, object] | MappingProxyType[str, object], ...] = ()

    def __post_init__(self) -> None:
        # Deep-freeze: convert any mutable dicts inside the tuple to
        # MappingProxyType so the frozen dataclass is truly immutable.
        frozen = tuple(
            MappingProxyType(d) if isinstance(d, dict) else d
            for d in self.overrides
        )
        object.__setattr__(self, "overrides", frozen)


@dataclass(frozen=True)
class TemporalSeparation:
    """Temporal separation alternative declaration (§15.3.2)."""

    alternative: str = "same-actor-with-retrospective"
    retrospective_window_days: int = 10
    rationale: str = ""


@dataclass(frozen=True)
class ManifestMetadata:
    """Manifest metadata — organisational and governance fields."""

    organisation: str = ""
    ratified_by: MappingProxyType[str, str] | None = None
    ratification_date: str | None = None
    review_interval_days: int | None = None
    temporal_separation: TemporalSeparation | None = None

    def __post_init__(self) -> None:
        if isinstance(self.ratified_by, dict):
            object.__setattr__(
                self, "ratified_by", MappingProxyType(self.ratified_by)
            )


@dataclass(frozen=True)
class BoundaryEntry:
    """A boundary declaration in an overlay."""

    function: str
    transition: str
    from_tier: int | None = None
    to_tier: int | None = None
    restored_tier: int | None = None
    provenance: MappingProxyType[str, object] | None = None
    validation_scope: MappingProxyType[str, object] | None = None
    overlay_scope: str = ""
    overlay_path: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.provenance, dict):
            object.__setattr__(
                self, "provenance", MappingProxyType(self.provenance)
            )
        if isinstance(self.validation_scope, dict):
            object.__setattr__(
                self, "validation_scope", MappingProxyType(self.validation_scope)
            )


@dataclass(frozen=True)
class OptionalFieldEntry:
    """An optional-by-contract field declaration from an overlay."""

    field: str
    approved_default: object
    rationale: str
    overlay_scope: str = ""
    overlay_path: str = ""


@dataclass(frozen=True)
class ContractBinding:
    """Binds a named contract to implementing functions."""

    contract: str
    functions: tuple[str, ...]


@dataclass(frozen=True)
class WardlineManifest:
    """Root manifest — trust topology and governance policy."""

    governance_profile: str = "lite"
    tiers: tuple[TierEntry, ...] = ()
    rules: RulesConfig = field(default_factory=RulesConfig)
    delegation: DelegationConfig = field(default_factory=DelegationConfig)
    module_tiers: tuple[ModuleTierEntry, ...] = ()
    dependency_taint: tuple[DependencyTaintEntry, ...] = ()
    metadata: ManifestMetadata = field(default_factory=ManifestMetadata)
    exception_age_limits: MappingProxyType[str, int] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True)
class WardlineOverlay:
    """Overlay — local boundary declarations and rule tuning."""

    overlay_for: str = ""
    boundaries: tuple[BoundaryEntry, ...] = ()
    rule_overrides: tuple[dict[str, object], ...] = ()
    optional_fields: tuple[OptionalFieldEntry, ...] = ()
    contract_bindings: tuple[ContractBinding, ...] = ()


class ScannerConfigError(Exception):
    """Raised when wardline.toml contains invalid configuration."""


# Known keys in the [wardline] section of wardline.toml.
_KNOWN_KEYS: frozenset[str] = frozenset({
    "target_paths",
    "exclude_paths",
    "enabled_rules",
    "disabled_rules",
    "default_taint",
    "analysis_level",
    "max_unknown_raw_percent",
    "allow_registry_mismatch",
    "allow_permissive_distribution",
    "known_validators",
    "known_validators_extra",
    "max_expansion_rounds",
    "strict_governance",
    "governance",
})


@dataclass(frozen=True)
class ScannerConfig:
    """Scanner configuration loaded from ``wardline.toml``.

    Use the ``from_toml()`` factory to load and normalise from a file.
    The factory performs all post-load normalisation (path strings to
    ``pathlib.Path``, rule ID strings to ``RuleId`` enum, taint state
    tokens to ``TaintState`` enum) before constructing the frozen
    dataclass.
    """

    target_paths: tuple[Path, ...] = ()
    exclude_paths: tuple[Path, ...] = ()
    enabled_rules: tuple[RuleId, ...] = ()
    disabled_rules: tuple[RuleId, ...] = ()
    default_taint: TaintState | None = None
    analysis_level: int = 1
    max_unknown_raw_percent: float | None = None
    allow_registry_mismatch: bool = False
    allow_permissive_distribution: bool = False
    known_validators: tuple[str, ...] | None = None
    known_validators_extra: tuple[str, ...] = ()
    max_expansion_rounds: int = 1
    strict_governance: bool = False
    fingerprint_max_age_days: int = 180

    def __post_init__(self) -> None:
        if not (1 <= self.analysis_level <= 3):
            raise ValueError(
                f"analysis_level must be 1, 2, or 3, got {self.analysis_level!r}"
            )
        if self.max_unknown_raw_percent is not None and not (
            0 <= self.max_unknown_raw_percent <= 100
        ):
            raise ValueError(
                f"max_unknown_raw_percent must be 0-100, got {self.max_unknown_raw_percent}"
            )
        if self.max_expansion_rounds < 1:
            raise ValueError("max_expansion_rounds must be >= 1")

    @classmethod
    def from_toml(cls, path: Path) -> ScannerConfig:
        """Load scanner config from a TOML file.

        Uses binary mode (``'rb'``) as required by ``tomllib``.
        Normalises paths, rule IDs, and taint state tokens.
        Raises ``ScannerConfigError`` for unknown keys or invalid values.
        """
        from wardline.core.severity import RuleId
        from wardline.core.taints import TaintState

        with open(path, "rb") as f:
            data = tomllib.load(f)

        try:
            wardline_section = data["wardline"]
        except KeyError:
            wardline_section = data

        # Validate: reject unknown keys
        unknown = set(wardline_section.keys()) - _KNOWN_KEYS
        if unknown:
            raise ScannerConfigError(
                f"unknown keys in wardline.toml: {sorted(unknown)}"
            )

        # Parse and validate target_paths — resolve relative to config
        # file's directory, not CWD, so paths work regardless of where
        # the user invokes ``wardline scan``.
        config_dir = path.resolve().parent
        try:
            _target_paths_raw = wardline_section["target_paths"]
        except KeyError:
            _target_paths_raw = []
        target_paths = tuple(
            (config_dir / p).resolve() if not Path(p).is_absolute() else Path(p)
            for p in _target_paths_raw
        )
        try:
            _exclude_paths_raw = wardline_section["exclude_paths"]
        except KeyError:
            _exclude_paths_raw = []
        exclude_paths = tuple(
            (config_dir / p).resolve() if not Path(p).is_absolute() else Path(p)
            for p in _exclude_paths_raw
        )

        # Parse and validate rule IDs
        enabled_rules: tuple[RuleId, ...] = ()
        try:
            _enabled_rules_raw = wardline_section["enabled_rules"]
        except KeyError:
            _enabled_rules_raw = []
        for r in _enabled_rules_raw:
            try:
                enabled_rules = (*enabled_rules, RuleId(r))
            except ValueError:
                raise ScannerConfigError(
                    f"invalid rule ID in enabled_rules: {r!r}"
                ) from None

        disabled_rules: tuple[RuleId, ...] = ()
        try:
            _disabled_rules_raw = wardline_section["disabled_rules"]
        except KeyError:
            _disabled_rules_raw = []
        for r in _disabled_rules_raw:
            try:
                disabled_rules = (*disabled_rules, RuleId(r))
            except ValueError:
                raise ScannerConfigError(
                    f"invalid rule ID in disabled_rules: {r!r}"
                ) from None

        # Parse and validate default_taint
        raw_taint = wardline_section.get("default_taint")
        default_taint: TaintState | None = None
        if raw_taint:
            try:
                default_taint = TaintState(raw_taint)
            except ValueError:
                raise ScannerConfigError(
                    f"invalid taint state: {raw_taint!r}"
                ) from None

        try:
            analysis_level = wardline_section["analysis_level"]
        except KeyError:
            analysis_level = 1
        if isinstance(analysis_level, bool) or not isinstance(analysis_level, int):
            raise ScannerConfigError(
                f"analysis_level must be 1, 2, or 3, got {analysis_level!r}"
            )
        if not (1 <= analysis_level <= 3):
            raise ScannerConfigError(
                f"analysis_level must be 1, 2, or 3, got {analysis_level!r}"
            )

        # Parse max_unknown_raw_percent
        max_pct = wardline_section.get("max_unknown_raw_percent")
        if max_pct is not None:
            if not isinstance(max_pct, (int, float)):
                raise ScannerConfigError(
                    "max_unknown_raw_percent must be a number, "
                    f"got {type(max_pct).__name__}"
                )
            if max_pct < 0 or max_pct > 100:
                raise ScannerConfigError(
                    f"max_unknown_raw_percent must be 0-100, got {max_pct}"
                )

        known_validators_raw = wardline_section.get("known_validators")
        known_validators_extra_raw = wardline_section.get("known_validators_extra")

        known_validators: tuple[str, ...] | None = None
        known_validators_extra: tuple[str, ...] = ()

        if known_validators_raw is not None:
            if not isinstance(known_validators_raw, list):
                raise ScannerConfigError("known_validators must be a list of strings")
            known_validators = tuple(str(v) for v in known_validators_raw)
            if known_validators_extra_raw is not None:
                logger.warning("known_validators and known_validators_extra both set — known_validators wins")

        if known_validators_extra_raw is not None and known_validators_raw is None:
            if not isinstance(known_validators_extra_raw, list):
                raise ScannerConfigError("known_validators_extra must be a list of strings")
            known_validators_extra = tuple(str(v) for v in known_validators_extra_raw)

        try:
            max_expansion_rounds = int(wardline_section["max_expansion_rounds"])
        except KeyError:
            max_expansion_rounds = 1
        if max_expansion_rounds < 1:
            raise ScannerConfigError("max_expansion_rounds must be >= 1")

        try:
            _allow_registry_mismatch = wardline_section["allow_registry_mismatch"]
        except KeyError:
            _allow_registry_mismatch = False
        try:
            _allow_permissive_distribution = wardline_section["allow_permissive_distribution"]
        except KeyError:
            _allow_permissive_distribution = False
        try:
            _strict_governance = wardline_section["strict_governance"]
        except KeyError:
            _strict_governance = False

        # Parse [governance] section (optional)
        governance_section = wardline_section.get("governance", {})
        if not isinstance(governance_section, dict):
            raise ScannerConfigError("governance must be a table, not a scalar")
        _fp_max_age = governance_section.get("fingerprint_max_age_days", 180)
        if not isinstance(_fp_max_age, int) or isinstance(_fp_max_age, bool):
            raise ScannerConfigError(
                f"governance.fingerprint_max_age_days must be an integer, got {type(_fp_max_age).__name__}"
            )
        if _fp_max_age < 1:
            raise ScannerConfigError(
                f"governance.fingerprint_max_age_days must be >= 1, got {_fp_max_age}"
            )

        return cls(
            target_paths=target_paths,
            exclude_paths=exclude_paths,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            default_taint=default_taint,
            analysis_level=analysis_level,
            max_unknown_raw_percent=max_pct,
            allow_registry_mismatch=bool(_allow_registry_mismatch),
            allow_permissive_distribution=bool(_allow_permissive_distribution),
            known_validators=known_validators,
            known_validators_extra=known_validators_extra,
            max_expansion_rounds=max_expansion_rounds,
            strict_governance=bool(_strict_governance),
            fingerprint_max_age_days=_fp_max_age,
        )
