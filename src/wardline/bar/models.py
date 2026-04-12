"""BAR policy-tree data models."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType, ModuleType
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from pathlib import Path


def freeze_value(value: object) -> object:
    """Recursively freeze JSON-like structures for deterministic bundle inputs."""
    if isinstance(value, dict):
        return MappingProxyType({key: freeze_value(inner) for key, inner in value.items()})
    if isinstance(value, list):
        return tuple(freeze_value(inner) for inner in value)
    return value


@dataclass(frozen=True)
class LoadedBarSkillPack:
    """Versioned BAR reviewer skill-pack loaded from the active policy tree."""

    skill_pack_id: str
    skill_pack_version: str
    assets: tuple[str, ...]
    content: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "assets", tuple(self.assets))


@dataclass(frozen=True)
class LoadedBarPolicy:
    """A BAR policy tree loaded from the published governance docs."""

    version: str
    root: Path
    pipeline_name: str
    policy_hash: str
    model_pin: MappingProxyType[str, object] | dict[str, object]
    skill_pack: LoadedBarSkillPack
    aggregation_module: ModuleType
    panel_roles: tuple[str, ...]

    def __post_init__(self) -> None:
        if isinstance(self.model_pin, dict):
            object.__setattr__(self, "model_pin", MappingProxyType(self.model_pin))
        object.__setattr__(self, "panel_roles", tuple(self.panel_roles))


@dataclass(frozen=True)
class ResolvedSourceRef:
    """A deterministic excerpt resolved from a ledger ``source_refs`` entry."""

    source_ref: str
    path: str
    selector: str
    excerpt: str


@dataclass(frozen=True)
class ResolvedFileContent:
    """Repository content captured at the reviewed commit."""

    path: str
    content: str


@dataclass(frozen=True)
class EvidenceOutput:
    """Captured evidence output for a single ledger evidence-class entry."""

    class_name: str
    target: str
    status: Literal["ok", "unsupported", "error"]
    mode: Literal["command_result", "file_snapshot", "git_history", "refusal"]
    summary: str
    content: str
    note: str | None = None
    command: tuple[str, ...] = ()
    exit_code: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", tuple(self.command))


@dataclass(frozen=True)
class BarReviewBundle:
    """Frozen BAR review inputs for one obligation at one commit identity."""

    obligation_id: str
    obligation_record: MappingProxyType[str, object] | dict[str, object]
    source_refs_content: tuple[ResolvedSourceRef, ...]
    implementation_surface_content: tuple[ResolvedFileContent, ...]
    evidence_class_outputs: tuple[EvidenceOutput, ...]
    commit_ref: str
    manifest_hash: str
    corpus_hash: str | None
    policy_hash: str

    def __post_init__(self) -> None:
        if isinstance(self.obligation_record, dict):
            object.__setattr__(self, "obligation_record", freeze_value(self.obligation_record))
        object.__setattr__(self, "source_refs_content", tuple(self.source_refs_content))
        object.__setattr__(self, "implementation_surface_content", tuple(self.implementation_surface_content))
        object.__setattr__(self, "evidence_class_outputs", tuple(self.evidence_class_outputs))
