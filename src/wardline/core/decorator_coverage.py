"""Decorator coverage report for trust-annotated entities.

This is the row-level sibling of ``assure``: ``assure`` gives the rollup, while this
module lists every declared trust-surface entity with its current verdict, findings,
identity, and optional open-work state.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from wardline.core.dossier import WorkProvider, WorkSection, classify_entity_trust
from wardline.core.finding import Kind, SuppressionState
from wardline.core.identity import ContentStatus, EntityBinding, IdentityStatus
from wardline.core.run import run_scan

if TYPE_CHECKING:
    from wardline.core.run import ScanResult
    from wardline.scanner.context import AnalysisContext
    from wardline.scanner.index import Entity


class BindingProvider(Protocol):
    """Optional identity source for one qualname."""

    def binding_for(self, qualname: str) -> EntityBinding | None: ...


@dataclass(frozen=True, slots=True)
class IdentityCoverage:
    available: bool
    locator: str
    sei: str | None
    identity_status: IdentityStatus
    content_status: ContentStatus
    content_hash: str | None
    reason: str | None = None

    @classmethod
    def unavailable(cls, locator: str, reason: str) -> IdentityCoverage:
        return cls(
            available=False,
            locator=locator,
            sei=None,
            identity_status=IdentityStatus.UNAVAILABLE,
            content_status=ContentStatus.UNKNOWN,
            content_hash=None,
            reason=reason,
        )

    @classmethod
    def from_binding(cls, binding: EntityBinding) -> IdentityCoverage:
        return cls(
            available=binding.sei is not None,
            locator=binding.locator,
            sei=binding.sei,
            identity_status=binding.identity,
            content_status=binding.content,
            content_hash=binding.content_hash,
            reason=None if binding.sei is not None else "no SEI resolved",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "locator": self.locator,
            "sei": self.sei,
            "identity_status": self.identity_status.value,
            "content_status": self.content_status.value,
            "content_hash": self.content_hash,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class DecoratorCoverageRow:
    qualname: str
    path: str | None
    line: int | None
    decorators: list[str]
    declared_tier: str | None
    actual_tier: str | None
    verdict: str
    finding_state: str
    active_finding_fingerprints: list[str] = field(default_factory=list)
    suppressed_finding_fingerprints: list[str] = field(default_factory=list)
    identity: IdentityCoverage | None = None
    work: WorkSection | None = None

    def to_dict(self) -> dict[str, Any]:
        identity = self.identity or IdentityCoverage.unavailable(
            _locator_for(self.qualname), "loomweave not configured"
        )
        work = self.work or WorkSection.unavailable("filigree not configured")
        return {
            "qualname": self.qualname,
            "path": self.path,
            "line": self.line,
            "decorators": list(self.decorators),
            "declared_tier": self.declared_tier,
            "actual_tier": self.actual_tier,
            "verdict": self.verdict,
            "finding_state": self.finding_state,
            "active_finding_fingerprints": list(self.active_finding_fingerprints),
            "suppressed_finding_fingerprints": list(self.suppressed_finding_fingerprints),
            "identity": identity.to_dict(),
            "work": work.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class DecoratorCoverageReport:
    rows: list[DecoratorCoverageRow]

    @property
    def summary(self) -> dict[str, int]:
        total = len(self.rows)
        clean = sum(1 for row in self.rows if row.finding_state == "clean")
        defect = sum(1 for row in self.rows if row.finding_state == "defect")
        unknown = sum(1 for row in self.rows if row.finding_state == "unknown")
        suppressed = sum(1 for row in self.rows if row.finding_state == "suppressed")
        return {
            "total": total,
            "clean": clean,
            "defect": defect,
            "unknown": unknown,
            "suppressed": suppressed,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"summary": self.summary, "rows": [row.to_dict() for row in self.rows]}


def _locator_for(qualname: str) -> str:
    return f"python:function:{qualname}"


def _decorators_of(entity: Entity) -> list[str]:
    return [f"@{ast.unparse(dec)}" for dec in entity.node.decorator_list]


def _identity_for(provider: BindingProvider | None, qualname: str) -> tuple[IdentityCoverage, EntityBinding | None]:
    locator = _locator_for(qualname)
    if provider is None:
        return IdentityCoverage.unavailable(locator, "loomweave not configured"), None
    try:
        binding = provider.binding_for(qualname)
    except Exception as exc:
        return IdentityCoverage.unavailable(locator, f"loomweave unreachable: {exc}"), None
    if binding is None:
        return IdentityCoverage.unavailable(locator, "loomweave returned no identity"), None
    return IdentityCoverage.from_binding(binding), binding


def _work_for(provider: WorkProvider | None, binding: EntityBinding | None) -> WorkSection:
    if provider is None:
        return WorkSection.unavailable("filigree not configured")
    if binding is None or binding.sei is None:
        return WorkSection.unavailable("no entity binding: cannot resolve work")
    try:
        section = provider.work(binding)
    except Exception as exc:
        return WorkSection.unavailable(f"source unreachable: {exc}")
    return section if section is not None else WorkSection.unavailable("source returned no data")


def _finding_state(verdict: str, active: list[str], suppressed: list[str]) -> str:
    if active:
        return "defect"
    if suppressed:
        return "suppressed"
    if verdict == "unknown":
        return "unknown"
    return "clean"


def decorator_coverage_from_scan(
    result: ScanResult,
    context: AnalysisContext,
    *,
    binding_provider: BindingProvider | None = None,
    work_provider: WorkProvider | None = None,
) -> DecoratorCoverageReport:
    rows: list[DecoratorCoverageRow] = []
    for qualname in sorted(context.declared_qualnames):
        entity = context.entities.get(qualname)
        location = entity.location if entity is not None else None
        verdict = classify_entity_trust(result, context, qualname)
        defects = [
            finding for finding in result.findings if finding.qualname == qualname and finding.kind is Kind.DEFECT
        ]
        active = sorted(finding.fingerprint for finding in defects if finding.suppressed is SuppressionState.ACTIVE)
        suppressed = sorted(
            finding.fingerprint for finding in defects if finding.suppressed is not SuppressionState.ACTIVE
        )
        identity, binding = _identity_for(binding_provider, qualname)
        work = _work_for(work_provider, binding)
        rows.append(
            DecoratorCoverageRow(
                qualname=qualname,
                path=location.path if location is not None else None,
                line=location.line_start if location is not None else None,
                decorators=_decorators_of(entity) if entity is not None else [],
                declared_tier=verdict.declared_tier,
                actual_tier=verdict.actual_tier,
                verdict=verdict.verdict,
                finding_state=_finding_state(verdict.verdict, active, suppressed),
                active_finding_fingerprints=active,
                suppressed_finding_fingerprints=suppressed,
                identity=identity,
                work=work,
            )
        )
    return DecoratorCoverageReport(rows=rows)


def build_decorator_coverage(
    root: Path,
    *,
    config_path: Path | None = None,
    confine_to_root: bool = True,
    binding_provider: BindingProvider | None = None,
    work_provider: WorkProvider | None = None,
) -> DecoratorCoverageReport:
    result = run_scan(root, config_path=config_path, confine_to_root=confine_to_root)
    if result.context is None:
        return DecoratorCoverageReport(rows=[])
    return decorator_coverage_from_scan(
        result,
        result.context,
        binding_provider=binding_provider,
        work_provider=work_provider,
    )
