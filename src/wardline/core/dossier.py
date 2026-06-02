# src/wardline/core/dossier.py
"""Track 4 — the Loom entity dossier: envelope + assembler.

Wardline is the dossier **assembler** (it composes each tool's slice; it does NOT
become the store). One freshness-honest call returns everything an agent needs to
reason about a function without reading its source: trust posture (Wardline's own,
re-derived FRESH), structure/linkages (Clarion), and open work (Filigree), joined
on a single entity identity — the opaque SEI when available.

This module (T4.1) defines the ``EntityDossier`` envelope and its token discipline;
the assembler that fills sections from real/stubbed sources is added in T4.2.

Design invariants (from the dossier design spec §5 + SEI conformance §2.1):

* **Two orthogonal freshness axes, never collapsed.** Every cross-tool section
  carries an identity axis (``IdentityStatus``: alive / orphaned / unavailable —
  "is this the same entity?") AND a content axis (``ContentStatus``: fresh / stale
  / unknown — "has its code changed?"). Neither is ever inferred from the other.
  These are reused verbatim from :mod:`wardline.clarion.identity` (Track 3) so the
  dossier keys on the same SEI types the SEI-client produces.
* **SEI is opaque.** It is carried verbatim as the binding key, never parsed.
* **No false-green.** An absent/unreachable source yields an *honest partial*
  section (``available=False`` + reason), never fabricated data and never a crash.
  Over-budget content is trimmed with an EXPLICIT, elision-honest truncation marker
  (shown-of-total) — a silent cap reads as "covered everything" when it did not.
* **Zero-dependency base.** Stdlib only; no tokenizer, no blake3, no extras.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from wardline.clarion.identity import ContentStatus, EntityBinding, IdentityStatus
from wardline.core.errors import DossierError
from wardline.core.finding import Kind, SuppressionState
from wardline.core.run import run_scan

if TYPE_CHECKING:
    from wardline.core.run import ScanResult
    from wardline.scanner.context import AnalysisContext
    from wardline.scanner.index import Entity

# The one-call default envelope must fit a small context slice (program spec §2
# Track 4 DoD). drill/chain expansions (T4.3+) may exceed this; the budget is the
# DEFAULT envelope's bar.
DOSSIER_TOKEN_BUDGET = 2000


# --- token estimation -------------------------------------------------------

_TOKEN_RE = re.compile(r"\w+|[^\w\s]")


def estimate_tokens(text: str) -> int:
    """A conservative, deterministic token estimate — no tokenizer dependency.

    Returns ``max(ceil(len/3), word+punctuation pieces)``. Both terms err toward
    OVER-counting relative to a real BPE tokenizer:

    * ``ceil(len/3)`` uses 3 chars/token (denser than the ~4 chars/token English
      rule of thumb) because JSON is punctuation-dense;
    * the piece count treats every word-run and every non-space punctuation char as
      its own token, which is what BPE does to the brace/quote/colon-heavy JSON the
      envelope serialises to.

    Over-counting is the deliberately safe direction for a fail-closed tool: an
    over-estimate trims an envelope a little early (a re-derive cost); an
    *under*-estimate would let an over-budget envelope through unlabeled — a
    false-green. This is an ESTIMATE, not a tokenizer; it is never represented as
    an exact count.
    """
    if not text:
        return 0
    char_est = -(-len(text) // 3)  # ceil(len / 3)
    piece_est = len(_TOKEN_RE.findall(text))
    return max(char_est, piece_est)


# --- envelope sections ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IdentitySection:
    """Who the entity is + its two-axis freshness. The load-bearing minimum: the
    budgeter trims lists, never this section."""

    qualname: str
    kind: str | None
    path: str | None
    line_start: int | None
    line_end: int | None
    sei: str | None  # opaque SEI — the binding key when present; never parsed
    keyed_on_sei: bool
    identity_status: IdentityStatus  # alive / orphaned / unavailable
    content_status: ContentStatus  # fresh / stale / unknown
    content_hash: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "qualname": self.qualname,
            "kind": self.kind,
            "path": self.path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "sei": self.sei,
            "keyed_on_sei": self.keyed_on_sei,
            "identity_status": self.identity_status.value,
            "content_status": self.content_status.value,
            "content_hash": self.content_hash,
        }


@dataclass(frozen=True, slots=True)
class ShapeSection:
    """Signature + decorators with trust semantics RESOLVED (not raw text)."""

    signature: str | None
    decorators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"signature": self.signature, "decorators": list(self.decorators)}


@dataclass(frozen=True, slots=True)
class FindingRef:
    """A compact reference to one active finding on the entity."""

    rule_id: str
    severity: str
    message: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class TrustSection:
    """Wardline's OWN posture. FRESH by construction — it is re-derived on demand,
    so it never carries a stale verdict and needs no freshness flag (dossier spec
    §6: "re-derive cheap")."""

    declared_return: str | None
    actual_return: str | None
    gate_verdict: str  # "clean" | "defect"
    active_findings: list[FindingRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared_return": self.declared_return,
            "actual_return": self.actual_return,
            "gate_verdict": self.gate_verdict,
            "active_findings": [f.to_dict() for f in self.active_findings],
            "freshness": "fresh_by_construction",
        }


@dataclass(frozen=True, slots=True)
class LinkagesSection:
    """Call-graph neighbourhood from Clarion. Both freshness axes surfaced."""

    available: bool
    callers: list[str]
    callees: list[str]
    scc_peers: list[str]
    identity_status: IdentityStatus
    content_status: ContentStatus
    reason: str | None = None

    @classmethod
    def unavailable(cls, reason: str) -> LinkagesSection:
        return cls(
            available=False,
            callers=[],
            callees=[],
            scc_peers=[],
            identity_status=IdentityStatus.UNAVAILABLE,
            content_status=ContentStatus.UNKNOWN,
            reason=reason,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "callers": list(self.callers),
            "callees": list(self.callees),
            "scc_peers": list(self.scc_peers),
            "identity_status": self.identity_status.value,
            "content_status": self.content_status.value,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class TicketRef:
    """A compact reference to one Filigree issue bound to / touching the entity."""

    issue_id: str
    status: str | None = None
    priority: str | None = None
    title: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "status": self.status,
            "priority": self.priority,
            "title": self.title,
        }


@dataclass(frozen=True, slots=True)
class WorkSection:
    """Open work from Filigree. Both freshness axes surfaced (DRIFT == content STALE
    on an alive identity, per SEI conformance §2.1 — the two-axis model subsumes the
    old standalone DRIFT flag)."""

    available: bool
    tickets: list[TicketRef]
    identity_status: IdentityStatus
    content_status: ContentStatus
    reason: str | None = None

    @classmethod
    def unavailable(cls, reason: str) -> WorkSection:
        return cls(
            available=False,
            tickets=[],
            identity_status=IdentityStatus.UNAVAILABLE,
            content_status=ContentStatus.UNKNOWN,
            reason=reason,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "tickets": [t.to_dict() for t in self.tickets],
            "identity_status": self.identity_status.value,
            "content_status": self.content_status.value,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ElidedSection:
    """One honestly-reported elision: a list was trimmed to fit the budget; record
    what it was, how many are shown, and the true total (never a silent cap)."""

    section: str  # e.g. "trust.active_findings", "linkages.callers"
    shown: int
    total: int

    def to_dict(self) -> dict[str, Any]:
        return {"section": self.section, "shown": self.shown, "total": self.total}


@dataclass(frozen=True, slots=True)
class Truncation:
    """The envelope's elision marker. ``truncated`` is False on a complete envelope;
    when True, ``elided`` names every trimmed list with shown-of-total counts."""

    truncated: bool
    elided: list[ElidedSection] = field(default_factory=list)
    note: str | None = None

    @classmethod
    def none(cls) -> Truncation:
        return cls(truncated=False, elided=[], note=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "truncated": self.truncated,
            "elided": [e.to_dict() for e in self.elided],
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class EntityDossier:
    """The one-call envelope. JSON-serialisable via :meth:`to_dict`; token-bounded
    via :func:`bound_to_budget`."""

    identity: IdentitySection
    shape: ShapeSection
    trust: TrustSection
    linkages: LinkagesSection
    work: WorkSection
    synthesis: str | None
    truncation: Truncation

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "shape": self.shape.to_dict(),
            "trust": self.trust.to_dict(),
            "linkages": self.linkages.to_dict(),
            "work": self.work.to_dict(),
            "synthesis": self.synthesis,
            "truncation": self.truncation.to_dict(),
        }

    def estimated_tokens(self) -> int:
        return estimate_tokens(json.dumps(self.to_dict(), sort_keys=True))


# --- token budgeting --------------------------------------------------------

# Lists are trimmed in this order (lowest value first) until the envelope fits.
# Identity/shape/trust-verdict are never trimmed — only the variable-length lists
# and finally the synthesis prose.
_LIST_TRIM_ORDER = (
    "linkages.scc_peers",
    "linkages.callers",
    "linkages.callees",
    "work.tickets",
    "trust.active_findings",
)


def _list_for(dossier: EntityDossier, key: str) -> list[Any]:
    section, attr = key.split(".", 1)
    return list(getattr(getattr(dossier, section), attr))


def _with_list(dossier: EntityDossier, key: str, items: list[Any]) -> EntityDossier:
    section, attr = key.split(".", 1)
    new_section = dataclasses.replace(getattr(dossier, section), **{attr: items})
    return dataclasses.replace(dossier, **{section: new_section})


def bound_to_budget(dossier: EntityDossier, *, budget: int = DOSSIER_TOKEN_BUDGET) -> EntityDossier:
    """Return a copy of *dossier* whose estimated token size fits ``budget``,
    trimming variable-length lists (and finally the synthesis prose) in priority
    order and recording every elision honestly in :class:`Truncation`.

    Identity and shape are never trimmed — they are the load-bearing minimum. If a
    list is trimmed, ``Truncation.elided`` reports its shown-of-total counts so a
    caller always knows something was dropped (no silent cap / false-green)."""
    if dossier.estimated_tokens() <= budget:
        return dataclasses.replace(dossier, truncation=Truncation.none())

    totals = {key: len(_list_for(dossier, key)) for key in _LIST_TRIM_ORDER}
    current = dossier

    # Pass 1: shrink lists, cheapest-value first, halving until the envelope fits.
    for key in _LIST_TRIM_ORDER:
        while current.estimated_tokens() > budget and _list_for(current, key):
            items = _list_for(current, key)
            current = _with_list(current, key, items[: len(items) // 2])

    # Pass 2: if still over (e.g. a huge synthesis string), drop synthesis.
    synthesis_dropped = False
    if current.estimated_tokens() > budget and current.synthesis is not None:
        current = dataclasses.replace(current, synthesis=None)
        synthesis_dropped = True

    elided = [
        ElidedSection(section=key, shown=len(_list_for(current, key)), total=totals[key])
        for key in _LIST_TRIM_ORDER
        if len(_list_for(current, key)) < totals[key]
    ]
    note_bits = []
    if elided:
        note_bits.append("lists trimmed to fit token budget")
    if synthesis_dropped:
        note_bits.append("synthesis dropped to fit token budget")
    note = "; ".join(note_bits) or "trimmed to fit token budget"
    return dataclasses.replace(current, truncation=Truncation(truncated=True, elided=elided, note=note))


# --- source-provider seams (T4.2 stubs; T4.3 wires the live readers) ---------


class LinkageProvider(Protocol):
    """The Clarion call-graph read seam. T4.2 ships stubs only; T4.3 supplies a live
    provider (HTTP linkages / a Clarion-MCP path) keyed on the binding's SEI. A
    provider may return ``None`` (no opinion) or raise (unreachable) — the assembler
    turns either into an honest ``unavailable`` section, never a crash."""

    def linkages(self, binding: EntityBinding) -> LinkagesSection | None: ...


class WorkProvider(Protocol):
    """The Filigree open-work read seam. T4.2 ships stubs only; T4.3 supplies a live
    provider reading ``list_associations_by_entity`` keyed on the binding's SEI.
    Same None/raise → ``unavailable`` contract as :class:`LinkageProvider`."""

    def work(self, binding: EntityBinding) -> WorkSection | None: ...


# --- the assembler ----------------------------------------------------------


def _signature_of(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Render the entity's signature from its AST (args + return annotation)."""
    args = ast.unparse(node.args)
    if node.returns is not None:
        return f"({args}) -> {ast.unparse(node.returns)}"
    return f"({args})"


def _decorators_of(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """The entity's decorators as declared (trust decorators are self-describing,
    e.g. ``@trusted(level='INTEGRAL')``)."""
    return [f"@{ast.unparse(dec)}" for dec in node.decorator_list]


def _build_identity(entity: Entity, binding: EntityBinding | None) -> IdentitySection:
    """Compose the identity section. The SEI (and its two status axes) come from the
    caller-supplied opaque binding — Track 4 never resolves a SEI itself (that is
    Track 3's lane). With no binding, identity degrades honestly to UNAVAILABLE."""
    return IdentitySection(
        qualname=entity.qualname,
        kind=entity.kind,
        path=entity.location.path,
        line_start=entity.location.line_start,
        line_end=entity.location.line_end,
        sei=binding.sei if binding is not None else None,
        keyed_on_sei=binding.keyed_on_sei if binding is not None else False,
        identity_status=binding.identity if binding is not None else IdentityStatus.UNAVAILABLE,
        content_status=binding.content if binding is not None else ContentStatus.UNKNOWN,
        content_hash=binding.content_hash if binding is not None else None,
    )


def _build_trust(result: ScanResult, context: AnalysisContext, qualname: str) -> TrustSection:
    """Wardline's OWN posture, re-derived from the live scan → FRESH by construction."""
    declared = context.project_return_taints.get(qualname)
    actual = context.function_return_taints.get(qualname)
    active = [
        FindingRef(
            rule_id=f.rule_id,
            severity=f.severity.value,
            message=f.message,
            line=f.location.line_start,
        )
        for f in result.findings
        if f.qualname == qualname and f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE
    ]
    return TrustSection(
        declared_return=declared.value if declared is not None else None,
        actual_return=actual.value if actual is not None else None,
        gate_verdict="defect" if active else "clean",
        active_findings=active,
    )


def _section_from_provider(
    provider: Any,
    method: str,
    binding: EntityBinding | None,
    *,
    unavailable: Any,
    not_configured: str,
) -> Any:
    """Call an optional source provider fail-soft. No provider → not-configured
    unavailable; a ``None`` return → no-opinion unavailable; any raise → unreachable
    unavailable carrying the reason. The dossier never fails wholesale on an optional
    source (dossier design §8.1)."""
    if provider is None:
        return unavailable(not_configured)
    bind = binding if binding is not None else EntityBinding(locator="")
    try:
        section = getattr(provider, method)(bind)
    except Exception as exc:  # fail-soft: an optional source is never load-bearing
        return unavailable(f"source unreachable: {exc}")
    if section is None:
        return unavailable("source returned no data")
    return section


def _synthesize(identity: IdentitySection, trust: TrustSection, linkages: LinkagesSection, work: WorkSection) -> str:
    """The best-effort actionable join. Degrades with its inputs — it never asserts a
    join it could not compute (no call-graph locus without linkages; no ticket without
    work)."""
    bits: list[str] = []
    if trust.active_findings:
        rules = ", ".join(sorted({f.rule_id for f in trust.active_findings}))
        bits.append(
            f"{identity.qualname} declares {trust.declared_return} but its actual return is "
            f"{trust.actual_return} ({rules})."
        )
    else:
        bits.append(f"{identity.qualname} is trust-clean (declared {trust.declared_return}).")
    if linkages.available and (linkages.callers or linkages.callees):
        bits.append(f"{len(linkages.callers)} caller(s), {len(linkages.callees)} callee(s) in the call graph.")
    else:
        bits.append("call-graph locus unavailable (no Clarion linkages).")
    if work.available and work.tickets:
        bits.append(f"{len(work.tickets)} open ticket(s) touch it.")
    else:
        bits.append("open-work unavailable (no Filigree).")
    return " ".join(bits)


def build_dossier(
    entity: str,
    *,
    root: Path,
    config_path: Path | None = None,
    confine_to_root: bool = False,
    binding: EntityBinding | None = None,
    linkage_provider: LinkageProvider | None = None,
    work_provider: WorkProvider | None = None,
    budget: int = DOSSIER_TOKEN_BUDGET,
) -> EntityDossier:
    """Assemble the one-call dossier for ``entity`` (a qualname).

    Composes Wardline's OWN trust posture for real (re-scan → FRESH) with Clarion
    linkages and Filigree open work read through optional provider seams. Absent /
    unreachable sources degrade to an honest ``unavailable`` (the call still
    succeeds); the SEI is an OPAQUE input the envelope is keyed on. The result is
    always token-bounded with an explicit truncation marker.

    Raises :class:`DossierError` when ``entity`` is not in the scanned set — a
    tool-execution fault the agent must act on (re-scan / fix the qualname).
    """
    result = run_scan(root, config_path=config_path, confine_to_root=confine_to_root)
    context = result.context
    if context is None or entity not in context.entities:
        raise DossierError(f"entity not found in scanned set: {entity}")
    target = context.entities[entity]

    identity = _build_identity(target, binding)
    shape = ShapeSection(signature=_signature_of(target.node), decorators=_decorators_of(target.node))
    trust = _build_trust(result, context, entity)
    linkages = _section_from_provider(
        linkage_provider,
        "linkages",
        binding,
        unavailable=LinkagesSection.unavailable,
        not_configured="clarion linkages not configured",
    )
    work = _section_from_provider(
        work_provider,
        "work",
        binding,
        unavailable=WorkSection.unavailable,
        not_configured="filigree not configured",
    )
    synthesis = _synthesize(identity, trust, linkages, work)
    dossier = EntityDossier(
        identity=identity,
        shape=shape,
        trust=trust,
        linkages=linkages,
        work=work,
        synthesis=synthesis,
        truncation=Truncation.none(),
    )
    return bound_to_budget(dossier, budget=budget)
