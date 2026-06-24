# src/wardline/core/finding.py
"""The Finding record — the central cross-subproject contract (stdlib-only).

Designed as a superset of Filigree's scan-results intake so SP4 emission is
serialization, not translation. Wardline owns the analysis *fact*; finding
*lifecycle* (status, seen_count, issue_id, timestamps) is Filigree's domain
and is deliberately absent here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# Sentinel ``Location.path`` for whole-run engine diagnostics not tied to any
# source file (``WLN-L3-*`` and the unknown-kernel-code ``WLN-ENGINE-DIAGNOSTIC``
# fallback). NOTE: the per-file engine FACTs (PARSE-ERROR / FILE-SKIPPED /
# NO-MODULE / SOURCE-ROOT-MISSING) carry their real relpath, NOT this sentinel.
# Sentinel findings are not tied to a source line; their fingerprint is built
# from identifying fields, so the line-based fingerprint invariant does not
# apply to them. Lives in core so both the emitter (scanner.diagnostics) and
# the suppression guard (core.suppression) reference one constant.
ENGINE_PATH = "<engine>"

# Rule ids for files where analysis was ATTEMPTED OR EXPECTED but FAILED / never
# happened — a genuine under-scan: parse/read failures, files too deep to walk
# (recursion), and missing source roots. Some are gate-eligible DEFECTs and some
# are non-gating FACTs, so callers also count them separately
# (ScanSummary.unanalyzed) to expose the under-scan independent of severity.
#
# WLN-ENGINE-NO-MODULE is DELIBERATELY EXCLUDED: a file that maps to no module
# (e.g. a top-level / src/__init__.py) is a benign layout artifact with nothing to
# analyze, not a failure. It is still emitted as an observable FACT, but folding it
# in here would make a normal src-layout repo report "could not be analyzed" on
# every scan — diluting the signal and hiding real failures in habitual noise.
#
# Single source of truth shared by the analyzer (emitter), discovery, and run.
UNANALYZED_RULE_IDS = frozenset(
    {
        "WLN-ENGINE-PARSE-ERROR",
        "WLN-ENGINE-FILE-SKIPPED",
        "WLN-ENGINE-SOURCE-ROOT-MISSING",
        # A file that parsed but whose analysis raised (per-file isolation, e.g. the Rust
        # frontend catching a RecursionError on a pathologically deep expression) — a
        # genuine under-scan, counted so it never reads as a clean result.
        "WLN-ENGINE-FILE-FAILED",
    }
)

# Rule ids that mean the scan result is not complete enough to reconcile absent
# fingerprints as fixed. This deliberately includes per-function under-analysis
# while leaving ScanSummary.unanalyzed scoped to file/source-root under-scans.
INCOMPLETE_ANALYSIS_RULE_IDS = UNANALYZED_RULE_IDS | {"WLN-ENGINE-FUNCTION-SKIPPED"}


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARN = "WARN"
    INFO = "INFO"
    NONE = "NONE"  # facts / metrics carry no defect severity


class Kind(StrEnum):
    DEFECT = "defect"
    FACT = "fact"
    CLASSIFICATION = "classification"
    METRIC = "metric"
    SUGGESTION = "suggestion"


class SuppressionState(StrEnum):
    ACTIVE = "active"  # not suppressed — the default
    BASELINED = "baselined"  # matched a baseline fingerprint
    WAIVED = "waived"  # matched an active waiver
    JUDGED = "judged"  # LLM triage judged it a FALSE_POSITIVE (SP5)


class Maturity(StrEnum):
    STABLE = "stable"
    PREVIEW = "preview"


@dataclass(frozen=True, slots=True)
class Location:
    path: str  # repo-relative POSIX path; Filigree's file_path anchor
    line_start: int | None = None
    line_end: int | None = None
    col_start: int | None = None  # retained for SARIF; Filigree ignores columns
    col_end: int | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str  # namespaced WLN-*
    message: str
    severity: Severity
    kind: Kind
    location: Location
    fingerprint: str  # stable cross-run identity (SP1 folds in taint-path identity)
    suggestion: str | None = None
    qualname: str | None = None  # dotted module.qualified_name (Loomweave reconciliation key)
    confidence: float | None = None
    related_entities: tuple[str, ...] = ()
    # Immutability is shallow: the contained mapping is not deep-frozen and must
    # be treated as read-only by convention. SP1 may enforce via MappingProxyType.
    properties: Mapping[str, Any] = field(default_factory=dict)
    suppressed: SuppressionState = SuppressionState.ACTIVE
    suppression_reason: str | None = None
    maturity: Maturity = Maturity.STABLE
    # MIGRATION-ONLY breadcrumb (P4 / `wardline rekey`), NEVER serialized — no
    # serializer references it (``to_jsonl``/SARIF/``to_filigree_metadata``/store-doc
    # builders are all explicit-field dicts), so it stays out of the frozen identity
    # corpus and every wire payload. It carries the OLD (wlfp1) ``taint_path`` string
    # so the migration can recompute a finding's pre-rekey fingerprint
    # (``compute_finding_fingerprint_v0``) from the same scan. ``None`` for rules whose
    # old taint_path was ``None`` (singletons / PY-WL-103 / PY-WL-104 / PY-WL-120-return);
    # set by the multi-emit rules whose old taint_path was non-empty. Removable once
    # every project has migrated (a no-corpus-impact cleanup).
    taint_path_v0: str | None = None

    def to_jsonl(self) -> str:
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "kind": self.kind.value,
            "location": {
                "path": self.location.path,
                "line_start": self.location.line_start,
                "line_end": self.location.line_end,
                "col_start": self.location.col_start,
                "col_end": self.location.col_end,
            },
            "fingerprint": self.fingerprint,
            "suggestion": self.suggestion,
            "qualname": self.qualname,
            "confidence": self.confidence,
            "related_entities": list(self.related_entities),
            "properties": dict(self.properties),
            "suppression_state": self.suppressed.value,
            "suppression_reason": self.suppression_reason,
            "maturity": self.maturity.value,
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)


# --- Finding fingerprint (SP2 §7) --------------------------------------------
# Stable cross-run identity. The fingerprint is the cross-tool JOIN KEY: Filigree
# associates issues to it and the baseline/waiver stores key on it, so it MUST be
# invariant to taint-resolution drift — it must not move across builds while the
# source is byte-identical (weft-4a9d0f863c: it moved across three builds because
# resolved taint tiers and ``via_callee`` were folded in, and those legitimately
# change as the rule suite is extended/refined).
#
# INVARIANT (enforce at every call site — see tests/golden/identity): ``taint_path``
# carries ONLY a SOURCE-DERIVED discriminator. A component may appear in
# ``taint_path`` only if it is derived purely from source tokens / lexical position
# (a sink dotted-name, a callee spelling as written, a decorator marker/level token,
# a call's ``col_offset``, or a singleton entity body discriminator) — NOT a
# resolved ``TaintState`` tier and NOT ``via_callee`` — and is load-bearing. For
# multi-emit rules, it separates two distinct findings that share (rule_id, path,
# qualname). For singleton entity-level rules, it may bind the finding to the
# current source body/signature so a same-qualname redefinition cannot inherit a
# stale suppression. Rules with no additional source discriminator still pass
# ``taint_path=None``.
# Resolved tiers belong in ``message``/``properties``, never the join key.
# This invariant is no longer convention-only: ``scanner.diagnostics.build_collision_findings``
# enforces it at runtime over the full emitted set (wardline-8fb773a7af) — two DISTINCT
# findings sharing a fingerprint surface a loud WLN-ENGINE-FINGERPRINT-COLLISION DEFECT
# that trips the gate, instead of one silently masking the other on the joins.
#
# ``line_start`` is DELIBERATELY NOT hashed (wlfp2, wardline-8654423823): a benign
# comment above an entity shifts every line below it but is the same source, so it
# must not churn the cross-tool join key. Multi-emit rules therefore discriminate
# co-located findings with an ENTITY-RELATIVE position — ``node.lineno -
# entity.location.line_start`` plus the call's ``col_offset:end_col_offset`` — which
# is invariant to the whole entity moving (a comment above it). NOTE: it is
# entity-relative, NOT move-stable in the strong sense — a comment inserted INSIDE
# the entity above the node still shifts the relative offset (accepted; the contract
# is identical-source -> identical-fingerprint, and that edit is not identical source).
# ``line_start`` remains on ``Finding.location`` for SARIF regions and display.
def compute_finding_fingerprint(
    *,
    rule_id: str,
    path: str,
    qualname: str | None = None,
    taint_path: str | None = None,
) -> str:
    digest = hashlib.sha256()
    parts = (rule_id, path, qualname or "", taint_path or "")
    digest.update("\x00".join(parts).encode())
    return digest.hexdigest()


# --- Self-describing fingerprint scheme (P1 scheme-infra) --------------------
# The fingerprint is the cross-tool JOIN KEY (baseline / waiver / judged stores
# and the Filigree wire). Stamping a scheme onto it at the wire/store boundary
# lets a store that was written under a different hash formula LOUD-FAIL on load
# (``SchemeMismatchError``) instead of silently joining stale values and
# orphaning every verdict. The IN-MEMORY ``Finding.fingerprint`` stays bare
# 64-hex; the prefix is applied only when serialising to a store/wire and
# stripped (``parse_fingerprint``) when reading one back. ``wlfp1`` is this
# (line_start-IN) formula; ``wlfp2`` is the line_start-OUT core formula. Rule-level
# discriminator changes within the same core formula intentionally fail active for
# old suppressions instead of requiring a global scheme bump for every rule.
FINGERPRINT_SCHEME = "wlfp2"

_HEX_DIGITS = frozenset("0123456789abcdef")


def format_fingerprint(scheme: str, fingerprint: str) -> str:
    """Stamp a bare 64-hex fingerprint with its scheme for the wire/store.

    The inverse of :func:`parse_fingerprint`. Does not validate ``fingerprint``
    here — callers pass ``Finding.fingerprint``, already a bare digest.
    """
    return f"{scheme}:{fingerprint}"


def parse_fingerprint(value: str) -> tuple[str, str]:
    """Split a ``scheme:hex`` fingerprint into ``(scheme, bare_hex)``.

    Pure FORMAT parser: it returns whatever scheme token is present and does
    NOT judge whether that scheme is the one this build expects — scheme
    *mismatch* is the store loaders' concern (``SchemeMismatchError``). Raises
    ``ValueError`` on a structurally malformed value: no colon, empty scheme, or
    a hex part that is not exactly 64 lowercase hex characters.
    """
    scheme, sep, hexpart = value.partition(":")
    if sep != ":" or not scheme:
        raise ValueError(f"not a scheme-prefixed fingerprint: {value!r}")
    if len(hexpart) != 64 or any(c not in _HEX_DIGITS for c in hexpart):
        raise ValueError(f"invalid fingerprint hex (need 64 lowercase hex): {hexpart!r}")
    return scheme, hexpart


def require_fingerprint_scheme(document: Mapping[str, Any], *, store_name: str) -> None:
    """Loud-fail (``SchemeMismatchError``) if ``document``'s ``fingerprint_scheme``
    header is absent or differs from this build's :data:`FINGERPRINT_SCHEME`.

    The baseline/judged/waivers loaders all call this. **Loader order is
    load-bearing:** call it AFTER the empty-guard (a fresh/empty store must
    return empty, never raise) and BEFORE the version check (a version-mismatch
    raised first would hide the actionable ``wardline rekey`` hint). A non-string
    header is treated as missing.
    """
    # Imported lazily-at-module-load: errors imports nothing from wardline, so
    # this top-of-module import would be acyclic, but the symbol is only needed
    # here — keep it local to avoid widening finding.py's import surface.
    from wardline.core.errors import SchemeMismatchError

    raw = document.get("fingerprint_scheme")
    found = raw if isinstance(raw, str) else None
    if found != FINGERPRINT_SCHEME:
        raise SchemeMismatchError(store_name=store_name, found=found, expected=FINGERPRINT_SCHEME)


# --- Weft wire mapping (pure; SP4 uses these to build the scan-results body) -
_SEVERITY_TO_FILIGREE: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.ERROR: "high",
    Severity.WARN: "medium",
    Severity.INFO: "low",
    Severity.NONE: "info",
}

_PROPERTY_ACCESSOR_QUALNAME_SUFFIXES = (":setter", ":deleter")


def severity_to_filigree(severity: Severity) -> str:
    """Map Wardline's 4-level (+NONE) vocabulary to Filigree's 5-level set."""
    return _SEVERITY_TO_FILIGREE[severity]


def _to_wire_qualname(qualname: str) -> str:
    """Return the cross-tool reconciliation qualname for Wardline metadata."""
    for suffix in _PROPERTY_ACCESSOR_QUALNAME_SUFFIXES:
        if qualname.endswith(suffix):
            return qualname.removesuffix(suffix)
    return qualname


def to_filigree_metadata(finding: Finding) -> dict[str, Any]:
    """Build the ``metadata.wardline.*`` subtree (semantic JSON, not byte-stable)."""
    wardline: dict[str, Any] = {
        "fingerprint": format_fingerprint(FINGERPRINT_SCHEME, finding.fingerprint),
        "internal_severity": finding.severity.value,
        "kind": finding.kind.value,
    }
    if finding.qualname is not None:
        wardline["qualname"] = _to_wire_qualname(finding.qualname)
    if finding.confidence is not None:
        wardline["confidence"] = finding.confidence
    if finding.related_entities:
        wardline["related_entities"] = list(finding.related_entities)
    if finding.properties:
        wardline["properties"] = dict(finding.properties)
    if finding.suppressed is not SuppressionState.ACTIVE:
        wardline["suppression_state"] = finding.suppressed.value
        if finding.suppression_reason is not None:
            wardline["suppression_reason"] = finding.suppression_reason
    return {"wardline": wardline}
