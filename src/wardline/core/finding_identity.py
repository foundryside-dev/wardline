# src/wardline/core/finding_identity.py
"""The single fingerprint JOIN predicate (P1 scheme-infra).

Every store join — baseline, judged, waivers — happens here, in ONE place, so
the suppression layer asks "what is this finding's identity verdict?" rather than
re-implementing the waiver > judged > baseline precedence inline. Factoring it
out lets the rekey migration (P4) populate ``drifted_from`` (the old-scheme
fingerprint a verdict carried from) without changing the suppression-layer
signature. In this phase ``drifted_from`` is always None — there is no second
scheme yet.

Precedence (unchanged from the historical inline logic): an ACTIVE **waiver**
(explicit human intent, carries an expiry) wins over a **judged** FALSE_POSITIVE
verdict (carries the model rationale), which wins over a silent **baseline**
match.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from wardline.core.baseline import Baseline
from wardline.core.judged import JudgedSet
from wardline.core.waivers import WaiverSet


@dataclass(frozen=True, slots=True)
class IdentityResolution:
    """The verdict of joining one fingerprint against the three stores.

    ``matched_on`` is ``"waiver"`` / ``"judged"`` / ``"baseline"`` / None.
    ``reason`` is the waiver reason, then the judge rationale, then None
    (baseline carries none). ``drifted_from`` is the old-scheme fingerprint the
    verdict was carried from — always None until P4 wires the rekey.
    """

    matched: bool
    matched_on: str | None
    drifted_from: str | None
    reason: str | None


def resolve_identity(
    fingerprint: str,
    *,
    baseline: Baseline,
    waivers: WaiverSet,
    judged: JudgedSet,
    today: date,
) -> IdentityResolution:
    """Resolve one bare fingerprint against the stores, honouring waiver > judged
    > baseline precedence. Pure; ``today`` is injected so waiver expiry is
    hermetic. Invokes the stores' existing membership APIs — it is a predicate,
    not a fourth store."""
    waiver = waivers.match(fingerprint, today)
    if waiver is not None:
        return IdentityResolution(matched=True, matched_on="waiver", drifted_from=None, reason=waiver.reason)
    judged_fp = judged.match(fingerprint)
    if judged_fp is not None:
        return IdentityResolution(matched=True, matched_on="judged", drifted_from=None, reason=judged_fp.rationale)
    if baseline.contains(fingerprint):
        return IdentityResolution(matched=True, matched_on="baseline", drifted_from=None, reason=None)
    return IdentityResolution(matched=False, matched_on=None, drifted_from=None, reason=None)
