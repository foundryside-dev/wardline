# src/wardline/scanner/rules/untrusted_reaches_trusted.py
"""PY-WL-101 — untrusted data reaches a trusted producer.

Fires on an *anchored* function whose ACTUAL returned-value taint is strictly
less-trusted than its DECLARED return tier — i.e. untrusted data flows out of a
function that claims to produce trusted data. Gated by a trust claim: the
declared return must NOT be in the raw/freedom zone, which excludes
``@external_boundary`` (whose job is to return raw) and all undecorated code, and
is what makes the strict rank comparison safe. Declaration-gated, so it emits at
base severity (NOT tier-modulated).

**Trust-boundary delegation.** A trust-RAISING transition — a function whose body
taint is strictly less-trusted than its declared return (the taint shape unique
to ``@trust_boundary``) — is EXEMPT from this rule and delegated to PY-WL-102.
Reason: such a validator's parameters seed at the raw body taint, and the engine
does not narrow taint after a ``raise`` guard, so the L2 actual return is always
the raw body taint — meaning *every* ``@trust_boundary`` (correct or not) would
fire here. That is noise, not signal: the statically-decidable property for a
validator is "can it reject at all", which is exactly PY-WL-102's check. So
PY-WL-101 polices ``@trusted`` producers (body == declared) only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

# INVARIANT (taint-combination audit, F1): MIXED_RAW is CURRENTLY UNREACHABLE —
# no sound analysis path produces it (every combiner uses least_trusted, which is
# closed over the reachable set {INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW,
# UNKNOWN_RAW}; F5's parser guards keep the trio out of the stdlib table and the
# disk cache). If MIXED_RAW ever became reachable, PY-WL-101 and the tier-
# modulated rules would DISAGREE on it: PY-WL-101 would FIRE on it as the ACTUAL
# return of a @trusted producer (body==declared, which passes the trust-raising
# gate at :86-87), because at rank 7 it is strictly less trusted than any clean
# declared tier (the rank comparison at the `actual` check below), whereas
# severity_model.modulate treats it as the freedom zone and SUPPRESSES (returns
# NONE). The firing is NOT unconditional: if the body itself is MIXED_RAW (the
# realistic route to a MIXED_RAW actual return), the :86-87 body-less-trusted-than-
# declared gate suppresses first and delegates to PY-WL-102, so 101 does not fire
# there. NOTE the _RAW_ZONE set here is the
# SUPPRESSION gate on the *declared* tier (the `declared in _RAW_ZONE: continue`
# below) — MIXED_RAW's membership in it is inert, because you never *declare*
# MIXED_RAW; the firing is via the actual-return rank, not this set. The F5 guards
# are what preserve the invariant that this asymmetry stays latent. See
# docs/decisions/2026-05-31-wardline-taint-lattice-retain.md and
# docs/concepts/taint-algebra.md.
_RAW_ZONE: frozenset[TaintState] = frozenset(
    {TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW}
)

METADATA = RuleMetadata(
    rule_id="PY-WL-101",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description=(
        "A trust-anchored function returns data less trusted than the level it "
        "declares — untrusted data reaches a trusted producer with no validation."
    ),
    examples_violation=("@trusted\ndef f(p):\n    return read_raw(p)",),
    examples_clean=("@trusted(level='ASSURED')\ndef f(p):\n    return validate(read_raw(p))",),
)


class UntrustedReachesTrusted:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue
            body = context.project_taints.get(qualname)
            declared = context.project_return_taints.get(qualname)
            if declared is None or declared in _RAW_ZONE:
                continue  # trust-claim gate
            # Trust-RAISING transition (body less trusted than return) is
            # @trust_boundary's shape — covered by PY-WL-102, not PY-WL-101.
            if body is not None and TRUST_RANK[body] > TRUST_RANK[declared]:
                continue
            actual = context.function_return_taints.get(qualname)
            if actual is None:
                continue  # no value-bearing return -> nothing to police
            if TRUST_RANK[actual] <= TRUST_RANK[declared]:
                continue  # returns data at-least-as-trusted as declared
            taint_path = f"{actual.value}->{declared.value}|{prov.via_callee or ''}"
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares return trust {declared.value} but actually "
                        f"returns {actual.value} (less trusted) — untrusted data reaches a "
                        f"trusted producer"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        taint_path=taint_path,
                    ),
                    qualname=qualname,
                    properties={"declared_return": declared.value, "actual_return": actual.value},
                )
            )
        return findings
