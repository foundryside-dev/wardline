"""PY-WL-113 — a trust boundary that fails OPEN (CWE-636 / CWE-703).

A trust-RAISING transition (declared return strictly MORE trusted than body — the
taint shape unique to ``@trust_boundary``) that contains an ``except`` handler
which swallows the failure and SUBSTITUTES a value-bearing result instead of
re-raising — either by returning it directly (``return p``, ``return DEFAULT``,
``return cached``) or by ASSIGNING it to a name the function then returns by
fall-through (``result = p`` in the handler, ``return result`` after the ``try``).
Such a boundary can be bypassed by *triggering* the exception: the validation it
appears to perform is discarded and a "valid-looking" value is returned in its
place, so untrusted data passes the boundary untouched. It fails open, not closed.

The most insidious shape is the self-catch, where the handler catches the very
exception the boundary's own rejection raises:

    @trust_boundary(to_level='ASSURED')
    def v(p):
        try:
            if bad(p):
                raise ValueError          # the rejection ...
            return p
        except ValueError:
            return p                      # ... immediately caught and bypassed

This is why the rule does NOT gate on a broad ``except`` — a *narrow* handler that
names the rejection's own exception type is the worst case, not the mildest.

**The boundary-integrity trio partitions cleanly:**
  - PY-WL-102 — boundary with NO rejection path (cannot reject at all);
  - PY-WL-111 — rejection only via ``assert`` (stripped under ``python -O``);
  - PY-WL-113 — rejection exists but is defeated by a fail-open handler.
A handler that re-raises (even conditionally) is fail-closed and never matches
(conservative, mirroring ``has_rejection_path``); a handler that returns a
falsy/empty constant is signalling REJECTION, not substituting, and also never
matches (see ``_is_falsy_constant_return``).

Declaration-gated (the ``@trust_boundary`` decorator is the opt-in), so it emits at
base severity — NOT tier-modulated — exactly like 102 and 111.

**Residual FP:** a declared boundary that legitimately catches an *unrelated*
exception and returns a default for a non-validation reason. Rare inside a thing
explicitly declared as a validator, and swallow-and-substitute in a validator is
itself the smell; tracked, not hidden.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules._ast_helpers import (
    handler_substitutes_on_failure,
    own_except_handlers,
    returned_var_names,
)
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-113",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description=(
        "A trust boundary fails open — an exception handler swallows the failure and "
        "returns a substitute value instead of re-raising, so the boundary can be "
        "bypassed by triggering the exception (CWE-636)."
    ),
    examples_violation=(
        "@trust_boundary(to_level='ASSURED')\ndef v(p):\n"
        "    try:\n        if not ok(p):\n            raise ValueError\n        return p\n"
        "    except ValueError:\n        return p",
    ),
    examples_clean=(
        "@trust_boundary(to_level='ASSURED')\ndef v(p):\n"
        "    try:\n        if not ok(p):\n            raise ValueError\n        return p\n"
        "    except ValueError:\n        raise",
    ),
)


class FailOpenBoundary:
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
            ret = context.project_return_taints.get(qualname)
            if body is None or ret is None:
                continue
            # Trust-raising transition (== @trust_boundary): body less-trusted than return.
            if TRUST_RANK[body] <= TRUST_RANK[ret]:
                continue
            returned = returned_var_names(entity.node)
            if not any(handler_substitutes_on_failure(h, returned) for h in own_except_handlers(entity.node)):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares a trust boundary ({body.value} -> {ret.value}) "
                        f"but an except handler swallows the failure and returns a substitute "
                        f"value instead of re-raising — it fails open, so the boundary is bypassable"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        # Join-key stability (weft-4a9d0f863c): one finding per anchored qualname,
                        # so (rule, path, line, qualname) is already unique. body/return tiers are
                        # resolved values that drift as the suite is extended — keep them off the key.
                        taint_path=None,
                    ),
                    qualname=qualname,
                    properties={"body_taint": body.value, "return_taint": ret.value},
                )
            )

        return findings
