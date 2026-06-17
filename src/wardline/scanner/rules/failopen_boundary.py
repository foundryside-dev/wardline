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

**The boundary-integrity family partitions FOUR ways** (wardline-718048a518) —
at most one of {102, 111, 113, 119} fires per boundary:
  - PY-WL-119 — the bare degenerate shape (single ``return <param>``);
  - PY-WL-102 — every other shape with NO rejection path (cannot reject at all);
  - PY-WL-111 — rejection only via ``assert`` (stripped under ``python -O``).
    This precedence is deliberate: an assert inside a ``try`` caught by a
    substituting handler is still 111's (the rejection is assert-only);
  - PY-WL-113 — a REAL rejection exists but a fail-open handler defeats it.

This rule enforces its premise in code, not just prose:
  1. a real (production-surviving) rejection must EXIST — an own-scope ``raise``
     / rejection-shaped ``return``, or a one-hop same-module raising helper call
     (``rejecting_helper_calls``). No rejection → 102's domain; assert-only →
     111's domain;
  2. the rejection must be SWALLOWABLE by the matching handler — lexically inside
     that handler's own ``try`` body (the self-catch), or inside the handler
     itself (a handler that conditionally rejects but substitutes on the other
     path). A rejection wholly OUTSIDE the ``try`` (validate-then-cache shapes)
     cannot be defeated by the handler, so the boundary fails CLOSED and the rule
     stays silent.

A handler that re-raises (even conditionally) is fail-closed and never matches
(conservative, mirroring ``has_rejection_path``); a handler that returns a
falsy/empty constant is signalling REJECTION, not substituting, and also never
matches (see ``_is_falsy_constant_return``).

Declaration-gated (the ``@trust_boundary`` decorator is the opt-in), so it emits at
base severity — NOT tier-modulated — exactly like 102 and 111.

**Residual FP:** a declared boundary whose ``try`` body holds its rejection AND an
unrelated exception source, with a narrow handler for only the unrelated type.
The rule does not match exception TYPES (the self-catch worst case is a *narrow*
handler), so it cannot tell that pair apart; tracked, not hidden.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules._ast_helpers import (
    _own_statements,
    block_has_real_rejection,
    handler_substitutes_on_failure,
    has_real_rejection,
    rejecting_helper_calls,
    returned_var_names,
)
from wardline.scanner.rules._sink_helpers import module_alias_map
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
            # Premise 1 (the family partition): a REAL rejection must exist. None at
            # all -> PY-WL-102's domain; assert-only -> PY-WL-111's domain.
            alias_map = module_alias_map(qualname, context)
            rejecting_calls = rejecting_helper_calls(entity, context.entities, context.call_site_callees, alias_map)
            if not (has_real_rejection(entity.node, alias_map) or rejecting_calls):
                continue
            # Premise 2: the rejection must be SWALLOWABLE by the substituting
            # handler — inside its own try body, or inside the handler itself.
            returned = returned_var_names(entity.node)
            if not any(
                handler_substitutes_on_failure(handler, returned)
                and (
                    block_has_real_rejection(try_stmt.body, rejecting_calls, alias_map)
                    or block_has_real_rejection(handler.body, rejecting_calls, alias_map)
                )
                for try_stmt in _own_statements(entity.node)
                if isinstance(try_stmt, (ast.Try, ast.TryStar))
                for handler in try_stmt.handlers
            ):
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
