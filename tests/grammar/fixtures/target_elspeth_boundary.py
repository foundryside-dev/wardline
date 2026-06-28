"""Scanned target mirroring elspeth's real ``@trust_boundary`` usage — analyzed
STATICALLY, never executed (so ``elspeth`` need not exist).

``validates`` returns a constant (validated) on its only path — clean.
``leaks`` returns its untrusted ``source_param`` unvalidated — declared ASSURED by the
pack's seed but actually EXTERNAL_RAW, so a builtin trust-contract rule must fire.
"""

from elspeth.contracts.trust_boundary import trust_boundary


@trust_boundary(tier=3, source="external response body", source_param="response_data")
def validates(response_data):  # CLEAN: validated/constant return
    if not response_data:
        raise ValueError("reject malformed input")
    return "ok"


@trust_boundary(tier=3, source="external response body", source_param="response_data")
def leaks(response_data):  # TP: returns raw untrusted data, declared validated
    return response_data
