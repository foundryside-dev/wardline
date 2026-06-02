"""Scanned target for the acceptance fixture — analyzed STATICALLY, never executed
(so ``myproj`` need not exist). ``clean`` returns validated data on its only path;
``leaks`` returns raw, and must fire the agent-defined MYPROJ-001."""

import myproj.trust  # noqa: F401  (static marker module; never imported at scan time)

from wardline.decorators import trust_boundary


def read_raw(p):
    return p


@trust_boundary(to_level="ASSURED")
def validate(p):
    if not p:
        raise ValueError("reject")
    return p


@myproj.trust.sanitized(to_level="ASSURED")
def clean(p):  # CLEAN: returns validated (ASSURED) data — no MYPROJ-001
    return validate(p)


@myproj.trust.sanitized(to_level="ASSURED")
def leaks(p):  # TP: returns raw (UNKNOWN_RAW) — MYPROJ-001 fires
    return read_raw(p)
