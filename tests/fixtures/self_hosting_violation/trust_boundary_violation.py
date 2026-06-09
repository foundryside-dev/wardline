"""Non-vacuous self-hosting fixture: a real trust decorator plus a tainted return
that MUST fire a tier-gated rule (PY-WL-101). Kept OUT of src/ so the src/ self-scan
stays clean; this proves the self-hosting pipeline CAN catch a real violation."""

from wardline.decorators import trusted


def read_raw(p):  # undecorated source surrogate -> UNKNOWN_RAW seed
    return p


@trusted(level="ASSURED")
def leaks_untrusted(p):  # TP: returns raw (UNKNOWN_RAW) from a @trusted producer
    return read_raw(p)
