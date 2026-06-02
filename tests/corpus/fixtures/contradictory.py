# Corpus fixtures for PY-WL-110 (contradictory trust declaration).
from wardline.decorators import external_boundary, trust_boundary, trusted


@trusted
@external_boundary
def conflicting(p):  # TP: @trusted + @external_boundary — contradictory markers
    return p


@trust_boundary(to_level="ASSURED")
def single_marker(p):  # clean: one marker, can reject -> no rule fires
    if not p:
        raise ValueError
    return p
