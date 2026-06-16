"""Trust-boundary validators. A boundary with no rejection path (cannot say "no")
must fire PY-WL-102; a boundary that can reject is clean."""

from wardline.decorators import trust_boundary


@trust_boundary(to_level="ASSURED")
def no_rejection(p):  # TP: cannot reject → PY-WL-102 (laundered shape; bare return-p is PY-WL-119's)
    cleaned = p
    return cleaned


@trust_boundary(to_level="GUARDED")
def no_rejection_guarded(p):  # TP: cannot reject → PY-WL-102 (laundered shape; bare return-p is PY-WL-119's)
    cleaned = p
    return cleaned


@trust_boundary(to_level="ASSURED")
def has_rejection(p):  # CLEAN: has a raise path
    if not p:
        raise ValueError("reject")
    return p
