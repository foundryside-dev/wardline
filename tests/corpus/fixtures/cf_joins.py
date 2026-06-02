"""Control-flow-join shapes. A @trusted producer whose SOME branch returns raw
must fire PY-WL-101 (weakest-link). Clean counterparts return validated data on
every branch and must produce NO finding."""

from wardline.decorators import trust_boundary, trusted


def read_raw(p):  # undecorated source surrogate → UNKNOWN_RAW seed
    return p


@trust_boundary(to_level="ASSURED")
def validate(p):
    if not p:
        raise ValueError("reject")
    return p


@trusted(level="ASSURED")
def if_branch_leaks(flag, p):  # TP: else branch returns raw
    if flag:
        return validate(read_raw(p))
    return read_raw(p)


@trusted(level="ASSURED")
def try_branch_leaks(p):  # TP: except branch returns raw
    try:
        return validate(read_raw(p))
    except ValueError:
        return read_raw(p)


@trusted(level="ASSURED")
def if_branch_clean(flag, p):  # CLEAN: both branches validated → no finding
    if flag:
        return validate(read_raw(p))
    return validate(read_raw(p))
