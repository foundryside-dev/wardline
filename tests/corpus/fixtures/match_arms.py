"""Match-arm assignment shapes (the L2 _handle_match path). A match arm that binds
raw and is then returned must fire PY-WL-101; an all-arms-validated counterpart is
clean."""

from wardline.decorators import trust_boundary, trusted


def read_raw(p):
    return p


@trust_boundary(to_level="ASSURED")
def validate(p):
    if not p:
        raise ValueError("reject")
    return p


@trusted(level="ASSURED")
def match_arm_leaks(cmd, p):  # TP: one arm binds raw, returned
    match cmd:
        case "a":
            v = validate(read_raw(p))
        case _:
            v = read_raw(p)
    return v


@trusted(level="ASSURED")
def match_arm_clean(cmd, p):  # CLEAN: every arm validated
    match cmd:
        case "a":
            v = validate(read_raw(p))
        case _:
            v = validate(read_raw(p))
    return v
