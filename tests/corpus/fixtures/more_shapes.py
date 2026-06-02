"""Additional true-positive shapes for corpus breadth + precision-guard diversity.
Each @trusted/@trust_boundary function here returns under-trusted data and must fire
PY-WL-101 (or PY-WL-102), exercising aggregation, indirection, aliased sources, and
laundering. Their clean siblings must stay finding-free."""

from wardline.decorators import trust_boundary, trusted


def read_raw(p):  # undecorated source surrogate → UNKNOWN_RAW
    return p


@trust_boundary(to_level="ASSURED")
def validate(p):
    if not p:
        raise ValueError("reject")
    return p


@trusted(level="ASSURED")
def direct_raw(p):  # TP: canonical raw return
    return read_raw(p)


@trusted(level="ASSURED")
def dict_of_raw(p):  # TP: dict value aggregation carries the weakest element
    return {"clean": validate(p), "raw": read_raw(p)}


@trusted(level="ASSURED")
def str_wrapped_raw(p):  # TP: propagating builtin str() preserves raw
    return str(read_raw(p))


@trusted(level="ASSURED")
def chained_indirection(p):  # TP: two-hop var chain still returns raw
    a = read_raw(p)
    b = a
    return b


@trusted(level="ASSURED")
def fstring_raw(p):  # TP: f-string interpolating raw stays raw
    raw = read_raw(p)
    return f"value={raw}"


@trusted(level="ASSURED")
def list_of_raw(p):  # TP: container aggregation carries the weakest element
    return [validate(p), read_raw(p)]


@trusted(level="ASSURED")
def augassign_raw(p):  # TP: augmented assignment merges raw in
    acc = validate(p)
    acc += read_raw(p)
    return acc


@trusted(level="ASSURED")
def launders_through_broken_boundary(p):  # TP: declared ASSURED but body re-derives raw
    raw = read_raw(p)
    if raw:
        return read_raw(p)
    return validate(p)


@trust_boundary(to_level="ASSURED")
def passthrough_no_check(p):  # TP: PY-WL-102 — boundary that cannot reject
    cleaned = p
    return cleaned


@trusted(level="ASSURED")
def clean_validated(p):  # CLEAN: validated on the only path → no finding
    return validate(p)
