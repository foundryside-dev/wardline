# FP sentinel for PY-WL-102: a trust boundary with a real raise-on-invalid rejection
# path CAN say "no", so the degenerate-boundary rule must stay silent.
from wardline.decorators import trust_boundary


@trust_boundary(to_level="ASSURED")
def validate_token(p):  # FP sentinel: raise path = real rejection
    if not isinstance(p, str) or not p.isalnum():
        raise ValueError("reject")
    return p
