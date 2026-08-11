# FP sentinel for PY-WL-110: the SAME trust marker repeated. PY-WL-110 fires only on
# two or more *distinct* canonical markers, so a repeated matching marker is a clean
# declaration and the engine must stay silent. This is the `match` interaction
# counterpart to the `contradiction` interaction specimen in fixtures/contradictory.py:
# the pair is what proves the rule discriminates "two markers" from "two DIFFERENT
# markers" rather than merely counting decorators.
from wardline.decorators import trust_boundary


@trust_boundary(to_level="ASSURED")
@trust_boundary(to_level="ASSURED")
def repeated_matching_marker(p):  # FP sentinel: one distinct marker + a real rejection path
    if not p:
        raise ValueError("rejected")
    return p
