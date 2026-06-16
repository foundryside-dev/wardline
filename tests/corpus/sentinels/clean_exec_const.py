# FP sentinel for PY-WL-107: eval over a constant-only argument — no untrusted value
# can reach the dynamic-exec sink, so the engine must stay silent.
from wardline.decorators import trusted


@trusted(level="ASSURED")
def const_eval(p):  # FP sentinel: literal source text, nothing tainted flows in
    return eval("1 + 1")
