# Corpus fixture for PY-WL-107 (untrusted -> dynamic-code-exec sink).
from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted(level="ASSURED")
def evals_untrusted(p):  # TP: EXTERNAL_RAW reaches eval() in a trusted-tier fn
    src = read_raw(p)
    eval(src)
    return 1
