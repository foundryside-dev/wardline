# Corpus fixture for PY-WL-105 (untrusted arg -> trusted callee at a call site).
from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted(level="ASSURED")
def store(x):  # a trusted producer (body operates on ASSURED data)
    return 1


def handler(p):  # TP: passes EXTERNAL_RAW into the trusted callee store()
    store(read_raw(p))
