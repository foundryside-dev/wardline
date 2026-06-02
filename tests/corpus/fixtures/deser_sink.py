# Corpus fixture for PY-WL-106 (untrusted -> deserialization sink).
import pickle

from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted(level="ASSURED")
def loads_untrusted(p):  # TP: EXTERNAL_RAW reaches pickle.loads in a trusted-tier fn
    b = read_raw(p)
    pickle.loads(b)
    return 1
