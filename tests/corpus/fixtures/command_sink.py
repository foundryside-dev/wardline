# Corpus fixture for PY-WL-108 (untrusted -> OS-command sink).
import os

from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted(level="ASSURED")
def runs_untrusted(p):  # TP: EXTERNAL_RAW reaches os.system in a trusted-tier fn
    cmd = read_raw(p)
    os.system(cmd)
    return 1
