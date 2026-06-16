# Corpus fixture for the BARE-NAME receiver-shadow launder (wardline-f6a29ce23a).
# A raw LOCAL shadows the from-imported clean function ``literal_eval``; the
# bare-name call path used to return the import's clean taint_map entry (GUARDED),
# laundering the raw value past the os.system sink. Discriminating: with the fix
# removed the finding disappears (manifest entry goes stale -> corpus gate fails).
import os
from ast import literal_eval  # noqa: F401  (shadowed on purpose below — that IS the fixture)

from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted(level="ASSURED")
def bare_shadow_sink(p):  # TP: raw local shadows the imported 'literal_eval' -> PY-WL-108
    literal_eval = read_raw(p)  # noqa: F811  (intentional import-name shadow)
    cmd = literal_eval(p)
    os.system(cmd)
    return 1
