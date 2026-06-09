# Corpus fixture for the receiver-shadow taint launder (wardline-f6a29ce23a).
# A raw LOCAL shadows the imported stdlib module ``ast``; the early taint_map
# short-circuit in _resolve_call used to return the module entry's clean taint for
# ``ast.literal_eval`` (GUARDED — the one reliably-minted clean stdlib dotted key),
# laundering the raw receiver past the os.system sink. This is a DISCRIMINATING
# regression guard: with the fix removed the finding disappears (manifest entry
# goes stale -> corpus gate fails), unlike a project-import shape whose dotted key
# is never minted clean (so it fires via the RAW_ZONE fallthrough either way).
import ast  # noqa: F401  (shadowed on purpose below — that IS the fixture)
import os

from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted(level="ASSURED")
def shadowed_sink(p):  # TP: raw local shadows the 'ast' module -> PY-WL-108 must fire
    ast = read_raw(p)  # noqa: F811  (intentional module-name shadow)
    cmd = ast.literal_eval(p)
    os.system(cmd)
    return 1
