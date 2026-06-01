"""Aliased-stdlib source and a single-hop indirection return (also exercises T1.3).
`json.loads` returns GUARDED (shape-validated, semantics unchecked) — less trusted
than the declared ASSURED, so a @trusted(ASSURED) producer returning it fires
PY-WL-101, even when reached through an import alias or a local variable."""

import json as _json

from wardline.decorators import trusted


@trusted(level="ASSURED")
def aliased_sink(blob):  # TP: aliased json.loads resolves to a GUARDED source
    return _json.loads(blob)


@trusted(level="ASSURED")
def indirect_return(blob):  # TP: raw flows through a local var (indirection)
    data = _json.loads(blob)
    return data
