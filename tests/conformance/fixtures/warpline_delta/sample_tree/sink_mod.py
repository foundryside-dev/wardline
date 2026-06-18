"""The caller/sink of ``source_mod.tainted_source`` (caller-closure axis, spec §5.3a).

The PY-WL-101 taint finding anchors HERE (``downstream_sink``), downstream of the source
the worklist names. It is only computed when this file reaches the analyzer — which, for a
worklist that names ``source_mod.tainted_source``, happens ONLY because the reverse-edge
caller closure pulls this caller file in. The negative case (scanning the source module
alone) yields no finding, proving the closure is load-bearing.
"""

from source_mod import tainted_source

from wardline.decorators import trusted


@trusted
def downstream_sink(p):
    return tainted_source(p)
