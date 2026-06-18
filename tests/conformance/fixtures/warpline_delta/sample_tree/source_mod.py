"""The changed callee/source the worklist names (caller-closure axis, spec §5.3a).

Warpline's worklist is a "changed + DOWNSTREAM (callee)" set, but a taint finding anchors
caller-side (at the sink). This module defines the ``@external_boundary`` source; the
PY-WL-101 finding for the flow lands in ``sink_mod.downstream_sink``, NOT here. A worklist
naming ``tainted_source`` must pull ``sink_mod.py`` into the analyzed set via the reverse-
edge caller closure so the sink finding is computed at all.
"""

from wardline.decorators import external_boundary


@external_boundary
def tainted_source(p):
    return p
