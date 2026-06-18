"""Affected module for the warpline delta-scope golden.

``alpha`` is the entity the reverify worklist names; ``gamma`` is a CO-LOCATED entity
in the same file that the worklist does NOT name. Both carry a PY-WL-101 ERROR (a
``@trusted`` function returning the result of an ``@external_boundary`` source). The
golden asserts the delta DISPLAY shows only ``alpha`` while the gate population retains
``gamma`` (gate-not-narrowed axis / INV-4).
"""

from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted
def alpha(p):
    return read_raw(p)


@trusted
def gamma(p):
    return read_raw(p)
