"""Unaffected module for the warpline delta-scope golden.

``beta`` carries its own PY-WL-101 ERROR, but no worklist names anything in this file.
The golden asserts ``b.py`` is NOT analyzed in delta mode (scoped-file-set axis) and so
``beta`` is absent from both the display and the (a.py-scoped) gate population.
"""

from wardline.decorators import external_boundary, trusted


@external_boundary
def read_raw(p):
    return p


@trusted
def beta(p):
    return read_raw(p)
