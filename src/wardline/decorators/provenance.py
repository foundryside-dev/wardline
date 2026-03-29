"""Group 4 decorators — Internal Data Provenance.

These decorators mark functions with internal data provenance metadata
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "int_data",
]

int_data = wardline_decorator(
    4,
    "int_data",
    _wardline_int_data=True,
)
"""Mark a function that produces or manages internal provenance-sensitive data. Enforced by SCN-021."""
