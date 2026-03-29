"""Group 3 decorators — Plugin markers.

These decorators mark functions as system plugins for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "system_plugin",
]

system_plugin = wardline_decorator(
    3,
    "system_plugin",
    _wardline_system_plugin=True,
)
"""Mark a function as a system plugin entry point. Enforced by SCN-021."""
