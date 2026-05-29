# src/wardline/decorators/__init__.py
"""Wardline's generic trust-declaration decorators (static-analysis markers)."""

from __future__ import annotations

from wardline.decorators.trust import external_boundary, trust_boundary, trusted

__all__ = ["external_boundary", "trust_boundary", "trusted"]
