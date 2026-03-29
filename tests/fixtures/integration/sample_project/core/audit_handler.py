"""Fixture: audit handler with PY-WL-006 and PY-WL-007 patterns.

This file lives under core/ and triggers:
- PY-WL-006: audit-critical write inside a broad exception handler
- PY-WL-007: isinstance() runtime type check on internal data
"""


class AuditLog:
    def emit(self, event: str) -> None:
        pass


audit = AuditLog()


def process_with_audit(data: object) -> None:
    """PY-WL-006: audit call inside a broad exception handler."""
    try:
        audit.emit("processing_started")
    except Exception:
        audit.emit("processing_error")  # audit call in broad handler


def classify_input(data: object) -> str:
    """PY-WL-007: isinstance() runtime type check on internal data."""
    if isinstance(data, dict):
        return "mapping"
    if isinstance(data, list):
        return "sequence"
    return "other"
