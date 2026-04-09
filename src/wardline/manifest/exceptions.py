"""Exception register loading and validation.

Loads ``wardline.exceptions.json``, validates against JSON schema, and
performs load-time UNCONDITIONAL re-validation against the severity matrix.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

import jsonschema

from wardline.core import matrix
from wardline.core.severity import Exceptionability, GovernancePath
from wardline.manifest.loader import ManifestLoadError
from wardline.manifest.models import ExceptionEntry

_SCHEMA_DIR = Path(__file__).parent / "schemas"
_EXCEPTIONS_FILENAME = "wardline.exceptions.json"


def load_exceptions(manifest_dir: Path) -> tuple[ExceptionEntry, ...]:
    """Load and validate wardline.exceptions.json from *manifest_dir*.

    Returns empty tuple if the file does not exist.
    Raises ManifestLoadError on schema or governance validation failure.
    """
    path = manifest_dir / _EXCEPTIONS_FILENAME
    if not path.exists():
        return ()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ManifestLoadError(f"Cannot read {path}: {exc}") from exc

    # Schema validation
    schema_path = _SCHEMA_DIR / "exceptions.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ManifestLoadError(
            f"Cannot read exception schema {schema_path}: {exc}"
        ) from exc
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        raise ManifestLoadError(
            f"Exception register schema validation failed: {exc.message}"
        ) from exc

    entries: list[ExceptionEntry] = []
    for raw in data.get("exceptions", []):
        entry = ExceptionEntry(
            id=raw["id"],
            rule=raw["rule"],
            taint_state=raw["taint_state"],
            location=raw["location"],
            exceptionability=raw["exceptionability"],
            severity_at_grant=raw["severity_at_grant"],
            rationale=raw["rationale"],
            reviewer=raw["reviewer"],
            expires=raw.get("expires"),
            provenance=raw.get("provenance"),
            agent_originated=raw.get("agent_originated"),
            ast_fingerprint=raw.get("ast_fingerprint", ""),
            recurrence_count=raw.get("recurrence_count", 0),
            governance_path=GovernancePath(raw.get("governance_path", "standard")),
            last_refreshed_by=raw.get("last_refreshed_by"),
            last_refresh_rationale=raw.get("last_refresh_rationale"),
            last_refreshed_at=raw.get("last_refreshed_at"),
            analysis_level=raw.get("analysis_level", 1),
            migrated_from=raw.get("migrated_from"),
            migrated_by=raw.get("migrated_by"),
            elimination_path=raw.get("elimination_path"),
            elimination_cost=raw.get("elimination_cost"),
        )
        _validate_not_unconditional(entry, path)
        _validate_ast_fingerprint(entry, path)
        entries.append(entry)

    return tuple(entries)


def _validate_not_unconditional(entry: ExceptionEntry, path: Path) -> None:
    """Reject exceptions targeting UNCONDITIONAL severity matrix cells."""
    rule_id = entry.rule
    taint = entry.taint_state

    cell = matrix.lookup(rule_id, taint)
    if cell.exceptionability == Exceptionability.UNCONDITIONAL:
        raise ManifestLoadError(
            f"Exception '{entry.id}' targets UNCONDITIONAL cell "
            f"({entry.rule}, {entry.taint_state}) in {path}. "
            f"UNCONDITIONAL findings cannot be excepted."
        )


def _validate_ast_fingerprint(entry: ExceptionEntry, path: Path) -> None:
    """Reject exceptions with blank ast_fingerprint."""
    if not entry.ast_fingerprint:
        raise ManifestLoadError(
            f"Exception '{entry.id}' has blank ast_fingerprint in {path}. "
            f"Run 'wardline exception refresh {entry.id}' to compute one."
        )


def _validate_exception_age(
    entry: ExceptionEntry,
    age_limits: Mapping[str, int],
    global_max_days: int,
) -> list[str]:
    """Check if exception exceeds its class-specific or global age limit.

    Returns a list of warning messages (not errors -- expired exceptions
    are governance findings, not load failures).
    """
    if not entry.expires:
        return []

    try:
        expires_date = date.fromisoformat(entry.expires)
    except ValueError:
        return []

    # Check against class-specific limit
    class_limit = age_limits.get(entry.exceptionability)
    effective_limit = class_limit if class_limit is not None else global_max_days

    # Compute age from grant: if last_refreshed_at exists, use it; otherwise
    # approximate from expires - effective_limit (grant date unknown)
    if entry.last_refreshed_at:
        try:
            grant_date = date.fromisoformat(entry.last_refreshed_at)
        except ValueError:
            return []
    else:
        grant_date = expires_date - timedelta(days=effective_limit)

    age_days = (date.today() - grant_date).days
    if age_days > effective_limit:
        return [
            f"Exception '{entry.id}' ({entry.exceptionability}) is {age_days} days old, "
            f"exceeding {entry.exceptionability} limit of {effective_limit} days"
        ]
    return []


def check_exception_ages(
    entries: tuple[ExceptionEntry, ...],
    age_limits: Mapping[str, int],
    global_max_days: int = 365,
) -> tuple[str, ...]:
    """Check all exceptions for age limit violations. Returns warning messages."""
    warnings: list[str] = []
    for entry in entries:
        warnings.extend(_validate_exception_age(entry, age_limits, global_max_days))
    return tuple(warnings)
