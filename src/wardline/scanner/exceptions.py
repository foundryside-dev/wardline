"""Exception matching and finding suppression.

Matches findings against active exceptions using the four-tuple key:
(rule, taint_state, location, ast_fingerprint). Produces governance
findings for stale, unknown-provenance, recurring, and no-expiry exceptions.
"""

from __future__ import annotations

import ast
import datetime
import logging
import tokenize
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.core.severity import (
    Exceptionability,
    RuleId,
    Severity,
)
from wardline.scanner.context import Finding, make_governance_finding
from wardline.scanner.fingerprint import compute_ast_fingerprint

if TYPE_CHECKING:
    from wardline.manifest.models import ExceptionEntry

logger = logging.getLogger(__name__)

_PLACEHOLDER_PATTERNS: frozenset[str] = frozenset(
    {"tbd", "todo", "n/a", "na", "fixme", "xxx", "later"}
)


def _parse_location(location: str) -> tuple[str, str | None]:
    """Parse 'file_path::qualname' into (file_path, qualname)."""
    file_path, sep, qualname = location.partition("::")
    return (file_path, qualname) if sep else (location, None)


def apply_exceptions(
    findings: list[Finding],
    exceptions: tuple[ExceptionEntry, ...],
    project_root: Path,
    *,
    now: datetime.date | None = None,
    analysis_level: int = 1,
    taint_map: dict[str, object] | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """Match findings against exceptions, return (processed, governance).

    ``now`` accepts a date for clock injection in tests (defaults to today).
    ``analysis_level`` enables level-stale detection.
    ``taint_map`` enables taint-drift detection (qualname -> TaintState).
    """
    if now is None:
        now = datetime.date.today()

    # Build index: (rule, taint_state, location) -> [exceptions]
    index: dict[tuple[str, str, str], list[ExceptionEntry]] = {}
    # Also track exceptions by (rule, location) for drift detection
    location_index: dict[tuple[str, str], list[ExceptionEntry]] = {}
    for exc in exceptions:
        key = (exc.rule, exc.taint_state, exc.location)
        index.setdefault(key, []).append(exc)
        loc_key = (exc.rule, exc.location)
        location_index.setdefault(loc_key, []).append(exc)

    # Cache for parsed AST fingerprints: (file_path, qualname) -> fingerprint
    _fp_cache: dict[tuple[str, str], str | None] = {}
    # Cache for parsed ASTs: absolute file_path -> parsed tree (or None on failure)
    _ast_cache: dict[str, ast.Module | None] = {}

    processed: list[Finding] = []
    governance: list[Finding] = []

    # Emit governance findings for all exceptions (regardless of matching)
    _emit_register_governance(exceptions, governance, now)

    # Track level-stale exception IDs — stale exceptions do NOT suppress
    stale_exception_ids: set[str] = set()

    # Level-stale detection: exception analysis_level < active scan level
    for exc in exceptions:
        # Skip expired exceptions
        if exc.expires is not None:
            try:
                expiry = datetime.date.fromisoformat(exc.expires)
                if expiry < now:
                    continue
            except ValueError:
                pass

        if exc.analysis_level < analysis_level:
            exc_file, exc_qualname = _parse_location(exc.location)
            governance.append(_governance_finding(
                RuleId.GOVERNANCE_EXCEPTION_LEVEL_STALE,
                exc_file,
                1,
                f"Exception '{exc.id}' was granted at analysis level "
                f"{exc.analysis_level} but scan is running at level "
                f"{analysis_level} — exception is inactive until re-granted",
                qualname=exc_qualname,
                exception_id=exc.id,
                original_rule=exc.rule,
            ))
            stale_exception_ids.add(exc.id)

    # Taint-drift detection: exception taint_state vs current effective taint
    drifted_ids: set[str] = set()
    if taint_map is not None:
        for exc in exceptions:
            # Skip expired exceptions
            if exc.expires is not None:
                try:
                    expiry = datetime.date.fromisoformat(exc.expires)
                    if expiry < now:
                        continue
                except ValueError:
                    pass

            exc_file, exc_qualname = _parse_location(exc.location)
            if exc_qualname is not None and exc_qualname in taint_map:
                current_taint = str(taint_map[exc_qualname])
                if exc.taint_state != current_taint:
                    governance.append(_governance_finding(
                        RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT,
                        exc_file,
                        1,
                        f"Exception '{exc.id}' was granted for taint "
                        f"{exc.taint_state} but function is now "
                        f"{current_taint}",
                        qualname=exc_qualname,
                        exception_id=exc.id,
                        original_rule=exc.rule,
                    ))
                    drifted_ids.add(exc.id)

    for finding in findings:
        if finding.qualname is None:
            # Module-level findings can't be exception-matched
            processed.append(finding)
            continue

        # Relativize file_path so location keys match CLI-added exceptions.
        # Resolve project_root to handle both relative and absolute file_paths.
        try:
            rel_path = str(Path(finding.file_path).relative_to(project_root.resolve()))
        except ValueError:
            rel_path = finding.file_path

        location = f"{rel_path}::{finding.qualname}"
        if finding.taint_state is None:
            processed.append(finding)
            continue
        key = (finding.rule_id, finding.taint_state, location)
        candidates = index.get(key)

        if candidates is None:
            processed.append(finding)
            continue

        # Check if finding's exceptionability allows suppression
        if finding.exceptionability == Exceptionability.UNCONDITIONAL:
            processed.append(finding)
            continue

        # Compute fingerprint once per (file, qualname) — use absolute path
        # for file reading, project_root for consistent hash with CLI.
        # The AST is cached per file to avoid O(n) re-parses when a file
        # has multiple exception-matched functions.
        fp_key = (rel_path, finding.qualname)
        if fp_key not in _fp_cache:
            abs_path = finding.file_path
            if abs_path not in _ast_cache:
                try:
                    with tokenize.open(abs_path) as fh:
                        source = fh.read()
                    _ast_cache[abs_path] = ast.parse(
                        source, filename=abs_path,
                    )
                except (OSError, SyntaxError, UnicodeDecodeError):
                    _ast_cache[abs_path] = None
            _fp_cache[fp_key] = compute_ast_fingerprint(
                Path(abs_path), finding.qualname,
                project_root=project_root,
                tree=_ast_cache[abs_path],
            )
        current_fp = _fp_cache[fp_key]

        # Guard: if fingerprint computation failed, leave unsuppressed
        if current_fp is None:
            processed.append(finding)
            continue

        matched = False
        for exc in candidates:
            # Level-stale exceptions are inactive — skip them
            if exc.id in stale_exception_ids:
                continue

            # Drifted exceptions are inactive — skip them
            if exc.id in drifted_ids:
                continue

            # Check expiry
            if exc.expires is not None:
                try:
                    expiry = datetime.date.fromisoformat(exc.expires)
                except ValueError:
                    logger.warning("Exception %s has unparseable expiry %r — skipped", exc.id, exc.expires)
                    continue
                if expiry < now:
                    continue  # Expired

            if exc.ast_fingerprint and current_fp != exc.ast_fingerprint:
                # Stale — fingerprint mismatch
                governance.append(_governance_finding(
                    RuleId.GOVERNANCE_STALE_EXCEPTION,
                    finding.file_path,
                    finding.line,
                    f"Exception '{exc.id}' has stale AST fingerprint "
                    f"(expected {exc.ast_fingerprint}, got {current_fp})",
                    qualname=finding.qualname,
                    exception_id=exc.id,
                    original_rule=exc.rule,
                ))
                continue

            if not exc.ast_fingerprint:
                # Empty fingerprint = always stale
                governance.append(_governance_finding(
                    RuleId.GOVERNANCE_STALE_EXCEPTION,
                    finding.file_path,
                    finding.line,
                    f"Exception '{exc.id}' has no AST fingerprint — "
                    f"run 'wardline exception refresh {exc.id}' to compute one",
                    qualname=finding.qualname,
                    exception_id=exc.id,
                    original_rule=exc.rule,
                ))
                continue

            # Severity drift: severity_at_grant != current finding severity
            if exc.severity_at_grant != str(finding.severity):
                governance.append(_governance_finding(
                    RuleId.GOVERNANCE_EXCEPTION_SEVERITY_DRIFT,
                    finding.file_path,
                    finding.line,
                    f"Exception '{exc.id}' was granted at severity "
                    f"{exc.severity_at_grant} but finding is now "
                    f"{finding.severity}",
                    qualname=finding.qualname,
                    exception_id=exc.id,
                    original_rule=exc.rule,
                ))

            # Match! Suppress the finding
            suppressed = replace(
                finding,
                severity=Severity.SUPPRESS,
                exceptionability=Exceptionability.TRANSPARENT,
                exception_id=exc.id,
                exception_expires=exc.expires,
            )
            processed.append(suppressed)
            matched = True
            break

        if not matched:
            processed.append(finding)

    return processed, governance


def _emit_register_governance(
    exceptions: tuple[ExceptionEntry, ...],
    governance: list[Finding],
    now: datetime.date,
) -> None:
    """Emit governance findings for exception register health."""
    for exc in exceptions:
        # Check expiry first — skip governance for expired exceptions
        if exc.expires is not None:
            try:
                expiry = datetime.date.fromisoformat(exc.expires)
                if expiry < now:
                    continue
            except ValueError:
                pass

        exc_file, exc_qualname = _parse_location(exc.location)

        if exc.agent_originated is None:
            governance.append(_governance_finding(
                RuleId.GOVERNANCE_UNKNOWN_PROVENANCE,
                exc_file,
                1,
                f"Exception '{exc.id}' has unknown agent provenance "
                f"(agent_originated is null)",
                qualname=exc_qualname,
                exception_id=exc.id,
                original_rule=exc.rule,
            ))

        if exc.recurrence_count >= 2:
            governance.append(_governance_finding(
                RuleId.GOVERNANCE_RECURRING_EXCEPTION,
                exc_file,
                1,
                f"Exception '{exc.id}' has been renewed {exc.recurrence_count} times",
                qualname=exc_qualname,
                exception_id=exc.id,
                original_rule=exc.rule,
            ))

        if exc.expires is None:
            governance.append(_governance_finding(
                RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION,
                exc_file,
                1,
                f"Exception '{exc.id}' has no expiry date",
                qualname=exc_qualname,
                exception_id=exc.id,
                original_rule=exc.rule,
            ))

        if exc.elimination_path is not None:
            _stripped = exc.elimination_path.strip()
            if not _stripped or _stripped.lower() in _PLACEHOLDER_PATTERNS or len(_stripped) < 10:
                governance.append(_governance_finding(
                    RuleId.GOVERNANCE_WEAK_ELIMINATION_PATH,
                    exc_file,
                    1,
                    f"Exception '{exc.id}' has a weak elimination_path: "
                    f"{exc.elimination_path!r} — should describe the architectural "
                    f"change that eliminates the need for this exception",
                    qualname=exc_qualname,
                    exception_id=exc.id,
                    original_rule=exc.rule,
                ))


def _governance_finding(
    rule_id: RuleId,
    file_path: str,
    line: int,
    message: str,
    *,
    qualname: str | None = None,
    exception_id: str | None = None,
    original_rule: str | None = None,
) -> Finding:
    """Create a governance pseudo-rule finding (delegates to shared factory)."""
    return make_governance_finding(
        rule_id,
        message,
        file_path=file_path,
        line=line,
        qualname=qualname,
        exception_id=exception_id,
        original_rule=original_rule,
    )
