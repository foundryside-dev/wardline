"""wardline exception — exception register lifecycle commands."""

from __future__ import annotations

import ast
import datetime
import json
import logging
import os
import sys
import tokenize
import uuid
from pathlib import Path
from typing import Any

import click

from wardline.core import matrix
from wardline.core.severity import Exceptionability, RuleId
from wardline.core.taints import TaintState
from wardline.scanner.fingerprint import compute_ast_fingerprint

logger = logging.getLogger(__name__)

# Rule governance context — explains why each rule matters
_RULE_GOVERNANCE_CONTEXT: dict[str, str] = {
    "PY-WL-001": (
        "This rule detects code that silently fabricates values for missing dictionary "
        "keys, bypassing validation. Fabricated defaults can mask data corruption or "
        "inject unvalidated values into trusted pipelines."
    ),
    "PY-WL-002": (
        "This rule detects attribute access that silently fabricates values via "
        "fallback defaults (three-argument getattr). Fabricated defaults bypass "
        "validation and can inject unvalidated values into trusted pipelines."
    ),
    "PY-WL-003": (
        "This rule detects existence-checking patterns used as structural gates "
        "(hasattr, 'key' in dict, match/case). Existence checks in place of proper "
        "validation create a false sense of structural safety."
    ),
    "PY-WL-004": (
        "This rule detects exception handlers that catch too broadly (bare except, "
        "except Exception, except BaseException). Broad handlers can mask errors, "
        "swallow security-relevant exceptions, and hide data corruption."
    ),
    "PY-WL-005": (
        "This rule detects exception handlers that silently swallow exceptions "
        "(pass, ellipsis, continue, break). Silent exception handling destroys "
        "diagnostic evidence and can mask security-relevant failures."
    ),
    "PY-WL-006": (
        "This rule detects audit writes in broad exception handlers. Catching "
        "broad exceptions can mask errors while still writing to audit trails, "
        "potentially recording corrupted or misleading audit data."
    ),
    "PY-WL-007": (
        "This rule detects runtime type-checking on internal data. isinstance/type "
        "checks on data that should be statically typed indicate a trust boundary "
        "violation or missing upstream validation."
    ),
    "PY-WL-008": (
        "This rule detects validation with no rejection path. Code that validates "
        "data but has no mechanism to reject invalid input creates a false sense "
        "of security — the validation result is computed but never acted on."
    ),
    "PY-WL-009": (
        "This rule detects semantic validation without prior shape validation. "
        "Performing semantic checks before confirming the data structure is valid "
        "can produce misleading results or mask structural corruption."
    ),
}

_EXCEPTIONS_FILENAME = "wardline.exceptions.json"


def _create_exception(
    rule: str,
    location: str,
    taint_state: str,
    rationale: str,
    reviewer: str,
    governance_path: str,
    expires: str | None,
    agent_originated: bool,
    analysis_level: int,
) -> None:
    """Shared implementation for ``add`` and ``grant`` commands."""
    # Validate rule ID
    try:
        rule_id = RuleId(rule)
    except ValueError:
        click.echo(f"Error: invalid rule ID: {rule}", err=True)
        sys.exit(1)

    # Validate taint state
    try:
        taint = TaintState(taint_state)
    except ValueError:
        click.echo(f"Error: invalid taint state: {taint_state}", err=True)
        sys.exit(1)

    # Check not UNCONDITIONAL
    cell = matrix.lookup(rule_id, taint)
    if cell.exceptionability == Exceptionability.UNCONDITIONAL:
        click.echo(
            f"Error: ({rule}, {taint_state}) is UNCONDITIONAL — cannot be excepted",
            err=True,
        )
        sys.exit(1)

    # Validate location format
    if "::" not in location:
        click.echo("Error: --location must be file_path::qualname", err=True)
        sys.exit(1)

    file_path, qualname = location.split("::", 1)

    # Agent-originated without expires
    if agent_originated and expires is None:
        click.echo("Error: agent-originated exceptions require --expires", err=True)
        sys.exit(1)

    # Validate expires format
    if expires is not None:
        try:
            datetime.date.fromisoformat(expires)
        except ValueError:
            click.echo(f"Error: invalid date format: {expires}", err=True)
            sys.exit(1)

    # Compute fingerprint
    fp = compute_ast_fingerprint(Path(file_path), qualname)
    if fp is None:
        click.echo(f"Error: cannot compute fingerprint for {location}", err=True)
        sys.exit(1)

    # Build entry
    exc_id = f"EXC-{uuid.uuid4().hex[:8].upper()}"
    entry: dict[str, Any] = {
        "id": exc_id,
        "rule": rule,
        "taint_state": taint_state,
        "location": location,
        "exceptionability": str(cell.exceptionability),
        "severity_at_grant": str(cell.severity),
        "rationale": rationale,
        "reviewer": reviewer,
        "expires": expires,
        "provenance": "cli",
        "agent_originated": agent_originated,
        "ast_fingerprint": fp,
        "recurrence_count": 0,
        "governance_path": governance_path,
        "analysis_level": analysis_level,
    }

    # Load or create exceptions file
    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)

    # Recurrence detection: if any existing exception matches the same
    # (rule, location), carry forward the highest recurrence_count + 1.
    # Per spec §10.4: "when an exception for the same rule at the same code
    # location is renewed after expiry, the renewal MUST be flagged as a
    # recurrence event."
    prior_count = max(
        (
            e.get("recurrence_count", 0)
            for e in data["exceptions"]
            if e.get("rule") == rule and e.get("location") == location
        ),
        default=-1,
    )
    if prior_count >= 0:
        entry["recurrence_count"] = prior_count + 1

    data["exceptions"].append(entry)
    _write_exceptions(exc_path, data)

    click.echo(f"Added exception {exc_id} for {rule} at {location} (analysis_level={analysis_level})")


@click.group()
def exception() -> None:
    """Manage the wardline exception register."""


@exception.command()
@click.option("--rule", required=True, help="Rule ID (e.g., PY-WL-001)")
@click.option("--location", required=True, help="file_path::qualname")
@click.option("--taint-state", required=True, help="Taint state (e.g., EXTERNAL_RAW)")
@click.option("--rationale", required=True, help="Why this exception is granted")
@click.option("--reviewer", required=True, help="Who approved this exception")
@click.option("--governance-path", default="standard", type=click.Choice(["standard", "expedited"]))
@click.option("--expires", default=None, help="Expiry date (ISO 8601, e.g., 2027-03-23)")
@click.option("--agent-originated", is_flag=True, default=False, help="Mark as agent-originated")
@click.option("--analysis-level", default=1, type=int, help="Analysis level to stamp on the exception")
def add(
    rule: str,
    location: str,
    taint_state: str,
    rationale: str,
    reviewer: str,
    governance_path: str,
    expires: str | None,
    agent_originated: bool,
    analysis_level: int,
) -> None:
    """Add a new exception to the register."""
    _create_exception(
        rule=rule,
        location=location,
        taint_state=taint_state,
        rationale=rationale,
        reviewer=reviewer,
        governance_path=governance_path,
        expires=expires,
        agent_originated=agent_originated,
        analysis_level=analysis_level,
    )


@exception.command()
@click.argument("ids", nargs=-1)
@click.option("--all", "refresh_all", is_flag=True, help="Refresh all non-expired exceptions")
@click.option("--actor", required=True, help="Who is performing this refresh")
@click.option("--rationale", required=True, help="Why the code change is safe")
@click.option("--confirm", is_flag=True, help="Required with --all")
@click.option("--dry-run", is_flag=True, help="Show rule context without modifying")
@click.option("--json", "json_output", is_flag=True, help="JSON output")
@click.option("--agent-originated", is_flag=True, default=False, help="Mark refresh as agent-originated")
def refresh(
    ids: tuple[str, ...],
    refresh_all: bool,
    actor: str,
    rationale: str,
    confirm: bool,
    dry_run: bool,
    json_output: bool,
    agent_originated: bool,
) -> None:
    """Refresh exception fingerprints after code changes."""
    if not ids and not refresh_all:
        click.echo("Error: provide exception IDs or use --all", err=True)
        sys.exit(1)

    if refresh_all and not confirm:
        click.echo("Error: --all requires --confirm", err=True)
        sys.exit(1)

    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)
    today = datetime.date.today().isoformat()
    today_date = datetime.date.today()

    updated = 0
    stale = 0
    results: list[dict[str, Any]] = []
    # File-level AST cache to avoid re-parsing the same file for each qualname
    _ast_cache: dict[str, ast.Module | None] = {}

    for entry in data["exceptions"]:
        if not refresh_all and entry["id"] not in ids:
            continue

        # Skip expired
        if entry.get("expires"):
            try:
                if datetime.date.fromisoformat(entry["expires"]) < today_date:
                    continue
            except ValueError:
                logger.warning(
                    "Invalid expiry date %r on %s — treating as non-expired",
                    entry["expires"], entry["id"],
                )

        location = entry["location"]
        rule = entry["rule"]

        if dry_run:
            # Show rule context
            desc = _RULE_GOVERNANCE_CONTEXT.get(rule, f"Rule {rule}")
            click.echo(f"\nException {entry['id']} for {rule}")
            click.echo(f"\n  {desc}")
            click.echo(f"\n  Granted because: \"{entry['rationale']}\"")
            click.echo(f"  Code at: {location}")
            click.echo(f"  Current fingerprint: {entry.get('ast_fingerprint', '<none>')}")
            continue

        # Display rule governance context (cognitive forcing function)
        desc = _RULE_GOVERNANCE_CONTEXT.get(rule, f"Rule {rule}")
        click.echo(f"\n  Refreshing {entry['id']} for {rule}: {desc}", err=True)

        if "::" not in location:
            results.append({"id": entry["id"], "status": "skipped", "reason": "invalid location"})
            continue

        file_path, qualname = location.split("::", 1)
        if file_path not in _ast_cache:
            try:
                with tokenize.open(file_path) as fh:
                    source = fh.read()
                _ast_cache[file_path] = ast.parse(source, filename=file_path)
            except (OSError, SyntaxError, UnicodeDecodeError):
                _ast_cache[file_path] = None
        new_fp = compute_ast_fingerprint(
            Path(file_path), qualname, tree=_ast_cache[file_path],
        )

        if new_fp is None:
            stale += 1
            results.append({"id": entry["id"], "status": "stale", "reason": "qualname not found"})
            continue

        old_fp = entry.get("ast_fingerprint", "")
        if old_fp and old_fp == new_fp:
            results.append({"id": entry["id"], "status": "unchanged"})
            continue

        # Update
        entry["ast_fingerprint"] = new_fp
        entry["last_refreshed_by"] = actor
        entry["last_refresh_rationale"] = rationale
        entry["last_refreshed_at"] = today
        if agent_originated:
            entry["refresh_agent_originated"] = True
        updated += 1
        results.append({"id": entry["id"], "status": "refreshed", "old_fp": old_fp, "new_fp": new_fp})

    if not dry_run:
        if refresh_all:
            data["last_batch_refresh"] = {
                "at": today,
                "by": actor,
                "rationale": rationale,
            }
        _write_exceptions(exc_path, data)

    if json_output:
        click.echo(json.dumps({"updated": updated, "stale": stale, "results": results}, indent=2))
    else:
        click.echo(f"Refreshed {updated} exception(s), {stale} stale")


@exception.command()
@click.argument("exc_id")
@click.option("--reason", default="", help="Reason for expiry")
def expire(exc_id: str, reason: str) -> None:
    """Mark an exception as expired."""
    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)
    today = datetime.date.today().isoformat()

    for entry in data["exceptions"]:
        if entry["id"] == exc_id:
            entry["expires"] = today
            _write_exceptions(exc_path, data)
            click.echo(f"Expired {exc_id} (expires: {today})")
            return

    click.echo(f"Error: exception {exc_id} not found", err=True)
    sys.exit(1)


@exception.command()
@click.option("--rule", required=True, help="Rule ID (e.g., PY-WL-001)")
@click.option("--location", required=True, help="file_path::qualname")
@click.option("--taint-state", required=True, help="Taint state (e.g., EXTERNAL_RAW)")
@click.option("--rationale", required=True, help="Why this exception is granted")
@click.option("--reviewer", required=True, help="Who approved this exception")
@click.option("--governance-path", default="standard", type=click.Choice(["standard", "expedited"]))
@click.option("--expires", default=None, help="Expiry date (ISO 8601, e.g., 2027-03-23)")
@click.option("--agent-originated", is_flag=True, default=False, help="Mark as agent-originated")
@click.option("--analysis-level", default=1, type=int, help="Analysis level to stamp on the exception")
def grant(
    rule: str,
    location: str,
    taint_state: str,
    rationale: str,
    reviewer: str,
    governance_path: str,
    expires: str | None,
    agent_originated: bool,
    analysis_level: int,
) -> None:
    """Grant a new exception (like 'add', stamps analysis_level)."""
    _create_exception(
        rule=rule,
        location=location,
        taint_state=taint_state,
        rationale=rationale,
        reviewer=reviewer,
        governance_path=governance_path,
        expires=expires,
        agent_originated=agent_originated,
        analysis_level=analysis_level,
    )


@exception.command("preview-drift")
@click.option("--analysis-level", default=1, type=int, help="Analysis level for taint computation")
@click.option("--manifest", "manifest_path", default=None, type=click.Path(exists=True), help="Path to wardline.yaml")
@click.option("--path", "scan_path", required=True, type=click.Path(exists=True), help="Path to scan for taint computation")
@click.option("--json", "json_output", is_flag=True, help="JSON output")
def preview_drift(
    analysis_level: int,
    manifest_path: str | None,
    scan_path: str,
    json_output: bool,
) -> None:
    """Preview which exceptions would drift under L3 taint analysis."""
    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)

    if not data["exceptions"]:
        click.echo("No exceptions to check.")
        return

    # Compute refined taints
    taint_map = _compute_taints(scan_path, manifest_path, analysis_level)

    # Compare each exception's taint_state against the refined taint
    drifted: list[dict[str, Any]] = []
    for entry in data["exceptions"]:
        location = entry["location"]
        if "::" not in location:
            continue
        _file_path, qualname = location.split("::", 1)
        if qualname not in taint_map:
            continue

        old_taint = entry["taint_state"]
        new_taint = taint_map[qualname].value
        if old_taint != new_taint:
            drifted.append({
                "id": entry["id"],
                "location": location,
                "rule": entry["rule"],
                "old_taint": old_taint,
                "new_taint": new_taint,
            })

    if json_output:
        click.echo(json.dumps({"drifted": drifted, "count": len(drifted)}, indent=2))
    elif drifted:
        click.echo(f"Found {len(drifted)} drifted exception(s):")
        for d in drifted:
            click.echo(f"  {d['id']} ({d['rule']}) at {d['location']}: {d['old_taint']} -> {d['new_taint']}")
    else:
        click.echo("No drift detected.")


@exception.command()
@click.option("--analysis-level", default=1, type=int, help="Analysis level for taint computation")
@click.option("--manifest", "manifest_path", default=None, type=click.Path(exists=True), help="Path to wardline.yaml")
@click.option("--path", "scan_path", required=True, type=click.Path(exists=True), help="Path to scan for taint computation")
@click.option("--confirm", is_flag=True, help="Required to actually perform migration")
@click.option("--actor", required=True, help="Who is performing this migration")
@click.option("--json", "json_output", is_flag=True, help="JSON output")
def migrate(
    analysis_level: int,
    manifest_path: str | None,
    scan_path: str,
    confirm: bool,
    actor: str,
    json_output: bool,
) -> None:
    """Migrate exception taint_state values to match current taint analysis."""
    if not confirm:
        click.echo("Error: --confirm is required to perform migration", err=True)
        sys.exit(1)

    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)

    if not data["exceptions"]:
        click.echo("No exceptions to migrate.")
        return

    # Compute refined taints
    taint_map = _compute_taints(scan_path, manifest_path, analysis_level)

    # Update drifted exceptions
    migrated: list[dict[str, Any]] = []
    for entry in data["exceptions"]:
        location = entry["location"]
        if "::" not in location:
            continue
        _file_path, qualname = location.split("::", 1)
        if qualname not in taint_map:
            continue

        old_taint = entry["taint_state"]
        new_taint = taint_map[qualname].value
        if old_taint != new_taint:
            # Fix 6: UNCONDITIONAL guard — if the new (rule, taint) cell is
            # UNCONDITIONAL, skip migration for this entry (cannot be excepted).
            try:
                new_taint_state = TaintState(new_taint)
                rule_id = RuleId(entry["rule"])
                new_cell = matrix.lookup(rule_id, new_taint_state)
                if new_cell.exceptionability == Exceptionability.UNCONDITIONAL:
                    migrated.append({
                        "id": entry["id"],
                        "location": location,
                        "old_taint": old_taint,
                        "new_taint": new_taint,
                        "skipped": True,
                        "reason": f"({entry['rule']}, {new_taint}) is UNCONDITIONAL",
                    })
                    continue
            except (ValueError, KeyError):
                pass  # If lookup fails, proceed with migration

            old_level = entry.get("analysis_level", 1)
            entry["migrated_from"] = f"taint_state was {old_taint} at level {old_level}"
            entry["taint_state"] = new_taint
            entry["analysis_level"] = analysis_level
            entry["migrated_by"] = actor
            migrated.append({
                "id": entry["id"],
                "location": location,
                "old_taint": old_taint,
                "new_taint": new_taint,
            })
        # Non-drifted entries are left untouched

    _write_exceptions(exc_path, data)

    if json_output:
        click.echo(json.dumps({"migrated": migrated, "count": len(migrated)}, indent=2))
    elif migrated:
        click.echo(f"Migrated {len(migrated)} exception(s):")
        for m in migrated:
            click.echo(f"  {m['id']} at {m['location']}: {m['old_taint']} -> {m['new_taint']}")
    else:
        click.echo("No exceptions needed migration.")


@exception.command()
@click.option("--json", "json_output", is_flag=True, help="JSON output")
def review(json_output: bool) -> None:
    """Review exceptions needing attention."""
    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)
    today = datetime.date.today()

    stale: list[str] = []
    expired: list[str] = []
    approaching: list[str] = []
    unknown_prov: list[str] = []
    recurring: list[str] = []
    total = 0
    expedited = 0
    # File-level AST cache to avoid re-parsing the same file for each qualname
    _review_ast_cache: dict[str, ast.Module | None] = {}

    for entry in data["exceptions"]:
        total += 1
        if entry.get("governance_path") == "expedited":
            expedited += 1

        # Check fingerprint
        location = entry["location"]
        if "::" in location:
            fp, qn = location.split("::", 1)
            if fp not in _review_ast_cache:
                try:
                    with tokenize.open(fp) as fh:
                        source = fh.read()
                    _review_ast_cache[fp] = ast.parse(source, filename=fp)
                except (OSError, SyntaxError, UnicodeDecodeError):
                    _review_ast_cache[fp] = None
            current = compute_ast_fingerprint(
                Path(fp), qn, tree=_review_ast_cache[fp],
            )
            stored = entry.get("ast_fingerprint", "")
            if not stored or current != stored:
                stale.append(entry["id"])

        # Expiry checks
        if entry.get("expires"):
            try:
                exp_date = datetime.date.fromisoformat(entry["expires"])
                if exp_date < today:
                    expired.append(entry["id"])
                elif exp_date <= today + datetime.timedelta(days=30):
                    approaching.append(entry["id"])
            except ValueError:
                logger.warning(
                    "Invalid expiry date %r on %s", entry["expires"], entry["id"],
                )

        if entry.get("agent_originated") is None:
            unknown_prov.append(entry["id"])

        if entry.get("recurrence_count", 0) >= 2:
            recurring.append(entry["id"])

    ratio = expedited / total if total > 0 else 0.0
    last_batch = data.get("last_batch_refresh")

    if json_output:
        result: dict[str, Any] = {
            "stale": stale,
            "expired": expired,
            "approaching_expiry": approaching,
            "unknown_provenance": unknown_prov,
            "recurring": recurring,
            "expedited_ratio": round(ratio, 3),
            "total": total,
        }
        if last_batch is not None:
            result["last_batch_refresh"] = last_batch
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"Exception Register Review ({total} total)")
        click.echo(f"  Stale (fingerprint mismatch): {len(stale)}")
        click.echo(f"  Expired: {len(expired)}")
        click.echo(f"  Approaching expiry (30d): {len(approaching)}")
        click.echo(f"  Unknown provenance: {len(unknown_prov)}")
        click.echo(f"  Recurring (count >= 2): {len(recurring)}")
        click.echo(f"  Expedited ratio: {ratio:.1%}")
        if last_batch is not None:
            click.echo(
                f"  Last batch refresh: {last_batch.get('at', '?')} "
                f"by {last_batch.get('by', '?')}"
            )


@exception.command("audit-mvp")
@click.option("--json", "json_output", is_flag=True, help="JSON output")
def audit_mvp(json_output: bool) -> None:
    """Re-evaluate MVP-era exceptions against the current severity matrix.

    Scans the exception register for entries with a ``migrated_from`` field
    (set during ``wardline exception migrate``) and compares the severity and
    exceptionability recorded at grant time against the current matrix result
    for the same (rule, taint_state) pair.

    This is a read-only command — it reports discrepancies but makes no changes.
    """
    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)

    if not data["exceptions"]:
        if json_output:
            click.echo(json.dumps({"migrated_count": 0, "changed": [], "unchanged": 0}, indent=2))
        else:
            click.echo("No exceptions in register.")
        return

    migrated_entries = [e for e in data["exceptions"] if e.get("migrated_from")]
    if not migrated_entries:
        if json_output:
            click.echo(json.dumps({"migrated_count": 0, "changed": [], "unchanged": 0}, indent=2))
        else:
            click.echo("No MVP-migrated exceptions found (no entries with 'migrated_from' field).")
        return

    changed: list[dict[str, Any]] = []
    unchanged = 0
    errors: list[dict[str, Any]] = []

    for entry in migrated_entries:
        exc_id = entry.get("id", "<unknown>")
        rule_str = entry.get("rule", "")
        taint_str = entry.get("taint_state", "")

        # Validate rule and taint_state
        try:
            rule_id = RuleId(rule_str)
        except ValueError:
            errors.append({"id": exc_id, "error": f"invalid rule ID: {rule_str}"})
            continue

        try:
            taint = TaintState(taint_str)
        except ValueError:
            errors.append({"id": exc_id, "error": f"invalid taint state: {taint_str}"})
            continue

        # Look up current matrix cell
        try:
            current_cell = matrix.lookup(rule_id, taint)
        except KeyError:
            errors.append({"id": exc_id, "error": f"no matrix entry for ({rule_str}, {taint_str})"})
            continue

        current_severity = str(current_cell.severity)
        current_exceptionability = str(current_cell.exceptionability)

        # Compare against grant-time values
        grant_severity = entry.get("severity_at_grant", "")
        grant_exceptionability = entry.get("exceptionability", "")

        severity_changed = grant_severity and grant_severity != current_severity
        exceptionability_changed = grant_exceptionability and grant_exceptionability != current_exceptionability

        if severity_changed or exceptionability_changed:
            record: dict[str, Any] = {
                "id": exc_id,
                "rule": rule_str,
                "taint_state": taint_str,
                "location": entry.get("location", ""),
                "migrated_from": entry.get("migrated_from", ""),
            }
            if severity_changed:
                record["severity_at_grant"] = grant_severity
                record["severity_current"] = current_severity
            if exceptionability_changed:
                record["exceptionability_at_grant"] = grant_exceptionability
                record["exceptionability_current"] = current_exceptionability
            changed.append(record)
        else:
            unchanged += 1

    if json_output:
        result: dict[str, Any] = {
            "migrated_count": len(migrated_entries),
            "changed": changed,
            "unchanged": unchanged,
        }
        if errors:
            result["errors"] = errors
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"MVP-migrated exceptions: {len(migrated_entries)}")
        if changed:
            click.echo(f"\nMatrix changes detected ({len(changed)}):")
            for c in changed:
                click.echo(f"  {c['id']} ({c['rule']} @ {c['taint_state']})")
                click.echo(f"    location: {c['location']}")
                click.echo(f"    migrated_from: {c['migrated_from']}")
                if "severity_at_grant" in c:
                    click.echo(f"    severity: {c['severity_at_grant']} -> {c['severity_current']}")
                if "exceptionability_at_grant" in c:
                    click.echo(f"    exceptionability: {c['exceptionability_at_grant']} -> {c['exceptionability_current']}")
        else:
            click.echo("No matrix changes detected — all migrated exceptions match current matrix.")
        if unchanged:
            click.echo(f"\nUnchanged: {unchanged}")
        if errors:
            click.echo(f"\nErrors ({len(errors)}):")
            for e in errors:
                click.echo(f"  {e['id']}: {e['error']}")


# --- Helpers ---

def _find_exceptions_file() -> Path:
    """Find wardline.exceptions.json relative to CWD."""
    # Walk up to find wardline.yaml, then use its directory
    from wardline.manifest.discovery import discover_manifest
    manifest_path = discover_manifest(Path.cwd())
    if manifest_path is not None:
        return manifest_path.parent / _EXCEPTIONS_FILENAME
    return Path.cwd() / _EXCEPTIONS_FILENAME


def _load_or_create(path: Path) -> dict[str, Any]:
    """Load exceptions file or create empty structure."""
    if path.exists():
        result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return result
    return {
        "$id": "https://wardline.dev/schemas/1.0/exceptions.schema.json",
        "exceptions": [],
    }


def _write_exceptions(path: Path, data: dict[str, Any]) -> None:
    """Write exceptions file with sorted, indented JSON."""
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _compute_taints(
    scan_path: str,
    manifest_path: str | None,
    analysis_level: int,
) -> dict[str, TaintState]:
    """Compute function-level taints for all .py files under scan_path.

    This is the authoritative implementation of taint computation for CLI
    commands.  Returns a merged dict mapping qualname -> TaintState across
    all files.  When analysis_level >= 3, runs L3 call-graph propagation.
    """
    from wardline.manifest.loader import load_manifest
    from wardline.scanner._qualnames import build_qualname_map
    from wardline.scanner.discovery import discover_annotations
    from wardline.scanner.taint.callgraph import extract_call_edges
    from wardline.scanner.taint.callgraph_propagation import propagate_callgraph_taints
    from wardline.scanner.taint.function_level import assign_function_taints

    manifest = None
    if manifest_path is not None:
        manifest = load_manifest(Path(manifest_path))

    merged_taint: dict[str, TaintState] = {}

    root = Path(scan_path).resolve()
    py_files: list[Path] = []
    if root.is_file():
        py_files = [root]
    else:
        for dirpath, _dirs, filenames in os.walk(root, followlinks=False):
            for fn in filenames:
                if fn.endswith(".py"):
                    py_files.append(Path(dirpath) / fn)

    for file_path in py_files:
        try:
            with tokenize.open(file_path) as fh:
                source = fh.read()
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue

        try:
            annotations = discover_annotations(tree, file_path)
            project_root = Path(manifest_path).parent if manifest_path is not None else None
            taint_map, _return_taint_map, taint_sources, _conflicts, _overclaims = assign_function_taints(
                tree, file_path, annotations, manifest,
                project_root=project_root,
            )
        except (AttributeError, KeyError, TypeError, ValueError, OSError) as exc:
            logger.warning("Taint assignment failed for %s: %s", file_path, exc)
            continue

        # L3: run per-file propagation (intra-module), matching engine behavior
        if analysis_level >= 3 and taint_map:
            try:
                qualname_map = build_qualname_map(tree)
                edges, resolved, unresolved = extract_call_edges(tree, qualname_map)
                refined, _provenance, _diagnostics = propagate_callgraph_taints(
                    edges, taint_map, taint_sources,
                    resolved, unresolved,
                    return_taint_map=_return_taint_map,
                )
                taint_map = refined
            except (AttributeError, KeyError, TypeError, ValueError) as exc:
                logger.warning(
                    "L3 taint propagation failed for %s: %s — using L1 taints",
                    file_path, exc,
                )

        merged_taint.update(taint_map)

    return merged_taint
