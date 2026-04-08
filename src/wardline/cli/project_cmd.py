"""wardline project — pre-generation context projection.

Scans uncommitted changes and reports new/resolved findings compared
to the last committed state, allowing developers to preview the impact
of their changes before committing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import click

from wardline.cli._helpers import cli_error
from wardline.cli.scan import EXIT_CONFIG_ERROR


@click.command("project")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--manifest", default=None, type=click.Path(exists=True),
              help="Path to wardline.yaml (auto-discovered if omitted).")
@click.option("--base-ref", default="HEAD", help="Git ref to compare against (default: HEAD).")
@click.option("--json-output", "json_out", is_flag=True, default=False,
              help="Output as JSON instead of human-readable summary.")
def project(
    path: str,
    manifest: str | None,
    base_ref: str,
    json_out: bool,
) -> None:
    """Preview findings impact of uncommitted changes.

    Compares the current working tree against BASE_REF to show which
    findings would be introduced or resolved by uncommitted changes.
    """
    from wardline.cli.scan import _load_manifest

    scan_path = Path(path).resolve()

    # Check git availability
    changed = _get_changed_py_files(scan_path, base_ref)
    if changed is None:
        cli_error("Not a git repository or git not available")
        sys.exit(EXIT_CONFIG_ERROR)

    if not changed:
        if json_out:
            click.echo(json.dumps({"status": "clean", "new": [], "resolved": []}, indent=2))
        else:
            click.echo("No Python files changed — nothing to project.")
        return

    # Load manifest
    manifest_result = _load_manifest(manifest, scan_path)
    if manifest_result is None:
        sys.exit(EXIT_CONFIG_ERROR)
    manifest_model, manifest_path = manifest_result

    # Run scan on current working tree (changed files only)
    current_findings = _scan_files(
        scan_path, manifest_model, manifest_path, changed,
    )

    # Run scan on base ref versions of the same files
    base_findings = _scan_base_ref(
        scan_path, base_ref, manifest_model, manifest_path, changed,
    )

    # Diff findings
    current_keys = {_finding_key(f) for f in current_findings}
    base_keys = {_finding_key(f) for f in base_findings}

    new_keys = current_keys - base_keys
    resolved_keys = base_keys - current_keys

    new_findings = [f for f in current_findings if _finding_key(f) in new_keys]
    resolved_findings = [f for f in base_findings if _finding_key(f) in resolved_keys]

    if json_out:
        report: dict[str, Any] = {
            "status": "changes_detected",
            "changed_files": len(changed),
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
            "new": [_finding_to_dict(f) for f in new_findings],
            "resolved": [_finding_to_dict(f) for f in resolved_findings],
        }
        click.echo(json.dumps(report, indent=2))
    else:
        click.echo(f"Changed files: {len(changed)}")
        click.echo(f"New findings:      {len(new_findings)}")
        click.echo(f"Resolved findings: {len(resolved_findings)}")

        if new_findings:
            click.echo("\n--- New findings ---")
            for f in new_findings:
                click.echo(f"  {f.rule_id.value} {f.file_path}:{f.line}  {f.message[:80]}")

        if resolved_findings:
            click.echo("\n--- Resolved findings ---")
            for f in resolved_findings:
                click.echo(f"  {f.rule_id.value} {f.file_path}:{f.line}  {f.message[:80]}")


def _finding_key(f: Any) -> tuple[str, str, str]:
    """Composite key for finding comparison (stable across line shifts)."""
    return (str(f.rule_id.value), f.file_path, f.qualname or "")


def _finding_to_dict(f: Any) -> dict[str, Any]:
    return {
        "rule": str(f.rule_id.value),
        "file": f.file_path,
        "line": f.line,
        "qualname": f.qualname,
        "message": f.message,
        "severity": f.severity.name if f.severity else None,
    }


def _get_changed_py_files(
    repo_path: Path, base_ref: str,
) -> frozenset[Path] | None:
    """Return resolved paths of .py files changed between base_ref and working tree."""
    try:
        git_root_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=10,
        )
        if git_root_result.returncode != 0:
            return None
        git_root = Path(git_root_result.stdout.strip())

        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", base_ref],
            cwd=str(repo_path), capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None

        files: set[Path] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and line.endswith(".py"):
                files.add((git_root / line).resolve())
        return frozenset(files)

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _scan_files(
    scan_path: Path,
    manifest_model: Any,
    manifest_path: Path,
    changed_files: frozenset[Path],
) -> list[Any]:
    """Run the scanner on changed files in the current working tree."""
    from wardline.scanner.engine import ScanEngine
    from wardline.scanner.rules import make_rules

    engine = ScanEngine(
        target_paths=(scan_path,),
        rules=make_rules(),
        manifest=manifest_model,
        project_root=manifest_path.parent,
        changed_files=changed_files,
    )
    result = engine.scan()
    return [f for f in result.findings if f.severity and f.severity.name == "ERROR"]


def _scan_base_ref(
    scan_path: Path,
    base_ref: str,
    manifest_model: Any,
    manifest_path: Path,
    changed_files: frozenset[Path],
) -> list[Any]:
    """Scan the base_ref versions of changed files by checking them out to a temp dir."""
    import tempfile

    from wardline.scanner.engine import ScanEngine
    from wardline.scanner.rules import make_rules

    git_root_result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=str(scan_path), capture_output=True, text=True, timeout=10,
    )
    if git_root_result.returncode != 0:
        return []
    git_root = Path(git_root_result.stdout.strip())

    with tempfile.TemporaryDirectory(prefix="wardline-project-") as tmpdir:
        tmp = Path(tmpdir)
        for changed_file in changed_files:
            try:
                rel = changed_file.relative_to(git_root)
            except ValueError:
                continue

            result = subprocess.run(
                ["git", "show", f"{base_ref}:{rel}"],
                cwd=str(git_root), capture_output=True, timeout=10,
            )
            if result.returncode != 0:
                continue

            dest = tmp / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(result.stdout)

        if not any(tmp.rglob("*.py")):
            return []

        engine = ScanEngine(
            target_paths=(tmp,),
            rules=make_rules(),
            manifest=manifest_model,
            project_root=manifest_path.parent,
        )
        scan_result = engine.scan()

        # Remap file paths back to original locations
        findings = []
        for f in scan_result.findings:
            if f.severity and f.severity.name == "ERROR":
                findings.append(f)
        return findings
