"""Evidence execution for BAR review bundles."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Final

from wardline.bar.models import EvidenceOutput

SUPPORTED_EVIDENCE_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "adversarial_corpus_minima_check",
        "ast_inspection",
        "coherence_check",
        "commit_history_review",
        "conformance_report",
        "corpus_verify",
        "exception_register_audit",
        "expedited_governance_ratio_check",
        "fingerprint_baseline_review",
        "manifest_schema_validation",
        "ratification_record",
        "reviewer_attestation",
        "sarif_rule_output",
        "static_code_review",
        "temporal_separation_audit",
        "unit_tests",
    }
)
_COMMAND_EXECUTION_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "coherence_check",
        "conformance_report",
        "corpus_verify",
        "exception_register_audit",
        "expedited_governance_ratio_check",
        "manifest_schema_validation",
        "sarif_rule_output",
    }
)
_REPO_SRC_ROOT: Final[Path] = Path(__file__).resolve().parents[2]


class BarEvidenceError(Exception):
    """Raised when BAR evidence inputs cannot be resolved safely."""


def ensure_clean_commit_ref(repo_root: Path, commit_ref: str) -> str:
    """Resolve a reviewed commit ref and reject dirty working-tree pseudo-refs."""
    if commit_ref.endswith("-dirty"):
        raise BarEvidenceError(
            f"dirty commit refs are not valid BAR review inputs: {commit_ref!r}"
        )
    resolved = _run_text_command(
        repo_root,
        ("git", "rev-parse", "--verify", f"{commit_ref}^{{commit}}"),
    )
    return resolved.stdout.strip()


def read_text_at_commit(repo_root: Path, commit_ref: str, relative_path: str) -> str:
    """Read a UTF-8 text file from the reviewed commit, ignoring the working tree."""
    normalized_path = normalize_repo_path(relative_path)
    result = _run_text_command(
        repo_root,
        ("git", "show", f"{commit_ref}:{normalized_path}"),
    )
    return result.stdout


def execute_evidence_classes(
    repo_root: Path,
    commit_ref: str,
    evidence_classes: tuple[dict[str, object], ...] | list[dict[str, object]],
    *,
    snapshot_root: Path | None = None,
) -> tuple[EvidenceOutput, ...]:
    """Execute or capture evidence outputs for one obligation."""
    outputs: list[EvidenceOutput] = []
    owned_snapshot_dir: TemporaryDirectory[str] | None = None
    resolved_snapshot_root = snapshot_root

    def ensure_snapshot_root() -> Path:
        nonlocal owned_snapshot_dir, resolved_snapshot_root
        if resolved_snapshot_root is None:
            owned_snapshot_dir = TemporaryDirectory()
            resolved_snapshot_root = materialize_commit_snapshot(
                repo_root,
                commit_ref,
                Path(owned_snapshot_dir.name),
            )
        return resolved_snapshot_root

    try:
        for raw_entry in evidence_classes:
            class_name = _require_str(raw_entry, "class")
            target = _require_str(raw_entry, "target")
            note = _optional_str(raw_entry.get("note"))

            if class_name not in SUPPORTED_EVIDENCE_CLASSES:
                outputs.append(
                    EvidenceOutput(
                        class_name=class_name,
                        target=target,
                        status="unsupported",
                        mode="refusal",
                        summary=(
                            "unsupported evidence class for BAR bundle assembly; "
                            "review must fail closed to insufficient_evidence"
                        ),
                        content="",
                        note=note,
                    )
                )
                continue

            if class_name == "unit_tests":
                outputs.append(_execute_unit_tests(ensure_snapshot_root(), target, note))
                continue

            if class_name in {"temporal_separation_audit", "commit_history_review"}:
                outputs.append(
                    _execute_history_evidence(
                        repo_root=repo_root,
                        commit_ref=commit_ref,
                        class_name=class_name,
                        target=target,
                        note=note,
                    )
                )
                continue

            if class_name in _COMMAND_EXECUTION_CLASSES:
                outputs.append(
                    _execute_snapshot_command_evidence(
                        snapshot_root=ensure_snapshot_root(),
                        class_name=class_name,
                        target=target,
                        note=note,
                    )
                )
                continue

            outputs.append(
                _capture_file_snapshot(
                    repo_root=repo_root,
                    commit_ref=commit_ref,
                    class_name=class_name,
                    target=target,
                    note=note,
                )
            )
    finally:
        if owned_snapshot_dir is not None:
            owned_snapshot_dir.cleanup()

    return tuple(outputs)


def normalize_repo_path(relative_path: str) -> str:
    """Normalize and validate a repo-relative path from the ledger."""
    candidate = relative_path.strip().replace("\\", "/")
    if candidate == "":
        raise BarEvidenceError("expected non-empty repo-relative path")
    pure_path = PurePosixPath(candidate)
    if pure_path.is_absolute() or ".." in pure_path.parts:
        raise BarEvidenceError(f"invalid repo-relative path {relative_path!r}")
    return pure_path.as_posix()


def _capture_file_snapshot(
    *,
    repo_root: Path,
    commit_ref: str,
    class_name: str,
    target: str,
    note: str | None,
) -> EvidenceOutput:
    file_target = _normalize_target_path(target)
    try:
        content = read_text_at_commit(repo_root, commit_ref, file_target)
    except BarEvidenceError as exc:
        return EvidenceOutput(
            class_name=class_name,
            target=target,
            status="error",
            mode="file_snapshot",
            summary=str(exc),
            content="",
            note=note,
        )
    return EvidenceOutput(
        class_name=class_name,
        target=target,
        status="ok",
        mode="file_snapshot",
        summary=f"captured {file_target} at commit {commit_ref}",
        content=content,
        note=note,
    )


def _execute_history_evidence(
    *,
    repo_root: Path,
    commit_ref: str,
    class_name: str,
    target: str,
    note: str | None,
) -> EvidenceOutput:
    try:
        history_paths = _history_paths_for_target(class_name=class_name, target=target)
        command = (
            "git",
            "log",
            "--format=%H%x1f%aI%x1f%an%x1f%s",
            commit_ref,
            "--",
            *history_paths,
        )
        result = _run_text_command(repo_root, command)
    except BarEvidenceError as exc:
        return EvidenceOutput(
            class_name=class_name,
            target=target,
            status="error",
            mode="git_history",
            summary=str(exc),
            content="",
            note=note,
        )
    return EvidenceOutput(
        class_name=class_name,
        target=target,
        status="ok",
        mode="git_history",
        summary=f"captured git history for {', '.join(history_paths)} at {commit_ref}",
        content=result.stdout,
        note=note,
        command=command,
        exit_code=result.returncode,
    )


def _execute_unit_tests(snapshot_root: Path, target: str, note: str | None) -> EvidenceOutput:
    pytest_target = _normalize_pytest_target(target)
    environment = os.environ.copy()
    python_path = str(snapshot_root / "src")
    existing_python_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{python_path}{os.pathsep}{existing_python_path}"
        if existing_python_path
        else python_path
    )
    command = (sys.executable, "-m", "pytest", "-q", pytest_target)
    try:
        result = subprocess.run(
            command,
            cwd=snapshot_root,
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
    except OSError as exc:
        return EvidenceOutput(
            class_name="unit_tests",
            target=target,
            status="error",
            mode="command_result",
            summary=f"unable to execute pytest target {pytest_target}: {exc}",
            content="",
            note=note,
            command=command,
        )

    content = _merge_command_streams(result.stdout, result.stderr)
    summary = (
        f"pytest target {pytest_target} passed"
        if result.returncode == 0
        else f"pytest target {pytest_target} exited with status {result.returncode}"
    )
    return EvidenceOutput(
        class_name="unit_tests",
        target=target,
        status="ok",
        mode="command_result",
        summary=summary,
        content=content,
        note=note,
        command=command,
        exit_code=result.returncode,
    )


def materialize_commit_snapshot(repo_root: Path, commit_ref: str, destination: Path) -> Path:
    archive_result = _run_binary_command(
        repo_root,
        ("git", "archive", "--format=tar", commit_ref),
    )
    with tarfile.open(fileobj=io.BytesIO(archive_result.stdout), mode="r|*") as archive:
        archive.extractall(destination, filter="data")
    return destination


def compute_manifest_hash(snapshot_root: Path, manifest_path: str = "wardline.yaml") -> str:
    """Compute the manifest hash for a materialized commit snapshot."""
    from wardline.cli.scan import _compute_manifest_hash

    resolved_manifest_path = snapshot_root / normalize_repo_path(manifest_path)
    manifest_hash = _compute_manifest_hash(resolved_manifest_path)
    if manifest_hash is None:
        raise BarEvidenceError(f"manifest file not found in reviewed snapshot: {manifest_path}")
    return manifest_hash


def compute_corpus_hash(snapshot_root: Path, corpus_dir: str = "corpus") -> str:
    """Compute the corpus hash for a materialized commit snapshot."""
    from wardline.cli.corpus_cmds import _compute_corpus_hash

    resolved_corpus_dir = snapshot_root / normalize_repo_path(corpus_dir)
    if not resolved_corpus_dir.is_dir():
        raise BarEvidenceError(f"corpus directory not found in reviewed snapshot: {corpus_dir}")
    return _compute_corpus_hash(resolved_corpus_dir)


def _execute_snapshot_command_evidence(
    *,
    snapshot_root: Path,
    class_name: str,
    target: str,
    note: str | None,
) -> EvidenceOutput:
    command = _command_for_evidence_class(snapshot_root=snapshot_root, class_name=class_name, target=target)
    try:
        result = subprocess.run(
            command,
            cwd=snapshot_root,
            capture_output=True,
            text=True,
            check=False,
            env=_command_environment(snapshot_root),
        )
    except OSError as exc:
        return EvidenceOutput(
            class_name=class_name,
            target=target,
            status="error",
            mode="command_result",
            summary=f"unable to execute BAR evidence command for {class_name}: {exc}",
            content="",
            note=note,
            command=command,
        )

    content = _merge_command_streams(result.stdout, result.stderr)
    summary = (
        f"{class_name} evidence command succeeded for {target}"
        if result.returncode == 0
        else f"{class_name} evidence command exited with status {result.returncode} for {target}"
    )
    return EvidenceOutput(
        class_name=class_name,
        target=target,
        status="ok",
        mode="command_result",
        summary=summary,
        content=content,
        note=note,
        command=command,
        exit_code=result.returncode,
    )


def _history_paths_for_target(*, class_name: str, target: str) -> tuple[str, ...]:
    if class_name == "commit_history_review":
        return (_normalize_target_path(target),)

    prefix = "git history for "
    raw_paths = target[len(prefix):] if target.startswith(prefix) else target
    raw_paths = raw_paths.replace(", and ", ", ").replace(" and ", ", ")
    paths = [
        normalize_repo_path(path)
        for path in (part.strip() for part in raw_paths.split(","))
        if path != ""
    ]
    if not paths:
        raise BarEvidenceError(f"no repository paths found in temporal audit target {target!r}")
    return tuple(paths)


def _normalize_target_path(target: str) -> str:
    file_target, _, _selector = target.partition("::")
    return normalize_repo_path(file_target)


def _normalize_pytest_target(target: str) -> str:
    file_target, separator, selector = target.partition("::")
    normalized_file = normalize_repo_path(file_target)
    if separator == "":
        return normalized_file
    return f"{normalized_file}::{selector}"


def _require_str(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or value == "":
        raise BarEvidenceError(f"evidence class entry must define non-empty string field {key!r}")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BarEvidenceError("evidence class note must be a string when present")
    return value


def _merge_command_streams(stdout: str, stderr: str) -> str:
    if stdout and stderr:
        return f"{stdout}\n[stderr]\n{stderr}"
    if stderr:
        return f"[stderr]\n{stderr}"
    return stdout


def _run_text_command(
    repo_root: Path,
    command: tuple[str, ...],
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise BarEvidenceError(f"unable to execute {' '.join(command)}: {exc}") from exc
    if result.returncode != 0:
        raise BarEvidenceError(
            f"command {' '.join(command)} failed with exit code {result.returncode}: {result.stderr.strip()}"
        )
    return result


def _run_binary_command(
    repo_root: Path,
    command: tuple[str, ...],
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            cwd=repo_root,
            capture_output=True,
            text=False,
            check=False,
        )
    except OSError as exc:
        raise BarEvidenceError(f"unable to execute {' '.join(command)}: {exc}") from exc
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise BarEvidenceError(
            f"command {' '.join(command)} failed with exit code {result.returncode}: {stderr}"
        )
    return result


def _command_for_evidence_class(
    *,
    snapshot_root: Path,
    class_name: str,
    target: str,
) -> tuple[str, ...]:
    scan_path = _default_scan_path(snapshot_root)
    manifest_path = _default_manifest_path(snapshot_root, target)

    if class_name == "coherence_check":
        return _python_cli_command(
            "manifest",
            "coherence",
            "--manifest",
            manifest_path,
            "--path",
            scan_path,
            "--json",
        )
    if class_name == "corpus_verify":
        return _python_cli_command(
            "corpus",
            "verify",
            "--corpus-dir",
            _default_corpus_dir(snapshot_root, target),
            "--json",
        )
    if class_name == "expedited_governance_ratio_check":
        return _python_cli_command(
            "regime",
            "verify",
            "--manifest",
            manifest_path,
            "--path",
            scan_path,
            "--json",
        )
    if class_name == "manifest_schema_validation":
        return _python_script_command(
            _manifest_schema_validation_script(),
            manifest_path,
        )
    if class_name == "conformance_report":
        return _python_script_command(
            _conformance_report_script(),
            manifest_path,
            scan_path,
            normalize_repo_path(target),
        )
    if class_name == "sarif_rule_output":
        return _python_script_command(
            _sarif_rule_output_script(),
            normalize_repo_path(target),
        )
    if class_name == "exception_register_audit":
        return _python_script_command(
            _exception_register_audit_script(),
            snapshot_root.as_posix(),
            normalize_repo_path(target),
        )
    raise BarEvidenceError(f"no BAR evidence command mapping for {class_name!r}")


def _command_environment(snapshot_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    pythonpath_entries = [str(snapshot_root / "src")]
    if not (snapshot_root / "src" / "wardline").is_dir():
        pythonpath_entries.append(str(_REPO_SRC_ROOT))
    existing_python_path = environment.get("PYTHONPATH")
    if existing_python_path:
        pythonpath_entries.append(existing_python_path)
    environment["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    return environment


def _python_cli_command(*args: str) -> tuple[str, ...]:
    return (
        sys.executable,
        "-c",
        "from wardline.cli.main import cli; cli()",
        *args,
    )


def _python_script_command(script: str, *args: str) -> tuple[str, ...]:
    return (sys.executable, "-c", script, *args)


def _default_manifest_path(snapshot_root: Path, target: str) -> str:
    normalized_target = normalize_repo_path(target)
    if normalized_target.endswith((".yaml", ".yml")) and (snapshot_root / normalized_target).is_file():
        return normalized_target
    default_manifest = snapshot_root / "wardline.yaml"
    if default_manifest.is_file():
        return "wardline.yaml"
    raise BarEvidenceError("unable to locate wardline.yaml for BAR evidence command execution")


def _default_scan_path(snapshot_root: Path) -> str:
    if (snapshot_root / "src").is_dir():
        return "src"
    return "."


def _default_corpus_dir(snapshot_root: Path, target: str) -> str:
    normalized_target = normalize_repo_path(target)
    candidate = snapshot_root / normalized_target
    if candidate.is_dir():
        return normalized_target
    if candidate.name == "corpus_manifest.json":
        return candidate.parent.relative_to(snapshot_root).as_posix()
    if (snapshot_root / "corpus").is_dir():
        return "corpus"
    raise BarEvidenceError("unable to locate corpus directory for BAR evidence command execution")


def _manifest_schema_validation_script() -> str:
    return textwrap.dedent(
        """
        from pathlib import Path
        import json
        import sys

        import yaml

        from wardline.manifest.loader import ManifestLoadError, WardlineYAMLError, load_manifest

        manifest_path = Path(sys.argv[1])
        try:
            manifest = load_manifest(manifest_path)
            print(json.dumps({
                "valid": True,
                "manifest": manifest_path.as_posix(),
                "governance_profile": getattr(manifest, "governance_profile", None),
            }, indent=2))
        except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError, OSError) as exc:
            print(json.dumps({
                "valid": False,
                "manifest": manifest_path.as_posix(),
                "error": str(exc),
            }, indent=2))
            raise SystemExit(1)
        """
    ).strip()


def _conformance_report_script() -> str:
    return textwrap.dedent(
        """
        from pathlib import Path
        import json
        import sys

        from wardline.cli.scan import _read_conformance_data, _read_conformance_gaps

        manifest_path = Path(sys.argv[1])
        scan_path = Path(sys.argv[2])
        target = Path(sys.argv[3])
        if not target.exists():
            print(json.dumps({
                "valid": False,
                "target": target.as_posix(),
                "error": "conformance report not found",
            }, indent=2))
            raise SystemExit(1)

        never_run, data_unavailable, data = _read_conformance_data(manifest_path)
        gaps = list(_read_conformance_gaps(manifest_path, scan_path=scan_path, _preloaded_data=data))
        print(json.dumps({
            "valid": not never_run and not data_unavailable,
            "target": target.as_posix(),
            "never_run": never_run,
            "data_unavailable": data_unavailable,
            "gaps": gaps,
            "summary": data.get("summary"),
            "inputs": data.get("inputs"),
        }, indent=2, sort_keys=True))
        if never_run or data_unavailable:
            raise SystemExit(1)
        """
    ).strip()


def _sarif_rule_output_script() -> str:
    return textwrap.dedent(
        """
        from pathlib import Path
        import json
        import sys

        target = Path(sys.argv[1])
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({
                "valid": False,
                "target": target.as_posix(),
                "error": str(exc),
            }, indent=2))
            raise SystemExit(1)

        runs = data.get("runs")
        if not isinstance(runs, list) or not runs:
            print(json.dumps({
                "valid": False,
                "target": target.as_posix(),
                "error": "SARIF file does not contain runs[0]",
            }, indent=2))
            raise SystemExit(1)

        first_run = runs[0]
        properties = first_run.get("properties", {}) if isinstance(first_run, dict) else {}
        results = first_run.get("results", []) if isinstance(first_run, dict) else []
        print(json.dumps({
            "valid": True,
            "target": target.as_posix(),
            "run_count": len(runs),
            "result_count": len(results) if isinstance(results, list) else None,
            "control_law": properties.get("wardline.controlLaw"),
            "control_law_degradations": properties.get("wardline.controlLawDegradations"),
            "manifest_hash": properties.get("wardline.manifestHash"),
            "commit_ref": properties.get("wardline.commitRef"),
        }, indent=2, sort_keys=True))
        """
    ).strip()


def _exception_register_audit_script() -> str:
    return textwrap.dedent(
        """
        from pathlib import Path
        import json
        import sys

        from wardline.manifest.exceptions import load_exceptions
        from wardline.manifest.loader import ManifestLoadError

        repo_root = Path(sys.argv[1])
        target = Path(sys.argv[2])
        manifest_dir = repo_root

        try:
            exceptions = load_exceptions(manifest_dir)
        except ManifestLoadError as exc:
            print(json.dumps({
                "valid": False,
                "target": target.as_posix(),
                "error": str(exc),
            }, indent=2))
            raise SystemExit(1)

        print(json.dumps({
            "valid": True,
            "target": target.as_posix(),
            "exception_count": len(exceptions),
        }, indent=2))
        """
    ).strip()
