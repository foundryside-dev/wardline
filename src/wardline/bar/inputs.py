"""Deterministic BAR review-bundle assembly."""

from __future__ import annotations

import re
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

from wardline.bar.evidence_exec import (
    BarEvidenceError,
    compute_corpus_hash,
    compute_manifest_hash,
    ensure_clean_commit_ref,
    execute_evidence_classes,
    materialize_commit_snapshot,
    read_text_at_commit,
)
from wardline.bar.ledger import BarLedgerError, load_obligation_from_compliance_ledger
from wardline.bar.models import (
    BarReviewBundle,
    ResolvedFileContent,
    ResolvedSourceRef,
)

_SOURCE_REF_RE: Final = re.compile(
    r"^(?P<path>docs/[^ ]+) (?P<selector>§[A-Za-z0-9][A-Za-z0-9._-]*(?:\([0-9]+\))?|property [0-9]+|WL-FIT-[A-Z0-9-]+)(?: .*)?$"
)
_SECTION_SELECTOR_RE: Final = re.compile(
    r"^§(?P<section>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\((?P<clause>[0-9]+)\))?$"
)
_PROPERTY_SELECTOR_RE: Final = re.compile(r"^property (?P<number>[0-9]+)$")


class BarInputError(Exception):
    """Raised when deterministic BAR inputs cannot be assembled safely."""


def assemble_review_bundle(
    *,
    repo_root: Path,
    ledger_path: Path,
    obligation_id: str,
    policy_hash: str,
) -> BarReviewBundle:
    """Assemble the frozen BAR review inputs for one obligation."""
    try:
        raw_obligation = load_obligation_from_compliance_ledger(ledger_path, obligation_id)
    except BarLedgerError as exc:
        raise BarInputError(str(exc)) from exc

    obligation_record = dict(raw_obligation)
    obligation_record.pop("reviewer_metadata", None)

    freshness_binding = _require_dict(raw_obligation, "freshness_binding")
    commit_ref = _require_str(freshness_binding, "commit_ref")
    manifest_hash = _require_str(freshness_binding, "manifest_hash")
    corpus_hash = _optional_str(freshness_binding.get("corpus_hash"))

    try:
        resolved_commit_ref = ensure_clean_commit_ref(repo_root, commit_ref)
    except BarEvidenceError as exc:
        raise BarInputError(str(exc)) from exc

    evidence_entries = _require_dict_list(raw_obligation, "evidence_classes")
    try:
        with TemporaryDirectory() as snapshot_dir:
            snapshot_root = materialize_commit_snapshot(
                repo_root,
                resolved_commit_ref,
                Path(snapshot_dir),
            )
            actual_manifest_hash = compute_manifest_hash(snapshot_root)
            _validate_input_hash(
                label="manifest_hash",
                expected=manifest_hash,
                actual=actual_manifest_hash,
            )

            actual_corpus_hash: str | None = None
            if corpus_hash is not None or _requires_corpus_hash(evidence_entries):
                actual_corpus_hash = compute_corpus_hash(snapshot_root)
                if corpus_hash is None:
                    raise BarInputError(
                        "freshness_binding must record corpus_hash when BAR evidence binds corpus state"
                    )
                _validate_input_hash(
                    label="corpus_hash",
                    expected=corpus_hash,
                    actual=actual_corpus_hash,
                )

            source_refs_content = tuple(
                resolve_source_ref_excerpt(repo_root, resolved_commit_ref, source_ref)
                for source_ref in _require_str_list(raw_obligation, "source_refs")
            )
            implementation_surface_content = tuple(
                ResolvedFileContent(
                    path=implementation_path,
                    content=_read_implementation_surface(
                        repo_root,
                        resolved_commit_ref,
                        implementation_path,
                    ),
                )
                for implementation_path in _require_str_list(raw_obligation, "implementation_surface")
            )
            evidence_class_outputs = execute_evidence_classes(
                repo_root,
                resolved_commit_ref,
                evidence_entries,
                snapshot_root=snapshot_root,
            )
    except BarEvidenceError as exc:
        raise BarInputError(str(exc)) from exc

    return BarReviewBundle(
        obligation_id=_require_str(raw_obligation, "id"),
        obligation_record=obligation_record,
        source_refs_content=source_refs_content,
        implementation_surface_content=implementation_surface_content,
        evidence_class_outputs=evidence_class_outputs,
        commit_ref=resolved_commit_ref,
        manifest_hash=actual_manifest_hash,
        corpus_hash=actual_corpus_hash,
        policy_hash=policy_hash,
    )


def resolve_source_ref_excerpt(repo_root: Path, commit_ref: str, source_ref: str) -> ResolvedSourceRef:
    """Resolve one ledger ``source_refs`` entry to a deterministic excerpt."""
    match = _SOURCE_REF_RE.match(source_ref)
    if match is None:
        raise BarInputError(f"unsupported source_ref syntax {source_ref!r}")

    path = match.group("path")
    selector = match.group("selector")
    try:
        document_text = read_text_at_commit(repo_root, commit_ref, path)
    except BarEvidenceError as exc:
        raise BarInputError(str(exc)) from exc

    if selector.startswith("§"):
        excerpt = _extract_section_excerpt(document_text, selector, path)
    elif selector.startswith("property "):
        excerpt = _extract_property_excerpt(document_text, selector, path)
    elif selector.startswith("WL-FIT-"):
        excerpt = _extract_requirement_excerpt(document_text, selector, path)
    else:
        raise BarInputError(f"unsupported source_ref selector {selector!r}")

    return ResolvedSourceRef(
        source_ref=source_ref,
        path=path,
        selector=selector,
        excerpt=excerpt,
    )


def _read_implementation_surface(repo_root: Path, commit_ref: str, implementation_path: str) -> str:
    try:
        return read_text_at_commit(repo_root, commit_ref, implementation_path)
    except BarEvidenceError as exc:
        raise BarInputError(str(exc)) from exc


def _extract_section_excerpt(document_text: str, selector: str, path: str) -> str:
    selector_match = _SECTION_SELECTOR_RE.match(selector)
    if selector_match is None:
        raise BarInputError(f"invalid section selector {selector!r} in {path}")
    section = selector_match.group("section")
    clause = selector_match.group("clause")
    lines = document_text.splitlines()

    heading_index: int | None = None
    heading_level: int | None = None
    heading_pattern = re.compile(rf"^(?P<marks>#+)\s+{re.escape(section)}(?:\s+|$)")
    for index, line in enumerate(lines):
        heading_match = heading_pattern.match(line)
        if heading_match is not None:
            heading_index = index
            heading_level = len(heading_match.group("marks"))
            break

    if heading_index is None or heading_level is None:
        raise BarInputError(f"unable to resolve section selector {selector!r} in {path}")

    section_end = len(lines)
    for index in range(heading_index + 1, len(lines)):
        next_heading_match = re.match(r"^(?P<marks>#+)\s+", lines[index])
        if next_heading_match is not None and len(next_heading_match.group("marks")) <= heading_level:
            section_end = index
            break

    section_lines = lines[heading_index:section_end]
    if clause is None:
        return "\n".join(section_lines).strip()

    clause_pattern = re.compile(rf"^\s*{re.escape(clause)}\.\s+")
    clause_index: int | None = None
    for index, line in enumerate(section_lines[1:], start=1):
        if clause_pattern.match(line):
            clause_index = index
            break
    if clause_index is None:
        raise BarInputError(f"unable to resolve clause selector {selector!r} in {path}")

    clause_end = len(section_lines)
    next_clause_pattern = re.compile(r"^\s*[0-9]+\.\s+")
    for index in range(clause_index + 1, len(section_lines)):
        line = section_lines[index]
        if line.startswith("#") or next_clause_pattern.match(line):
            clause_end = index
            break

    excerpt_lines = [section_lines[0], "", *section_lines[clause_index:clause_end]]
    return "\n".join(excerpt_lines).strip()


def _extract_property_excerpt(document_text: str, selector: str, path: str) -> str:
    property_match = _PROPERTY_SELECTOR_RE.match(selector)
    if property_match is None:
        raise BarInputError(f"invalid property selector {selector!r} in {path}")
    number = property_match.group("number")
    lines = document_text.splitlines()

    start_index: int | None = None
    property_pattern = re.compile(rf"^\*\*{re.escape(number)}\.\s+")
    for index, line in enumerate(lines):
        if property_pattern.match(line):
            start_index = index
            break
    if start_index is None:
        raise BarInputError(f"unable to resolve property selector {selector!r} in {path}")

    end_index = len(lines)
    next_property_pattern = re.compile(r"^\*\*[0-9]+\.\s+")
    for index in range(start_index + 1, len(lines)):
        if next_property_pattern.match(lines[index]):
            end_index = index
            break

    return "\n".join(lines[start_index:end_index]).strip()


def _extract_requirement_excerpt(document_text: str, selector: str, path: str) -> str:
    if path.endswith((".yaml", ".yml")):
        return _extract_yaml_requirement_excerpt(document_text, selector, path)
    if path.endswith(".md"):
        return _extract_markdown_requirement_excerpt(document_text, selector, path)
    raise BarInputError(f"unsupported requirement source file for selector {selector!r}: {path}")


def _extract_yaml_requirement_excerpt(document_text: str, selector: str, path: str) -> str:
    lines = document_text.splitlines()
    block_start: int | None = None
    start_pattern = re.compile(rf"^\s*-\s+id:\s+{re.escape(selector)}\s*$")
    next_pattern = re.compile(r"^\s*-\s+id:\s+")

    for index, line in enumerate(lines):
        if start_pattern.match(line):
            block_start = index
            break
    if block_start is None:
        raise BarInputError(f"unable to resolve requirement selector {selector!r} in {path}")

    block_end = len(lines)
    for index in range(block_start + 1, len(lines)):
        if next_pattern.match(lines[index]):
            block_end = index
            break
    return "\n".join(lines[block_start:block_end]).strip()


def _extract_markdown_requirement_excerpt(document_text: str, selector: str, path: str) -> str:
    row_pattern = re.compile(rf"^\|?\s*{re.escape(selector)}\s*\|")
    for line in document_text.splitlines():
        if row_pattern.match(line):
            return line.strip()
    raise BarInputError(f"unable to resolve requirement selector {selector!r} in {path}")


def _require_dict(data: dict[str, object], key: str) -> dict[str, object]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise BarInputError(f"obligation must define object field {key!r}")
    return value


def _require_dict_list(data: dict[str, object], key: str) -> list[dict[str, object]]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise BarInputError(f"obligation must define array[object] field {key!r}")
    return value


def _require_str(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or value == "":
        raise BarInputError(f"obligation must define non-empty string field {key!r}")
    return value


def _require_str_list(data: dict[str, object], key: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item != "" for item in value):
        raise BarInputError(f"obligation must define array[string] field {key!r}")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value == "":
        raise BarInputError("optional string field must be a non-empty string when present")
    return value


def _validate_input_hash(*, label: str, expected: str, actual: str) -> None:
    if expected != actual:
        raise BarInputError(
            f"freshness_binding.{label} mismatch: ledger records {expected!r}, "
            f"but reviewed commit resolves to {actual!r}"
        )


def _requires_corpus_hash(evidence_entries: list[dict[str, object]]) -> bool:
    return any(
        entry.get("class") in {"adversarial_corpus_minima_check", "corpus_verify"}
        for entry in evidence_entries
    )
