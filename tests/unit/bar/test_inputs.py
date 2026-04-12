"""Tests for deterministic BAR review-bundle assembly."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from wardline.bar.inputs import BarInputError, assemble_review_bundle, resolve_source_ref_excerpt
from wardline.bar.ledger import load_obligation_from_compliance_ledger

if TYPE_CHECKING:
    from pathlib import Path


def test_load_obligation_from_compliance_ledger(bar_fixture_repo: Path) -> None:
    obligation = load_obligation_from_compliance_ledger(
        bar_fixture_repo / "wardline.compliance.json",
        "R-BAR-BUNDLE-EXAMPLE",
    )

    assert obligation["id"] == "R-BAR-BUNDLE-EXAMPLE"
    assert obligation["source_refs"] == [
        "docs/spec/example-conformance.md §15.2(5)",
        "docs/spec/example-properties.md property 3",
        "docs/requirements/spec-fitness/example.yaml WL-FIT-CONF-010",
    ]
    assert obligation["implementation_surface"] == ["src/example_impl.py"]


def test_clause_extractor_resolves_source_ref_excerpt(bar_fixture_repo: Path) -> None:
    obligation = load_obligation_from_compliance_ledger(
        bar_fixture_repo / "wardline.compliance.json",
        "R-BAR-BUNDLE-EXAMPLE",
    )
    commit_ref = obligation["freshness_binding"]["commit_ref"]

    clause_excerpt = resolve_source_ref_excerpt(
        bar_fixture_repo,
        commit_ref,
        "docs/spec/example-conformance.md §15.2(5)",
    )
    property_excerpt = resolve_source_ref_excerpt(
        bar_fixture_repo,
        commit_ref,
        "docs/spec/example-properties.md property 3",
    )
    requirement_excerpt = resolve_source_ref_excerpt(
        bar_fixture_repo,
        commit_ref,
        "docs/requirements/spec-fitness/example.yaml WL-FIT-CONF-010",
    )

    assert "#### 15.2 Conformance criteria" in clause_excerpt.excerpt
    assert "5. Precision and recall are measured" in clause_excerpt.excerpt
    assert "**3. Deterministic output.**" in property_excerpt.excerpt
    assert "- id: WL-FIT-CONF-010" in requirement_excerpt.excerpt


def test_review_bundle_reads_implementation_surface_at_commit_ref(bar_fixture_repo: Path) -> None:
    (bar_fixture_repo / "src" / "example_impl.py").write_text(
        '"""Mutated working-tree implementation."""\n\nVALUE = "working-tree"\n',
        encoding="utf-8",
    )

    bundle = assemble_review_bundle(
        repo_root=bar_fixture_repo,
        ledger_path=bar_fixture_repo / "wardline.compliance.json",
        obligation_id="R-BAR-BUNDLE-EXAMPLE",
        policy_hash="sha256:test-policy",
    )

    assert bundle.obligation_id == "R-BAR-BUNDLE-EXAMPLE"
    assert "reviewer_metadata" not in bundle.obligation_record
    assert bundle.implementation_surface_content[0].path == "src/example_impl.py"
    assert 'VALUE = "committed"' in bundle.implementation_surface_content[0].content
    assert "working-tree" not in bundle.implementation_surface_content[0].content
    assert bundle.evidence_class_outputs[0].class_name == "unit_tests"
    assert bundle.evidence_class_outputs[0].status == "ok"
    assert bundle.evidence_class_outputs[0].exit_code == 0


def test_dirty_commit_ref_is_rejected(bar_fixture_repo: Path) -> None:
    ledger_path = bar_fixture_repo / "wardline.compliance.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    commit_ref = ledger["obligations"][0]["freshness_binding"]["commit_ref"]
    ledger["obligations"][0]["freshness_binding"]["commit_ref"] = f"{commit_ref}-dirty"
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(BarInputError, match="dirty commit refs"):
        assemble_review_bundle(
            repo_root=bar_fixture_repo,
            ledger_path=ledger_path,
            obligation_id="R-BAR-BUNDLE-EXAMPLE",
            policy_hash="sha256:test-policy",
        )


def test_manifest_hash_mismatch_is_rejected(bar_fixture_repo: Path) -> None:
    ledger_path = bar_fixture_repo / "wardline.compliance.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["obligations"][0]["freshness_binding"]["manifest_hash"] = "sha256:wrong"
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(BarInputError, match="freshness_binding.manifest_hash mismatch"):
        assemble_review_bundle(
            repo_root=bar_fixture_repo,
            ledger_path=ledger_path,
            obligation_id="R-BAR-BUNDLE-EXAMPLE",
            policy_hash="sha256:test-policy",
        )


def test_corpus_hash_mismatch_is_rejected(bar_fixture_repo: Path) -> None:
    ledger_path = bar_fixture_repo / "wardline.compliance.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["obligations"][0]["freshness_binding"]["corpus_hash"] = "sha256:wrong"
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(BarInputError, match="freshness_binding.corpus_hash mismatch"):
        assemble_review_bundle(
            repo_root=bar_fixture_repo,
            ledger_path=ledger_path,
            obligation_id="R-BAR-BUNDLE-EXAMPLE",
            policy_hash="sha256:test-policy",
        )
