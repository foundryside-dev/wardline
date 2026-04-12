"""Tests for BAR evidence execution."""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

from wardline.bar.evidence_exec import execute_evidence_classes
from wardline.bar.inputs import assemble_review_bundle

if TYPE_CHECKING:
    from pathlib import Path


def test_execute_unit_tests_evidence_class(bar_fixture_repo: Path) -> None:
    ledger = json.loads((bar_fixture_repo / "wardline.compliance.json").read_text(encoding="utf-8"))
    commit_ref = ledger["obligations"][0]["freshness_binding"]["commit_ref"]

    outputs = execute_evidence_classes(
        bar_fixture_repo,
        commit_ref,
        [{"class": "unit_tests", "target": "tests/unit/test_example_impl.py"}],
    )

    assert len(outputs) == 1
    output = outputs[0]
    assert output.class_name == "unit_tests"
    assert output.status == "ok"
    assert output.mode == "command_result"
    assert output.exit_code == 0
    assert "1 passed" in output.content


def test_unsupported_evidence_class_refuses_bundle(bar_fixture_repo: Path) -> None:
    ledger_path = bar_fixture_repo / "wardline.compliance.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["obligations"][0]["evidence_classes"] = [
        {"class": "runtime_descriptor_check", "target": "src/example_impl.py"}
    ]
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    bundle = assemble_review_bundle(
        repo_root=bar_fixture_repo,
        ledger_path=ledger_path,
        obligation_id="R-BAR-BUNDLE-EXAMPLE",
        policy_hash="sha256:test-policy",
    )

    assert len(bundle.evidence_class_outputs) == 1
    output = bundle.evidence_class_outputs[0]
    assert output.class_name == "runtime_descriptor_check"
    assert output.status == "unsupported"
    assert "insufficient_evidence" in output.summary


def test_execute_command_backed_evidence_classes(bar_fixture_repo: Path) -> None:
    ledger = json.loads((bar_fixture_repo / "wardline.compliance.json").read_text(encoding="utf-8"))
    commit_ref = ledger["obligations"][0]["freshness_binding"]["commit_ref"]
    sarif_path = bar_fixture_repo / "docs" / "verification.sarif.json"
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "properties": {
                            "wardline.controlLaw": "normal",
                            "wardline.manifestHash": ledger["obligations"][0]["freshness_binding"]["manifest_hash"],
                            "wardline.commitRef": commit_ref,
                        },
                        "results": [],
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "docs/verification.sarif.json"], cwd=bar_fixture_repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add sarif evidence"],
        cwd=bar_fixture_repo,
        check=True,
        capture_output=True,
        text=True,
    )
    commit_ref = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=bar_fixture_repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    outputs = execute_evidence_classes(
        bar_fixture_repo,
        commit_ref,
        [
            {"class": "manifest_schema_validation", "target": "wardline.yaml"},
            {"class": "coherence_check", "target": "wardline.yaml"},
            {"class": "corpus_verify", "target": "corpus/corpus_manifest.json"},
            {"class": "conformance_report", "target": "wardline.conformance.json"},
            {"class": "sarif_rule_output", "target": "docs/verification.sarif.json"},
        ],
    )

    assert [output.class_name for output in outputs] == [
        "manifest_schema_validation",
        "coherence_check",
        "corpus_verify",
        "conformance_report",
        "sarif_rule_output",
    ]
    assert all(output.mode == "command_result" for output in outputs)
    assert all(output.status == "ok" for output in outputs)
    assert outputs[0].exit_code == 0
    assert '"valid": true' in outputs[0].content.lower()
    assert outputs[1].command[0].endswith("python") or outputs[1].command[0].endswith("python3")
    assert outputs[2].exit_code is not None
    assert "specimens" in outputs[2].content.lower()
    assert outputs[3].exit_code is not None
    assert '"data_unavailable":' in outputs[3].content.lower()
    assert outputs[4].exit_code == 0
    assert '"control_law": "normal"' in outputs[4].content.lower()
