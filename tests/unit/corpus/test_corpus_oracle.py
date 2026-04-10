"""Corpus oracle property test — TP specimens produce findings, TN specimens do not."""

from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

from wardline.core.matrix import SEVERITY_MATRIX
from wardline.core.severity import RuleId
from wardline.core.taints import TaintState

CORPUS_ROOT = Path(__file__).parent.parent.parent.parent / "corpus"


@pytest.mark.integration
class TestCorpusOracle:
    """Run corpus verify and check that verdicts match expectations."""

    def test_corpus_verify_exits_cleanly(self) -> None:
        """wardline corpus verify --json should succeed (exit 0)."""
        result = subprocess.run(
            ["uv", "run", "wardline", "corpus", "verify", "--json"],
            capture_output=True,
            text=True,
            cwd=str(CORPUS_ROOT.parent),
            timeout=120,
        )
        # Parse JSON output even if exit code is non-zero, to give a useful message
        if result.stdout.strip():
            data = json.loads(result.stdout)
            failures = [
                entry for entry in data
                if entry.get("status") not in ("pass", "skip")
            ]
            assert result.returncode == 0, (
                f"corpus verify failed with {len(failures)} failure(s): "
                + ", ".join(f["specimen_id"] for f in failures[:5])
            )
        else:
            assert result.returncode == 0, (
                f"corpus verify produced no output; stderr: {result.stderr[:500]}"
            )

    def test_manifest_verdict_coverage(self) -> None:
        """Manifest has both TP and TN specimens for coverage."""
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        specimens = data["specimens"]

        verdicts = {s["verdict"] for s in specimens}
        assert "true_positive" in verdicts, "Corpus has no true_positive specimens"
        assert "true_negative" in verdicts, "Corpus has no true_negative specimens"

    def test_expected_match_aligns_with_verdict(self) -> None:
        """TP specimens should have expected_match=True or structured dict, TN should have False."""
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))

        mismatches: list[str] = []
        for s in data["specimens"]:
            verdict = s["verdict"]
            expected = s.get("expected_match")
            if verdict == "true_positive":
                if not (isinstance(expected, dict) or expected is True):
                    mismatches.append(f"{s['specimen_id']}: TP but expected_match={expected}")
                if isinstance(expected, dict):
                    if "line" not in expected or "text" not in expected:
                        mismatches.append(f"{s['specimen_id']}: TP structured match missing line/text")
            elif verdict == "true_negative" and expected is not False:
                mismatches.append(f"{s['specimen_id']}: TN but expected_match={expected}")

        assert not mismatches, f"{len(mismatches)} verdict/match mismatches: {mismatches[:5]}"


class TestCorpusIntegrity:
    """Corpus structural invariants — runs by default (no integration marker)."""

    def test_no_duplicate_sha256_within_rule(self) -> None:
        """Every specimen within a rule must have a unique fragment (sha256)."""
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))

        by_rule_sha: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for s in data["specimens"]:
            by_rule_sha[s["rule"]][s["sha256"]].append(s["specimen_id"])

        duplicates: list[str] = []
        for rule, sha_groups in sorted(by_rule_sha.items()):
            for sha, ids in sha_groups.items():
                if len(ids) > 1:
                    duplicates.append(f"{rule} sha={sha[:10]}: {ids}")

        assert not duplicates, (
            f"{len(duplicates)} duplicate sha256 groups:\n"
            + "\n".join(duplicates[:10])
        )

    def test_taint_invariant_rules_produce_identical_outputs(self) -> None:
        """PY-WL-008 and PY-WL-009 must produce identical severity/exceptionability for all taint states."""
        taint_invariant_rules = [RuleId.PY_WL_008, RuleId.PY_WL_009]
        all_taints = list(TaintState)

        for rule in taint_invariant_rules:
            cells = [SEVERITY_MATRIX[(rule, t)] for t in all_taints]
            severities = {c.severity for c in cells}
            exceptionabilities = {c.exceptionability for c in cells}
            assert len(severities) == 1, (
                f"{rule}: expected uniform severity, got {severities}"
            )
            assert len(exceptionabilities) == 1, (
                f"{rule}: expected uniform exceptionability, got {exceptionabilities}"
            )
