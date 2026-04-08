"""Corpus oracle property test — TP specimens produce findings, TN specimens do not."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

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
        """TP specimens should have expected_match=True, TN should have expected_match=False."""
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))

        mismatches: list[str] = []
        for s in data["specimens"]:
            verdict = s["verdict"]
            expected = s.get("expected_match")
            if verdict == "true_positive" and expected is not True:
                mismatches.append(f"{s['specimen_id']}: TP but expected_match={expected}")
            elif verdict == "true_negative" and expected is not False:
                mismatches.append(f"{s['specimen_id']}: TN but expected_match={expected}")

        assert not mismatches, f"{len(mismatches)} verdict/match mismatches: {mismatches[:5]}"
