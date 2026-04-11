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
            # Schema: {cells: [...], overall_verdict: "PASS"|"FAIL", summary: {...}}
            failing_cells = [
                cell for cell in data.get("cells", [])
                if cell.get("cell_verdict") == "FAIL"
            ]
            assert result.returncode == 0, (
                f"corpus verify failed (overall_verdict={data.get('overall_verdict')}) "
                f"with {len(failing_cells)} failing cell(s): "
                + ", ".join(
                    f"{c.get('rule')}@{c.get('taint_state')}"
                    for c in failing_cells[:5]
                )
            )
        else:
            assert result.returncode == 0, (
                f"corpus verify produced no output; stderr: {result.stderr[:500]}"
            )



class TestCorpusIntegrity:
    """Corpus structural invariants — runs by default (no integration marker)."""

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

    def test_no_orphaned_py_files(self) -> None:
        """Every .py file in specimens/ must have a corresponding .yaml file."""
        specimens_dir = CORPUS_ROOT / "specimens"
        yaml_stems = {p.with_suffix("") for p in specimens_dir.rglob("*.yaml")}
        orphans = [
            p for p in sorted(specimens_dir.rglob("*.py"))
            if p.with_suffix("") not in yaml_stems
        ]
        assert not orphans, (
            f"{len(orphans)} orphaned .py file(s) without YAML metadata:\n"
            + "\n".join(str(p.relative_to(CORPUS_ROOT)) for p in orphans[:10])
        )

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

    def test_structured_expected_match_coverage(self) -> None:
        """At least 80% of TP specimens must use structured expected_match."""
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))

        tp_total = 0
        tp_structured = 0
        tp_boolean: list[str] = []
        for s in data["specimens"]:
            if s["verdict"] == "true_positive":
                tp_total += 1
                if isinstance(s.get("expected_match"), dict):
                    tp_structured += 1
                else:
                    tp_boolean.append(s["specimen_id"])

        assert tp_total > 0, "No TP specimens found"
        ratio = tp_structured / tp_total

        assert ratio >= 0.80, (
            f"Structured expected_match coverage too low: "
            f"{tp_structured}/{tp_total} ({ratio:.0%}). "
            f"Boolean specimens: {tp_boolean[:10]}"
        )

    def test_no_new_boolean_expected_match_for_auto_migrated_rules(self) -> None:
        """Rules with auto-migration support must not have boolean expected_match.

        PY-WL-001 through PY-WL-005 and PY-WL-007 have mechanical AST patterns.
        New specimens for these rules must use structured expected_match.
        PY-WL-006, PY-WL-008, PY-WL-009 are excluded (manual-only).
        """
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))

        auto_rules = {f"PY-WL-{i:03d}" for i in (1, 2, 3, 4, 5, 7)}
        violations: list[str] = []
        for s in data["specimens"]:
            rule = s.get("rule", "") or s.get("rule_id", "")
            if (
                s["verdict"] == "true_positive"
                and rule in auto_rules
                and s.get("expected_match") is True
            ):
                violations.append(s["specimen_id"])

        assert not violations, (
            f"{len(violations)} auto-migratable specimens still use boolean "
            f"expected_match: {violations[:10]}"
        )

    def test_no_duplicate_sha256_across_rules(self) -> None:
        """No two specimens across different rules should share a sha256 hash."""
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))

        by_sha: dict[str, list[str]] = defaultdict(list)
        for s in data["specimens"]:
            by_sha[s["sha256"]].append(f"{s['rule']}:{s['specimen_id']}")

        collisions: list[str] = []
        for sha, ids in sorted(by_sha.items()):
            rules = {entry.split(":")[0] for entry in ids}
            if len(rules) > 1:
                collisions.append(f"sha={sha[:10]}: {ids}")

        assert not collisions, (
            f"{len(collisions)} cross-rule sha256 collision(s):\n"
            + "\n".join(collisions[:10])
        )

    def test_taint_invariant_rules_produce_identical_matrix_cells(self) -> None:
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

    def test_taint_invariant_rules_scanner_produces_identical_findings(self) -> None:
        """Scanner output for PY-WL-008/009 must be identical across taint states.

        This goes beyond the matrix test: it runs the actual rule implementation
        against a TP fragment under every taint state and verifies the scanner
        produces the same findings regardless of taint context.
        """
        import ast

        from wardline.manifest.models import BoundaryEntry
        from wardline.scanner.context import ScanContext
        from wardline.scanner.rules.py_wl_008 import RulePyWl008
        from wardline.scanner.rules.py_wl_009 import RulePyWl009

        cases = [
            (
                RulePyWl008,
                "def target(data):\n    result = validate(data)\n    return data\n",
                "shape_validation",
            ),
            (
                RulePyWl009,
                'def target(data):\n    if data["status"] == "active":\n        pass\n',
                "semantic_validation",
            ),
        ]
        all_taints = list(TaintState)

        for rule_cls, fragment, transition in cases:
            findings_by_taint: dict[str, list[tuple[str, str]]] = {}
            tree = ast.parse(fragment)

            for taint in all_taints:
                boundary = BoundaryEntry(
                    function="target",
                    transition=transition,
                    overlay_scope="/project/src",
                )
                rule = rule_cls(file_path="/project/src/handler.py")
                ctx = ScanContext(
                    file_path="/project/src/handler.py",
                    function_level_taint_map={"target": taint},
                    boundaries=(boundary,),
                )
                rule.set_context(ctx)
                rule.visit(tree)
                findings_by_taint[taint.name] = [
                    (f.rule_id, f.severity.name) for f in rule.findings
                ]

            reference_taint = all_taints[0].name
            reference = findings_by_taint[reference_taint]
            for taint_name, findings in findings_by_taint.items():
                assert findings == reference, (
                    f"{rule_cls.RULE_ID}: findings differ at {taint_name} vs {reference_taint}: "
                    f"{findings} != {reference}"
                )
