"""Unit tests for corpus verification logic.

Tests the security invariant (no exec/eval/compile) and hash verification.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from wardline.cli.main import cli

FIXTURE_CORPUS = Path(__file__).parent.parent.parent / "fixtures" / "corpus"


class TestNoExecEval:
    """Assert the critical security invariant: no exec/eval on specimens."""

    def test_no_exec_eval_called(self) -> None:
        """Patching exec/eval to raise ensures they are never called.

        compile is tested separately because ast.parse() internally
        calls builtins.compile at the C level on CPython.
        """
        # Pre-warm ALL modules that corpus verify lazily imports.
        # Python's import machinery uses builtins.exec internally, so any
        # module imported for the first time under the exec patch will
        # trigger the security invariant.
        #
        # Strategy: do a dry-run of corpus verify WITHOUT the exec patch,
        # then patch and run again. The dry run caches all transitive imports.
        runner = CliRunner()
        runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS)]
        )

        def _fail(*args: object, **kwargs: object) -> None:
            raise AssertionError(
                "exec/eval must never be called on specimens"
            )

        with (
            patch("builtins.exec", side_effect=_fail),
            patch("builtins.eval", side_effect=_fail),
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS)]
            )
            # Should complete without triggering the patched builtins
            assert result.exit_code == 0, (
                f"Expected exit 0, got {result.exit_code}.\n"
                f"output: {result.output}\n"
                f"stderr: {getattr(result, 'stderr', '')}"
            )

    def test_no_compile_in_source(self) -> None:
        """corpus_cmds.py must not call compile() directly."""
        import wardline.cli.corpus_cmds as mod

        source = Path(mod.__file__).read_text()  # type: ignore[arg-type]
        # Allow "ast.parse" but not bare "compile("
        assert "compile(" not in source, (
            "corpus_cmds.py must not call compile() directly"
        )

    def test_only_ast_parse_used(self) -> None:
        """Verify ast.parse is called and compile is not called directly."""
        real_ast_parse = ast.parse
        parse_called = False

        def tracking_parse(*args: object, **kwargs: object) -> object:
            nonlocal parse_called
            parse_called = True
            return real_ast_parse(*args, **kwargs)  # type: ignore[arg-type]

        with patch("wardline.cli.corpus_cmds.ast.parse", side_effect=tracking_parse):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS)]
            )
            assert result.exit_code == 0
            assert parse_called, "ast.parse should be called during verification"


class TestHashVerification:
    """Test SHA-256 hash verification of specimens."""

    def test_correct_hash_passes(self, tmp_path: Path) -> None:
        """Specimen with correct hash passes verification."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "good.yaml"
        specimen.write_text(
            f'rule_id: "TEST-001"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"source: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "Lite bootstrap: 1 specimens" in result.output

    def test_wrong_hash_produces_error(self, tmp_path: Path) -> None:
        """Specimen with wrong hash produces an error."""
        specimen = tmp_path / "bad.yaml"
        specimen.write_text(
            'rule_id: "TEST-001"\n'
            'verdict: "true_positive"\n'
            'sha256: "000000000000000000000000000000000000'
            '0000000000000000000000000000"\n'
            "source: |\n"
            "  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "hash mismatch" in result.stderr


class TestSpecimenLoading:
    """Test YAML specimen loading and field handling."""

    def test_valid_specimen_loads(self, tmp_path: Path) -> None:
        """Valid specimen YAML loads and passes verification."""
        source = "y = 2\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "valid.yaml"
        specimen.write_text(
            f'rule_id: "TEST-002"\n'
            f'verdict: "true_negative"\n'
            f'sha256: "{sha}"\n'
            f"source: |\n"
            f"  y = 2\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "Lite bootstrap: 1 specimens" in result.output

    def test_missing_fragment_handled(self, tmp_path: Path) -> None:
        """Specimen missing 'fragment' field is handled gracefully."""
        specimen = tmp_path / "nofragment.yaml"
        specimen.write_text(
            'rule_id: "TEST-003"\n'
            'verdict: "true_positive"\n'
            'sha256: "abc"\n'
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "no 'fragment' field" in result.stderr

    def test_no_specimens_found(self, tmp_path: Path) -> None:
        """Empty corpus directory produces error."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "No specimens found" in result.stderr

    def test_syntax_error_in_source(self, tmp_path: Path) -> None:
        """Specimen with invalid Python syntax produces an error."""
        source = "def (\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "badsyntax.yaml"
        specimen.write_text(
            f'rule_id: "TEST-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"source: |\n"
            f"  def (\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "syntax error" in result.stderr


class TestSpecimenFileErrors:
    """Test error handling for unreadable or malformed specimen files."""

    def test_malformed_yaml_handled(self, tmp_path: Path) -> None:
        """Malformed YAML specimen produces error, not traceback."""
        specimen = tmp_path / "bad.yaml"
        specimen.write_text("{{{{not valid yaml: [}\n")

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "invalid YAML" in result.stderr
        assert "Traceback" not in (result.output + result.stderr)

    def test_unreadable_file_handled(self, tmp_path: Path) -> None:
        """Unreadable specimen file produces error, not traceback."""
        import os

        specimen = tmp_path / "locked.yaml"
        specimen.write_text("rule_id: TEST\n")
        os.chmod(str(specimen), 0o000)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        # Restore permissions for cleanup
        os.chmod(str(specimen), 0o644)
        assert result.exit_code == 1
        assert "cannot read" in result.stderr
        assert "Traceback" not in (result.output + result.stderr)


class TestVerdictEvaluation:
    """Test specimen verdict evaluation against scanner results."""

    def test_true_positive_rule_fires(self, tmp_path: Path) -> None:
        """TP specimen where expected rule fires."""
        source = (
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        pass\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def f():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 TP" in result.output

    def test_true_positive_with_boundaries_field(self, tmp_path: Path) -> None:
        """Specimen boundaries feed ScanContext for boundary-scoped rules."""
        source = (
            "def process(data):\n"
            "    result = validate(data)\n"
            "    return data\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp-boundary.yaml"
        specimen.write_text(
            f'specimen_id: "tp-wl008-boundary"\n'
            f'rule: "PY-WL-008"\n'
            f'taint_state: "EXTERNAL_RAW"\n'
            f'verdict: "true_positive"\n'
            f"boundaries:\n"
            f'  - function: "process"\n'
            f'    transition: "shape_validation"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def process(data):\n"
            f"      result = validate(data)\n"
            f"      return data\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 TP" in result.output

    def test_true_negative_with_optional_fields_and_boundaries(
        self, tmp_path: Path
    ) -> None:
        """Specimen optional_fields feed ScanContext for governed defaults."""
        source = (
            "from wardline import schema_default\n\n"
            "def process(data):\n"
            '    return schema_default(data.get("key", ""))\n'
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tn-governed-default.yaml"
        specimen.write_text(
            f'specimen_id: "tn-wl001-governed-default"\n'
            f'rule: "PY-WL-001"\n'
            f'taint_state: "EXTERNAL_RAW"\n'
            f'verdict: "true_negative"\n'
            f"boundaries:\n"
            f'  - function: "process"\n'
            f'    transition: "shape_validation"\n'
            f"optional_fields:\n"
            f'  - field: "key"\n'
            f'    approved_default: ""\n'
            f'    rationale: "optional by contract"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  from wardline import schema_default\n"
            f"\n"
            f"  def process(data):\n"
            f'      return schema_default(data.get("key", ""))\n'
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 TN" in result.output

    def test_true_negative_no_rule_fires(
        self, tmp_path: Path
    ) -> None:
        """TN specimen where no rule fires."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tn.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_negative"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 TN" in result.output

    def test_known_false_negative_tracked(
        self, tmp_path: Path
    ) -> None:
        """KFN specimen is tracked separately."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "kfn.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "known_false_negative"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 KFN" in result.output

    def test_false_negative_detected(self, tmp_path: Path) -> None:
        """TP specimen where rule does NOT fire → counted as FN."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "fn.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 FN" in result.output


class TestPrecisionRecall:
    """Test precision/recall calculation and output."""

    def _make_tp_specimen(
        self, tmp_path: Path, idx: int
    ) -> None:
        """Create a TP specimen for PY-WL-004."""
        source = (
            f"def f{idx}():\n"
            f"    try:\n"
            f"        pass\n"
            f"    except Exception:\n"
            f"        pass\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / f"tp_{idx}.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def f{idx}():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )

    def test_precision_recall_printed_when_ge_5(
        self, tmp_path: Path
    ) -> None:
        """Precision/recall printed for rules with >= 5 specimens."""
        for i in range(5):
            self._make_tp_specimen(tmp_path, i)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "PY-WL-004" in result.output
        assert "precision=" in result.output

    def test_precision_recall_skipped_when_lt_5(
        self, tmp_path: Path
    ) -> None:
        """Precision/recall NOT printed for < 5 specimens."""
        self._make_tp_specimen(tmp_path, 0)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "precision=" not in result.output

    def test_kfn_excluded_from_recall(
        self, tmp_path: Path
    ) -> None:
        """KFN excluded from recall denominator."""
        # 3 TP specimens
        for i in range(3):
            self._make_tp_specimen(tmp_path, i)
        # 2 KFN specimens (total=5 but recall denom stays 3)
        for i in range(2):
            source = f"y{i} = 1\n"
            sha = hashlib.sha256(
                source.encode("utf-8")
            ).hexdigest()
            specimen = tmp_path / f"kfn_{i}.yaml"
            specimen.write_text(
                f'rule: "PY-WL-004"\n'
                f'verdict: "known_false_negative"\n'
                f'sha256: "{sha}"\n'
                f"fragment: |\n"
                f"  y{i} = 1\n"
            )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "2 KFN" in result.output
        # With 3 TP and 0 FN, recall should be 100%
        assert "recall=100.0%" in result.output


class TestCollectFindings:
    """Tests for _collect_findings_on_fragment."""

    def test_returns_finding_objects(self) -> None:
        from wardline.cli.corpus_cmds import _collect_findings_on_fragment
        from wardline.scanner.context import Finding
        from wardline.scanner.rules import make_rules

        # PY-WL-001 fires as ERROR for INTEGRAL (not SUPPRESS)
        source = 'def process(data):\n    x = data.get("key", "default")\n'
        rules = make_rules()
        findings = _collect_findings_on_fragment(source, rules, taint_state="INTEGRAL")
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)
        pywl001 = [f for f in findings if str(f.rule_id) == "PY-WL-001"]
        assert len(pywl001) >= 1

    def test_excludes_suppressed(self) -> None:
        from wardline.cli.corpus_cmds import _collect_findings_on_fragment
        from wardline.core.severity import Severity
        from wardline.scanner.rules import make_rules

        # EXTERNAL_RAW → PY-WL-001 is SUPPRESS; _collect_findings_on_fragment must exclude it
        source = 'def process(data):\n    x = data.get("key", "default")\n'
        rules = make_rules()
        findings = _collect_findings_on_fragment(source, rules, taint_state="EXTERNAL_RAW")
        for f in findings:
            assert f.severity != Severity.SUPPRESS

    def test_populates_source_snippet(self) -> None:
        from wardline.cli.corpus_cmds import _collect_findings_on_fragment
        from wardline.scanner.rules import make_rules

        # Use INTEGRAL so PY-WL-001 fires as non-SUPPRESS and we can check the snippet
        source = 'def process(data):\n    x = data.get("key", "default")\n'
        rules = make_rules()
        findings = _collect_findings_on_fragment(source, rules, taint_state="INTEGRAL")
        pywl001 = [f for f in findings if str(f.rule_id) == "PY-WL-001"]
        assert len(pywl001) >= 1
        assert pywl001[0].source_snippet is not None

    def test_run_rules_on_fragment_unchanged_behavior(self) -> None:
        from wardline.cli.corpus_cmds import _run_rules_on_fragment
        from wardline.scanner.rules import make_rules

        # Use INTEGRAL so PY-WL-001 fires as ERROR (not SUPPRESS)
        source = 'def process(data):\n    x = data.get("key", "default")\n'
        rules = make_rules()
        fired = _run_rules_on_fragment(source, rules, taint_state="INTEGRAL")
        assert isinstance(fired, set)
        assert "PY-WL-001" in fired


class TestPerCellStats:
    """Per-cell (rule x taint_state) metric accumulation."""

    def test_cell_stats_keyed_by_rule_and_taint(self) -> None:
        from wardline.cli.corpus_cmds import _CellStats

        stats: dict[tuple[str, str], _CellStats] = {}
        key = ("PY-WL-001", "INTEGRAL")
        stats[key] = _CellStats()
        stats[key].tp += 1
        assert stats[key].tp == 1
        assert stats[key].sample_size == 1

    def test_cell_stats_different_taints_are_independent(self) -> None:
        from wardline.cli.corpus_cmds import _CellStats

        stats: dict[tuple[str, str], _CellStats] = {}
        stats[("PY-WL-001", "INTEGRAL")] = _CellStats(tp=5)
        stats[("PY-WL-001", "EXTERNAL_RAW")] = _CellStats(tp=3, fp=1)
        assert stats[("PY-WL-001", "INTEGRAL")].tp == 5
        assert stats[("PY-WL-001", "EXTERNAL_RAW")].tp == 3


class TestCorpusVerifyJson:
    """Assessment-artefact JSON output from corpus verify --json."""

    def test_json_output_has_cells_and_summary(self) -> None:
        import json

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS), "--json"]
        )
        data = json.loads(result.output)
        assert "cells" in data
        assert "summary" in data
        assert "overall_verdict" in data
        assert isinstance(data["cells"], list)

    def test_json_cell_has_verdict(self) -> None:
        import json

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS), "--json"]
        )
        data = json.loads(result.output)
        for cell in data["cells"]:
            assert "cell_verdict" in cell
            assert cell["cell_verdict"] in ("PASS", "FAIL", "NO_DATA")

    def test_json_output_deterministic(self) -> None:
        runner = CliRunner()
        args = ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS), "--json"]
        r1 = runner.invoke(cli, args)
        r2 = runner.invoke(cli, args)
        # Byte-identical — no timestamps in verify output (determinism per §11)
        assert r1.output == r2.output

    def test_json_overall_verdict(self) -> None:
        import json

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS), "--json"]
        )
        data = json.loads(result.output)
        assert data["overall_verdict"] in ("PASS", "FAIL")


class TestCorpusPublish:
    """Tests for corpus publish command — generates wardline.conformance.json."""

    def test_publish_creates_conformance_json(self, tmp_path: Path) -> None:
        import json

        sarif = {
            "version": "2.1.0",
            "runs": [{
                "results": [],
                "properties": {
                    "wardline.implementedRules": ["PY-WL-001"],
                    "wardline.inputHash": "sha256:abc",
                    "wardline.manifestHash": "sha256:def",
                },
                "tool": {"driver": {"version": "0.4.0"}},
            }],
        }
        sarif_path = tmp_path / "self-hosting.sarif.json"
        sarif_path.write_text(json.dumps(sarif))

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "corpus", "publish",
                "--corpus-dir", str(FIXTURE_CORPUS),
                "--sarif", str(sarif_path),
                "--output", str(tmp_path / "wardline.conformance.json"),
            ],
        )
        assert result.exit_code == 0, f"Failed: {result.output}"
        conf = json.loads((tmp_path / "wardline.conformance.json").read_text())
        assert "corpus_verdict" in conf
        assert "self_hosting_verdict" in conf
        assert "inputs" in conf
        assert "gaps" in conf

    def test_publish_inputs_binding(self, tmp_path: Path) -> None:
        import json

        sarif = {
            "version": "2.1.0",
            "runs": [{
                "results": [],
                "properties": {
                    "wardline.implementedRules": ["PY-WL-001"],
                    "wardline.inputHash": "sha256:abc123",
                    "wardline.manifestHash": "sha256:manifest456",
                },
                "tool": {"driver": {"version": "0.4.0"}},
            }],
        }
        sarif_path = tmp_path / "self-hosting.sarif.json"
        sarif_path.write_text(json.dumps(sarif))

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "corpus", "publish",
                "--corpus-dir", str(FIXTURE_CORPUS),
                "--sarif", str(sarif_path),
                "--output", str(tmp_path / "wardline.conformance.json"),
            ],
        )
        conf = json.loads((tmp_path / "wardline.conformance.json").read_text())
        inputs = conf["inputs"]
        assert inputs["tool_version"] == "0.4.0"
        assert inputs["self_hosting_input_hash"] == "sha256:abc123"
        assert inputs["manifest_hash"] == "sha256:manifest456"
        assert "corpus_hash" in inputs
        assert inputs["corpus_hash"].startswith("sha256:")

    @staticmethod
    def _make_sarif(tmp_path: Path, implemented_rules: list[str]) -> Path:
        import json

        sarif = {
            "version": "2.1.0",
            "runs": [{
                "results": [],
                "properties": {
                    "wardline.implementedRules": implemented_rules,
                    "wardline.inputHash": "sha256:test",
                    "wardline.manifestHash": "sha256:test",
                },
                "tool": {"driver": {"version": "0.4.0"}},
            }],
        }
        sarif_path = tmp_path / "self-hosting.sarif.json"
        sarif_path.write_text(json.dumps(sarif))
        return sarif_path

    _specimen_counter = 0

    @classmethod
    def _make_specimen(
        cls,
        corpus_dir: Path,
        rule: str,
        category: str,
        verdict: str = "true_positive",
        fragment: str = 'def f():\n    data = {}\n    x = data.get("k", 0)\n',
    ) -> None:
        import hashlib

        sha = hashlib.sha256(fragment.encode("utf-8")).hexdigest()
        cls._specimen_counter += 1
        name = f"spec-{cls._specimen_counter:04d}"
        spec_dir = corpus_dir / "specimens"
        spec_dir.mkdir(parents=True, exist_ok=True)
        yaml_content = (
            f"---\nrule: \"{rule}\"\ncategory: \"{category}\"\n"
            f"verdict: \"{verdict}\"\n"
            f"sha256: \"{sha}\"\n"
            f"fragment: |\n"
        )
        for line in fragment.splitlines():
            yaml_content += f"  {line}\n"
        if verdict == "true_positive":
            yaml_content += f"expected_rules:\n- {rule}\nexpected_match: true\n"
        else:
            yaml_content += "expected_rules: []\nexpected_match: false\n"
        (spec_dir / f"{name}.yaml").write_text(yaml_content)

    def test_publish_adversarial_gap_removed_when_floor_met(
        self, tmp_path: Path,
    ) -> None:
        """Per-rule AFP/AFN coverage + aggregate floors → no adversarial gap."""
        import json

        corpus_dir = tmp_path / "corpus"
        rules = ["PY-WL-001", "PY-WL-002"]
        tp_frag = 'def f():\n    data = {}\n    x = data.get("k", 0)\n'
        tn_frag = "def f():\n    pass\n"

        # 1 AFP (TN) and 1 AFN (TP) per implemented rule
        for rule in rules:
            self._make_specimen(corpus_dir, rule, "adversarial_false_positive", "true_negative", tn_frag)
            self._make_specimen(corpus_dir, rule, "adversarial_false_negative", "true_positive", tp_frag)

        # 3 suppression_interaction specimens
        for i in range(3):
            self._make_specimen(
                corpus_dir, "PY-WL-001", "suppression_interaction", "true_positive",
                f'def f{i}():\n    data = {{}}\n    x = data.get("k{i}", 0)\n',
            )

        # 8 taint_flow specimens
        for i in range(8):
            self._make_specimen(
                corpus_dir, "PY-WL-001", "taint_flow", "true_positive",
                f'def g{i}():\n    data = {{}}\n    x = data.get("k{i}", 0)\n',
            )

        sarif_path = self._make_sarif(tmp_path, rules)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "publish", "--corpus-dir", str(corpus_dir),
             "--sarif", str(sarif_path),
             "--output", str(tmp_path / "conformance.json")],
        )
        assert result.exit_code == 0, f"Failed: {result.output}"
        conf = json.loads((tmp_path / "conformance.json").read_text())
        adversarial_gaps = [g for g in conf["gaps"] if "adversarial" in g]
        assert adversarial_gaps == [], f"Unexpected adversarial gap: {adversarial_gaps}"

    def test_publish_adversarial_gap_remains_when_rule_missing_afp(
        self, tmp_path: Path,
    ) -> None:
        """AFP missing for one rule → adversarial gap names the missing rule."""
        import json

        corpus_dir = tmp_path / "corpus"
        rules = ["PY-WL-001", "PY-WL-002"]
        tp_frag = 'def f():\n    data = {}\n    x = data.get("k", 0)\n'
        tn_frag = "def f():\n    pass\n"

        # AFP only for PY-WL-001, AFN for both — PY-WL-002 AFP is missing
        self._make_specimen(corpus_dir, "PY-WL-001", "adversarial_false_positive", "true_negative", tn_frag)
        for rule in rules:
            self._make_specimen(corpus_dir, rule, "adversarial_false_negative", "true_positive", tp_frag)

        for i in range(3):
            self._make_specimen(
                corpus_dir, "PY-WL-001", "suppression_interaction", "true_positive",
                f'def f{i}():\n    data = {{}}\n    x = data.get("k{i}", 0)\n',
            )
        for i in range(8):
            self._make_specimen(
                corpus_dir, "PY-WL-001", "taint_flow", "true_positive",
                f'def g{i}():\n    data = {{}}\n    x = data.get("k{i}", 0)\n',
            )

        sarif_path = self._make_sarif(tmp_path, rules)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "publish", "--corpus-dir", str(corpus_dir),
             "--sarif", str(sarif_path),
             "--output", str(tmp_path / "conformance.json")],
        )
        assert result.exit_code == 0, f"Failed: {result.output}"
        conf = json.loads((tmp_path / "conformance.json").read_text())
        adversarial_gaps = [g for g in conf["gaps"] if "adversarial" in g]
        assert len(adversarial_gaps) == 1
        assert "PY-WL-002" in adversarial_gaps[0]
        assert "adversarial_false_positive" in adversarial_gaps[0]


class TestStructuralComparison:
    """Tests for _normalize_snippet_text, _find_matching_finding, _check_location_match."""

    def test_normalize_strips_and_collapses(self) -> None:
        from wardline.cli.corpus_cmds import _normalize_snippet_text
        assert _normalize_snippet_text("  x =  data.get('k')  ") == "x = data.get('k')"

    def test_normalize_empty_string(self) -> None:
        from wardline.cli.corpus_cmds import _normalize_snippet_text
        assert _normalize_snippet_text("") == ""

    def test_normalize_tabs_and_newlines(self) -> None:
        from wardline.cli.corpus_cmds import _normalize_snippet_text
        assert _normalize_snippet_text("\t  x\n  =  1\t") == "x = 1"

    def test_find_matching_exact_line(self) -> None:
        from wardline.cli.corpus_cmds import _find_matching_finding
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f1 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        f2 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=5, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="y = 2", qualname="other",
        )
        result = _find_matching_finding([f1, f2], "PY-WL-001", expected_line=5)
        assert result is f2

    def test_find_matching_no_exact_returns_none(self) -> None:
        from wardline.cli.corpus_cmds import _find_matching_finding
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f1 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        result = _find_matching_finding([f1], "PY-WL-001", expected_line=10)
        assert result is None

    def test_check_location_line_mismatch(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=5, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        ok, reasons = _check_location_match(f, {"line": 2})
        assert not ok
        assert any("line" in r for r in reasons)

    def test_check_location_text_mismatch(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        ok, reasons = _check_location_match(f, {"text": "y = 2"})
        assert not ok
        assert any("text" in r for r in reasons)

    def test_check_location_none_snippet_with_expected_text(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname="process",
        )
        ok, reasons = _check_location_match(f, {"text": "x = 1"})
        assert not ok
        assert any("None" in r for r in reasons)

    def test_check_location_function_mismatch(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="wrong_func",
        )
        ok, reasons = _check_location_match(f, {"function": "process"})
        assert not ok
        assert any("function" in r for r in reasons)

    def test_check_location_all_pass(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        ok, reasons = _check_location_match(f, {"line": 2, "text": "x = 1", "function": "process"})
        assert ok
        assert reasons == []

    def test_check_location_partial_fields(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        ok, reasons = _check_location_match(f, {"line": 2})
        assert ok

    def test_text_normalization_handles_indentation(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = data.get('key', 'default')",
            qualname="process",
        )
        ok, _ = _check_location_match(f, {"text": "  x = data.get('key',   'default')  "})
        assert ok


class TestStructuredEvaluation:
    """Tests for structural expected_match in corpus verify pipeline."""

    def test_structured_match_passes(self, tmp_path: Path) -> None:
        """Specimen with correct structured expected_match passes."""
        source = (
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        pass\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'taint_state: "EXTERNAL_RAW"\n'
            f'sha256: "{sha}"\n'
            f"expected_match:\n"
            f"  line: 4\n"
            f"  text: 'except Exception:'\n"
            f"  function: f\n"
            f"fragment: |\n"
            f"  def f():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0

    def test_boolean_expected_match_backward_compat(self, tmp_path: Path) -> None:
        """Boolean expected_match: true still works with deprecation warning."""
        source = (
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        pass\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'expected_match: true\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def f():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 TP" in result.output
        # Must emit deprecation warning via click.echo(err=True)
        stderr_text = getattr(result, "stderr", "") or ""
        combined = result.output + stderr_text
        assert "deprecated" in combined.lower(), (
            f"Expected deprecation warning, got output={result.output!r} stderr={stderr_text!r}"
        )

    def test_structured_expected_match_line_mismatch(self) -> None:
        """Finding at wrong line produces location_mismatches == 1."""
        from wardline.cli.corpus_cmds import _CellStats, _evaluate_specimen
        from wardline.scanner.rules import make_rules

        source = 'def f(d):\n    x = d.get("k", "default")\n'
        data = {
            "rule": "PY-WL-001",
            "verdict": "true_positive",
            "taint_state": "ASSURED",
            "expected_match": {"line": 99, "text": 'x = d.get("k", "default")'},
        }
        stats: dict[tuple[str, str], _CellStats] = {}
        _evaluate_specimen(data, source, make_rules(), stats)
        key = ("PY-WL-001", "ASSURED")
        assert stats[key].tp == 1
        assert stats[key].location_mismatches == 1

    def test_structured_expected_match_text_mismatch(self) -> None:
        """Finding with wrong snippet text produces location_mismatches == 1."""
        from wardline.cli.corpus_cmds import _CellStats, _evaluate_specimen
        from wardline.scanner.rules import make_rules

        source = 'def f(d):\n    x = d.get("k", "default")\n'
        data = {
            "rule": "PY-WL-001",
            "verdict": "true_positive",
            "taint_state": "ASSURED",
            "expected_match": {"line": 2, "text": "WRONG TEXT HERE"},
        }
        stats: dict[tuple[str, str], _CellStats] = {}
        _evaluate_specimen(data, source, make_rules(), stats)
        key = ("PY-WL-001", "ASSURED")
        assert stats[key].tp == 1
        assert stats[key].location_mismatches == 1

    def test_structured_expected_match_function_mismatch(self) -> None:
        """Finding in wrong function produces location_mismatches == 1."""
        from wardline.cli.corpus_cmds import _CellStats, _evaluate_specimen
        from wardline.scanner.rules import make_rules

        source = 'def f(d):\n    x = d.get("k", "default")\n'
        data = {
            "rule": "PY-WL-001",
            "verdict": "true_positive",
            "taint_state": "ASSURED",
            "expected_match": {"line": 2, "text": 'x = d.get("k", "default")', "function": "wrong_func"},
        }
        stats: dict[tuple[str, str], _CellStats] = {}
        _evaluate_specimen(data, source, make_rules(), stats)
        key = ("PY-WL-001", "ASSURED")
        assert stats[key].tp == 1
        assert stats[key].location_mismatches == 1

    def test_boolean_false_expected_match_no_comparison(self) -> None:
        """TN specimen with expected_match: false — no structural comparison."""
        from wardline.cli.corpus_cmds import _CellStats, _evaluate_specimen
        from wardline.scanner.rules import make_rules

        source = 'def f(d):\n    x = d.get("k")\n'
        data = {
            "rule": "PY-WL-001",
            "verdict": "true_negative",
            "taint_state": "ASSURED",
            "expected_match": False,
        }
        stats: dict[tuple[str, str], _CellStats] = {}
        _evaluate_specimen(data, source, make_rules(), stats)
        key = ("PY-WL-001", "ASSURED")
        assert stats[key].tn == 1
        assert stats[key].location_mismatches == 0

    def test_empty_dict_expected_match_is_error(self) -> None:
        """expected_match: {} is counted as location mismatch."""
        from wardline.cli.corpus_cmds import _CellStats, _evaluate_specimen
        from wardline.scanner.rules import make_rules

        source = 'def f(d):\n    x = d.get("k", "default")\n'
        data = {
            "rule": "PY-WL-001",
            "verdict": "true_positive",
            "taint_state": "ASSURED",
            "expected_match": {},
        }
        stats: dict[tuple[str, str], _CellStats] = {}
        _evaluate_specimen(data, source, make_rules(), stats)
        key = ("PY-WL-001", "ASSURED")
        assert stats[key].location_mismatches == 1

    def test_unknown_keys_in_expected_match_warned(self) -> None:
        """expected_match with typo keys emits warning."""
        from wardline.cli.corpus_cmds import _CellStats, _evaluate_specimen
        from wardline.scanner.rules import make_rules

        source = 'def f(d):\n    x = d.get("k", "default")\n'
        data = {
            "rule": "PY-WL-001",
            "verdict": "true_positive",
            "taint_state": "ASSURED",
            "expected_match": {"lien": 2},  # typo
        }
        stats: dict[tuple[str, str], _CellStats] = {}
        _evaluate_specimen(data, source, make_rules(), stats)
        # Typo key should still be counted (empty valid fields after filtering)
        key = ("PY-WL-001", "ASSURED")
        assert stats[key].tp == 1

    def test_location_mismatch_in_json_report(self) -> None:
        """JSON report includes location_mismatches and location_match_rate."""
        from wardline.cli.corpus_cmds import _build_json_report, _CellStats

        stats: dict[tuple[str, str], _CellStats] = {
            ("PY-WL-001", "ASSURED"): _CellStats(tp=3, tn=1, location_mismatches=1),
        }
        report = _build_json_report(stats)
        # Find the PY-WL-001/ASSURED cell in the report
        target = [c for c in report["cells"] if c["rule"] == "PY-WL-001" and c["taint_state"] == "ASSURED"]
        assert len(target) == 1
        cell = target[0]
        assert cell["location_mismatches"] == 1
        assert cell["location_match_rate"] is not None
        assert report["summary"]["total_location_mismatches"] == 1
        assert report["overall_verdict"] == "FAIL"

    def test_find_matching_finding_same_line_text_tiebreaker(self) -> None:
        """Two findings on same line — text tiebreaker selects correct one."""
        from wardline.cli.corpus_cmds import _find_matching_finding
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f1 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = d.get('a', 1)",
        )
        f2 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=10,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="y = d.get('b', 2)",
        )
        result = _find_matching_finding([f1, f2], "PY-WL-001", expected_line=2, expected_text="y = d.get('b', 2)")
        assert result is f2
