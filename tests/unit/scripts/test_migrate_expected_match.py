"""Tests for the expected_match migration script (oracle independence + safety)."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import yaml
from scripts.migrate_expected_match import compute_expected_location, migrate_specimen


class TestOracleIndependence:
    """Migration script must not import scanner rule logic."""

    def test_migration_script_does_not_import_scanner_rules(self) -> None:
        """Verify no scanner rule/engine/taint imports in migration script."""
        before = set(sys.modules.keys())
        # Force re-import to capture fresh module state
        import scripts.migrate_expected_match  # noqa: F401

        after = set(sys.modules.keys())
        delta = after - before
        forbidden = {m for m in delta if m.startswith(("wardline.scanner.rules", "wardline.scanner.engine", "wardline.scanner.taint"))}
        assert not forbidden, f"Migration script imported forbidden modules: {forbidden}"


class TestMigrationSafety:
    """Migration script must not use exec/eval and must use safe YAML loading."""

    def test_migration_script_no_exec_eval(self) -> None:
        """Migration script never calls exec() or eval()."""
        import builtins

        original_exec = builtins.exec
        original_eval = builtins.eval
        calls: list[str] = []

        def spy_exec(*a, **kw):  # type: ignore[no-untyped-def]
            calls.append("exec")
            return original_exec(*a, **kw)

        def spy_eval(*a, **kw):  # type: ignore[no-untyped-def]
            calls.append("eval")
            return original_eval(*a, **kw)

        with patch.object(builtins, "exec", spy_exec), patch.object(builtins, "eval", spy_eval):
            # Run compute_expected_location on a simple fragment
            compute_expected_location('def f(d):\n    x = d.get("k", 1)\n', "PY-WL-001")

        assert "exec" not in calls, "Migration logic called exec()"
        assert "eval" not in calls, "Migration logic called eval()"


    def test_migration_script_uses_safe_loader(self) -> None:
        """Migration script uses WardlineSafeLoader, not bare yaml.safe_load or yaml.load."""
        import ast as ast_mod

        script_path = Path(__file__).resolve().parents[3] / "scripts" / "migrate_expected_match.py"
        source = script_path.read_text()
        tree = ast_mod.parse(source)

        unsafe_calls: list[str] = []
        for node in ast_mod.walk(tree):
            if not isinstance(node, ast_mod.Call) or not isinstance(node.func, ast_mod.Attribute):
                continue
            if node.func.attr == "safe_load":
                unsafe_calls.append(f"line {node.lineno}: yaml.safe_load() — use WardlineSafeLoader")
            elif node.func.attr == "load":
                loader_args = [kw for kw in node.keywords if kw.arg == "Loader"]
                if not loader_args:
                    unsafe_calls.append(f"line {node.lineno}: yaml.load() without Loader=")

        assert not unsafe_calls, (
            "Migration script uses unsafe YAML loading:\n" + "\n".join(unsafe_calls)
        )


class TestComputeExpectedLocation:
    """Unit tests for the shared AST pattern matcher."""

    def test_py_wl_001_dict_get(self) -> None:
        result = compute_expected_location('def f(d):\n    x = d.get("k", 1)\n', "PY-WL-001")
        assert result is not None
        assert result["line"] == 2
        assert result["function"] == "f"

    def test_py_wl_002_getattr(self) -> None:
        result = compute_expected_location('def f(obj):\n    x = getattr(obj, "a", None)\n', "PY-WL-002")
        assert result is not None
        assert result["line"] == 2
        assert result["function"] == "f"

    def test_py_wl_003_in_check(self) -> None:
        result = compute_expected_location('def f(d):\n    if "k" in d:\n        pass\n', "PY-WL-003")
        assert result is not None
        assert result["line"] == 2

    def test_py_wl_004_broad_except(self) -> None:
        result = compute_expected_location("def f():\n    try:\n        pass\n    except Exception:\n        pass\n", "PY-WL-004")
        assert result is not None
        assert result["line"] == 4
        assert result["text"] == "except Exception:"

    def test_py_wl_005_silent_except(self) -> None:
        result = compute_expected_location("def f():\n    try:\n        pass\n    except Exception:\n        pass\n", "PY-WL-005")
        assert result is not None
        assert result["line"] == 4

    def test_py_wl_007_isinstance(self) -> None:
        result = compute_expected_location("def f(d):\n    if isinstance(d, dict):\n        pass\n", "PY-WL-007")
        assert result is not None
        assert result["line"] == 2
        assert result["function"] == "f"

    def test_manual_rule_returns_none(self) -> None:
        """PY-WL-006/008/009 have no AST patterns — returns None."""
        result = compute_expected_location("def f():\n    pass\n", "PY-WL-006")
        assert result is None

    def test_syntax_error_returns_none(self) -> None:
        result = compute_expected_location("def f(:\n", "PY-WL-001")
        assert result is None

    def test_no_match_returns_none(self) -> None:
        result = compute_expected_location("def f():\n    pass\n", "PY-WL-001")
        assert result is None


class TestMigrationIdempotency:
    """Migration script produces identical output when run twice."""

    def test_migration_idempotent(self, tmp_path: Path) -> None:
        """Running migration twice produces identical output."""
        specimen = {
            "specimen_id": "TEST-TP-01",
            "rule": "PY-WL-001",
            "fragment": 'def f(d):\n    x = d.get("k", 1)\n',
            "verdict": "true_positive",
            "expected_match": True,
            "sha256": "abc123",
            "taint_state": "EXTERNAL_RAW",
        }
        yaml_path = tmp_path / "test.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(specimen, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, explicit_start=True)

        # First migration
        status1 = migrate_specimen(yaml_path, dry_run=False, verbose=False)
        with open(yaml_path) as f:
            content1 = f.read()

        # Second migration
        status2 = migrate_specimen(yaml_path, dry_run=False, verbose=False)
        with open(yaml_path) as f:
            content2 = f.read()

        assert status1 == "migrated"
        assert status2 == "skip_structured"
        assert content1 == content2

    def test_migration_dry_run(self, tmp_path: Path) -> None:
        """--dry-run does not modify files."""
        specimen = {
            "specimen_id": "TEST-TP-02",
            "rule": "PY-WL-001",
            "fragment": 'def f(d):\n    x = d.get("k", 1)\n',
            "verdict": "true_positive",
            "expected_match": True,
            "sha256": "abc123",
            "taint_state": "EXTERNAL_RAW",
        }
        yaml_path = tmp_path / "test.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(specimen, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, explicit_start=True)

        original = yaml_path.read_text()
        status = migrate_specimen(yaml_path, dry_run=True, verbose=False)
        assert status == "would_migrate"
        assert yaml_path.read_text() == original

    def test_migration_preserves_tn_specimens(self, tmp_path: Path) -> None:
        """TN/KFN specimens keep expected_match: false."""
        specimen = {
            "specimen_id": "TEST-TN-01",
            "rule": "PY-WL-001",
            "fragment": 'def f(d):\n    x = d.get("k")\n',
            "verdict": "true_negative",
            "expected_match": False,
            "sha256": "abc123",
            "taint_state": "EXTERNAL_RAW",
        }
        yaml_path = tmp_path / "test.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(specimen, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, explicit_start=True)

        status = migrate_specimen(yaml_path, dry_run=False, verbose=False)
        assert status == "skip_tn_kfn"

        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        assert data["expected_match"] is False

    def test_migration_round_trip_yaml(self, tmp_path: Path) -> None:
        """Migrated YAML round-trips through safe_load(safe_dump(...)) without loss."""
        specimen = {
            "specimen_id": "TEST-TP-03",
            "rule": "PY-WL-002",
            "fragment": 'def f(obj):\n    x = getattr(obj, "a", None)\n',
            "verdict": "true_positive",
            "expected_match": True,
            "sha256": "abc123",
            "taint_state": "EXTERNAL_RAW",
        }
        yaml_path = tmp_path / "test.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(specimen, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, explicit_start=True)

        migrate_specimen(yaml_path, dry_run=False, verbose=False)

        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        # Round-trip through dump/load
        roundtripped = yaml.safe_load(yaml.dump(data, Dumper=yaml.SafeDumper))
        assert roundtripped["expected_match"] == data["expected_match"]
