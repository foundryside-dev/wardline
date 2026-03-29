"""Integration tests for wardline-decorators package split.

Verifies:
1. wardline.decorators is importable
2. All 38 registry decorators are accessible
3. Decorator application works (stamps _wardline_* attributes)
4. No scanner/CLI/manifest modules leak into decorator imports
"""

from __future__ import annotations

import pytest

from wardline.core.registry import REGISTRY


@pytest.mark.integration
class TestDecoratorPackageContract:
    """The decorator package exposes all registered decorators."""

    def test_all_registry_decorators_importable(self) -> None:
        """Every REGISTRY entry is importable from wardline.decorators."""
        import wardline.decorators as dec_mod

        missing = []
        for name in REGISTRY:
            if not hasattr(dec_mod, name):
                missing.append(name)
        assert missing == [], f"Decorators missing from wardline.decorators: {missing}"

    def test_decorator_stamps_attributes(self) -> None:
        """Decorators stamp _wardline_groups on the target function."""
        from wardline.decorators import integrity_critical

        @integrity_critical
        def my_func() -> None:
            pass

        assert hasattr(my_func, "_wardline_groups")
        assert isinstance(my_func._wardline_groups, frozenset)

    def test_decorator_namespace_matches_all(self) -> None:
        """wardline.decorators.__all__ covers every REGISTRY entry."""
        from wardline.decorators import __all__ as dec_all

        for name in REGISTRY:
            assert name in dec_all, f"REGISTRY entry '{name}' missing from __all__"

    def test_stacked_decorators_accumulate_groups(self) -> None:
        """Multiple decorators accumulate _wardline_groups."""
        from wardline.decorators import integrity_critical, deterministic

        @integrity_critical
        @deterministic
        def my_func() -> None:
            pass

        groups = my_func._wardline_groups
        assert len(groups) >= 2

    def test_decorator_import_does_not_pull_cli(self) -> None:
        """Importing decorators does not eagerly import CLI modules."""
        import sys

        cli_before = {k for k in sys.modules if k.startswith("wardline.cli")}

        import wardline.decorators  # noqa: F811

        cli_after = {k for k in sys.modules if k.startswith("wardline.cli")}
        new_cli = cli_after - cli_before
        assert len(new_cli) == 0, (
            f"Decorator import eagerly loaded CLI modules: {new_cli}"
        )

    def test_wheel_contains_only_decorators(self) -> None:
        """The built wheel contains wardline/decorators/ and nothing else."""
        import zipfile
        from pathlib import Path

        wheel_dir = Path(__file__).parent.parent.parent / "packages" / "wardline-decorators" / "dist"
        wheels = list(wheel_dir.glob("*.whl"))
        if not wheels:
            pytest.skip("No wheel built — run 'cd packages/wardline-decorators && uv build --wheel' first")

        with zipfile.ZipFile(wheels[0]) as zf:
            names = zf.namelist()

        # Should have wardline/decorators/ files
        decorator_files = [n for n in names if n.startswith("wardline/decorators/")]
        assert len(decorator_files) >= 15, f"Expected >=15 decorator files, got {len(decorator_files)}"

        # Should NOT have core/, scanner/, cli/, manifest/, runtime/
        for forbidden in ["wardline/core/", "wardline/scanner/", "wardline/cli/", "wardline/manifest/", "wardline/runtime/"]:
            leaked = [n for n in names if n.startswith(forbidden)]
            assert leaked == [], f"Wheel contains forbidden module: {leaked}"
