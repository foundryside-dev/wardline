"""Test that the public API is importable from the top-level package."""

from __future__ import annotations


class TestPublicAPI:
    def test_decorators_importable(self) -> None:
        from wardline import external_boundary, integral_writer, validates_shape
        assert callable(external_boundary)
        assert callable(validates_shape)
        assert callable(integral_writer)

    def test_core_types_importable(self) -> None:
        from wardline import AuthorityTier, TaintState
        assert hasattr(TaintState, "INTEGRAL")
        assert hasattr(AuthorityTier, "TIER_1")

    def test_schema_default_importable(self) -> None:
        from wardline import schema_default
        assert schema_default(42) == 42

    def test_version_still_importable(self) -> None:
        from wardline import __version__
        assert isinstance(__version__, str)

    def test_all_is_defined(self) -> None:
        import wardline
        assert hasattr(wardline, "__all__")
        assert "__version__" in wardline.__all__
        assert "external_boundary" in wardline.__all__
        assert "TaintState" in wardline.__all__
