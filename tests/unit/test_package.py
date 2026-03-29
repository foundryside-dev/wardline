"""Smoke test: wardline package is importable."""

import wardline


def test_version_exists() -> None:
    assert wardline.__version__ == "1.0.0"
