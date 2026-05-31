import wardline


def test_version_is_exported() -> None:
    assert isinstance(wardline.__version__, str)
    assert wardline.__version__.startswith("0.3.0")
