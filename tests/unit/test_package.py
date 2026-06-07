import wardline


def test_version_is_exported() -> None:
    assert isinstance(wardline.__version__, str)
    # Pin the release line, not the rc suffix, so cutting a new rc doesn't break this.
    assert wardline.__version__.startswith("1.0.0")
