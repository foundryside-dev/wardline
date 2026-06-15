import wardline


def test_version_is_exported() -> None:
    assert isinstance(wardline.__version__, str)
    # Pin the 1.0.x release line, not the exact patch, so a point release doesn't break this.
    assert wardline.__version__.startswith("1.0.")
