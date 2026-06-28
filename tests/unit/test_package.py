import re

import wardline


def test_version_is_exported() -> None:
    assert isinstance(wardline.__version__, str)
    # Assert a stable 1.x semver shape, not an exact minor/patch, so a point or
    # minor release doesn't break this (1.0.x → 1.1.0 and onward).
    assert re.fullmatch(r"1\.\d+\.\d+", wardline.__version__), wardline.__version__
