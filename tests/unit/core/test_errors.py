import pytest

from wardline.core.errors import ConfigError, DiscoveryError, WardlineError


def test_subclasses_are_wardline_errors() -> None:
    assert issubclass(ConfigError, WardlineError)
    assert issubclass(DiscoveryError, WardlineError)


def test_raises_and_is_catchable_as_base() -> None:
    with pytest.raises(WardlineError):
        raise ConfigError("bad config")
