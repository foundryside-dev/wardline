import inspect

import pytest

import wardline.core.errors as errors
from wardline.core.errors import WardlineError


def test_subclasses_are_wardline_errors() -> None:
    for name, obj in inspect.getmembers(errors, inspect.isclass):
        if obj is not WardlineError and issubclass(obj, Exception):
            assert issubclass(obj, WardlineError), f"{name} does not inherit from WardlineError"


def test_raises_and_is_catchable_as_base() -> None:
    with pytest.raises(WardlineError):
        raise errors.ConfigError("bad config")
