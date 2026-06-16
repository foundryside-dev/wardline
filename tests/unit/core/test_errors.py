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


def test_scheme_mismatch_error_is_actionable_configerror() -> None:
    # Subclasses ConfigError so existing `except ConfigError` / CLI exit-2
    # mapping keeps working unchanged.
    assert issubclass(errors.SchemeMismatchError, errors.ConfigError)
    e = errors.SchemeMismatchError(store_name="baseline.yaml", found="wlfp0", expected="wlfp1")
    msg = str(e)
    assert "baseline.yaml" in msg  # names the offending file
    assert "wlfp1" in msg  # names the scheme this build expects
    assert "wardline rekey" in msg  # the actionable next step
    assert "--resume" in msg  # the recovery path for an interrupted migration
    assert e.store_name == "baseline.yaml"
    assert e.found == "wlfp0"
    assert e.expected == "wlfp1"


def test_scheme_mismatch_error_renders_absent_header() -> None:
    # A store with NO fingerprint_scheme header passes found=None; the message
    # must still be readable and still point at `wardline rekey`.
    e = errors.SchemeMismatchError(store_name="waivers.yaml", found=None, expected="wlfp1")
    msg = str(e)
    assert "waivers.yaml" in msg
    assert "wardline rekey" in msg
