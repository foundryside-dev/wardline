# tests/unit/core/test_sei_resolution.py
from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.core.sei_resolution import locator_to_qualname, resolve_query_filters


def test_locator_to_qualname() -> None:
    assert locator_to_qualname("python:function:pkg.mod.func") == "pkg.mod.func"
    assert locator_to_qualname("python:class:pkg.mod.Class") == "pkg.mod.Class"
    assert locator_to_qualname("python:something") == "something"
    assert locator_to_qualname("barename") == "barename"


class _FakeClarion:
    def __init__(self, *, supported=True, alive=True, locator="python:function:svc.leaky"):
        self._supported = supported
        self._alive = alive
        self._locator = locator

    def capabilities(self):
        return {"sei": {"supported": self._supported, "version": 1}}

    def resolve_sei(self, sei):
        if self._alive:
            return {"alive": True, "current_locator": self._locator}
        return {"alive": False}


def test_resolve_query_filters_no_sei() -> None:
    # where is None
    assert resolve_query_filters(None, Path("."), None) is None

    # qualname is missing or not a string or doesn't start with sei:
    where = {"rule_id": "PY-WL-101"}
    assert resolve_query_filters(where, Path("."), None) == where

    where2 = {"qualname": 123}
    assert resolve_query_filters(where2, Path("."), None) == where2

    where3 = {"qualname": "svc.leaky"}
    assert resolve_query_filters(where3, Path("."), None) == where3


def test_resolve_query_filters_missing_url() -> None:
    # No clarion client and WARDLINE_CLARION_URL is not set
    with pytest.raises(WardlineError, match="no Clarion URL configured"):
        resolve_query_filters({"qualname": "sei:clarion:eid:abc"}, Path("."), None)


def test_resolve_query_filters_unsupported_sei() -> None:
    client = _FakeClarion(supported=False)
    with pytest.raises(WardlineError, match="Clarion instance does not support SEI"):
        resolve_query_filters({"qualname": "sei:clarion:eid:abc"}, Path("."), None, clarion_client=client)


def test_resolve_query_filters_failed_to_resolve() -> None:
    client = _FakeClarion(alive=False)
    with pytest.raises(WardlineError, match="cannot resolve SEI to a qualname"):
        resolve_query_filters({"qualname": "sei:clarion:eid:abc"}, Path("."), None, clarion_client=client)


def test_resolve_query_filters_success() -> None:
    client = _FakeClarion()
    where = {"qualname": "sei:clarion:eid:abc", "rule_id": "PY-WL-101"}
    resolved = resolve_query_filters(where, Path("."), None, clarion_client=client)
    assert resolved == {"qualname": "svc.leaky", "rule_id": "PY-WL-101"}
