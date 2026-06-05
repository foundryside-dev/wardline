# tests/unit/loomweave/test_extra_guard.py
import builtins

import pytest

from wardline.core.errors import LoomweaveError, WardlineError
from wardline.loomweave import require_blake3


def test_loomweave_error_is_a_wardline_error():
    assert issubclass(LoomweaveError, WardlineError)


def test_require_blake3_returns_the_module_when_installed():
    # blake3 is installed in the dev env (the `loomweave` extra is in `dev`).
    mod = require_blake3()
    assert hasattr(mod, "blake3")


def test_require_blake3_raises_actionable_error_when_missing(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "blake3":
            raise ModuleNotFoundError("No module named 'blake3'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(LoomweaveError, match=r"install .*wardline\[loomweave\]"):
        require_blake3()
