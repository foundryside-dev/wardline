from __future__ import annotations

import importlib.util
import urllib.error
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_live_module() -> ModuleType:
    path = ROOT / "tests" / "e2e" / "test_clarion_live.py"
    spec = importlib.util.spec_from_file_location("wardline_clarion_live_oracle", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_explicit_clarion_binary_uses_runtime_probe_not_strings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_live_module()
    binary = tmp_path / "clarion"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("WARDLINE_CLARION_BIN", str(binary))

    def _no_strings(*args: object, **kwargs: object) -> object:
        raise AssertionError("explicit Clarion binary should not be filtered by `strings`")

    monkeypatch.setattr(module.subprocess, "run", _no_strings)

    assert module._resolve_clarion() == str(binary)


def test_clarion_live_config_binds_to_ephemeral_port_zero(tmp_path: Path) -> None:
    module = _load_live_module()
    config = tmp_path / "clarion.yaml"

    module._write_clarion_config(config)

    assert "bind: 127.0.0.1:0" in config.read_text(encoding="utf-8")


def test_clarion_live_base_url_comes_from_reported_bind_port() -> None:
    module = _load_live_module()

    assert module._base_url_from_clarion_log("INFO Clarion HTTP read API listening bind=127.0.0.1:45123 auth=hmac") == (
        "http://127.0.0.1:45123"
    )


def test_clarion_live_wardline_route_probe_distinguishes_missing_route(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_live_module()

    def _missing(*args: object, **kwargs: object) -> object:
        raise urllib.error.HTTPError("http://127.0.0.1/api/wardline/taint-facts", 404, "Not Found", {}, None)

    monkeypatch.setattr(module.urllib.request, "urlopen", _missing)
    assert module._wardline_taint_route_live("http://127.0.0.1:1") is False

    def _auth_required(*args: object, **kwargs: object) -> object:
        raise urllib.error.HTTPError("http://127.0.0.1/api/wardline/taint-facts", 401, "Unauthorized", {}, None)

    monkeypatch.setattr(module.urllib.request, "urlopen", _auth_required)
    assert module._wardline_taint_route_live("http://127.0.0.1:1") is True
