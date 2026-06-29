"""Lazy loaders for optional runtime dependencies."""

from __future__ import annotations

from typing import Any

from wardline.core.errors import ConfigError


def extra_install_hint(extra: str) -> str:
    """Install command for a wardline ``extra``, naming both installers.

    ``uv tool install`` REPLACES the tool environment with exactly the named extras (it
    does not merge), and ``pip install`` targets the active venv rather than the tool env
    — so a uv-tool user reinstalls via ``uv tool`` (pip would patch the wrong env), a venv
    user via ``pip``. The scan-pipeline extras self-include ``wardline[scanner]``, so a
    single-extra reinstall is self-sufficient under either installer.
    """
    return f"`uv tool install 'wardline[{extra}]'` (uv tool) or `pip install 'wardline[{extra}]'` (venv)"


def _scanner_extra_message(feature: str, package: str) -> str:
    return f"{feature} requires {package} from the scanner extra — install {extra_install_hint('scanner')}."


def require_yaml(feature: str) -> Any:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        if exc.name == "yaml":
            raise ConfigError(_scanner_extra_message(feature, "PyYAML")) from exc
        raise
    return yaml


def require_jsonschema(feature: str) -> Any:
    try:
        import jsonschema
    except ModuleNotFoundError as exc:
        if exc.name == "jsonschema":
            raise ConfigError(_scanner_extra_message(feature, "jsonschema")) from exc
        raise
    return jsonschema
