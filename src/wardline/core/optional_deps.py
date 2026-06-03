"""Lazy loaders for optional runtime dependencies."""

from __future__ import annotations

from typing import Any

from wardline.core.errors import ConfigError


def _scanner_extra_message(feature: str, package: str) -> str:
    return f"{feature} requires {package} from the scanner extra; install `wardline[scanner]`."


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
