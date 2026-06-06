"""MCP resource catalog and readers for Wardline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wardline.core import config as config_mod
from wardline.core.config_schema import WARDLINE_SCHEMA
from wardline.core.paths import weft_config_path
from wardline.mcp.protocol import _INVALID_PARAMS, McpError

ResourceDef = tuple[str, str, str]

RESOURCE_CATALOG: tuple[ResourceDef, ...] = (
    ("wardline://vocab", "Trust vocabulary descriptor", "text/yaml"),
    ("wardline://rules", "Rule catalog", "application/json"),
    ("wardline://config", "Effective project config", "application/json"),
    ("wardline://config-schema", "Config JSON Schema", "application/json"),
)


def list_resources() -> list[dict[str, str]]:
    return [{"uri": uri, "name": name, "mimeType": mime} for uri, name, mime in RESOURCE_CATALOG]


def read_resource(root: Path, uri: str | None) -> tuple[str, str]:
    """Return (text, mime_type) for a resource URI."""
    if uri == "wardline://vocab":
        from wardline.core.descriptor import descriptor_to_yaml

        return descriptor_to_yaml(), "text/yaml"
    if uri == "wardline://config-schema":
        return json.dumps(WARDLINE_SCHEMA, ensure_ascii=False), "application/json"
    if uri == "wardline://rules":
        from wardline.scanner.rules import _ALL_RULE_CLASSES

        rules: list[dict[str, Any]] = []
        for cls in _ALL_RULE_CLASSES:
            inst = cls()
            rules.append(
                {
                    "rule_id": inst.rule_id,
                    "base_severity": inst.base_severity.value,
                    "description": cls.metadata.description,
                }
            )
        return json.dumps({"rules": rules}, ensure_ascii=False), "application/json"
    if uri == "wardline://config":
        cfg = config_mod.load(weft_config_path(root))
        return json.dumps(
            {
                "source_roots": list(cfg.source_roots),
                "exclude": list(cfg.exclude),
                "rules_enable": list(cfg.rules_enable),
                "rules_severity": dict(cfg.rules_severity),
            },
            ensure_ascii=False,
        ), "application/json"
    raise McpError(f"unknown resource: {uri}", code=_INVALID_PARAMS)
