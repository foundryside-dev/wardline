"""JSON Schema (draft 2020-12) for ``wardline.yaml``.

Single source of truth for the config shape. ``additionalProperties: false`` at
the top level turns a typo'd key into a hard ``ConfigError`` (fail-loud), and the
schema doubles as config documentation. Bounds here MUST agree with
``parse_judge_settings`` (context_lines >= 0, max_findings >= 1, floor 0..1).
"""

from __future__ import annotations

from typing import Any

WARDLINE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "source_roots": {"type": "array", "items": {"type": "string"}},
        "exclude": {"type": "array", "items": {"type": "string"}},
        "rules": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "enable": {"type": "array", "items": {"type": "string"}},
                "severity": {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
        "baseline": {"type": "object"},
        "waivers": {"type": "array", "items": {"type": "object"}},
        "judge": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "model": {"type": "string"},
                "context_lines": {"type": "integer", "minimum": 0},
                "max_findings": {"type": "integer", "minimum": 1},
                "policy_file": {"type": "string"},
                "write_confidence_floor": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            },
        },
        "filigree": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"url": {"type": "string"}},
        },
        "clarion": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"url": {"type": "string"}},
        },
    },
}
