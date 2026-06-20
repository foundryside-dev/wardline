"""JSON Schema (draft 2020-12) for the ``[wardline]`` table of ``weft.toml``.

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
        # Operator override for wardline's machine-state subtree location (default
        # .weft/wardline). Validated HERE at config.load() time, but CONSUMED ELSEWHERE:
        # core.paths._store_dir_override re-reads it via a raw tomllib parse that bypasses
        # this schema, so a schema-invalid weft.toml can still have its store_dir honored.
        # That seam is safe because weft_state_dir CONFINES the value under root (it is the
        # confinement, not this schema, that bounds it) — see core.paths.weft_state_dir.
        "store_dir": {"type": "string"},
        "source_roots": {"type": "array", "items": {"type": "string"}},
        "exclude": {"type": "array", "items": {"type": "string"}},
        "packs": {"type": "array", "items": {"type": "string"}},
        "untrusted_sources": {"type": "array", "items": {"type": "string"}},
        "sanitisers": {"type": "array", "items": {"type": "string"}},
        "provenance_clash": {"type": "boolean"},
        "rules": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "enable": {"type": "array", "items": {"type": "string"}},
                "severity": {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
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
        "artifacts": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "dir": {"type": "string", "minLength": 1},
                "retain": {"type": "integer", "minimum": 1},
            },
        },
        "autofix": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "boundary_exception": {
                    "type": "string",
                    "pattern": r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$",
                },
            },
        },
    },
}
