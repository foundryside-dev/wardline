"""Explicit policy for paths named by untrusted scan configuration."""

from __future__ import annotations

from enum import StrEnum


class SourceRootConfinement(StrEnum):
    """Whether configured source roots and discovered symlinks may leave the scan root.

    This policy does not validate a caller-supplied MCP path or config argument. MCP
    request paths are independently confined by ``wardline.mcp.tooling.resolve_under_root``
    before the configuration is loaded. A config file being inside the project root does
    not make paths named by its contents safe; discovery applies this second policy.
    """

    PROJECT_ROOT = "project-root"
    LEGACY_ALLOW_ESCAPE = "legacy-allow-escape"

    @property
    def confines_to_project(self) -> bool:
        return self is SourceRootConfinement.PROJECT_ROOT
