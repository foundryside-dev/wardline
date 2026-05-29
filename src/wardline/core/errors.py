"""Wardline error hierarchy (stdlib-only)."""


class WardlineError(Exception):
    """Base class for all expected Wardline errors."""


class ConfigError(WardlineError):
    """Raised when wardline.yaml is malformed or invalid."""


class DiscoveryError(WardlineError):
    """Raised when source discovery cannot proceed."""
