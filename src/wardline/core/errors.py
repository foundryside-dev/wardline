"""Wardline error hierarchy (stdlib-only)."""


class WardlineError(Exception):
    """Base class for all expected Wardline errors."""


class ConfigError(WardlineError):
    """Raised when wardline.yaml is malformed or invalid."""


class DiscoveryError(WardlineError):
    """Raised when source discovery cannot proceed."""


class FiligreeEmitError(WardlineError):
    """Filigree rejected the scan-results payload (HTTP >= 400) — a Wardline bug."""


class JudgeConfigurationError(WardlineError):
    """The judge cannot run: missing API key or operator-actionable misconfig."""


class JudgeTransportError(WardlineError):
    """The judge transport failed after configuration succeeded (network / HTTP status)."""


class JudgeContractError(WardlineError):
    """The judge returned data violating the response contract — crash, never coerce."""


class ClarionError(WardlineError):
    """A Clarion-integration error the user must act on (missing extra, a 4xx
    bad request, a bad --clarion-url). Soft Clarion conditions — outage, 5xx,
    403 WRITE_DISABLED/PROJECT_MISMATCH — are NOT this; they warn and continue."""


class AttestError(WardlineError):
    """An attestation build refused: e.g. a dirty working tree without
    ``allow_dirty``. A tool-execution fault the operator must act on."""


class DossierError(WardlineError):
    """A dossier tool-execution fault the agent must act on: the requested entity is
    not in the scanned set, or its module could not be analysed. Optional-source
    faults (Clarion/Filigree unreachable) are NOT this — those degrade to an
    ``unavailable`` section so the call still succeeds (dossier design §8.2)."""
