"""Wardline error hierarchy (stdlib-only)."""


class WardlineError(Exception):
    """Base class for all expected Wardline errors."""


class ConfigError(WardlineError):
    """Raised when weft.toml [wardline] is malformed or invalid."""


class SchemeMismatchError(ConfigError):
    """A store's fingerprint scheme does not match this build's (P1 scheme-infra).

    Raised at store-LOAD time when a baseline/judged/waivers file carries a
    ``fingerprint_scheme`` header that differs from (or is absent vs.) the scheme
    this build computes. Joining stale-scheme fingerprints would silently orphan
    every verdict, so we fail LOUD with the file name and the actionable next
    step. Subclasses ``ConfigError`` so existing ``except ConfigError`` handling
    and the CLI exit-2 mapping apply unchanged.
    """

    def __init__(self, *, store_name: str, found: str | None, expected: str) -> None:
        self.store_name = store_name
        self.found = found
        self.expected = expected
        found_desc = "missing" if found is None else repr(found)
        super().__init__(
            f"{store_name}: fingerprint scheme {found_desc} does not match this build's "
            f"{expected!r}. Run `wardline rekey` to migrate this project's stores "
            f"(or `wardline rekey --resume` to finish an interrupted migration; "
            f"pre-1.0: no automatic upgrade)."
        )


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


class LoomweaveError(WardlineError):
    """A Loomweave-integration error the user must act on (missing extra, a 4xx
    bad request, a bad --loomweave-url). Soft Loomweave conditions — outage, 5xx,
    403 WRITE_DISABLED/PROJECT_MISMATCH — are NOT this; they warn and continue."""


class AttestError(WardlineError):
    """An attestation build refused: e.g. a dirty working tree without
    ``allow_dirty``. A tool-execution fault the operator must act on."""


class LegisArtifactError(WardlineError):
    """A signed legis scan-artifact could not be built honestly: signing was
    requested but git provenance is unavailable (non-repo / no tree) or the
    working tree is dirty without ``allow_dirty``. Signing a ``commit_sha`` /
    ``tree_sha`` that does not match the scanned content would be false
    provenance, so it is refused rather than emitted. A tool-execution fault the
    operator must act on (CLI → exit 2; MCP → isError result)."""


class RustToolingError(WardlineError):
    """The Rust frontend's tree-sitter toolchain (the ``wardline[rust]`` extra) is
    unavailable. Raised lazily by ``wardline.rust._tree_sitter.require_rust`` with
    an actionable install hint — the base package and the ``scanner`` extra never
    import tree-sitter, so a bare install stays zero-dependency."""


class DossierError(WardlineError):
    """A dossier tool-execution fault the agent must act on: the requested entity is
    not in the scanned set, or its module could not be analysed. Optional-source
    faults (Loomweave/Filigree unreachable) are NOT this — those degrade to an
    ``unavailable`` section so the call still succeeds (dossier design §8.2)."""
