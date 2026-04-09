# Glossary

Terms you will encounter in Wardline output, documentation, and configuration.

| Term | Definition |
|------|-----------|
| **Analysis level** | Depth of taint tracking: L1 (function-level), L2 (variable-level), L3 (call-graph). Higher levels find more violations but scan slower. See [Analysis Levels](../guides/analysis-levels.md). |
| **Assured** | Taint state for Tier 2 data — structurally and semantically validated. See [Taint States](taint-states.md). |
| **Authority tier** | One of four trust levels (1=highest to 4=lowest) assigned to code and data. See [Taint States](taint-states.md). |
| **Boundary** | A function decorated with `@validates_shape`, `@validates_semantic`, `@validates_external`, or `@restoration_boundary` that promotes data from a lower tier to a higher tier. |
| **Coherence check** | Cross-reference validation run by `wardline coherence` — verifies manifest, decorators, exception registry, and fingerprint baseline are mutually consistent. |
| **Control law** | Enforcement state of the scanner: `normal` (full enforcement), `alternate` (degraded but running), or `direct` (manifest unavailable, minimal enforcement). |
| **Decorator** | A Python `@decorator` from `wardline.decorators` that annotates a function with trust-boundary metadata. See [Decorator Vocabulary](decorators.md). |
| **Exception** | A recorded decision to accept a finding that would otherwise block the scan. Managed via `wardline exception`. See [Governance](../guides/governance.md). |
| **Exceptionability** | Whether a finding can be excepted: UNCONDITIONAL (no), STANDARD (with approval), RELAXED (easily), TRANSPARENT (auto-suppressed). See [Severity Matrix](severity-matrix.md). |
| **External_raw** | Taint state for Tier 4 data — untrusted external input. See [Taint States](taint-states.md). |
| **Finding** | A single violation or diagnostic emitted by the scanner. Contains rule ID, severity, location, taint state, and exceptionability. |
| **Fingerprint** | AST-based hash of a function's structure. Used to detect when code changes under an existing exception. |
| **Governance profile** | Project-level policy setting: `lite` (fewer mandatory fields) or `assurance` (all governance fields mandatory). See [Profiles](../guides/profiles.md). |
| **Guarded** | Taint state for Tier 3 data — shape-validated but not semantically verified. See [Taint States](taint-states.md). |
| **Integral** | Taint state for Tier 1 data — audit-critical, highest trust. See [Taint States](taint-states.md). |
| **Join** | The operation that combines two taint states when data flows merge. Produces the least-trusted common state. See [Taint States](taint-states.md#join-lattice). |
| **Manifest** | The `wardline.yaml` file that declares which modules belong to which tier, governance profile, and rule overrides. See [Manifest Reference](manifest.md). |
| **Mixed_raw** | Taint state produced when incompatible taint states merge — the absorbing element of the join lattice. See [Taint States](taint-states.md). |
| **Overlay** | A per-directory `wardline.overlay.yaml` file that extends the root manifest with local boundary declarations and rule overrides. See [Manifest Reference](manifest.md). |
| **Rejection path** | A branch in a validation boundary function that raises an exception or returns early on invalid input. Required by PY-WL-008. |
| **Restoration boundary** | A `@restoration_boundary` decorator that re-promotes data to a higher tier with explicit evidence (structural, semantic, integrity, institutional). |
| **SARIF** | Static Analysis Results Interchange Format (v2.1.0). Wardline's output format for CI/CD integration. See [SARIF Format](sarif-format.md). |
| **Severity** | How a finding affects the scan exit code: ERROR (blocks, exit 1), WARNING (informational), SUPPRESS (hidden unless verbose). See [Severity Matrix](severity-matrix.md). |
| **Taint state** | The validation confidence level carried by data: one of 8 canonical states. See [Taint States](taint-states.md). |
| **Tier** | Shorthand for authority tier (1-4). See **Authority tier**. |
| **Transition** | A declared taint-state change on a boundary decorator, e.g., `(EXTERNAL_RAW, GUARDED)` on `@validates_shape`. |
| **Unknown_raw / Unknown_guarded / Unknown_assured** | Taint states assigned when the scanner lacks sufficient evidence to determine full validation status. See [Taint States](taint-states.md). |
| **Validation boundary** | See **Boundary**. |

## Further Reading

- [Getting Started](../getting-started.md) — 15-minute introduction
- [Wardline Lite](../spec/wardline-lite.md) — 5-question practical overview
