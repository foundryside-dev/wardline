# Glossary

Terms you will encounter in Wardline output, documentation, and configuration.

| Term | Definition |
|------|-----------|
| **Analysis level** | Depth of taint tracking: L1 (function-level), L2 (variable-level), L3 (call-graph). Higher levels find more violations but scan slower. See [Analysis Levels](../guides/analysis-levels.md). |
| **Annotation group** | A numbered grouping (1-17) of related wardline decorators that enforce a cohesive set of contracts. Groups 1-4 are framework-mandated (authority tier flow); groups 5-17 are supplementary. See [Supplementary Groups](supplementary-groups.md). |
| **Assured** | Taint state for Tier 2 data — structurally and semantically validated. See [Taint States](taint-states.md). |
| **Authority tier** | One of four trust levels (1=highest to 4=lowest) assigned to code and data. See [Taint States](taint-states.md). |
| **Boundary** | A function decorated with `@validates_shape`, `@validates_semantic`, `@validates_external`, or `@restoration_boundary` that promotes data from a lower tier to a higher tier. |
| **Call edge** | A directed link from one function to another in a call graph, representing a function call. Used by L3 analysis to propagate taint interprocedurally. |
| **Coherence check** | Cross-reference validation run by `wardline coherence` — verifies manifest, decorators, exception registry, and fingerprint baseline are mutually consistent. |
| **Conformance gap** | A known deviation from Wardline specification requirements. Tracked in SARIF output (`wardline.conformanceGaps`) to signal where scanner behaviour does not fully conform to normative rules. |
| **Control law** | Enforcement state of the scanner: `normal` (full enforcement), `alternate` (degraded but running), or `direct` (manifest unavailable, minimal enforcement). See **Degradation condition** for what triggers alternate/direct. |
| **Convergence bound** | A safety limit on the number of fixed-point propagation iterations in L3 analysis. Exceeding it emits the `L3-CONVERGENCE-BOUND` diagnostic. |
| **Coverage ratio** | Fraction of scanned functions with a statically-known taint state (0.0-1.0). Values below 0.8 indicate manifest gaps. Reported in SARIF as `wardline.coverageRatio`. |
| **Decorator** | A Python `@decorator` from `wardline.decorators` that annotates a function with trust-boundary metadata. See [Decorator Vocabulary](decorators.md). |
| **Degradation condition** | A reason the control law becomes `alternate` or `direct`. One of: `conformance_gaps_present`, `manifest_unavailable`, `ratification_overdue`, `rules_disabled`, `stale_exceptions_present`. |
| **Exception** | A recorded decision to accept a finding that would otherwise block the scan. Managed via `wardline exception`. See [Governance](../guides/governance.md). |
| **Exceptionability** | Whether a finding can be excepted: UNCONDITIONAL (no), STANDARD (with approval), RELAXED (easily), TRANSPARENT (auto-suppressed). See [Severity Matrix](severity-matrix.md). |
| **Expedited ratio** | Fraction of active exceptions granted via the expedited governance path (0.0-1.0). Capped at 15% by coherence checks; exceeding it signals governance bypass. |
| **External_raw** | Taint state for Tier 4 data — untrusted external input. See [Taint States](taint-states.md). |
| **Finding** | A single violation or diagnostic emitted by the scanner. Contains rule ID, severity, location, taint state, and exceptionability. |
| **Fingerprint** | AST-based hash of a function's structure. Used to detect when code changes under an existing exception. |
| **Fixed-point propagation** | The iterative algorithm that propagates taint through function call chains in L3 analysis until no taint assignments change. Subject to the **convergence bound**. |
| **Gate-blocking** | A finding with ERROR severity and no active exception. Gate-blocking findings cause scan exit code 1. The count is `wardline.gateBlockingCount` in SARIF output. |
| **Governance path** | The approval route for an exception: `standard` (requires reviewer approval) or `expedited` (fast-track, subject to the 15% **expedited ratio** threshold). |
| **Governance profile** | Project-level policy setting: `lite` (fewer mandatory fields) or `assurance` (all governance fields mandatory). See [Profiles](../guides/profiles.md). |
| **Guarded** | Taint state for Tier 3 data — shape-validated but not semantically verified. See [Taint States](taint-states.md). |
| **Integral** | Taint state for Tier 1 data — audit-critical, highest trust. See [Taint States](taint-states.md). |
| **Join** | The operation that combines two taint states when data flows merge. Produces the least-trusted common state. See [Taint States](taint-states.md#join-lattice). |
| **Known validator** | A function (declared in the manifest or detected heuristically) that unconditionally raises on invalid input. Used by PY-WL-008 to recognise two-hop rejection paths. |
| **Manifest** | The `wardline.yaml` file that declares which modules belong to which tier, governance profile, and rule overrides. See [Manifest Reference](manifest.md). |
| **Mixed_raw** | Taint state produced when incompatible taint states merge — the absorbing element of the join lattice. See [Taint States](taint-states.md). |
| **Overlay** | A per-directory `wardline.overlay.yaml` file that extends the root manifest with local boundary declarations and rule overrides. See [Manifest Reference](manifest.md). |
| **Qualname** | Fully-qualified Python name of a callable (e.g., `myapp.handlers.auth.handle_login`). Used in findings, exceptions, and `wardline explain`. |
| **Ratification** | Formal sign-off of manifest metadata by an authorised person. Includes `ratification_date` and `review_interval_days`. Overdue ratification degrades the control law. |
| **Rejection path** | A branch in a validation boundary function that raises an exception or returns early on invalid input. Required by PY-WL-008. |
| **Restoration boundary** | A `@restoration_boundary` decorator that re-promotes data to a higher tier with explicit evidence (structural, semantic, integrity, institutional). |
| **Retrospective scan** | A scan run with `--retrospective COMMIT_RANGE` that analyses findings introduced during a degraded-law window. Results are marked with `wardline.retroactiveScan: true` in SARIF. |
| **SARIF** | Static Analysis Results Interchange Format (v2.1.0). Wardline's output format for CI/CD integration. See [SARIF Format](sarif-format.md). |
| **SCC** | Strongly Connected Component — a maximal set of functions that call each other (directly or indirectly) in a call graph. L3 analysis computes SCCs to propagate taint efficiently. |
| **Severity** | How a finding affects the scan exit code: ERROR (blocks, exit 1), WARNING (informational), SUPPRESS (hidden unless verbose). See [Severity Matrix](severity-matrix.md). |
| **Severity cell** | A single entry in the 72-cell matrix: the (severity, exceptionability) pair for a given (rule, taint state) combination. See [Severity Matrix](severity-matrix.md). |
| **Taint state** | The validation confidence level carried by data: one of 8 canonical states. See [Taint States](taint-states.md). |
| **Temporal separation** | A governance requirement that the author and approver of enforcement artefact changes are different people, or approval is deferred to a retrospective review window. Required in `assurance` profile. |
| **Tier** | Shorthand for authority tier (1-4). See **Authority tier**. |
| **Transition** | A declared taint-state change on a boundary decorator, e.g., `(EXTERNAL_RAW, GUARDED)` on `@validates_shape`. |
| **Two-hop rejection delegation** | PY-WL-008's ability to follow rejection paths through a second-hop function call (e.g., a boundary that delegates validation to a library function). |
| **Unknown_raw / Unknown_guarded / Unknown_assured** | Taint states assigned when the scanner lacks sufficient evidence to determine full validation status. See [Taint States](taint-states.md). |
| **Validation boundary** | See **Boundary**. |
| **Verification mode** | A scan mode (`--verification-mode`) that produces deterministic output with no timestamps. Suitable for reproducible CI and diffable SARIF. |

## Further Reading

- [Getting Started](../getting-started.md) — 15-minute introduction
- [Wardline Lite](../spec/wardline-lite.md) — 5-question practical overview
