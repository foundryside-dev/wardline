# Decision: `core/` Ownership — Stays in `wardline`

**Status:** Decided
**Date:** 2026-03-29
**Filigree:** wardline-f6332cfad6

## Context

The `wardline-decorators` package split requires resolving where `core/` lives.
`decorators/_base.py` eagerly imports `REGISTRY` from `core/registry.py`.
`scanner/discovery.py` and `runtime/base.py` also eagerly import `REGISTRY`.

## Options Considered

| Option | Description | Verdict |
|--------|-------------|---------|
| **(A) `wardline-decorators` depends on `wardline`** | `core/` stays in `wardline`. Decorators package declares `wardline` as a dependency and imports `wardline.core.registry`. | **Selected** |
| **(B) Extract `wardline-core` as third package** | `core/` becomes its own package. Both `wardline` and `wardline-decorators` depend on it. | Rejected |
| **(C) Duplicate `core/` into decorators** | Copy `registry.py` (and transitive deps `taints.py`) into the decorators package. | Rejected |

## Decision: Option A

`core/` stays in `wardline`. `wardline-decorators` declares `wardline` as a dependency.

## Rationale

1. **`core/` is small (634 lines, 6 files) but widely coupled.** Five packages plus tests import from it. The coupling is read-only — consumers reference frozen registries and enums, never mutate them.

2. **Option B (three packages) adds installation complexity for zero user benefit.** Users who want decorators already need `wardline` for scanning. A third package creates a diamond dependency (`wardline` → `wardline-core` ← `wardline-decorators`) with version-pinning risk. Three packages for 634 lines of pure-data enums is over-engineered.

3. **Option C (duplication) creates divergence risk.** `REGISTRY` has 38 entries with hardcoded attribute contracts. `SEVERITY_MATRIX` has 72 cells. `RuleId` has 25 members. Any addition or rename must be synchronised across copies. The `scanner` and `runtime` packages also import `REGISTRY` eagerly — they'd need to know which copy to use, creating import-path confusion.

4. **The dependency direction is natural.** Decorators are the thinnest layer — they stamp `_wardline_*` attributes using `REGISTRY` entries. The scanner is the thick layer — it reads those attributes. Having decorators depend on the package that defines the contract registry is the correct dependency arrow.

## Consequences

- `wardline-decorators` will have one dependency: `wardline` (for `wardline.core`).
- The "zero deps" requirement in the Filigree tracker (`wardline-c87a727ebe`) must be updated — the package will have one intra-project dependency, but zero third-party dependencies. This preserves the spirit (no PyYAML, no jsonschema) while acknowledging the registry coupling.
- Users can `pip install wardline` and get everything. Users who want decorator-only analysis tooling install `wardline-decorators` which pulls `wardline` transitively.
- `core/` continues to be the single source of truth for enums, registries, and the severity matrix.

## What This Unblocks

- `wardline-4ddcb887f0` — Execute wardline-decorators package split (now knows the import path strategy)
- `wardline-9c00c39d83` — Promote schemas to v1.0 (no longer waiting on package topology)
