# ADR: First-party / native-module import resolution in the self-scan

- **Status:** Accepted
- **Date:** 2026-06-05
- **Resolves:** Pre-Rust core hardening Task C (milestone `wardline-53412b86bc`,
  task `wardline-2479b182f5`).

## Context

Wardline's import-resolution diagnostic emits `WLN-ENGINE-UNKNOWN-IMPORT`
(`kind: fact`, `severity: NONE`) for `from X import …` where `X` is not a project
module, not stdlib, and not a known marker import (`scanner/diagnostics.py`).
"Project module" membership comes from `project_modules`, built from the `.py`
files discovered in the scanned tree (`analyzer.py`).

Today a self-scan of `src/` emits **zero** `wardline.*` unknown imports, because
`wardline.core.*` has `.py` files present and so lands in `project_modules`. But
`wardline.core` is about to become a **native (compiled) PyO3 module**. A
compiled extension has no Python AST for an AST import analyzer to follow, so
`wardline.core.*` will drop out of `project_modules` and every internal
`from wardline.core.registry import …` (in `grammar.py`, `decorators/_base.py`,
`core/descriptor.py`, `decorator_provider.py`, `doctor.py`) would start emitting
`WLN-ENGINE-UNKNOWN-IMPORT` — systemic self-scan noise that is purely an artifact
of the engine's own packaging, not a real coverage gap.

This is a forward-looking hazard: the fix belongs on the Python tree now, so the
Rust migration only has to extend a list rather than chase down new noise.

## Decision

**Add a declarative native / first-party module allowlist that resolves a
declared module prefix cleanly even when it has no Python AST in the scanned
tree.** Concretely, in `scanner/diagnostics.py`:

```python
_NATIVE_FIRST_PARTY_PREFIXES: frozenset[str] = frozenset({"wardline.core", "wardline.decorators"})

def _is_native_first_party(mod: str) -> bool:
    return any(mod == p or mod.startswith(p + ".") for p in _NATIVE_FIRST_PARTY_PREFIXES)
```

`diagnose_unknown_imports` skips a module when `_is_native_first_party(mod)` is
true, right after the existing `project_modules` check.

Design points:

1. **Declarative + minimal seam.** A module-level `frozenset` constant — the Rust
   migration edits exactly this one list (add a compiled submodule's dotted
   prefix). A YAML manifest + loader was considered and rejected as YAGNI for a
   two-entry list (an extra optional-dep read path + its own drift test, for no
   present benefit). The constant *is* declarative.

2. **A prefix set, not alias-specific.** This is distinct from
   `_BUILTIN_MARKER_IMPORTS` (which resolves specific decorator *names* on the
   statically-modelled marker modules). The native allowlist means "any import
   from this prefix is first-party, resolve it" — appropriate because a compiled
   module's whole surface is first-party.

3. **Dotted-boundary matching — no over-suppression.** Matching is `mod == p or
   mod.startswith(p + ".")`, so only the declared package and its true
   submodules resolve. `wardline.core_helpers` is NOT suppressed by the
   `wardline.core` prefix; an undeclared `wardline.experimental.*` still fires;
   and a genuine third-party `from acme_unknown import x` still fires. All three
   are guarded by tests.

4. **Behaviour-preserving today.** On the current Python tree (where the `.py`
   files exist), the allowlist changes nothing — `wardline.core.*` already
   resolves via `project_modules`, so the self-scan output is unchanged (verified:
   `wardline scan src` still emits 0 `WLN-ENGINE-UNKNOWN-IMPORT`). The allowlist
   only becomes load-bearing once the module is compiled.

## Consequences

- **No self-scan noise after the Rust migration.** When `wardline.core` is
  native, its imports resolve via the allowlist instead of lighting up
  `WLN-ENGINE-UNKNOWN-IMPORT`.
- **The list is the documented seam.** The Rust migration extends
  `_NATIVE_FIRST_PARTY_PREFIXES` with any new compiled submodule prefix and
  touches nothing else in the resolver.
- **No precision loss.** Genuine unknown third-party imports — and even
  undeclared `wardline.*` submodules — still report, so the diagnostic keeps its
  value.
- **Identity-oracle neutral.** Engine diagnostics are excluded from the Task A
  identity corpus, so this change is corpus-neutral by construction (the parity
  gate stays green).

## References

- `src/wardline/scanner/diagnostics.py` — `_NATIVE_FIRST_PARTY_PREFIXES`,
  `_is_native_first_party`, `diagnose_unknown_imports`.
- `tests/unit/scanner/test_diagnostics.py` — native-case + over-suppression +
  precision (adjacent-prefix) tests.
