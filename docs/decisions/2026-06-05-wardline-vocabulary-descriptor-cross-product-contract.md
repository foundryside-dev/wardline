# ADR: The on-disk vocabulary descriptor is the cross-product contract

- **Status:** Accepted
- **Date:** 2026-06-05
- **Resolves:** Pre-Rust core hardening Task B (milestone `wardline-53412b86bc`,
  task `wardline-5877e31767`); retires the in-process-import coupling of
  Loomweave ADR-018 on the Wardline side. Loomweave-side switch tracked at
  `loomweave-1f6241b329`.

## Context

Loomweave's Python plugin historically imported `wardline.core.registry.REGISTRY`
in-process to learn Wardline's trust-decorator vocabulary (Loomweave ADR-018) — a
cross-process import of a sibling's internals. Wardline's core is about to become
a **native (compiled) module** (PyO3 + maturin abi3); a Rust-backed
`wardline.core.registry` imported cross-process by a sibling's Python plugin is
fragile and, post-migration, unsupportable — a compiled module has no stable
Python import surface for a peer to depend on.

Wardline already emits an NG-25 descriptor (`build_vocabulary_descriptor()`,
`wardline vocab`, committed `src/wardline/core/vocabulary.yaml`, MCP
`wardline://vocab`) generated *from* `REGISTRY` and guarded byte-identical by
`test_committed_vocabulary_yaml_matches_registry`. What was missing for it to be
*the* contract: a self-describing format-version field, a documented file
location, and the explicit retirement statement.

Loomweave has already built the read side (`plugins/python/.../wardline_descriptor.py`,
spec `loomweave/.../2026-06-05-descriptor-backed-wardline-annotation-metadata-design.md`):
it reads the descriptor **without importing Wardline**, ignores unknown top-level
keys, and gates on `version == "wardline-generic-2"`. It left two assumptions
"pending Wardline Task B" — the canonical file location and the `schema` field.

## Decision

**The on-disk descriptor is the canonical, versioned cross-product contract for
Wardline's trust vocabulary. Nothing outside `wardline.core` may import it —
external consumers read the descriptor.**

1. **Two-axis versioning.** The envelope carries two distinct fields:
   - `schema` — the descriptor **format** version, `"wardline.vocabulary/v1"`
     (the cross-product contract *shape*: envelope + entry fields and their
     semantics). New module constant `DESCRIPTOR_SCHEMA`.
   - `version` — the vocabulary **content** version, `REGISTRY_VERSION`
     (`"wardline-generic-2"`; which decorators exist).
   Conflating them would force a consumer to re-handle the shape on every
   vocabulary bump. A consumer gates shape expectations on `schema` and content
   expectations on `version`, and **tolerates unknown future entry fields**
   within the same `schema`.

2. **Entry shape (stable).** Each entry is `{canonical_name: str, group: int,
   attrs: {name: type-name str}}`. Per-call-site levels (the parametric
   `to_level`/`level` FunctionTaint mapping) are **deliberately out of scope** —
   they are provider-owned (`DecoratorTaintSourceProvider` reads them per call
   site); the descriptor round-trips `REGISTRY`, not the provider.

3. **File location.** The **canonical, always-present** descriptor is the
   wheel-shipped `wardline/core/vocabulary.yaml` (resolvable via
   `importlib.resources.files("wardline.core")` or `importlib.metadata`). A
   project may *optionally* emit a project-local override with
   `wardline vocab > .wardline/vocabulary.yaml` (e.g. to pin a vocab version in
   its repo); Wardline does **not** auto-emit it (no silent scan side effect).
   Consumers may prefer a project-local copy and fall back to the package copy.

4. **Generated, never hand-maintained.** The committed `vocabulary.yaml` is
   emitted from `REGISTRY` by `wardline vocab`; the byte-identity drift test
   (`test_committed_vocabulary_yaml_matches_registry`) fails CI if it goes stale,
   so the descriptor can never disagree with the live registry.

5. **In-process import coupling retired (Wardline side).** The descriptor
   suffices for external consumers — `test_committed_yaml_is_consumable_as_pure_data`
   proves the vocabulary is recoverable from the file's bytes without importing
   `wardline.core.registry`. `wardline.core` will become native; **no peer may
   import it.** The remaining half (Loomweave switching `import REGISTRY` → reading
   the descriptor) is `loomweave-1f6241b329`, out of Wardline's scope.

6. **Corpus-neutral.** The descriptor / `vocabulary.yaml` is **not** part of the
   Task A identity oracle, so adding `schema` triggers no corpus re-baseline (the
   Task A parity gate stays green — verified).

## Consequences

- **No cross-process import of a soon-to-be-native module.** The contract is a
  plain versioned file, stable across Wardline's Python→Rust core migration.
- **Additive, non-breaking.** Adding `schema` does not break Loomweave's current
  reader (it ignores unknown top-level keys — verified live: Loomweave's
  `wardline_descriptor` parses the schema'd file as `status=enabled`,
  `version=wardline-generic-2`, all three entries). Loomweave's two pending
  assumptions are now resolved (see the hand-off doc).
- **Backward-compatible drift guard.** The existing byte-identity test keeps the
  committed file honest; the new `schema` field is folded into it.
- **Forward path for breaking changes.** A future shape change bumps `schema` to
  `wardline.vocabulary/v2` with a coordinated consumer migration — never a silent
  reshape.

## References

- `src/wardline/core/descriptor.py` — `DESCRIPTOR_SCHEMA`, `build_vocabulary_descriptor`.
- `src/wardline/core/vocabulary.yaml` — the committed, wheel-shipped descriptor.
- `tests/unit/core/test_descriptor.py` — envelope/schema/pure-data-read + byte-identity drift tests.
- `docs/integration/2026-06-05-wardline-descriptor-loomweave-handoff.md` — Loomweave hand-off.
- Loomweave: `plugins/python/src/loomweave_plugin_python/wardline_descriptor.py`,
  `scripts/check-wardline-version-bounds.py`, `loomweave-1f6241b329`.
