# Hand-off: Wardline vocabulary descriptor → Loomweave plugin migration

**For:** Loomweave (`loomweave-1f6241b329`) · **From:** Wardline pre-Rust hardening
Task B (`wardline-5877e31767`) · **Date:** 2026-06-05

Wardline's side of retiring the in-process `import wardline.core.registry.REGISTRY`
coupling (Loomweave ADR-018) is **complete**. This document is the contract Loomweave
consumes to finish the switch. Loomweave's reader already exists
(`plugins/python/src/loomweave_plugin_python/wardline_descriptor.py`); the two
items it marked "PO-confirm against Wardline Task B" are resolved below.

## The descriptor (exact emitted shape)

`wardline vocab` (and the committed `vocabulary.yaml`) emits:

```yaml
schema: wardline.vocabulary/v1
version: wardline-generic-2
entries:
- canonical_name: external_boundary
  group: 1
  attrs: {}
- canonical_name: trust_boundary
  group: 1
  attrs:
    _wardline_to_level: TaintState
- canonical_name: trusted
  group: 1
  attrs:
    _wardline_level: TaintState
```

- `schema` — descriptor **format** version. Gate shape expectations on this.
- `version` — vocabulary **content** version (`wardline-generic-2` today).
- `entries[]` — `{canonical_name: str, group: int, attrs: {str: str}}`. `attrs`
  maps the stamped `_wardline_*` attribute name to its taint-type **name**
  (shape, not a value). **Per-call-site levels are NOT here** — the parametric
  `to_level`/`level` mapping is provider-owned; the descriptor is the vocabulary,
  not the per-site taint.

## Resolution of Loomweave's two pending assumptions

1. **`schema` field — now pinned.** `schema: wardline.vocabulary/v1`. Contract
   for consumers: gate shape on `schema`; **tolerate unknown future entry/top-
   level fields** within the same `schema` (Loomweave's reader already ignores
   unknown top-level keys — correct). A breaking shape change will bump to
   `wardline.vocabulary/v2` with coordinated migration, never a silent reshape.

2. **File location — resolved.** The **canonical, always-present** descriptor is
   the wheel-shipped `wardline/core/vocabulary.yaml`
   (`importlib.resources.files("wardline.core")/"vocabulary.yaml"`, or via
   `importlib.metadata.files("wardline")`). Wardline does **not** auto-emit a
   project-local copy (no silent scan side effect). A project may *optionally*
   pin one with `wardline vocab > .wardline/vocabulary.yaml`. Loomweave's existing
   two-tier read (project `.wardline/vocabulary.yaml` → package
   `wardline/core/vocabulary.yaml`) is exactly right and needs no change;
   `EXPECTED_DESCRIPTOR_VERSION = "wardline-generic-2"` matches.

## Example read (no Wardline import)

```python
from importlib.resources import files
import yaml

text = files("wardline.core").joinpath("vocabulary.yaml").read_text(encoding="utf-8")
data = yaml.safe_load(text)
assert data["schema"] == "wardline.vocabulary/v1"   # gate on shape
assert data["version"] == "wardline-generic-2"      # gate on content version
vocab = {e["canonical_name"]: e for e in data["entries"]}
# vocab["trust_boundary"]["attrs"] == {"_wardline_to_level": "TaintState"}
```

This was **verified live**: Loomweave's `wardline_descriptor._state_from_text`
parses the schema'd `vocabulary.yaml` to `status=enabled`,
`descriptor_version=wardline-generic-2`, entries
`{external_boundary, trust_boundary, trusted}`.

## What Loomweave does next (out of Wardline scope — `loomweave-1f6241b329`)

Switch the plugin from `import wardline.core.registry.REGISTRY` to the descriptor
reader (already built). After that, `wardline.core` becoming a native module is a
non-event for Loomweave. **The native-module migration must not land before this
switch** (or a thin Python `REGISTRY` shim must remain) — see the Rust-cutover
prerequisites in the milestone PO note.

## References

- Wardline ADR: `docs/decisions/2026-06-05-wardline-vocabulary-descriptor-cross-product-contract.md`
- Wardline emitter: `src/wardline/core/descriptor.py`, `src/wardline/core/vocabulary.yaml`
- Loomweave reader: `plugins/python/src/loomweave_plugin_python/wardline_descriptor.py`,
  `scripts/check-wardline-version-bounds.py`,
  spec `docs/superpowers/specs/2026-06-05-descriptor-backed-wardline-annotation-metadata-design.md`
