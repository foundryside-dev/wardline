# Schema Migration Path: v0.1 → v1.0

**Status:** Decided
**Date:** 2026-03-29
**Filigree:** wardline-4a976ab350

## 1. What "Frozen" Means Operationally

After v1.0 promotion, the following contracts are immutable:

| Artefact | Guarantee |
|----------|-----------|
| JSON Schema `required` fields | Never removed. New required fields = new schema version. |
| JSON Schema `enum` values | Never removed or renamed. New values may be added (additive). |
| `$id` URL pattern | `https://wardline.dev/schemas/1.0/<name>.schema.json` — stable indefinitely. |
| `EXPECTED_SCHEMA_VERSION` | `"1.0"` until a future `2.0` (not planned). |
| `RuleId` enum values | Never removed. New rule IDs may be added. |
| `REGISTRY` entry keys | Never removed. New decorators may be added. |
| `TaintState` enum values | Never removed or renamed. |
| `Severity`, `Exceptionability` values | Never removed. |

**Additive changes** (new optional fields, new enum values, new rule IDs) are permitted within v1.0 without a version bump. **Subtractive or renaming changes** require a new major version.

## 2. Migration Strategy: Hard Break, No Dual-Accept

**Decision:** v1.0 is a hard break. The loader will accept `1.0` only, not both `0.1` and `1.0`.

**Rationale:**
- Wardline is pre-release. There are zero external consumers of `0.1` manifests.
- Dual-accept creates validation ambiguity (which schema to validate against?) and testing surface (must test both paths forever).
- The `0.1` → `1.0` change is almost entirely URL-string bumps — no structural migration needed. Users (us) update one `$id` line per file.
- We are the only user. Every `0.1` document is in this repository and can be updated atomically.

## 3. Files That Change

### Schema files (5 files)
Update `$id` URL from `/schemas/0.1/` to `/schemas/1.0/`:
- `src/wardline/manifest/schemas/wardline.schema.json`
- `src/wardline/manifest/schemas/overlay.schema.json`
- `src/wardline/manifest/schemas/exceptions.schema.json`
- `src/wardline/manifest/schemas/fingerprint.schema.json`
- `src/wardline/manifest/schemas/corpus-specimen.schema.json`

### Constants (3 locations)
- `src/wardline/manifest/loader.py:40` — `EXPECTED_SCHEMA_VERSION = "0.1"` → `"1.0"`
- `src/wardline/core/registry.py:10` — `REGISTRY_VERSION = "0.1"` → `"1.0"`
- `src/wardline/manifest/regime.py:218` — `schema_version="0.1"` → `"1.0"`

### Hardcoded `$id` URLs (2 locations)
- `src/wardline/cli/exception_cmds.py:643` — `$id` in `_load_or_create()`
- `src/wardline/cli/fingerprint_cmd.py:157` — `$id` in `update` command

### Tool version
- `src/wardline/scanner/sarif.py:260` — `tool_version: str = "0.1.0"` → `"1.0.0"`

### Data files
- `wardline.yaml:6` — `$id` URL
- `wardline.exceptions.json` — `$id` field
- `wardline.fingerprint.json` (if exists) — `$id` field
- `corpus/corpus_manifest.json` — `spec_version: "0.1"` → `"1.0"`
- `scripts/generate_corpus.py:408` — `spec_version` literal

### Test fixtures (~15 locations across 5 files)
- `tests/unit/test_wp04_hardening.py` — `EXPECTED_SCHEMA_VERSION` references
- `tests/unit/cli/test_coherence_cmd.py` — inline YAML `$id` strings
- `tests/unit/cli/test_exception_migration.py` — inline fixture `$id`
- `tests/unit/cli/test_fingerprint_cmd.py` — inline `$id` and `schema_version`
- `tests/unit/cli/test_regime_cmd.py` — inline YAML `$id`
- `tests/unit/corpus/test_corpus_skeleton.py` — `spec_version == "0.1"` assertion

## 4. Rollback Procedure

If a critical gap is found within 30 days post-freeze:

1. Revert the version-bump commit (single atomic commit makes this trivial).
2. `EXPECTED_SCHEMA_VERSION` goes back to `"0.1"`.
3. All data files revert to `0.1` `$id` URLs.
4. Document the gap in a new Filigree issue with `P0` priority.
5. Fix the gap, then re-promote.

Since there are no external consumers and no published PyPI package yet, rollback has zero blast radius.

## 5. Post-Freeze Change-Control

After v1.0 is published:

- **Additive changes** (new optional schema fields, new enum values): Update schema files directly. No version bump. Document in CHANGELOG.
- **Subtractive/breaking changes**: Require a new `$id` version segment (`2.0`), a new `EXPECTED_SCHEMA_VERSION`, and a migration plan. This triggers a new decision doc.
- **Schema file changes** require a PR with explicit review — add `src/wardline/manifest/schemas/` to CODEOWNERS.

## 6. Implementation Sequence

This is the execution order for `wardline-9c00c39d83` (Promote schemas to v1.0):

1. Update `EXPECTED_SCHEMA_VERSION` and all 5 schema `$id` fields in one commit.
2. Update all hardcoded `$id` URLs in CLI commands.
3. Update `REGISTRY_VERSION`, `tool_version`, `regime.py` literal.
4. Update `wardline.yaml`, `wardline.exceptions.json`, `corpus_manifest.json`.
5. Update `generate_corpus.py`.
6. Update all test fixtures.
7. Run full test suite (unit + integration).
8. Run self-hosting scan to verify.
9. Tag as release candidate.

All steps in a single commit — this is an atomic version bump, not a structural change.
