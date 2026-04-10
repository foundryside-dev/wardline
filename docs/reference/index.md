# Reference

## I need to...

| Question | Start here |
|----------|-----------|
| Understand why a rule fired on my code | [Rules](rules.md) then [Severity Matrix](severity-matrix.md) |
| Know what severity/exceptionability applies | [Severity Matrix](severity-matrix.md) |
| Pick the right decorator for a function | [Decorators](decorators.md) |
| Understand a taint state like UNKNOWN_GUARDED | [Taint States](taint-states.md) |
| Fix a scan error or warning | [Error Messages](error-messages.md) |
| Consume wardline output in CI | [SARIF Format](sarif-format.md) then [CLI](cli.md) |
| Configure wardline.yaml or overlays | [Manifest](manifest.md) |
| Look up a term I don't recognise | [Glossary](glossary.md) |

---

## All Reference Documents

### Core Concepts

- [**Taint States**](taint-states.md) — The 8 canonical taint states, authority tiers, and the join lattice
- [**Severity Matrix**](severity-matrix.md) — 72-cell lookup: (rule, taint state) to (severity, exceptionability)
- [**Rules**](rules.md) — All rule IDs: canonical pattern rules, supplementary rules, diagnostics, and governance findings
- [**Glossary**](glossary.md) — Definitions for terms used in wardline output and documentation

### Configuration

- [**Manifest**](manifest.md) — Field-by-field reference for `wardline.yaml` and `wardline.overlay.yaml`
- [**Decorators**](decorators.md) — The 38 wardline decorators organised into 17 groups
- [**Supplementary Groups**](supplementary-groups.md) — Decorator groups beyond the core authority-tier flow

### Output & Integration

- [**CLI**](cli.md) — All commands, subcommands, flags, and exit codes
- [**SARIF Format**](sarif-format.md) — Annotated SARIF v2.1.0 output with every `wardline.*` property documented
- [**Error Messages**](error-messages.md) — Common errors by exit code, with causes and fixes
- [**Governance Retention**](governance-retention.md) — Audit retention requirements for SARIF, exception register, and fingerprint baseline
