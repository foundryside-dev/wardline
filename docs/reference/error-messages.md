# Error Messages Reference

Common errors from `wardline scan` and other commands, organized by exit code.

## Exit Code 2: Configuration Error

These errors prevent the scan from running. Fix the configuration before retrying.

| Error | Cause | Fix |
|-------|-------|-----|
| `Manifest not found` | No `wardline.yaml` in the project root or `--manifest` path | Create `wardline.yaml` — see [Getting Started](../getting-started.md#creating-a-manifest) |
| `Invalid manifest` | `wardline.yaml` fails JSON Schema validation | Run `wardline manifest validate` for detailed errors |
| `Registry mismatch` | Exception registry references rules/taint states not in current matrix | Run `wardline exception refresh` to update stale entries, or pass `--allow-registry-mismatch` |
| `Overlay policy error` | An overlay file violates governance constraints (e.g., overriding a locked rule) | Check `wardline.overlay.yaml` against manifest governance policy |
| `Resolved file stale` | `wardline.resolved.json` hash does not match current manifest | Re-run `wardline resolve` to regenerate, or pass `--allow-stale-resolved` |
| `Output file cannot be written` | `-o` path is not writable | Check file permissions and directory existence |

## Exit Code 1: Findings Present

The scan completed but found violations.

| Situation | Meaning | Fix |
|-----------|---------|-----|
| Unexcepted ERROR findings | At least one finding has severity ERROR and no covering exception | Fix the code (see [Rule Reference](rules.md)), or grant an exception via `wardline exception add` |
| `--max-unknown-raw-percent` exceeded | Too many `UNKNOWN_RAW` findings relative to files scanned | Add `module_tiers` entries or decorators to reduce unknowns |
| `--strict-governance` with GOVERNANCE findings | Governance findings treated as blocking | Address governance concerns or remove `--strict-governance` |

## Exit Code 3: Internal Tool Error

The scanner itself failed. This is a bug.

| Situation | Action |
|-----------|--------|
| `TOOL-ERROR` finding in output | Report the issue with the SARIF output attached |
| Stack trace on stderr | Report with `--debug` output |

## Common Warnings (Non-Blocking)

These appear in SARIF output but do not affect the exit code:

| Warning | Meaning | Action |
|---------|---------|--------|
| `GOVERNANCE-STALE-EXCEPTION` | An exception's AST fingerprint no longer matches the code | Run `wardline fingerprint update` then `wardline exception refresh` |
| `GOVERNANCE-TAINT-DEGRADED` | File scanned with empty taint map (no decorators or manifest entries) | Add `module_tiers` entry for the file's package |
| `GOVERNANCE-MODULE-TIERS-BLANKET` | Module default covers >80% of functions with no decorator evidence | Add decorators to key functions, or accept the blanket assignment |
| `L3-LOW-RESOLUTION` | L3 call graph has >70% unresolved edges | Add decorators to called functions, or accept lower-precision results |
| `WARDLINE-UNRESOLVED-DECORATOR` | A `@wardline.*` decorator could not be matched to the registry | Check the decorator name for typos; ensure `wardline` is installed |

## Coherence Check Errors

From `wardline coherence`:

| Check | Meaning | Fix |
|-------|---------|-----|
| `Orphaned exception` | Exception references a function that no longer exists | Remove the exception via `wardline exception expire` |
| `Fingerprint drift` | Code changed but fingerprint baseline not updated | Run `wardline fingerprint update` |
| `Decorator/manifest conflict` | Function has both a taint decorator and a conflicting `module_tiers` entry | Remove one — decorators take precedence over `module_tiers` |

## Further Reading

- [CLI Reference](cli.md) — full command options and exit codes
- [Governance Walkthrough](../guides/governance.md) — managing exceptions
- [Troubleshooting](../guides/troubleshooting.md) — diagnostic decision tree
