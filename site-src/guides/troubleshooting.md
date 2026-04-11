# Troubleshooting

Common questions and diagnostic steps when working with Wardline.

## "Why is my function getting UNKNOWN_RAW taint?"

The scanner assigns `UNKNOWN_RAW` when it has no evidence for a function's taint
state. Check:

1. **Is the function's module in `module_tiers`?** If not, add it:
   ```yaml
   module_tiers:
     - path: "src/myapp/services/"
       default_taint: "ASSURED"
   ```

2. **Does the function have a decorator?** Decorators override `module_tiers`.
   Add `@external_boundary`, `@validates_shape`, etc. as appropriate.

3. **At L3: Are callers decorated?** L3 propagates taint through call chains,
   but unresolved call edges default to `UNKNOWN_RAW`.

Use `wardline explain <qualname>` to see the taint resolution path:

```bash
wardline explain myapp.services.user.get_user
```

## "Why does the same rule give ERROR in one file and SUPPRESS in another?"

Severity depends on **taint state**, not the file. A function in an `INTEGRAL`
module gets ERROR; the same pattern in an `EXTERNAL_RAW` module gets SUPPRESS.

Check the function's taint state:

```bash
wardline explain myapp.core.auth.lookup_user
```

Then look up the rule + taint state in the [Severity Matrix](../reference/severity-matrix.md).

## "The scan is slow at L3"

L3 builds a full call graph. Reduce scan time by:

- **Adding decorators**: Resolved call edges are cheaper than unresolved ones
- **Using L1/L2 in CI**: Reserve L3 for nightly scans
- **Scanning a subset**: `wardline scan src/myapp/core/` instead of `src/`

## "I have a finding on code I can't change"

Use an exception:

```bash
wardline exception add \
  --rule PY-WL-004 \
  --location "src/vendor/legacy.py::handle_error" \
  --taint-state GUARDED \
  --rationale "Third-party code, cannot modify" \
  --elimination-path "Replace vendor library" \
  --expires 2026-12-31
```

See [Governance Walkthrough](governance.md) for the full process.

## "Scan exits with code 2 but I don't see an error"

Exit code 2 is a configuration error. Run with `--debug` for details:

```bash
wardline scan src/ --debug 2>debug.log
```

Common causes:
- Missing `wardline.yaml` — see [Getting Started](../getting-started.md#creating-a-manifest)
- Stale `wardline.resolved.json` — re-run `wardline resolve`
- Invalid overlay file — check `wardline.overlay.yaml` syntax

See [Error Messages Reference](../reference/error-messages.md) for a full list.

## "My exception stopped working after a code change"

When code changes, the AST fingerprint changes, and the exception becomes stale.
The scanner emits `GOVERNANCE-STALE-EXCEPTION`.

Fix:

```bash
# Update fingerprints to match current code
wardline fingerprint update

# Refresh exceptions against updated fingerprints
wardline exception refresh
```

## "How do I see what the scanner thinks about a function?"

```bash
wardline explain myapp.core.auth.lookup_user
```

This shows:
- The function's effective taint state
- How that taint was determined (decorator, manifest, callgraph)
- Which rules apply and their severity
- Whether any exceptions cover it

## "I added a decorator but the finding didn't go away"

Check:
1. **Correct decorator?** `@validates_shape` promotes to GUARDED, not ASSURED.
   If the caller expects ASSURED, you need `@validates_semantic` too.
2. **Rejection path present?** PY-WL-008 fires if the boundary function has
   no `raise` or guarded early return.
3. **Right transition?** The decorator's transition must match the data flow.
   `@validates_shape` expects `EXTERNAL_RAW` input.
4. **Re-scanned?** Scan results are not cached — re-run `wardline scan`.

## Further Reading

- [Error Messages Reference](../reference/error-messages.md) — error lookup table
- [Rule Quick Reference](../reference/rules.md) — what each rule means
- [CLI Reference](../reference/cli.md) — command options
