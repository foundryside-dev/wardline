# Governance Profiles: Lite vs Assurance

Wardline supports two governance profiles that control how strictly findings
and exceptions are enforced.

## Quick Comparison

| | Lite (default) | Assurance |
|---|---|---|
| **Target** | Open-source, startups, early-stage | Regulated, production, compliance-critical |
| **Governance gaps** | Emit warnings | Emit errors (block build) |
| **Coherence failures** | Manual gating | Auto-gate (build fails) |
| **Exception fields** | Recommended | All mandatory |
| **Temporal separation** | Alternatives allowed | Must be enforced |
| **Typical adoption stage** | Initial rollout, growing teams | Mature annotation coverage |

## When to Use Lite

Use `lite` when:

- You are adopting Wardline for the first time
- Your decorator coverage is still growing
- You want findings to inform but not block development
- Your team is learning the trust-tier model

Lite is the default. You do not need to set it explicitly.

```yaml
# wardline.yaml — lite is the default
governance_profile: "lite"
```

## When to Use Assurance

Use `assurance` when:

- Your codebase has comprehensive decorator coverage
- You operate under regulatory or compliance requirements
- You want governance gaps to block the build, not just warn
- You are ready for strict exception management

```yaml
# wardline.yaml
governance_profile: "assurance"
```

## What Changes with Assurance

### Coherence failures auto-gate

In `lite`, a coherence failure (e.g., orphaned exception, fingerprint drift)
produces a warning. In `assurance`, it produces an error and fails the build.

### All exception fields are mandatory

In `lite`, fields like `elimination_path` and `expires` are recommended. In
`assurance`, they are required — `wardline exception add` will reject entries
without them.

### Temporal separation must be enforced

Temporal separation is a governance mechanism that ensures policy changes and
enforcement changes do not happen in the same commit. In `lite`, alternatives
to temporal separation are allowed. In `assurance`, it must be enforced.

## Migration Path

Moving from `lite` to `assurance`:

1. Run `wardline coherence` and fix all findings
2. Ensure all exceptions have `expires` and `elimination_path`
3. Set `governance_profile: "assurance"` in `wardline.yaml`
4. Run `wardline scan` — any new governance errors must be resolved

This is a one-way ratchet in practice — going back to `lite` from `assurance`
weakens governance guarantees and should be treated as a deliberate decision.

## Further Reading

- [Manifest Reference](../reference/manifest.md#governance_profile) — configuration field
- [Governance Walkthrough](governance.md) — exception management
- [Adoption Guide](adoption.md) — incremental rollout strategy
- [Spec §9: Governance Model](../spec/wardline-01-09-governance-model.md) — normative definition
