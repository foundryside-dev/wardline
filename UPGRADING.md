# Upgrading Wardline

Migration notes for changes that can alter a previously-green run. Newest first.

## To v1.0 — the `--fail-on` gate no longer honors committed suppressions by default

**What changed.** `.wardline/baseline.yaml`, `wardline.yaml` waivers, and
`.wardline/judged.yaml` are all committed repository content, so a malicious pull
request could add a suppression entry keyed to its own new defect's fingerprint and
clear the gate. The `--fail-on` gate now evaluates the **unsuppressed** population by
default: baseline / waiver / judged still **annotate** the emitted findings
(`suppressed: baselined | waived | judged`) but no longer clear the gate.

**Symptom on upgrade.** A repository whose committed baseline used to clear
`wardline scan --fail-on=ERROR` goes **red with no change to its own code**, because
the baselined defects re-enter the gate population. Wardline now says so out loud — a
clean run that trips solely on baselined findings (and was given neither
`--trust-suppressions` nor `--new-since`) prints:

```
migration: baseline present but not honored by default since v1.0 (secure gate default) —
N baselined ERROR+ defect(s) re-enter the gate. Pass --trust-suppressions for a trusted
local checkout or --new-since <merge-base> in CI. See UPGRADING.md.
```

The same signal rides the MCP `scan` result at `gate.migration_hint`, and the gate
block always carries a `reason` and the `evaluated` population so "0 active + gate
FAILED" never reads as a bug.

**How to restore a passing gate.** Pick the one that matches your trust posture:

- **CI (recommended): `--new-since <merge-base>`.** Scopes both the emitted findings
  and the gate to what changed since the ref — an operator-supplied, unforgeable
  ratchet a PR cannot tamper with. A baselined defect that is *not* in the diff stops
  gating; a brand-new defect still trips.
- **Trusted local checkout: `--trust-suppressions`** (CLI) / `trust_suppressions: true`
  (MCP `scan`). Restores the old post-suppression gate. Use **only** where the
  suppression files are trusted — never to enforce on untrusted PR content. This is
  what the `judge` workflow uses internally.

Keeping the baseline up to date (`wardline baseline update`) and clearing real debt is
the durable fix; the flags above are the migration bridge.

**Not affected.** legis's scan artifact and the "one judge / reproduces Wardline's gate
population exactly" property are derived from the gate population, so they already
reflect the secure view. Only the local `--fail-on` exit code changed.
