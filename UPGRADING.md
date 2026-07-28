# Upgrading Wardline

Migration notes for changes that can alter a previously-green run. Newest first.

## To v1.4 — wider FastAPI coverage; lineless defects gate; `ScanResult` API change

**Precise FastAPI request-input coverage can surface new findings.** Exact nested
`Request` members are now recognised as untrusted sources, and route body
parameters typed with a project Pydantic model are seeded as tainted (ordinary
`BaseModel` parameters, `Depends(...)` provider results, and non-route functions
are deliberately *not* seeded). A FastAPI project that scanned green may now
report real defects on those paths. **What to do:** fix them at the boundary, or
— if you must defer — mind the secure default: the gate evaluates the
*unsuppressed* population, so scope CI with `--new-since <merge-base>` rather
than relying on a committed baseline.

**A lineless source `DEFECT` now gates instead of being downgraded away.**
Previously a source-level DEFECT arriving without a start line was silently
downgraded to a non-gating FACT (to avoid an unsafe fingerprint join). It is now
replaced by a deterministic `WLN-ENGINE-LINELESS-DEFECT` engine diagnostic that
**keeps the original severity and `DEFECT` kind** — so it is gate-eligible —
while carrying the original rule id, path, fingerprint, and kind in its
properties under a collision-safe fingerprint. The downgrade allowlist ships
empty by design: no shipping rule is known to emit a lineless DEFECT today, so
this is primarily a fail-closed guard against a future one silently leaving the
gate population. If your scan does hit it, the diagnostic is a real
under-analysis signal, not noise.

**Two related fail-closed changes.** A delta scan whose source binding is
malformed now keeps the finding ACTIVE rather than treating `<engine>` as an
unchanged path and clearing the gate, and `WLN-ENGINE-PYDANTIC-DISCOVERY-LIMIT`
now counts as an incomplete-analysis signal that survives delta filtering —
an under-analyzed scan can no longer quietly read as a complete one.

**An in-root symlinked `*.py` source file is now reported at its canonical
target.** Discovery hands downstream the resolved path that passed confinement
(so a later retarget of a mutable symlink cannot redirect analysis) and
deduplicates a file reachable through both its symlink and its real path. If
your tree has an in-root `alias.py -> real.py`, findings previously anchored at
`alias.py` now anchor at `real.py`. Because the path participates in the
fingerprint, that **re-keys** those findings: any baseline/waiver/judged entry
for them must be regenerated (`wardline baseline update`). Out-of-root symlink
targets were skipped before and still are. This affects symlinked source files
only.

**Pre-1.4 attestation bundles no longer re-derive byte-identically.** The signed
`wardline-attest-2` payload gained a required `sei_diagnostics` key, so
`wardline attest --verify <bundle> --reproduce` on a bundle built by 1.3.x
reports `reproduced: false` with `mismatches: ["sei_diagnostics"]`.
`signature_valid` is **unaffected** — the recorded signature still verifies, and
consumers that read named keys (including Warpline's `parse_attest_bundle`) are
unaffected. **What to do:** rebuild the bundle under 1.4.0 if you gate on
`--reproduce`.

**`wardline doctor` flags an unpinned Filigree emit URL.** A configured Filigree
URL that is not project-scoped now reports an error with a source-specific
remedy (run `wardline doctor --repair` to rewrite `.mcp.json`, unset/repoint
`WARDLINE_FILIGREE_URL`, or fix the `--filigree-url` flag) instead of passing as
`ok`. Server-mode Filigree fail-closes unscoped writes, so this was a silent
misconfiguration.

**In-process API: `ScanResult.gate_findings` is gone.** Embedders that read or
construct `ScanResult` directly must use the mandatory frozen
`ScanResult.gate_population`, which carries an immutable finding **tuple** plus a
closed `GateSuppressionPosture` (`UNSUPPRESSED` / `HONORS_SUPPRESSIONS`), instead
of the old nullable `gate_findings` sentinel. Read
`result.gate_population.findings`, `result.gate_population.posture`, or the
`result.gate_population.honors_suppressions` convenience property. Note the
findings are a tuple, not a list, so `isinstance(..., list)` checks must be
relaxed. The CLI, MCP, JSONL/SARIF, Legis-artifact, and
Filigree/Loomweave wires are unchanged — this affects Python callers only.

## To v1.3 — federation transports refuse redirects; signing fails closed

**Redirects are never followed on credential-bearing transports**
(`wardline-f68c483d92`). Previously urllib followed a 3xx, re-sending
`Authorization`/`X-Weft-*` headers to the redirect target (cross-origin included)
and rewriting a redirected POST into a body-less GET whose 200 read as a clean
emit — a silent false green. If your `--filigree-url` / `--loomweave-url` /
OpenRouter endpoint resolves through a redirect (an `http→https` upgrade, a host
alias), the transport now refuses the first 3xx fail-closed: emits report
failure, `verify_token` reports inconclusive, and the promote/judge legs reject
loudly. **What to do:** point the URL at the final, post-redirect target. The
taint gate itself is unaffected — federation stays non-gating enrichment.

**Signing paths fail closed on indeterminate git state.** A failed `git status`
no longer coerces to *clean*: the legis artifact signs only on a proven-clean
tree, and `attest` signs an indeterminate tree only under explicit
`allow_dirty` (recording `dirty: null` uncoerced). A CI job that signed from a
checkout where git state could not be read now fails instead of producing a
falsely-clean signed bundle.

## To v1.2 — preview rules now gate (soundness)

`wardline-4ada23bb09`. The `--fail-on` gate previously **ignored** any rule whose
`maturity` is `preview`, so a scan could pass green while an active ERROR defect
was present. `maturity` is now purely informational; **preview rules gate (and
are baselineable) exactly like stable rules**, matching the documented contract.

**Who is affected.** A repository that scans green today but contains one of the
previously-non-gating preview findings will now correctly **fail**. At
`--fail-on ERROR`: `PY-WL-118` (SQL injection), `PY-WL-119` (no-op/degenerate
trust boundary), `PY-WL-120` (stored taint → trusted), `PY-WL-121` (XXE),
`PY-WL-122` (SSTI), `PY-WL-124` (native-library load). At lower thresholds also
`PY-WL-116`/`117`/`123`/`126` (WARN) and `PY-WL-125` (INFO).

**What to do.** This is a real finding, not noise — fix it at the boundary/sink.
If you must defer, mind the secure default: the gate evaluates the *unsuppressed*
population, so a committed baseline or waiver clears it **only** under
`--trust-suppressions` (a trusted local checkout), not in a default CI run. In
**CI**, scope the gate with `--new-since <merge-base>` so it fires only on changed
code; a baselined/waived finding alone will not turn the build green. (`wardline
baseline` / the `waiver_add` MCP tool still record the suppression for the
trusted-checkout and `--new-since` paths.) There is no config flag to restore the
old "preview never gates" behavior.

## To v1.0 — Weft config/store consolidation (BREAKING)

Wardline's operator config and machine state moved onto the Weft federation
convention. **There is no automatic migration** — an operator with an existing
`wardline.yaml` and `.wardline/` must move both by hand. The changes:

**1. Config moved `wardline.yaml` (YAML) → `weft.toml` `[wardline]` table (TOML).**
Wardline now reads its settings from the `[wardline]` table of a shared,
operator-authored `weft.toml` at the scan root, parsed with stdlib `tomllib` (no
new dependency). A missing, unreadable, or unparseable `weft.toml` silently falls
back to built-in defaults — it never hard-fails. (Unknown keys or out-of-range
values inside a *present* `[wardline]` table still fail loud, as before.)
`--config` now points at a TOML file.

**2. State moved `.wardline/` → `.weft/wardline/` (no fallback).** `baseline.yaml`,
`judged.yaml`, and the newly relocated `waivers.yaml` all live under
`.weft/wardline/` now. Wardline does **not** read the old `.wardline/` location —
re-create the baseline, or `git mv` the directory (the file contents and keys are
unchanged). An operator may relocate this subtree with `[wardline].store_dir` in
`weft.toml`. The attest signing key still lives in `.env` (unchanged).

**3. Waivers are no longer a config key.** They are machine/CLI-written
suppression state in `.weft/wardline/waivers.yaml` (written by the MCP
`waiver_add` tool, or hand-edited). The `waivers:` config block is gone.

**4. Sibling endpoint URL config keys were removed.** `[wardline.filigree].url`
and `[wardline.loomweave].url` are no longer valid. Sibling URLs resolve only via
the `--filigree-url` / `--loomweave-url` flag, the `WARDLINE_FILIGREE_URL` /
`WARDLINE_LOOMWEAVE_URL` env var, or the published
`<root>/.weft/<sibling>/ephemeral.port` file (legacy `<root>/.<sibling>/ephemeral.port`
tolerated). Binding auto-wiring was dropped: `wardline install` / `wardline doctor`
now only **detect** siblings and write no config.

**5. `wardline install <pack>` is guidance-only.** It no longer writes config to
activate a trust-grammar pack; it prints the snippet to add `packs = [...]` to
`weft.toml` `[wardline]` by hand (packs import and execute code, so they stay
operator-authored). Assert the pack at scan/judge time with `--trust-pack`.

### Operator migration steps

1. **Create `weft.toml`.** Translate your `wardline.yaml` keys into TOML under a
   `[wardline]` table (YAML → TOML; everything nests under `[wardline]`). For
   example:

   ```yaml
   # OLD wardline.yaml
   source_roots: [src]
   exclude: ["build/**"]
   rules:
     enable: ["PY-WL-101"]
     severity:
       PY-WL-101: ERROR
   judge:
     model: anthropic/claude-opus-4-8
     context_lines: 30
   ```

   ```toml
   # NEW weft.toml
   [wardline]
   source_roots = ["src"]
   exclude = ["build/**"]

   [wardline.rules]
   enable = ["PY-WL-101"]
   severity = { "PY-WL-101" = "ERROR" }

   [wardline.judge]
   model = "anthropic/claude-opus-4-8"
   context_lines = 30
   ```

   Drop any `filigree:` / `loomweave:` URL blocks (removed) and any `waivers:`
   block (now state — see step 3). Delete the old `wardline.yaml`.

2. **Move the state directory.** Either re-create the baseline at the new
   location:

   ```console
   $ wardline baseline create .   # writes .weft/wardline/baseline.yaml
   ```

   or move the existing files in place (contents and keys are unchanged):

   ```console
   $ mkdir -p .weft && git mv .wardline .weft/wardline
   ```

   Commit `.weft/wardline/` like you committed `.wardline/`.

3. **Move waivers.** Any `waivers:` you had in `wardline.yaml` become the
   `waivers:` list of `.weft/wardline/waivers.yaml` (same entry shape:
   `fingerprint` / `reason` / optional `expires`). Add new ones with the MCP
   `waiver_add` tool or by hand-editing that file.

4. **Pin sibling URLs out of config.** If you relied on a `filigree:`/`loomweave:`
   config URL, set it instead via the `--filigree-url`/`--loomweave-url` flag, the
   `WARDLINE_FILIGREE_URL`/`WARDLINE_LOOMWEAVE_URL` env var, or let live discovery
   read the published `.weft/<sibling>/ephemeral.port`.

5. **Activate packs by hand.** If you used `wardline install <pack>` to enable a
   pack, add `packs = ["<pack>"]` to `weft.toml` `[wardline]` yourself, then pass
   `--trust-pack <pack>` at scan/judge time.

## To v1.0 — the `--fail-on` gate no longer honors committed suppressions by default

**What changed.** `.weft/wardline/baseline.yaml`, `.weft/wardline/waivers.yaml`, and
`.weft/wardline/judged.yaml` are all committed repository content, so a malicious pull
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
