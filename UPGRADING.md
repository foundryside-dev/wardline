# Upgrading Wardline

Migration notes for changes that can alter a previously-green run. Newest first.

## To the next release (recommended v1.2) — preview rules now gate (soundness)

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
If you must defer, use the normal escape hatches: `wardline baseline` (or the
`waiver_add` MCP tool) to suppress a specific finding, or `--new-since <ref>` to
scope the gate to changed code. There is no config flag to restore the old
"preview never gates" behavior.

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
