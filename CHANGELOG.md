# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Gate verdict is now explicit (no vacuous green).** `GateDecision` carries a
  `verdict` (`NOT_EVALUATED` / `PASSED` / `FAILED`) and a `would_trip_at` (the
  highest severity that would trip on the evaluated population, or null). A bare
  scan with no `--fail-on` reports `verdict: NOT_EVALUATED` + `would_trip_at`
  instead of a clean-looking `tripped: false`, so an agent's first scan is never a
  false green. Surfaced on every gate block (MCP `scan`, agent-summary,
  `scan_file_findings`) and on the CLI as a `gate: NOT_EVALUATED — …` line
  (weft-b937e53854).
- **Bounded default scan output + pagination.** The MCP `scan` tool returns a
  bounded page (≤25 finding bodies) by default so a bare call cannot overflow an
  agent's context (previously ~123KB on one line). New `full: true` lifts the cap;
  new `offset` pages through the rest via `agent_summary.truncation.next_offset`.
  `explain: true` inlines provenance into the `agent_summary.active_defects`
  entries (capped, announced) (weft-439d09fc8d).
- **Emit destination is now echoed (no silent misroute).** Every Filigree emit
  status block (MCP `scan`, agent-summary, CLI) carries a `destination`
  (`{url, project, project_pinned}`) naming where findings were sent; the CLI
  success line names the destination project. When the URL pins no project,
  `project_pinned: false` surfaces that Filigree resolves it server-side — the
  silent-misroute shape behind the lacuna→filigree contamination — so a
  wrong-project write is visible at the caller (C-10(a)).
- `wardline doctor` now verifies the Filigree federation token: it probes the
  configured daemon (URL resolved from `.mcp.json`/env) with the token wardline
  would emit and reports a `filigree.auth` check. `--repair` recovers the
  daemon-accepted token from local mints and pins it as `WEFT_FEDERATION_TOKEN`
  in `.env`, removing a stale `WARDLINE_FILIGREE_TOKEN` line.
- **Zero-ceremony Filigree auth on a same-host install (F1).** The outbound token
  resolver now reads Filigree's auto-minted `<root>/.weft/filigree/federation_token`
  (the C-9e same-host cross-member read) as a middle rung — after the canonical
  `WEFT_FEDERATION_TOKEN` (env then `.env`) and before the deprecated
  `WARDLINE_FILIGREE_TOKEN` fallback. A fresh same-host install with no
  env/`.env`/`.mcp.json` token now authenticates against the per-project daemon
  with no operator config, mirroring filigree's own 3-tier resolution. The mint
  file is read-only (wardline never mints it); a missing/unreadable file falls
  through cleanly to the legacy/off rungs (emit stays soft-fail) (weft-23574069a1).

### Changed
- **BREAKING (wire): per-finding `suppressed` key renamed to `suppression_state`.**
  The JSONL stream, the Filigree `metadata.wardline.*` subtree, and the signed
  **legis scan artifact** now emit `suppression_state` (values unchanged:
  `active`/`baselined`/`waived`/`judged`). This eliminates the "active" overload
  (the per-finding *state* vs the summary `active` *count*). Because the legis
  artifact is signed, the canonical bytes — and the golden signature — change;
  **legis must adopt `suppression_state` on its ingest/co-sign side** before the
  signed hop verifies again (the opt-in `legis_e2e` oracle stays red until then)
  (weft-f506e5f845).
- The MCP `scan` response no longer carries a top-level `findings` array; finding
  bodies live solely in `agent_summary` (the single canonical carrier). The
  `truncation` block moved under `agent_summary` (weft-439d09fc8d).
- The MCP `summary` block adds an `informational` bucket so
  `active + baselined + waived + judged + informational == total`
  (weft-f506e5f845).
- The Filigree emit `disabled_reason` now distinguishes *no token sent* from
  *token sent but rejected (401)* and names the URL it tried, instead of a flat
  "set WEFT_FEDERATION_TOKEN" that implied absence (weft-23574069a1 / C-7).
- **BREAKING: Weft config/store consolidation.** Operator config moved from
  `wardline.yaml` (YAML) to the `[wardline]` table of a shared, operator-authored
  `weft.toml` (TOML), read via stdlib `tomllib` (zero new dependency). An
  auto-discovered `weft.toml` that is missing falls back to built-in defaults
  silently; one that is present-but-unparseable (or whose `[wardline]` is not a
  table) falls back with a **warning** (a shared federation file may have another
  member's broken section — wardline never crashes, but no longer downgrades policy
  silently). An **explicit `--config`** that is missing OR present-but-malformed
  **raises** (the operator named it; silently dropping their policy is a
  false-green). Unknown/out-of-range keys in a *present, well-formed* `[wardline]`
  table still fail loud. `--config` now points at a TOML file. Machine-written state
  moved from `.wardline/` to `.weft/wardline/` — `baseline.yaml`, `judged.yaml`,
  and the newly relocated `waivers.yaml` all live there (no fallback to the old
  path; the attest signing key stays in `.env`). Waivers are **no longer a config
  key** — they are machine state in `.weft/wardline/waivers.yaml` (written by the
  MCP `waiver_add` tool / `add_waiver`). Sibling endpoint URL config keys were
  **removed** (`[wardline.filigree].url` / `[wardline.loomweave].url` are not
  valid); sibling URLs resolve only via the `--filigree-url`/`--loomweave-url`
  flag, the `WARDLINE_FILIGREE_URL`/`WARDLINE_LOOMWEAVE_URL` env var, or the
  published `<root>/.weft/<sibling>/ephemeral.port` file (legacy
  `<root>/.<sibling>/ephemeral.port` tolerated). Binding auto-wiring was dropped:
  `wardline install`/`doctor` now only **detect** siblings and write no config.
  `wardline install <pack>` is **guidance-only** — it emits the snippet to add
  `packs = [...]` to `weft.toml` `[wardline]` rather than writing config (packs
  stay operator-authored). An operator may relocate the state subtree with
  `[wardline].store_dir`. No automatic migration — see UPGRADING.md for operator
  steps.
- **Filigree bearer credential now read from the federation-scoped
  `WEFT_FEDERATION_TOKEN`.** The federation loopback token was renamed
  `WEFT_FEDERATION_TOKEN` (deconfliction plumbing across the Weft federation). The
  loader now prefers it — checking env then `.env` — and the operator-facing
  auth-rejected messages point at the new name. The previous `WARDLINE_FILIGREE_TOKEN`
  is honored as a **deprecated fallback** (read after the new name), so existing
  deployments keep working with no change; migrate at leisure. Only the token *value*
  must match what the Filigree operator configured.
- **`wardline doctor --repair`/`install` now preserves operator-pinned
  `--filigree-url`/`--loomweave-url` args** in the `.mcp.json` wardline server entry
  (in the order the operator wrote them) instead of normalizing them away. Previously
  every repair rewrote the entry to the bare canonical args, silently stripping a
  fixed-port sibling emit/discovery target the published-port rung cannot reconstruct.

### Fixed
- **Explicit `--config` pointing at a malformed (but existing) `weft.toml` no longer
  silently falls back to default policy.** The guard previously covered only a
  *missing* explicit path; a present-but-unparseable one slipped through C-9c's
  fail-soft and dropped the operator's severity overrides/excludes silently — a
  false-green in the gate. An explicit path now raises `ConfigError` on a parse
  error or non-table `[wardline]`; an auto-discovered `weft.toml` warns (instead of
  failing silently) before falling back. (PR-review finding)
- **PR-review polish (latent, no behavior change):** `GateDecision` now rejects a
  `fail_on` that is not a valid `Severity` value at construction; `AgentSummary`
  rejects a negative `max_findings`; `filigree_disabled_reason` derives
  auth-rejection from `status` (the inconsistent `auth_rejected`/`status` triple is
  no longer expressible); legis `signed`/`dirty` status is read through one shared
  `legis_artifact_outcome` authority instead of being re-derived on each surface;
  the dead `config` input was dropped from the MCP `waiver_add` schema.

## [1.0.0rc2] - 2026-06-06

### Added
- **MCP `scan` payload controls — `where` now shrinks the payload, plus
  `summary_only` / `max_findings` / `include_suppressed` and a default explain cap
  (dogfood friction #4).** `where` previously filtered only the top-level `findings`
  list; the `agent_summary` arrays still inlined every suppressed finding, so a filter
  matching zero findings still returned dozens. `where` now filters the `agent_summary`
  arrays too. New args: `summary_only: true` (counts + gate, no finding bodies — the
  smallest "did the gate pass?" payload), `include_suppressed: false` (drop suppressed
  bodies; counts stay in `summary`), and `max_findings: N` (cap the returned bodies).
  `explain: true` no longer inlines provenance for *every* active defect — the one-shot
  blowup that returned 56,820 chars on one line — it is capped at 10 by default
  (raise/lower with `max_findings`). Every cut is reported in a new `truncation` block
  (`findings_total` / `findings_returned` / `findings_truncated` /
  `explanations_truncated`) so a bounded payload never reads as "covered everything."
  `summary`/`gate` always describe the whole project; the CLI `--format agent-summary`
  output is unchanged.
- **The `--fail-on` gate verdict now explains itself (dogfood friction #2/#3).** A scan
  reporting `summary.active: 0` while `gate.tripped: true` no longer reads as a bug. The
  gate block (CLI stderr, MCP `scan` result, and the agent-summary) carries a human
  `reason` — e.g. `"34 suppressed ERROR+ defect(s) (baseline/waiver/judged) not cleared;
  pass --trust-suppressions (trusted checkout) or --new-since <ref> (PR)"` for a
  suppressed-only trip, `"N active ERROR+ defect(s) at or above ERROR"` for a genuine one
  (no misdirection to the suppression flags) — and an `evaluated` string naming the judged population
  (`unsuppressed …` by default vs `post-suppression … honored` under
  `--trust-suppressions`). Counts come from the annotated findings, so they match
  `summary`.
- **Loud migration signal for the secure gate-default rollout (dogfood friction #3).**
  When a committed `.wardline/baseline.yaml` exists, the gate trips **solely** because
  baselined defects re-enter the unsuppressed population, and neither
  `--trust-suppressions` nor `--new-since` was passed, Wardline now prints a one-line
  `migration:` hint (CLI stderr; MCP `scan` `gate.migration_hint`; and the agent-summary
  `gate.migration_hint`) pointing at the escape hatches and the new **`UPGRADING.md`**.
  This is the "my repo went red with no code change" case made self-explaining; the
  secure default itself is unchanged.
- Live Loomweave port resolution (consumer half of Loomweave **ADR-044**): Wardline
  now reads Loomweave's published read-API port from `<project>/.loomweave/ephemeral.port`
  and inserts it into `resolve_loomweave_url` precedence as `flag > env > published
  port > wardline.yaml`. A live serve's real port self-heals over a stale/default
  literal in `wardline.yaml`, so a mis-pinned URL no longer silently strands
  federation for a second project (the failure ADR-034's instance-ID guard catches
  as `PROJECT_MISMATCH`). Read-never-compute, loopback-by-construction, fail-soft
  (missing / malformed / out-of-range / unreadable → fall through to config); skipped
  under `strict_defaults`. A deliberate `--loomweave-url` flag or env var still always
  wins. No change to wire behaviour or the HMAC signer.
- Signed scan handoff to **legis** (the Weft governance plugin): `wardline scan
  --format legis` (CLI) and an opt-in `legis_artifact` block on the MCP `scan` result
  produce the verbatim-postable `scan` for legis's `POST /wardline/scan-results`. The
  artifact carries four provenance fields (`scanner_identity`, `rule_set_version`,
  `commit_sha`, `tree_sha`) and an `artifact_signature` — `hmac-sha256:v2:<hex>` over
  legis-canonical JSON (sorted-key, tight-separator, non-ASCII-preserved), byte-exact
  with legis's signer (pinned by a golden vector captured from real legis). The shared
  secret is read from `WARDLINE_LEGIS_ARTIFACT_KEY` (env or `.env`); unset → unsigned
  with `unverified` provenance. Signing refuses a dirty / non-git tree (false
  provenance); the MCP block is fail-soft, the CLI is loud (exit 2). The artifact carries
  the **whole scan**, each finding projected onto legis's accepted vocabulary — `properties`
  filtered to the eight trust tiers (diagnostics like `sink`/`callee`/`markers`
  dropped; the rich MCP/SARIF/Loomweave wire is unchanged), suppression proof carried in
  `properties`, and `baselined`/`judged` mapped onto legis's `suppressed`. `active`
  stays `active`, so legis reproduces Wardline's gate population exactly (one judge);
  legis enforces its own 500-finding cap (a larger scan is rejected loudly, never silently truncated).
  The hermetic conformance test now mirrors legis's *full* ingest validation (trust
  tiers, suppression proof, supported states), closing the prior false-green. See
  [Signed scan handoff to legis](guides/legis-handoff.md).
- `wardline assure` CLI and MCP `assure` tool: trust-surface COVERAGE posture — how many
  declared trust boundaries (`@external_boundary` / `@trust_boundary` / `@trusted`) the
  engine reached a definite verdict on vs. how many are honestly unknown (`unknown` list),
  plus a `waiver_debt` rollup (days-to-expiry per configured waiver, lapsed entries
  surfaced not dropped). Zero-config — reads what every scan already computes.
- `wardline attest` CLI and MCP `attest` / `verify_attestation` tools: signed, reproducible
  evidence bundle (`schema: wardline-attest-1`) capturing commit, ruleset hash, the full
  assurance posture, and per-boundary verdicts. HMAC-SHA256 signed with an install-minted
  project key (`wardline install` appends `WARDLINE_ATTEST_KEY` to `.env`). The CLI and MCP
  default to refusing a dirty working tree (`--allow-dirty` / `allow_dirty: true` to
  override, records `dirty: true` honestly). `verify_attestation` checks signature (offline)
  and optionally re-derives the payload at the current tree (`--reproduce` / `reproduce:
  true`). SEI-keyed boundaries opt-in via `--loomweave-url` (fail-soft).
- `file_finding` (MCP tool + `wardline file-finding` CLI): file ONE finding by fingerprint
  into a tracked Filigree issue, returning its id (idempotent, fail-soft). Scan emission now
  sets `mark_unseen=True` (non-empty scans) so a fixed finding enters Filigree's
  `unseen_in_latest` state and a regressed one reopens its linked issue on the next scan.
  (Issue close-on-fixed is gated on Filigree's clean-stale sweep.) (WS-A2)
- MCP `scan` now emits findings to Filigree when a `--filigree-url` is configured, at
  parity with the CLI (a `filigree` block in the scan result; fail-soft — an unreachable
  sibling or rejected payload is reported, never fails the scan). Closes the CLI/MCP
  finding-emission asymmetry. (WS-A1)
- MCP `scan` gains a server-side `where` filter (rule_id/qualname/severity/suppression/kind/
  path_glob/sink/tier) and an `explain: true` mode that inlines each active defect's taint
  provenance — killing the scan-then-N-explains round-trips. New read-only `wardline findings`
  CLI verb shares the same filter core. (WS-B1, WS-B2)

### Fixed
- **`next_actions` is gate-aware — never reads as "passed" when the gate failed
  (dogfood re-test, #2).** When the gate trips solely on baselined findings,
  `summary.active` is 0, so the agent-summary's `next_actions` used to say
  *"no active defects; rescan after edits"* — telling the agent it passed while the
  gate FAILED. It now emits a scan action naming the gate failure and the escape
  hatches (trust_suppressions / new_since / clear the baseline; see `gate.reason` /
  `gate.migration_hint`). The active-defects and genuinely-clean paths are unchanged.
- **CLI/MCP distinguish a Filigree `401` (auth-rejected) from transport-unreachable
  (dogfood friction #5).** A `401` (token absent) was reported as *"could not reach
  Filigree"*, sending agents to chase a broken-bridge theory. `EmitResult` now carries
  `status` + `auth_rejected`; the CLI prints *"Filigree returned 401 (auth rejected) …
  set WARDLINE_FILIGREE_TOKEN"* (and a distinct `5xx` "server error" vs the genuine
  "could not reach"), and the MCP `scan` `filigree_emit` block / agent-summary carry the
  same discriminated `disabled_reason`. A `403` is reported as *"forbidden (token present
  but lacks access)"* rather than telling the agent to set a token that won't help.
  `401`/`403` stays **soft** (non-load-bearing, never exit-2) — only the message changed.
- **`scan --format legis --allow-dirty` emits an unsigned dev artifact instead of
  refusing (dogfood friction #1).** On a dirty working tree `scan --format legis`
  failed `exit 2` naming an `allow_dirty` flag that was never exposed — presenting
  identically to "legis is broken," the session's single biggest rabbit hole. The flag
  is now exposed (`--allow-dirty` CLI / `allow_dirty` MCP `scan`). The honest fix: a
  dirty tree under `--allow-dirty` does **not** sign — the only readable `tree_sha` is
  the *committed* one, which does not describe dirty working content, so signing it
  would be false provenance. It falls through to the **unsigned** dev artifact, clearly
  marked `dirty: true` (legis records it `unverified`). Signing stays clean-tree-only;
  the loud refusal without `--allow-dirty` is unchanged. Lets the dev/tour loop exercise
  the Wardline→legis handshake without a commit.
- **PY-WL-110 (contradictory-trust) now fires for the `weft_markers` namespace
  (soundness; `wardline-d62845bb18`).** The rule hardcoded
  `wardline.decorators.*` as the only recognised marker prefix, so a contradictory
  `@trusted` + `@external_boundary` stack imported from the renamed `weft_markers`
  shim (the namespace authors are steered toward post-rebrand) was silently *not*
  flagged. The prefix set is now derived from `BUILTIN_BOUNDARY_TYPES`
  (`{wardline.decorators, weft_markers}`) so the rule cannot drift from the grammar
  that seeds provenance. The other boundary rules read resolved provenance and never
  had this gap.
- **Taint: lambda bindings are now branch-local (`wardline-36016d26f3`).** The
  `_CURRENT_LAMBDA_BINDINGS` map was shared across `if`/`else`, `try`/`except`, and
  `match` arms (unlike `var_taints`), so a lambda bound in one arm leaked into a
  mutually-exclusive sibling and could over-fire (false positive) in adversarial
  branch layouts. Each arm is now walked against an arm-local copy and re-converged by
  layering each arm's *delta* onto the pre-branch state in source order — which both
  removes the cross-arm leak and preserves a rebinding made in a no-`else` / no-catch-all
  arm for a call after the branch (so no new false negative is introduced).
- **Loomweave HMAC signer resync (auth path was 401ing every signed request).**
  Wardline's request signature drifted from Loomweave's verifier (ADR-042): the
  canonical message is now `METHOD\nPATH\nSHA256HEX(body)\nTIMESTAMP\nNONCE` (the
  body-hash and timestamp were transposed) and every signed request now carries a
  fresh high-entropy `X-Weft-Nonce` (`secrets.token_hex(16)`) — Loomweave hard-requires
  the nonce (300s freshness window + replay cache) and 401s without it. The HMAC unit
  test is no longer self-referential: it pins the canonical message as a literal,
  Loomweave's HMAC known-answer vector (`auth.rs`), a frozen signature, and the
  three-header/fresh-nonce wire shape. Affects only the authenticated Loomweave path
  (reads against an unauthenticated serve were already fine).
- **legis one-judge property (P1 `wardline-48a5a8d062`).** `build_legis_artifact` now
  projects the **gate** population (`result.gate_findings`, the unsuppressed view the
  `--fail-on` gate evaluates) instead of the suppressed `result.findings`, mirroring
  `gate_decision`'s exact `is not None` fallback. A defect a committed
  baseline/waiver/judged self-suppresses now reaches legis as `active` (legis enforces
  it), so legis and Wardline's own gate judge the same population. `--trust-suppressions`
  (gate_findings is None) still projects the suppressed view. `finding_count` stays
  honest (both populations are the same length).

### Changed
- **CLI scan summary now labels the non-suppressed count `active`, not `new`**
  (`wardline-26e84dbd44`). The human summary line previously printed
  `… N new`, but every other surface — the `SuppressionState.ACTIVE` enum, the
  `ScanSummary.active` field, the MCP `summary.active` key, the agent-summary
  `active_defects` key, and the `wardline:loop` prompt — already said `active`.
  The CLI now matches, so an agent never reconciles a CLI "N new" against an MCP
  "active". Text-only (the count value is unchanged); no JSON/SARIF/wire field
  renamed. The new [Finding lifecycle & gate vocabulary](https://github.com/foundryside-dev/wardline/blob/main/docs/reference/finding-lifecycle-vocabulary.md)
  reference page is the single source of truth for these state words (and the
  three distinct meanings of "new" across the suite).
- **Filigree clients no longer crash the scan loop when Filigree auth is enabled.**
  `401`/`403` from `/api/weft/*` are now treated as **soft** (enrichment unavailable,
  like a 5xx/outage) across the emit and promote/file clients — previously a loud
  `FiligreeEmitError` while the dossier client degraded softly (now coherent). `400`
  (a Wardline payload bug) stays loud. Wardline can also now **send** a bearer token:
  a new `WARDLINE_FILIGREE_TOKEN` loader threads `Authorization: Bearer` through all
  three Filigree clients (emit, issue/promote, dossier work-provider) at every call
  boundary; absent a token, no header is sent (default-off loopback-trust posture,
  unchanged). No HMAC on this seam — it is bearer-only by design (ADR-018).
- Filigree gained the same consume-time published-port self-heal as Loomweave
  (ADR-044 twin): `resolve_filigree_url` now reads `<root>/.filigree/ephemeral.port`
  (precedence `flag > env > published > wardline.yaml`, skipped under `strict_defaults`),
  returning `http://localhost:<port>/api/weft/scan-results` to match `install/detect.py`'s
  writer. A live dashboard on a new port self-heals over a stale install-stamped literal.

### Security
- **Builtin trust-marker decorators are now trusted only when they resolve to the
  real exports — closes a spoofable false-green.** The default decorator seeding
  trusted ANY FQN whose prefix was a builtin marker module and whose final segment
  was a known marker name, without verifying the decorator resolved to Wardline's
  real package. A scanned project could ship its own `wardline/decorators/__init__.py`
  (or `weft_markers/__init__.py`) defining a no-op `trusted`/`trust_boundary`, apply
  it to a leaky function, and have the analyzer anchor it as TRUSTED — suppressing
  real taint→sink flows (a false GREEN that hides defects). Nested spoof paths
  (`wardline.decorators.evil.trusted`, `weft_markers.evil.trusted`) were also accepted.
  Builtin markers now match ONLY their exact public re-export (`P.<name>`) or
  implementation-module export (`P.trust.<name>`), and the provider FAILS CLOSED for a
  builtin marker root the scanned project shadows (defines its own top-level `wardline`
  / `weft_markers` package). The shadowed-root set is derived dynamically from the
  grammar (`{bt.module_prefix.split('.')[0] for bt in BUILTIN_BOUNDARY_TYPES if
  bt.builtin}`), so every builtin marker root is covered, not just `wardline`. Custom
  (non-builtin) grammar markers keep the documented prefix + canonical-name behavior —
  a project defining its own custom marker package is the intended extension use.
  **Cache-key hardening:** the per-root shadow state is folded into a shadow-aware
  provider fingerprint threaded through BOTH the pipeline dirty-detection key and the
  resolver's summary cache, so a TRUSTED summary computed under one shadow state can
  never be reused under another (cross-root cache poisoning). The fingerprint stays
  byte-identical to today's value when nothing is shadowed. **Loomweave residual
  (documented, not threaded):** the opt-in `--loomweave-url` taint-fact
  `content_hash_at_compute` is whole-file raw-byte blake3 only — it cannot observe
  shadow state, so identical file bytes scanned once unshadowed then under a shadow
  could serve a stale TRUSTED fact via the MCP `explain_taint` / Loomweave read path. The
  shadow bit is deliberately NOT mixed into this hash because it is a cross-tool
  contract value Loomweave's read path independently recomputes and compares; mixing in a
  Wardline-private bit would break fact reconciliation entirely. Closing it fully needs
  a Loomweave read-path contract change; the keying site carries an explicit comment. This
  path is opt-in and not the scan gate, so impact is lower.
- **The `--fail-on` gate no longer honours repository-controlled suppressions by
  default (closes a CI-gate bypass).** `.wardline/baseline.yaml`, `wardline.yaml`
  waivers, and `.wardline/judged.yaml` are all committed repository content, so a
  malicious pull request could add a suppression entry keyed to its own new defect's
  fingerprint and clear the gate. The gate now evaluates the **unsuppressed**
  population by default; baseline / waiver / judged still **annotate** the emitted
  findings (`suppressed: baselined | waived | judged`) but cannot clear the gate. The
  secure CI ratchet is the operator-supplied, unforgeable `--new-since <merge-base>`,
  which scopes **both** the emitted findings and the gate. A new `--trust-suppressions`
  flag (CLI) / `trust_suppressions` arg (MCP `scan`), default false, restores the old
  post-suppression gate for **trusted local checkouts** (and is what the `judge`
  workflow uses internally). `.wardline/judged.yaml` records now also **require**
  `verdict: FALSE_POSITIVE` on load — a missing or non-FP verdict is rejected, so a
  hand-edited judged entry cannot be smuggled in as a silent suppression
  (`build_judged_document` always emits it, so machine round-trips stay valid). New
  `ScanResult.gate_findings` field carries the unsuppressed gate population (None
  sentinel = trust suppressions / fall back to `findings`).

  > **BREAKING (acceptable at 0.x):** a CI job that relies on a committed baseline
  > (or waiver / judged file) to keep `wardline scan --fail-on=…` green will now go
  > **red** on upgrade, because the baselined defects re-enter the gate population. Add
  > `--new-since <merge-base>` (recommended for CI) or `--trust-suppressions` (trusted
  > checkouts only) to restore a passing gate. Note: legis's scan artifact and the
  > "one judge / reproduces Wardline's gate population exactly" property are derived
  > from the annotated `findings`, so they continue to reflect the suppressed view;
  > only the local `--fail-on` exit code changed.
- **Dangerous-sink rules now see lambda bodies (closes a false-green).** `_own_calls`
  treated `ast.Lambda` as a separate scope and only inspected lambda *default*
  expressions, so a sink reached inside a lambda *body* — `cb = lambda: eval(src)`,
  and likewise `exec` / `pickle.loads` / `subprocess` / dynamic `import` — was never
  handed to the sink rules (`PY-WL-106/107/108`), producing a silent false-negative.
  Lambda bodies are now traversed as part of the enclosing analyzable scope (lambdas
  are not indexed as separate entities, unlike `def`/`class`) — on **both** sides:
  sink *discovery* (`_own_calls`) and the L2 taint *walk*. The walk resolves each
  lambda body in a second pass (after the forward walk) against the **worst**
  (least-trusted) taint each captured variable holds *anywhere* in the function, in an
  isolated scope copy (lambda-local params/walrus never leak, and the lambda's own
  parameters shadow enclosing names of the same id). Whole-function-worst is the
  fail-closed choice for a closure, which defers execution to an unknown call time and
  captures free variables by reference: no single program-point snapshot is sound —
  the definition-site value misses a variable tainted *after* the lambda is defined
  (`src = "safe"; cb = lambda: eval(src); src = read_raw(p)`), and the final value
  misses a variable still raw *when the lambda is called* and cleaned only afterwards
  (`src = read_raw(p); cb = lambda: eval(src); cb(); src = "clean"`). Both are real
  deferred sinks and now fire. This closes the false-negative (raw →
  `eval`/`exec`/`pickle.loads`/`subprocess` in a lambda body now fires, including both
  deferred orderings) and removes the gross over-report where *any* lambda-body sink in
  a trusted function previously fell to the pessimistic flow-insensitive fallback and
  fired `UNKNOWN_RAW` regardless of the argument (`lambda: eval("safe")` and a
  `lambda cmd: eval(cmd)` whose param shadows an enclosing raw `cmd` no longer fire; no
  `WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK` warning is emitted). The remaining imprecision
  is a documented, conservative, waivable **false positive**: a variable raw only
  *before* the lambda captures it (e.g. `x = read_raw(p); x = "clean"; cb = lambda:
  eval(x)`) is treated tainted, because the analysis joins over the whole function
  rather than tracking the capture point — the safe direction for a security analyzer,
  and verified not to fire on wardline's own source (dogfood: 0 new). Regression tests
  cover discovery (`_own_calls`), both deferred orderings on `PY-WL-107`/`108`, no-fire
  on a clean local and a shadowing lambda parameter, and the documented conservative FP.
- **Local trust-pack guard no longer executes repository code while deciding.**
  `_is_local_pack()` resolved a `wardline.yaml` `packs:` entry with
  `importlib.util.find_spec()`, which imports (and runs) the parent of a dotted
  name (`evil.sub` → `evil/__init__.py`) — so the very guard meant to refuse
  executing a *local* pack executed it as a side effect of the check. Locality is
  now decided by pure filesystem inspection (stat only, never import), and the
  guard fails closed (malformed-but-importable names fall through to the walk
  rather than skipping it). Residual vector closed: a trusted published pack name
  shadowed by an attacker-committed local package on `sys.path`. (The pre-existing
  `--trust-pack` allowlist already gates this code path, so a default scan never
  reached it.)

## [1.0.0rc1] - 2026-06-02

### Changed

- **Cross-method class-attribute taint (soundness closure A).** Raw assigned to
  `self.<attr>` in one method and returned from (or passed to a sink in) ANOTHER
  method used to escape — the engine was function-level. A per-class attribute
  summary (the least-trusted value written to each `self.<attr>` across all methods)
  now seeds reads of that attribute, so `PY-WL-101`/`105` and the sink rules see raw
  data surfaced via instance state. This does NOT over-fire on the common OO shapes
  (validated setter + trusted getter, lazy-init): a `@trust_boundary`-validated write
  is trusted, so the summary stays trusted — measured FP=0 on hand-built patterns and
  on the dogfood + corpus trees. Two bounded residual FNs (never over-fires): a deep
  `self.y = self.x` attribute-to-attribute chain may under-resolve, and the attribute
  summary does not feed back into the L3 fixed point (attr-derived taint surfaced
  through a non-anchored method's return won't propagate to that method's callers).
- **Flow-sensitive sink-arg taint (soundness closure E).** The sink rules
  (`PY-WL-106`/`107`/`108`) and `PY-WL-105` now resolve a call argument's taint AT
  the sink statement, not from the function's final per-variable map. This closes a
  documented two-way imprecision: a variable trusted at the sink but reassigned raw
  *after* it no longer over-fires (a false positive), and one raw at the sink but
  sanitised *after* it now correctly fires (a fail-open it previously missed). The
  L2 walker captures a per-statement var-taint snapshot (`function_call_site_taints`
  on the analysis context); the expression combinators are unchanged.

### Internal

- **Soundness-regression locks for closures B / C / D.** Probing the Track-1.6
  candidate FN closures found three already sound — `*args`/`**kwargs` at call
  sites, comprehension/walrus targets, and decorator-wrapped (`functools.wraps`)
  callees all propagate taint correctly. Pinned with regression tests so a future
  refactor cannot silently reopen them. (No engine change for B/C/D.)

### Added

- **`PY-WL-111` — trust boundary whose only rejection path is `assert` (CWE-617).**
  A `@trust_boundary` that rejects bad input only via `assert` validates in
  development but is stripped under `python -O`, so the rejection silently
  vanishes in production. The one genuinely-generic, FP-safe builtin still worth
  adding (framework-specific sinks belong in opt-in trust-grammar packs).
  Declaration-gated, `ERROR`, partitions cleanly with `PY-WL-102`: 102 fires when
  a boundary cannot reject at all, 111 when it appears to reject but only via an
  `-O`-stripped guard. The shared `has_rejection_path` helper now counts `assert`
  so the two never double-fire.
- **Test guards (no behavior change):** a rule-examples meta-test asserting every
  builtin rule's `examples_violation`/`examples_clean` actually fire / stay clean
  (caught and fixed rotted `PY-WL-101` examples that referenced an undefined
  helper); a `RAW_ZONE` ↔ `TRUST_RANK` consistency pin; `least_trusted`
  idempotence + associativity (exhaustive); a fingerprint-stability test pinning
  the real anchor-line contract (anchor-preserving edits stay byte-identical, a
  line-shifting edit changes it by design); and a CLI ↔ MCP finding-parity
  differential guarding the "identical by construction" tenet.

- **Track 5 — trust-vocabulary convergence + legis CI (T5.1–T5.3).** The final
  Wardline track: one trust vocabulary, one judge, proven against legis. All
  Wardline-repo-only (legis is a fixed external contract; elspeth is inspiration
  only — no import, no linkage). The convergence was found to be *already
  substantially true*, so this track is proof + documentation that locks it in.
  - **T5.1 — vocabulary convergence (gap-check):** `docs/concepts/trust-vocabulary-convergence.md`
    records a keep/adopt/drop sweep of the trust effects elspeth pioneered against
    the Weft mechanisms that already deliver them — fabrication test ≈ PY-WL-102,
    custody ≈ the lattice + `taint_provenance`, fail-closed ≈ `UNKNOWN_*` +
    `WLN-ENGINE-*` FACTs (incl. `WLN-ENGINE-UNPROVABLE-BOUNDARY`), tiered boundary ≈
    `@trust_boundary(to_level=…)`, one-judge ≈ legis carrying Wardline's 8 tiers
    verbatim. All Covered; a `tier=` alias and a duplicate worked example are
    explicitly Dropped (the T2 extension-plane fixture `custom_grammar.py` already
    demonstrates an elspeth-style tiered boundary). No engine/decorator change.
  - **T5.2 — legis intake conformance:** Wardline's emitted findings/gate already
    match legis's `from_wire` ingest contract (verified: `severity` name, `kind`,
    `suppressed` values all align). A hermetic always-on contract test
    (`tests/conformance/test_legis_intake_contract.py`) vendors legis's contract and
    proves a real scan ingests cleanly and that legis's active-defect selection
    reproduces Wardline's own `summary.active` gate population (one judge: legis
    reads the verdict, never re-derives it). A new opt-in `legis_e2e` marker drives a
    live round-trip oracle (`tests/e2e/test_legis_live.py`) against a running legis's
    `POST /wardline/scan-results`, auto-skipping when absent.
  - **T5.3 — hash-granularity harmonisation:** an ADR
    (`docs/decisions/2026-06-02-wardline-hash-granularity-two-model.md`) formalizes
    the two-granularity model — whole-file (taint-store freshness,
    `content_hash_at_compute` ↔ Loomweave `current_file_hash`) vs entity-body
    (identity/association drift, Loomweave resolve `content_hash` ↔ Filigree
    `content_hash_at_attach`) — and the never-cross-compare rule. Discipline tests
    (`tests/conformance/test_hash_granularity.py`) lock the false-STALE-never
    property and guard that `content_status` is only called from the entity-body
    surface. No new hashing, no store change.
- **Track 4 — the Weft entity dossier (assembler + live wiring, T4.1–T4.3).** One
  freshness-honest call returns everything an agent needs to reason about a function
  without reading its source. Wardline is the **assembler** (composes each tool's
  slice; it does not become the store).
  - `core/dossier.py` — the `EntityDossier` envelope: frozen, JSON-serialisable, keyed
    on the **opaque SEI**, freshness-stamped on **both orthogonal axes** (identity
    alive/orphaned/unavailable × content fresh/stale/unknown, never collapsed). The
    default envelope is **token-bounded ≤2k** via a conservative deterministic estimator;
    over-budget content is trimmed with an explicit, elision-honest truncation marker
    (shown-of-total), and an untrimmable core is reported as EXCEEDS-budget — never a
    silent cap. `build_dossier` composes Wardline's OWN trust posture for real (re-scan
    → FRESH) with a **three-valued honest verdict** (defect / clean / **unknown** — an
    undeclared or under-scanned entity is never reported "clean"), and reads Loomweave
    linkages + Filigree work through injected `LinkageProvider`/`WorkProvider` seams.
    An absent / no-opinion / unreachable source degrades to an honest `unavailable`
    section — never fabricated, never a crash.
  - `loomweave/client.py` — `get_callers`/`get_callees` (HMAC-gated call-graph reads,
    fail-soft); `loomweave/dossier_sources.py` — `LoomweaveLinkageProvider` (live linkages,
    SEI identity axis + FRESH live-read content axis, one-sided outages named) and
    `resolve_entity_binding` (qualname → locator → opaque SEI binding via the Track-3
    `SeiResolver`; never mints or parses the SEI).
  - `filigree/dossier_client.py` — a dep-free urllib `FiligreeWorkProvider` reading
    ADR-029 entity-associations keyed on the SEI; compares `content_hash_at_attach`
    (same entity-body granularity as Loomweave's resolve) to set per-ticket **DRIFT** and
    a three-valued section content axis (STALE / UNKNOWN / FRESH — never guesses FRESH).
  - `weft_dossier.py` — `build_weft_dossier`, the orchestrator: probe Loomweave
    capabilities once, resolve the SEI binding, wire both providers, call the
    source-agnostic core assembler. Degrades honestly with whatever sources are present.
  - **Surface:** `wardline dossier <qualname>` (CLI) and a `dossier` MCP tool, both thin
    delegators to `build_weft_dossier` (CLI and MCP identical by construction — a parity
    test asserts byte-identical envelopes). `wardline mcp` gains `--filigree-url`.
  - The base package stays **zero-dependency** (the Filigree reader is stdlib urllib;
    Loomweave-consuming code lives behind the existing `wardline[loomweave]` extra). Verified
    by a live `loomweave_e2e` one-call dossier round-trip against a real `loomweave serve`.
- **Track 1.5 — rule-set breadth (4 → 10 curated rules).** Six new trust-taint rules,
  authored on the Track 2 grammar, each fail-closed/opt-in with violation+clean examples
  and labeled corpus fixtures (corpus FP rate stays 0%):
  - **PY-WL-105** — untrusted data passed to a trusted callee at a call site (CWE-501);
    the call-site analogue of PY-WL-101. Fires only on provably-untrusted args.
  - **PY-WL-106** — untrusted data reaches a deserialization sink (pickle/marshal/yaml.load, CWE-502).
  - **PY-WL-107** — untrusted data reaches a dynamic-code-execution sink (eval/exec/compile, CWE-95).
  - **PY-WL-108** — untrusted data reaches an OS-command sink (os.system/subprocess.*, CWE-78).
  - **PY-WL-109** — None leaks from a trusted producer (mixed value + bare/None return, CWE-394).
  - **PY-WL-110** — contradictory trust declaration (≥2 distinct trust markers on one entity).
  105–108 are call-site rules; 106/107/108 are tier-modulated (silent in the developer-freedom
  zone). All toggle via `wardline.yaml` `rules.enable`/`rules.severity` like the existing four.
- **Track 3 — SEI-client groundwork (T3.1–T3.3).** An opt-in `wardline[loomweave]`
  SEI abstraction (`wardline.loomweave.identity`) carries Loomweave's Stable Entity
  Identity as the **opaque, preferred** cross-tool binding handle, with an honest
  **two-axis** status (identity alive/orphaned/unavailable × content fresh/stale/unknown,
  never collapsed). `SeiResolver` reads Loomweave's `_capabilities` and **degrades
  gracefully** — when no `sei` capability is advertised it reports "identity
  unavailable" and keeps working on the locator, never guessing or crashing. The SEI
  is **never parsed** and **never enters Wardline finding fingerprints** (a golden-digest
  guard locks the fingerprint input set; the warm/cold byte-identical guarantee holds).
  Built against the spec'd wire contract (SEI standard §4 + Loomweave ADR-038, pinned
  `/api/v1/identity/*` routes) and verified live against a real SEI-serving `loomweave
  serve`. The base package stays zero-dependency (the module is stdlib-only).
- **Track 3 — rename-stable taint read-by-SEI (T3.4).** Consumes Loomweave's additive
  migration 0006 (a nullable `sei` column + `POST /api/wardline/taint-facts/by-sei`
  route + discrete `taint_store.read_by_sei` capability). `TaintStoreCapability`
  detects the route **gated separately from `sei.supported`** (an older SEI-capable
  Loomweave predates the route), fail-closed. `LoomweaveClient.batch_get_by_sei` reads
  taint facts by their stable **opaque SEI** — the surface by which a fact written
  under a former locator survives a rename — fail-soft like `batch_get` (outage/403 →
  None; route-absent 404 → loud read-skew). The write path is unchanged: Loomweave
  **stamps each fact's SEI server-side** from its alive `sei_bindings` row, so facts
  become SEI-tagged with no Wardline change. Verified live (write → resolve →
  read-by-SEI round-trip + bogus-SEI honest miss) and at the unit level (the
  deterministic rename model: by-new-locator misses, by-SEI hits). There is
  **no in-repo serve consumer** — by-SEI is the cross-tool rename-stable read surface
  for Track 5/legis and dossier-over-time (an explain fast-path consumer would be dead
  code: a renamed entity's fact is anchored to its old `source_file_path`, so a qualname
  change implies a content/path change and the fact reads stale). Base stays zero-dep.
- **Track 2 — extensible trust grammar.** The three trust decorators and four
  rules are no longer hardcoded: a project can declare custom **boundary types**
  (a trust transition + its L1 seed) and **rules** and register them via
  `wardline.scanner.grammar` — `default_grammar().extend(boundary_types=…, rules=…)`,
  run through `build_analyzer(grammar=…)`. The builtins are preloaded defaults and
  produce **byte-identical** findings to before (a corpus-wide golden enforces it);
  the released `wardline.core.registry` import surface is unchanged. The extension
  plane is a zero-dependency *code* seam (the same shape as `TaintSourceProvider`),
  not a config DSL.
- **`WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT** — a *custom* boundary type the engine
  cannot prove statically (an unreadable required level) seeds the fail-closed
  `UNKNOWN_RAW` **and** emits this observable FACT, so the extension plane inherits
  Wardline's no-false-green guarantee. Builtins stay silently fail-closed (oracle-
  preserving). A custom boundary stacked on a provable decorator is dragged to the
  fail-closed meet rather than silently over-trusted.

- **Track 1 — engine-quality floor.** A labeled false-positive corpus
  (`tests/corpus/`) with a manifest-driven FP-rate gate (≤5%; currently 0% over 21
  true-positive fixtures spanning control-flow joins, match arms, validators,
  broad/silent exceptions, aliased-stdlib sinks, and return indirection) plus
  waiver discipline (every waiver carries a reason; waiver count ≤ rule count).

### Fixed

- **Star-import false-negative** — `from wardline.decorators import *` now resolves
  the trust decorators statically (materialised from the in-process registry, never
  by importing/executing the target), so a `@trust_boundary`/`@trusted`/
  `@external_boundary` reached via star-import is seeded. Every other star import
  stays unresolved and keeps emitting the honest `WLN-ENGINE-UNKNOWN-IMPORT` FACT.
- **Explain provenance** — `compute_return_callee` resolves single-hop return
  indirection (`x = read_raw(p); return x`), so `explain`/PY-WL-101 names the
  contributing callee instead of `None`. Provenance only — taint values unchanged.

## [0.3.0] - 2026-05-31

### Added

- **`wardline install`** — one-command agent enablement. Injects a hash-fenced
  instruction block into `CLAUDE.md`/`AGENTS.md`, installs the `wardline-gate`
  skill into `.claude/`/`.agents/`, merges a `wardline` entry into `.mcp.json`,
  and detects Loomweave/Filigree to record bindings in `wardline.yaml`.
  `loomweave.url`/`filigree.url` are now runtime-read config fields (precedence:
  CLI flag > env var > `wardline.yaml`). Opt-out flags `--no-claude-md`,
  `--no-agents-md`, `--no-skill`, `--no-mcp`, `--no-bindings`; no SessionStart
  hook (re-run to refresh).

## [0.2.1] - 2026-05-31

### Added

- **Taint algebra concepts page + lattice-retention ADR** — a new
  `docs/concepts/taint-algebra.md` consolidates the taint-combination
  rationale (which operator runs where and why, the reachable-state set and its
  invariants, the per-rule consumption map, and the accepted "wrong-predicate
  validator" boundary) into one authoritative spec, and
  `docs/decisions/2026-05-31-wardline-taint-lattice-retain.md` records the
  decision to retain the 8-state lattice and the `taint_join` operator as the
  documented contrast operator (no production call site). Resolves the
  taint-combination audit findings F1, F3, F4, and F5.

### Changed

- **Reachable-state invariant now enforced at the taint parsers** — the two
  dynamic `TaintState` construction sites that previously accepted any canonical
  state are now constrained to their legal subsets: the bundled stdlib taint
  table accepts only `{ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`, and the
  disk-persistent summary cache's deserialiser accepts the full reachable set
  `{INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`. Both reject the
  never-produced trio (`MIXED_RAW`, `UNKNOWN_GUARDED`, `UNKNOWN_ASSURED`), so a
  corrupt/tampered cache file or a future stdlib-table entry carrying one is
  rejected (the cache file is dropped as cold-cache fallback) rather than
  silently injecting an otherwise-unreachable state. No behaviour change for
  valid inputs. Resolves audit finding F5.
- **Removed dead code in the L3 propagation kernel** — the unreachable inner
  unresolved-clamp in the per-SCC refinement round (subsumed by the preceding
  floor) was deleted, along with the now-orphaned `unresolved_counts` parameter
  of the internal `_compute_scc_round` helper. Behaviour-preserving. Resolves
  audit finding F2.
- **Corrected stale taint-combiner comments in the test suite** — the
  `test_variable_level.py` comments claiming control-flow merges "keep
  `taint_join`" predated the merge migration and misdescribed current behaviour;
  they now state those merges use `least_trusted` (wardline-4d9f840c24). Test
  comments only. Resolves audit finding F6.

### Fixed

- **Control-flow merge over-tainting (false positives)** — the statement-level
  control-flow merges (`if`/`else`, `for`/`while` back-edges, `try`/`except`
  handlers, `match` arms) combined per-variable taint via the provenance-clash
  join, so two clean-but-different-family branches (e.g.
  `if c: x = validate(p) else: x = guard(p)`) spuriously became `MIXED_RAW` and
  fired `PY-WL-101` on validated data. At a merge a variable holds the value of
  exactly one branch, so they now combine via the rank-meet weakest-link
  (`least_trusted`), matching the expression combiners; a raw branch still
  propagates and fires. This completes the `taint_join` → `least_trusted`
  migration for the L2 either-or paths.
- **L3 callee-combination over-tainting (false positives)** — the four
  callee-combination joins in the call-graph propagation engine
  (`minimum_scope.py`, plus `propagation.py`'s external-influence, Phase 1b
  seed-join, and per-round SCC refinement) combined the taints of a function's
  *set* of callees via the provenance-clash join. That is a function-summary
  aggregation of callee influence, not a single value built by merging two
  provenances, so a non-anchored function calling two clean-but-different-family
  callees (e.g. an `ASSURED` validator and an `INTEGRAL` helper) spuriously
  became `MIXED_RAW` (rank 7, in the firing raw zone) — an over-taint that,
  propagated up, fired `PY-WL-101` on clean data. All four sites now aggregate
  via the rank-meet weakest-link (`least_trusted`); a raw callee still
  propagates at its precise rank and fires. Completes the `taint_join` →
  `least_trusted` migration; the `taint_join` operator itself remains in
  `core/taints.py`.

## [0.2.0] - 2026-05-31

Adds a first-class MCP server and an opt-in persistent taint store, ships a
documentation site, and closes a taint soundness hole plus a batch of
hardening fixes. The base package stays zero-dependency.

### Added

- **MCP server** — a dependency-free, stdlib-only MCP-over-stdio server
  (`wardline mcp`, JSON-RPC 2.0, no SDK). Tools: `scan`, `explain_taint`,
  `judge` (network-fenced), `baseline_create`, `baseline_update`, `waiver_add`;
  resources `wardline://vocab|rules|config|config-schema` (findings are never a
  resource); one `wardline:loop` prompt. Tool-execution errors surface as
  `isError` results; protocol faults are JSON-RPC errors.
- **`explain_taint` provenance** — projects the real contributing return-taint
  callee for an anchored `PY-WL-101`, and (with the Loomweave store) walks the
  full N-hop taint chain (`chain: true`, explicit truncation via `max_hops`).
- **Loomweave taint store** — opt-in Loomweave-backed persistent taint store
  (`wardline[loomweave]` extra). `wardline scan --loomweave-url` persists per-entity
  taint facts; `explain_taint` serves a fresh fact from the store behind a
  never-serve-stale `blake3` freshness gate, falling back to a local re-scan.
  HMAC auth is stdlib; `blake3` is the sole (lazy) extra dependency.
- **Documentation site** — a Material for MkDocs site (home, getting-started,
  concepts, guides, CLI + vocabulary reference, agent-integration), built
  `--strict` in CI and deployed to GitHub Pages. New `docs` extra; the base
  package stays zero-dependency.

### Fixed

- **Taint soundness (fail-open)** — the L2 resolver (`_resolve_expr`) fell
  through to the function taint for unmodelled AST shapes, which in a `@trusted`
  producer reset untrusted data to the trusted tier and emitted a clean report.
  f-strings, `str()`/`.format()`/`.join()`, `.get()`/subscript, BoolOp,
  attribute reads, `await`, comprehensions, container-writes, `self`-method
  calls, and aliased serialization sinks now propagate taint correctly.
- **Expression-combiner over-tainting (false positives)** — value-building /
  either-or / container-summary combiners (BinOp, IfExp, BoolOp, list/dict
  literals, comprehensions, `.get`/`.pop` defaults, `+=`, container writes)
  combined via the provenance-clash join, so a benign literal + validated data
  spuriously became `MIXED_RAW`. They now combine via the rank-meet
  weakest-link, matching the f-string/`.format`/`.join` paths; raw still
  propagates. Control-flow merges deliberately retain the provenance join.
- **Scan observability** — parse-error, unreadable, recursion-skipped, and
  missing-source-root files are now counted (`ScanSummary.unanalyzed`) and
  surfaced, with an opt-in `--fail-on-unanalyzed` gate.
- An explicit `--config` path that does not exist now errors instead of
  silently falling back to the default policy.
- Line-less engine-diagnostic findings no longer crash the scan.
- The MCP server returns an `isError` result (which clients reliably surface)
  for unexpected tool-handler exceptions instead of a dropped `-32603`.

### Security

- **Path confinement (THREAT-001 residual)** — a symlinked `.py` inside a
  source-root could escape the project root and be read out-of-tree via the MCP
  `scan` tool. Each discovered file is now resolved under the root when
  confinement is requested (MCP path); CLI default behavior is unchanged.

### Removed

- Dropped the unused `weft` optional-dependency extra (`httpx`). The Filigree
  emitter and Loomweave producer-conformance support ship in `scanner` and use
  only the standard library (`urllib`), so the extra pulled in a dependency
  nothing imported.

## [0.1.0] - 2026-05-30

First public release. A generic, lightweight semantic-tainting static analyzer
for Python — enterprise-class trust-boundary analysis at small-team weight.

### Added

- **Taint engine** — AST-based semantic taint analysis with a trust lattice,
  call-graph propagation, function-summary caching, and `match`-statement
  handling. Zero runtime dependencies in the base package.
- **Trust vocabulary** — decorator-based trust markers (`@trusted`,
  `@boundary`, validators) resolved through a configurable vocabulary
  descriptor.
- **Rules** — `PY-WL-101` (untrusted-reaches-trusted), `PY-WL-102`
  (boundary-without-rejection), `PY-WL-103` (broad-except), `PY-WL-104`
  (silent-except), with per-rule severity overrides.
- **Outputs** — `wardline scan` emits findings as JSONL or SARIF, with a native
  Filigree emitter and Loomweave producer-conformance support for Weft
  integration.
- **Suppression model** — baseline files and waivers (with expiry), plus an
  opt-in LLM triage layer.
- **LLM triage judge** — opt-in `wardline judge` reads each active finding cold
  and labels it true/false positive with a rationale, writing confirmed
  false positives to `.wardline/judged.yaml`. Dependency-free transport
  (stdlib `urllib` → OpenRouter); requires `WARDLINE_OPENROUTER_API_KEY`.
- **Configuration** — `wardline.yaml`, validated fail-loud against a JSON
  Schema (unknown or mistyped keys are hard errors).
- **Packaging** — MIT-licensed; optional extras `scanner` (config + CLI) and
  `weft` (HTTP integrations).

[Unreleased]: https://github.com/foundryside-dev/wardline/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/foundryside-dev/wardline/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/foundryside-dev/wardline/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/foundryside-dev/wardline/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/foundryside-dev/wardline/releases/tag/v0.1.0
