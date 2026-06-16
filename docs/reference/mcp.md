# MCP tool reference

The wardline MCP server (`wardline mcp`) speaks JSON-RPC 2.0 over stdio and
exposes the analyzer to a coding agent without scraping terminal output. This
page documents every tool the server registers — 18 in all — in the order it
publishes them.

The server is **stateless**: no session is carried between calls. The read-only
tools (`scan`, `explain_taint`, `assure`, `dossier`, `decorator_coverage`,
`attest`, `verify_attestation`, `scan_job_status`) are pure functions of disk +
config. The rest mutate project files on disk or reach a sibling over the
network; each is marked below. Launch with `--read-only` to drop the
write-capable tools and `--no-network` to drop the network-capable ones.

Every tool is rooted at the launch project path (`--root`, default cwd). Any
`path`/`config`/`cache_dir`/`output` argument is confined under that root —
the same containment guarantee as the CLI.

For the matching command-line surface, see the [CLI reference](cli.md).

## Tool capability matrix

| Tool | Reads | Writes disk | Network | One-line purpose |
| --- | :---: | :---: | :---: | --- |
| `scan` | yes | — | opt | whole-program taint scan + gate verdict |
| `scan_job_start` | yes | yes | opt | start a file-backed background scan job |
| `scan_job_status` | yes | — | — | poll a scan job's status |
| `scan_job_cancel` | yes | yes | — | cancel a non-terminal scan job |
| `explain_taint` | yes | — | opt | explain ONE finding's taint provenance |
| `dossier` | yes | — | opt | one-call entity trust dossier |
| `assure` | yes | — | — | trust-surface coverage posture |
| `decorator_coverage` | yes | — | opt | inventory of trust-decorated entities |
| `attest` | yes | — | — | build a signed evidence bundle |
| `verify_attestation` | yes | — | — | verify an attestation bundle |
| `file_finding` | yes | yes | yes | promote ONE finding to a Filigree issue |
| `scan_file_findings` | yes | yes | yes | scan → emit → promote, one call |
| `judge` | yes | yes | yes | opt-in LLM triage of active defects |
| `baseline` | yes | yes | — | snapshot findings as the baseline |
| `waiver_add` | yes | yes | — | add a time-boxed waiver for ONE finding |
| `fix` | yes | yes | — | apply mechanical autofixes |
| `doctor` | yes | opt | — | install + federation health check |
| `rekey` | yes | opt | opt | migrate verdicts across a fingerprint-scheme change |

"opt" = the capability is exercised only when the relevant URL/flag is
configured (or, for `doctor`/`rekey`, only under the explicit write opt-in).

---

## `scan`

**Purpose:** whole-program taint scan of the project. Returns structured
findings, the suppression summary, and the gate verdict.

**Key params:** `path` (subdir), `fail_on` (`CRITICAL`/`ERROR`/`WARN`/`INFO`),
`fail_on_unanalyzed`, `lang` (`python`/`rust`), `where` (conjunctive filter:
`rule_id`, `qualname`, `severity`, `suppression`, `kind`, `path_glob`, `sink`,
`tier`), `explain` (inline each active defect's provenance), `summary_only`,
`full`, `max_findings`, `offset`, `include_suppressed`, `new_since`,
`trust_suppressions`, `legis_artifact`. By default the `--fail-on` gate
evaluates the **unsuppressed** population, so a repo-controlled
baseline/waiver/judged annotates a finding but does not clear it; pass
`trust_suppressions: true` for the trusted-local behaviour.

**Returns:** `files_scanned`, a whole-project `summary`
(`total`/`active`/`baselined`/`waived`/`judged`/`informational`/`unanalyzed`), a
`gate` block (`tripped`, `fail_on`, `exit_class` 0/1, `verdict`
NOT_EVALUATED/PASSED/FAILED, `would_trip_at`, sub-gate attribution), `loomweave`
/ `filigree` raw write/emit blocks (null when unconfigured), and the stable
`agent_summary` block (schema `wardline-agent-summary-1`): active defects first,
suppressed debt, engine facts, integration status, a pagination `truncation`
descriptor, and gate-aware `next_actions`. The finding bodies are **bounded by
default** (≤25) so a first call cannot overflow context; `full: true` lifts the
cap and `offset` pages the rest.

Read-only. When a Filigree URL is configured the scan also POSTs findings to it,
fail-soft (an unreachable sibling or rejected payload is reported in the
`filigree` block, never fails the scan).

## `scan_job_start`

**Purpose:** start a file-backed background scan job and return its stable job
id plus initial status. The MCP-safe surface for long scans — prefer it over
synchronous `scan` when a project may take more than a short call.

**Key params:** `path`, `config`, `format` (`jsonl`/`sarif`/`agent-summary`),
`output`, `fail_on`, `fail_on_unanalyzed`, `cache_dir`, `local_only`,
`timeout_seconds` (default 1800; `0` disables), `lang`, `new_since`,
`trust_suppressions`.

**Returns:** the scan-job status object — `job_id`, `status`
(`queued`/`running`/`running_stale`/`completed`/`completed_with_enrichment_failure`/`failed`/`cancelled`),
`phase`, `progress`, `heartbeat`, `pid`, `artifacts`, `failure_kind`, `error`,
`request`. Writes job state under `.weft/wardline/jobs/<job_id>/`.

## `scan_job_status`

**Purpose:** read the current status JSON for a file-backed scan job. Reports a
stale heartbeat or dead-worker terminal failure rather than leaving an
apparently hung job ambiguous.

**Key params:** `job_id` (required, 32 hex chars), `path`.

**Returns:** the same scan-job status object as `scan_job_start`. Read-only.

## `scan_job_cancel`

**Purpose:** cancel a non-terminal scan job and return the persisted terminal
status.

**Key params:** `job_id` (required, 32 hex chars), `path`.

**Returns:** the scan-job status object with a terminal `cancelled` status.
Writes the terminal status to disk.

## `explain_taint`

**Purpose:** explain ONE finding's taint — the immediate tainted callee, the
originating boundary, and the trust tiers at the sink. Call right after `scan`
and before editing: a stale fingerprint returns an error.

**Key params:** `fingerprint`, `path`, `line`, `sink_qualname` (when a Loomweave
store is configured this serves the explanation from the store instead of
re-scanning), `chain` (also walk the full taint chain to the originating
boundary — needs a configured Loomweave store; without one the `chain` block is
an explicit `status: unavailable` marker naming the missing capability),
`max_hops`.

**Returns:** the explanation object — `fingerprint`, `rule_id`, `sink_qualname`,
`location`, `tier_in`, `tier_out`, `immediate_tainted_callee`,
`source_boundary_qualname`, resolution counts, and a `remediation` hint.
Read-only.

## `dossier`

**Purpose:** one-call entity dossier for a function `entity` (a qualname): its
trust posture (declared vs actual taint, gate verdict, active findings — always
computed fresh), plus Loomweave call-graph linkages and Filigree open work
joined on the entity's opaque SEI.

**Key params:** `entity` (required — the function qualname, e.g.
`pkg.mod.func`), `config`.

**Returns:** a token-bounded (~2k) envelope with an explicit truncation marker.
The `identity` section is freshness-stamped on **both** axes (identity
alive/orphaned/unavailable + content fresh/stale/unknown) and is never trimmed;
each cross-tool section degrades to an honest `available: false` + `reason`
shape when its source is absent. Read-only — lets an agent read the whole
context without opening the source.

## `assure`

**Purpose:** trust-surface COVERAGE posture — how many declared trust boundaries
the engine reached a definite verdict on vs. how many are honestly unknown, plus
waiver debt. Consult before deciding to trust a module. (This is a coverage
question, not a compliance claim — see the
[assurance posture guide](../guides/assurance-posture.md).)

**Key params:** `path`, `config` (both optional; default to the server root and
`weft.toml` at the scan root).

**Returns:** the posture object — `boundaries_total`, `proven`, `defect_total`,
`unknown[]` (the honesty gap, each with `qualname`/`tier`/`location`/`reason`),
`engine_limited`, `coverage_pct` (`null` when there is no trust surface — never a
false-green 100%), `unanalyzed_total`, `unanalyzed_rule_ids`, `waiver_debt[]`,
`baselined_total`, `judged_total`. Identical to the CLI `assure` JSON by
construction (both call `build_posture`). Read-only.

## `decorator_coverage`

**Purpose:** stable JSON inventory of every wardline trust-decorated entity.

**Key params:** `path`, `config`.

**Returns:** `summary` plus `rows`; each row carries `qualname`, `path`/`line`,
`decorators`, declared/actual tier, gate `verdict`, active/suppressed finding
fingerprints, optional Loomweave SEI/content `identity`, and optional Filigree
linked `work` status. Optional sources degrade explicitly (`available: false`).
Read-only; reaches Loomweave/Filigree only when their URLs resolve.

## `attest`

**Purpose:** build a SIGNED, reproducible evidence bundle (commit, ruleset hash,
trust-surface posture, boundaries) for the project, HMAC-signed with the
install-minted project key.

**Key params:** `path`, `config`, `allow_dirty`, `cache_dir`, `trust_packs`,
`trust_local_packs`, `strict_defaults`. The MCP boundary **inverts** the core
default and refuses a dirty working tree unless `allow_dirty: true`, so an agent
cannot silently attest uncommitted changes. Requires an attest key
(`wardline install` mints one, or set `WARDLINE_ATTEST_KEY`).

**Returns:** the attestation bundle (`payload` + `signature`). SEI-keyed when a
Loomweave store is configured. Identical to the CLI `attest` by construction.
Read-only. See the [attestation guide](../guides/attestation.md).

## `verify_attestation`

**Purpose:** verify an attestation bundle's signature offline (needs the project
key) and optionally re-derive it at the current tree.

**Key params:** `bundle` (required — must contain `payload` and `signature`),
`reproduce` (`true` re-derives at the current tree), `path`, `config`,
`cache_dir`, `trust_packs`, `trust_local_packs`, `strict_defaults`.

**Returns:** `{signature_valid, reproduced, mismatches, note}`. Read-only.

## `file_finding`

**Purpose:** promote ONE finding (by `fingerprint`) into a tracked Filigree
issue and return its `issue_id`. Idempotent (re-filing returns the same issue).

**Key params:** `fingerprint` (required), `priority`, `labels`,
`attach_loomweave_identity` (resolve the finding qualname through Loomweave and
attach a Filigree entity association), `config`. Emit findings to Filigree first
(scan with a configured Filigree URL) so the fingerprint is known.

**Returns:** `reachable`, `issue_id`, `created`, `not_found` (true when Filigree
is reachable but the fingerprint is unknown — 404), `fingerprint`,
`disabled_reason`, and an `identity_attach` block when
`attach_loomweave_identity` was requested. Fail-soft on reachability (a 5xx
outage or 401/403 refusal is soft). Reconciliation (close-on-fixed /
reopen-on-regress) happens automatically on later scans. Writes to Filigree
(network) and requires a configured Filigree URL.

## `scan_file_findings`

**Purpose:** the one-shot agent workflow — run a scan, list active defects first
with inline explanation summaries, optionally emit to Filigree, promote selected
fingerprints or all active defects, and attach Loomweave identity when
available.

**Key params:** `path`, `fail_on`, `config`, `cache_dir`, `fingerprints`,
`all_active`, `dry_run` (defaults to dry-run unless `fingerprints` or
`all_active` are supplied), `priority`, `labels`. 

**Returns:** `mode` (`dry_run`/`all_active`/`fingerprints`), `files_scanned`,
`summary`, `gate`, `filigree_emit`, `active_defects[]` (each with `explanation`,
`promotion`, and `identity_attach` outcomes), `selected_count`, and
`unknown_fingerprints`. Partial failures stay visible per-finding. Writes to
Filigree (network) under the non-dry-run paths.

## `judge`

**Purpose:** NETWORK — opt-in LLM triage of active defects via OpenRouter
(needs `WARDLINE_OPENROUTER_API_KEY`). Labels each TRUE/FALSE positive. Never
run automatically; never folded into `scan`.

**Key params:** `model` (OpenRouter slug), `max_findings` (bound token spend),
`write` (append above-floor false positives to `.weft/wardline/judged.yaml` —
**without it the call is a dry run**), `context_lines`, `config`.

**Returns:** `verdicts[]` (each with `fingerprint`, `rule_id`, `path`, `line`,
`label` — the TRUE/FALSE-positive classification — `confidence`, and
`rationale`), plus `wrote` and `held_back` counts. Writes `judged.yaml` only
under `write: true`. See the [LLM triage judge guide](../guides/judge.md).

## `baseline`

**Purpose:** snapshot current defects as the baseline so only NEW findings
surface. Prefer FIXING a finding over baselining it.

**Key params:** `reason` (optional), `overwrite` (default `false` refuses to
clobber and returns `already_exists: true`; `true` re-derives and overwrites),
`config`, `cache_dir`, `trust_packs`, `trust_local_packs`, `strict_defaults`.

**Returns:** `baselined_count`, `path` (absolute path of
`.weft/wardline/baseline.yaml`), `reason`, and `already_exists` (when overwrite
was not requested). Writes the baseline file. See the
[suppression guide](../guides/suppression.md).

## `waiver_add`

**Purpose:** waive ONE finding by fingerprint with a mandatory reason and
expiry. Prefer fixing; a waiver is an audited, time-boxed exception.

**Key params:** `fingerprint` (required), `reason` (required), `expires`
(required, `YYYY-MM-DD`).

**Returns:** the waiver-add result. Writes `.weft/wardline/waivers.yaml`. The
recorded debt resurfaces in `assure`'s `waiver_debt[]` (including after the
expiry lapses). See [suppression — waivers](../guides/suppression.md#waivers).

## `fix`

**Purpose:** scan and apply mechanical autofixes to findings (currently only
`PY-WL-111`, assert-at-boundary rewrites).

**Key params:** `path`, `config`, `dry_run` (preview without modifying),
`apply` (must be `true` to modify files — the default is a preview).

**Returns:** `fixed` (map of file path → list of fix descriptions), `applied`
(true when written to disk), and a human-readable `message`. Writes source files
only under `apply: true`.

## `doctor`

**Purpose:** health-check the wardline install and federation wiring (the same
checks as CLI `doctor --fix`: instruction blocks, skills, MCP registration,
config parseability, sibling URLs, Filigree emit auth) PLUS this server's
self-identification: package version, pid, start time, and a source-FRESHNESS
verdict.

**Key params:** `repair` (default `false`, a pure probe that writes nothing;
`true` repairs install artifacts and re-pins a rejected federation token),
`filigree_url` (probed for emit auth — only loopback origins are probed with a
token).

**Returns:** the machine-readable doctor envelope plus a `server` block. If
`server.fresh` is `false`, this long-lived server predates the on-disk wardline
code and its results are stale — restart the MCP server. Read-only by default;
writes only under `repair: true`.

## `rekey`

**Purpose:** re-key baseline/waiver/judged verdicts across a fingerprint-scheme
change (after the engine's fingerprint *formula* migrates, NOT after ordinary
refactors — fingerprints are line-insensitive).

**Key params:** `path`, `config`, `cache_dir`, `apply` (default `false`, a
read-only probe reporting carry/orphan/collision counts), `resume` (finish an
interrupted migration from the journal without re-scanning), `rollback` (restore
the pre-migration stores byte-identical from the snapshot). `apply`/`resume`/
`rollback` are mutually exclusive and write-gated.

**Returns:** the rekey result — carried, orphaned, and collision counts (probe),
or the migration outcome (apply/resume/rollback). A migration snapshots stores
first and writes a resumable journal. Writes only under
`apply`/`resume`/`rollback`; the Filigree re-emit leg runs only under `apply`.
The CLI twin is `wardline rekey` (see the [CLI reference](cli.md)).
