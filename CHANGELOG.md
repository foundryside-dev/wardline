# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-06-18

### Fixed
- **Release validation now tags a CI-green head.** The formatter drift in
  `baseline`, `explain`, and the MCP server is normalized, and the glossary
  citation anchors were refreshed so the full GitHub Actions matrix passes on
  the release head before publication.

## [1.0.2] - 2026-06-18

### Fixed
- **Scanner boundary classification is stricter around runtime reachability.**
  Rejections guarded by `typing.TYPE_CHECKING` no longer rescue production
  trust boundaries, assert-only helper validators are attributed to
  `PY-WL-111` rather than `PY-WL-102`, and L2 fixpoint recursion now records a
  function skip with an `UNKNOWN_RAW` return instead of retaining stale pass-1
  facts.
- **Sink findings now carry call-site spans.** Python sink rules populate
  `line_end`, `col_start`, and `col_end`, allowing `explain-taint` to resolve
  the correct sink when multiple calls share one physical line. Frozen golden
  fixtures were refreshed to record the new span metadata without changing
  fingerprint values.
- **Filigree and Rust file-finding paths preserve language identity.**
  `scan-file-findings` and `file-finding` accept `--lang`, MCP mirrors the
  same argument, Rust findings emit `language: rust`, and Loomweave identity
  attachment re-scans in the requested frontend.
- **Federation and migration status is more honest.** Chunked Filigree emission
  preserves counts from already-accepted chunks and records pending findings as
  partial failures on auth/server/protocol rejection; incomplete rekey journals
  now resume deferred legs instead of refusing a forward rerun.
- **Discovery, baseline, and scan-job hardening.** Nested `.gitignore` anchors
  are scoped to their own directory, `build`/`dist` package names under source
  roots are scanned, preview findings are excluded from baselines because they
  never gate, and background scan jobs import Wardline from a trusted package
  root instead of the untrusted scanned repository.
- **MCP input schemas match runtime parsing.** `fail_on` and `where` filters
  advertise case-insensitive string inputs instead of closed uppercase-only
  enums, matching the server-side normalization used by agents.

## [1.0.1] - 2026-06-17

### Added
- **Pollable file-backed scan jobs.** `wardline scan-job start|status|cancel`
  (CLI) and the matching `scan_job_start` / `scan_job_status` / `scan_job_cancel`
  MCP tools run a long scan in a daemon-free worker subprocess that persists status
  JSON under `.weft/wardline/jobs/`, so an agent can start a slow scan and poll its
  heartbeat/progress instead of blocking a single MCP call. Status reads refresh
  liveness (dead-worker / stale-heartbeat) so a hung job is never ambiguous. The MCP
  surface is now 18 tools.
- **Filigree-emit capping and local-only fencing.** `scan` gains
  `--filigree-max-findings-per-request` (env `WARDLINE_FILIGREE_MAX_FINDINGS_PER_REQUEST`,
  default 1000) to bound per-POST payloads, and `--local-only`/`--no-emit` to disable
  sibling emission even when URLs resolve from flags/env/install state. Emission stays
  ENRICH-ONLY — a sibling's absence never breaks the core scan or gate.
- **Top-level documentation refreshed against the 2026-05-29..2026-06-12
  release-candidate surface.** The README now describes the current product shape:
  Python remains the full taint-analysis frontend; Rust is a command-injection
  preview behind `wardline[rust]`; configuration/state live in `weft.toml` and
  `.weft/wardline/`; the agent/MCP surface includes doctor, rekey, assurance,
  attestation, dossier, and finding-lifecycle tools; and the docs index points to
  the Rust, Weft, and assurance guides.
- **MCP structured tool output on all 15 tools** — every tool now declares an
  `outputSchema` in `tools/list` and returns `structuredContent` alongside the
  (byte-identical) text block on `tools/call`, so MCP-spec clients consume and
  validate results without parsing JSON out of a text blob. Tool-execution
  errors stay `isError` results and never carry `structuredContent`. The
  server now negotiates the MCP protocol revision (`2025-06-18` /
  `2025-03-26` / `2024-11-05`; previously hard-pinned to `2024-11-05`).
  Per-tool declarations (schemas, annotations, capabilities) moved out of
  `_register_tools` to module level next to their handlers
  (`wardline-47ff226ebe`, MCP-primary B1; declaration colocation from
  `wardline-80e457bc41`).
- **Standard MCP tool `annotations` + `title`** — each tool's `tools/list`
  entry now carries a human `title` and the standard `ToolAnnotations` hints
  (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`)
  derived from the existing capability model, so standard MCP clients see the
  read-only/destructive signal wardline already computes. The homegrown
  `capabilities` key is still emitted for existing consumers; hints describe
  the integration-free baseline posture and `ToolPolicy` remains the
  enforcement authority (`wardline-e63204176b`, MCP-primary B2).

### Fixed
- **`doctor` now self-heals a stale `--filigree-url` / `--loomweave-url` pin that
  shadows live published-port discovery.** When a sibling rotates ports, a
  `.mcp.json` flag frozen to the old port (e.g. a legacy `.filigree/ephemeral.port`
  rung outliving the rotation) silently outranks discovery and breaks emit. Plain
  `wardline doctor` now reports this as an actionable error — "configured
  `--filigree-url` is unreachable, but Filigree is live at … (published port)" —
  instead of masking it as a soft "daemon not reachable". `wardline doctor --repair`
  DROPS such a stale loopback pin (both siblings) so runtime published-port discovery
  owns the always-current port; remote (non-loopback) pins, and loopback pins with no
  live daemon, are left untouched. Filigree server mode still repairs a loopback pin
  to the live project scope (unscoped writes fail-close there).
- **PY-WL-108 no longer treats a quoted COMMAND word as sanitized.** The
  `shlex.quote` concat/f-string guard accepted `shlex.quote(raw) + " --version"`
  (and the f-string form) as safe, but quoting sanitizes a shell ARGUMENT, not the
  identity of the executable — the attacker still chose the program. The guard now
  requires the leading command word to be a string constant, so a quoted-command +
  constant-arg shape fires while the blessed constant-command + quoted-arg
  remediation (`"echo " + shlex.quote(raw)`) stays clean.
- **Install, attestation, and local automation hardening from the 2026-06-12
  security pass.** `wardline install`/doctor paths now refuse unsafe writes through
  symlinked published-port files, refuse to mint attestation keys into tracked
  environments, preserve loopback-scope handling without needless churn, and keep
  operator-pinned sibling URLs intact. Attestation capture disables repository
  `fsmonitor` while reading git state and fails stale reproduction instead of
  accepting mismatched evidence. The repo `make clean` target refuses symlinked
  cleanup targets, and CI pins the `setup-uv` action.
- **Scan/reporting correctness hardening from the latest review pass.** Grammar
  fingerprints now include seed dependencies, return-taint resolution uses the
  statement snapshot for the return being analyzed, recursive lambda taint
  resolution is guarded, `assure` counts unanalyzed files in coverage, and
  `scan-file-findings` honors the gate exit status. Default agent-summary output
  is guarded from oversized or misleading responses.
- **Filigree/Loomweave federation safety fixes.** Filigree token resolution now
  prioritizes env aliases over dotenv fallback, mark-unseen lifecycle emission is
  disabled for unanalyzed scans, strict MCP SEI filters preserve their defaults,
  and signed scan artifacts include scan scope so a receiver can distinguish
  evidence from different roots.
- **Non-string `issue_id` from Filigree promote is normalized to `null`** —
  the promote response is type-narrowed at the wire boundary, so a skewed
  2xx body can no longer leak a non-string `issue_id` into `file_finding` /
  `scan_file_findings` payloads (violating their published output schemas).
- **Type-skewed Loomweave store blobs coerce to `null` in `explain_taint`** —
  `tier_in`/`tier_out`/callee qualnames read from a store blob now get the
  same isinstance guards as the adjacent fingerprint/path fields.
- **`scan_file_findings` federation honesty** — the emit block's
  `disabled_reason` now uses the shared 401/403-vs-5xx-vs-transport ladder
  instead of a flat `filigree unreachable`, and the no-Filigree-URL branch no
  longer misattributes the identity-attach skip to a promote that never ran.

- **MCP `scan` tool `fail_on_unanalyzed` argument** — the CLI's
  `--fail-on-unanalyzed` knob over the MCP surface (default off, same as the
  CLI), so gate semantics are fully controllable on the primary surface. The
  unanalyzed gate now lives **inside** `gate_decision` (one shared
  implementation; the CLI exit-code OR is gone), and the gate block/decision
  gained sub-gate attribution: `gate.fail_on_unanalyzed`,
  `gate.severity_tripped`, `gate.unanalyzed_tripped` — so an agent can tell a
  severity trip from an under-scan trip without parsing `reason`. An
  unanalyzed trip's `next_actions` point at fixing what blocked analysis
  (suppressions cannot clear it). Side fix: CLI `--fail-on-unanalyzed` alone
  no longer prints `gate: NOT_EVALUATED` while exiting 1 — the verdict is now
  an honest `FAILED`/`PASSED` whenever either sub-gate ran
  (`wardline-7fd0f3a82c`, MCP-primary A4).
- **MCP `rekey` tool** — fingerprint-scheme migration over MCP via the same
  `core.rekey` the CLI drives (no second migration path). Probe-by-default
  (read-only match/orphan/collision report, writes nothing); `apply` /
  `resume` / `rollback` are explicit, mutually exclusive, write-gated args;
  `apply` re-emits to a configured Filigree (network-gated) like the CLI's
  `--filigree-url` leg. Orphaned verdicts are listed verbatim with the shared
  orphan-cause explanation (`wardline-d8cc650ab9`, MCP-primary A3).
- **MCP `doctor` tool** — the CLI `doctor --fix` health envelope over MCP
  (install artifacts, MCP registration, config parseability, sibling URLs,
  Filigree emit-auth probe; read-only by default, `repair: true` is the
  explicit write-gated opt-in) **plus server self-identification**: package
  version, pid, project root, start time, and a source-freshness verdict
  (`server.fresh` / `server.freshness` check) that detects a long-lived MCP
  server serving code older than the on-disk tree — the 2026-06-06
  stale-server incident class (`wardline-4c5165e896`, MCP-primary A2).
- **MCP `scan` tool `lang` argument** (`python` | `rust`, default `python`) —
  the same frontend selector as CLI `--lang`, so the Rust command-injection
  slice (`RS-WL-108`/`RS-WL-112`) is reachable over the MCP surface; CLI and
  MCP Rust scans return identical findings (pinned by a parity test). An
  unknown value is rejected loudly naming the valid set
  (`wardline-2ee1bbda82`, MCP-primary A1).
- **`wardline explain-taint <fingerprint> [PATH]`** — the CLI twin of the MCP
  `explain_taint` tool (same core builder, identical JSON: provenance slice,
  remediation hint, optional `--chain` walk via a Loomweave store), so a
  CLI-only agent no longer dead-ends at step 2 of the scan → explain → fix →
  rescan loop (dogfood N-2).
- **`wardline findings` flat filter flags** `--rule-id` / `--severity` /
  `--sink` alongside the JSON `--where` blob; a filter given via both is
  rejected, never silently overridden (dogfood N-5/X-5).
- **Nested-scan-root guard** (dogfood N-3, `wardline-8669de3576`): scanning a
  SUBDIRECTORY of a weft project (an ancestor carries `weft.toml` or
  `.weft/wardline/`) now emits a `WLN-ENGINE-NESTED-SCAN-ROOT` FACT and a loud
  CLI warning — qualnames are minted relative to the scan root, the project's
  baseline/waivers are not loaded, and output lands in the subdirectory.
  `scan --help`/`dossier --help` document the scan-root/qualname coupling, and
  the dossier's entity-not-found error now names the scan-relative form that
  WOULD match plus the project root to rerun against (dogfood N-8).

### Changed
- **Closed-vocabulary query values match case-insensitively** (`severity`,
  `suppression`, `kind`) in `wardline findings --where` and the MCP
  `scan(where=)`; an out-of-domain value (e.g. filigree's `medium`) now errors
  loudly naming the allowed vocabulary instead of silently returning empty
  (dogfood N-5). `--fail-on` accepts any casing (canonical uppercase echoed).
- **Six new PREVIEW sink rules, `PY-WL-121`–`PY-WL-126`** (the 2026-06-10
  coverage-gap families; all tier-modulated, argument-slot precise, and
  construct-then-method / callable-alias aware):
  - `PY-WL-121` — untrusted data reaches an **XML parsing** sink (CWE-611);
    per-sink severity calibrated to default parser posture (`lxml.etree.*` at
    ERROR — entity-resolving by default; stdlib etree/minidom/sax at WARN —
    billion-laughs DoS only since CPython 3.7.1). Only the document slot fires.
  - `PY-WL-122` — untrusted data **compiled into a server-side template**
    (jinja2 `Template`/`Environment.from_string`, mako `Template`; SSTI,
    CWE-1336, ERROR). A tainted *render variable* is the safe idiom and never fires.
  - `PY-WL-123` — untrusted **attribute NAME** in `setattr`/`getattr`
    (dynamic attribute injection / mass assignment, CWE-915, WARN). Fixed-name
    writes of untrusted *values* stay silent.
  - `PY-WL-124` — untrusted path reaches a **native-library load**
    (`ctypes.CDLL`/`WinDLL`/`OleDLL`/`PyDLL`, `ctypes.cdll.LoadLibrary`;
    CWE-114, ERROR).
  - `PY-WL-125` — untrusted data as the **log MESSAGE format string**
    (`logging.*` module-level and Logger-method forms; CWE-117, INFO — visible
    to an explicit `--fail-on INFO` without tripping the default gate). The
    lazy `%`-args parameterization (`logging.info('u=%s', raw)`) never fires.
  - `PY-WL-126` — untrusted **recipient/message** in `smtplib`
    `SMTP`/`SMTP_SSL` `.sendmail` (mail/CRLF header injection, CWE-93, WARN).
- **Per-file isolation: `WLN-ENGINE-FILE-FAILED`.** An unexpected exception
  while analyzing one file no longer aborts the whole scan (losing every other
  file's findings) — and is not a silent skip either: the scan continues and the
  failed file is named by a gate-eligible `WLN-ENGINE-FILE-FAILED` ERROR defect,
  counted toward `ScanSummary.unanalyzed` (the Rust frontend's per-file contract,
  now on the Python path).
- **New config diagnostic `WLN-CONFIG-SANITISER-SINK-COLLISION`.** A configured
  sanitiser that collides with a built-in serialisation sink of the same name
  (e.g. declaring `pickle.loads` a sanitiser) can never take effect — the
  conservative sink classification wins — yet it previously also suppressed
  `WLN-CONFIG-UNUSED-SANITISER`, making the dead declaration a silent no-op. One
  FACT per colliding sanitiser now names the collision so the operator learns
  their suppression attempt was overridden, not honoured.
- **Sink-family expansions across the existing sink rules** (each fires on more
  real-world shapes; shared machinery in `_sink_helpers` — construct-then-method
  receiver resolution, callable-alias bindings, `ArgSpec` argument-position
  matching, and a fail-closed per-argument taint resolver):
  - `PY-WL-118` (SQLi) adds **`executescript`** (sqlite3 cursor AND connection —
    multi-statement, no parameter binding at all), a fail-closed **receiver
    heuristic** (DB-driver binding/name evidence fires, executor/pool evidence
    suppresses, unknown receivers fire), and the **constant `text()` clause
    exemption** for the canonical SQLAlchemy parameterized pattern.
  - `PY-WL-117` (SSRF) now resolves **constructed client/session instance
    methods** (`httpx.Client()`, `requests.Session()`, `aiohttp.ClientSession`,
    chained and `with`-bound forms) plus client `base_url=`, and is **URL-slot
    precise** — a tainted `timeout=`/`headers=` with a clean URL no longer fires.
  - `PY-WL-116` (path traversal) adds the **filesystem-mutation** APIs
    (`os.remove`/`rename`/`makedirs`/…, `shutil.rmtree`/`copy*`/`move`),
    **`pathlib.Path` methods** on a tainted-constructed `Path`, and **archive
    extraction** (`tarfile`/`zipfile` `extract`/`extractall` — Zip Slip), with a
    literal **`filter="data"` exemption** (tarfile's safe extraction filter).
  - `PY-WL-106` (deserialization) adds the **OO streaming-unpickle API**
    (`pickle.Unpickler(stream).load()`), **`shelve.open`** (path slot only), and
    a curated **third-party CWE-502 table** (`dill`, `jsonpickle.decode`,
    `joblib.load`, `torch.load`, `numpy.load`) with two literal-keyword gates:
    `numpy.load` fires only with a literal `allow_pickle=True`; `torch.load` is
    suppressed by a literal `weights_only=True`.
  - `PY-WL-115` (dynamic import) adds **`runpy.run_path`/`run_module`** and
    **`importlib.util.spec_from_file_location`** (import-and-execute class).
  - `PY-WL-108` (command execution) adds the **argv-style program-execution
    family** (`os.exec*`/`os.spawn*`/`os.posix_spawn*`/`pty.spawn`) and decides
    **`shlex.quote` GUARDED semantics**: a quote call as a fragment of a
    constant-shaped concatenation/f-string guards the always-shell sinks
    (`os.system("echo " + shlex.quote(raw))` is clean); a bare whole-command
    quote still fires, and the guard never applies to the argv sinks.
  - `PY-WL-107` (eval/exec/compile) adds the `builtins.` and `__builtins__.`
    spellings.
- **Rust support.** A new `--lang rust` frontend (behind the
  `wardline[rust]` extra: tree-sitter, no base dependency) sweeps `*.rs` and flags
  command-injection trust-boundary defects — `RS-WL-108` (program injection, ERROR:
  untrusted data chooses the executable of `std::process::Command`) and `RS-WL-112`
  (shell injection, WARN: untrusted data reaches a `sh -c` command line). Trust is
  declared with a `/// @trusted(level=ASSURED|GUARDED)` doc-comment marker; analysis
  is default-clean and reuses the Python engine's taint lattice, severity modulation,
  and finding/gate machinery. A `.rs` file that does not fully parse is surfaced as
  `WLN-ENGINE-PARSE-ERROR` and never half-analyzed. The Python default path is
  byte-identical (identity oracle green). Rule coverage is the command-injection
  slice and `weft.toml` severity overrides do not yet apply to Rust findings. See
  the [Rust support guide](docs/guides/rust-preview.md).
- **Rust finding identity is graduated — RS-WL-* findings are baseline-eligible.**
  The whole-tree SP2 pass reads the real crate name from `Cargo.toml`
  (`[package].name`, `-`→`_`, two-branch crate-root registration mirroring the
  Loomweave extractor, symlink-safe) and routes cross-file modules, so every
  qualname/fingerprint carries its real crate prefix. Identity is frozen by a new
  byte-exact golden corpus (`tests/golden/identity/rust/`, the SP2 completion
  gate); the pre-SP2 `provisional_identity` plumbing (never-baseline-match /
  never-baseline-capture) is removed — baseline, waivers, and judged verdicts now
  apply to Rust findings exactly as for Python. (Pre-graduation RS-WL-*
  fingerprints change once; they were never baseline-eligible, so no migration.)
  Finding identity is keyed to the crate name: adding/removing a `Cargo.toml` or
  renaming the crate in the manifest rekeys RS-WL-* fingerprints (re-baseline
  after such a change); non-conformance files — outside `src/`, or in a
  manifest-less tree — carry a reserved `#out` route segment
  (`{crate}.#out.{...}` / `crate.#out.{...}`) so their qualnames can never
  collide with a Loomweave-conformant locator.
- **Rust frontend is a full ADR-049 producer (Loomweave Phase 1b).** The entity
  surface grows from callables-only to the full ten-kind contract set —
  `enum`/`trait`/`type_alias`/`const`/`static`/`macro` leaf entities, the `impl`
  block as its own entity with `module → impl → method` containment, per-kind
  `@cfg` twin discrimination (stacked `#[cfg]` attributes fold sorted-`&`-joined;
  reserved chars escape `%`→`%25`, `:`→`%3A`; comments are token-stream-invisible)
  — plus the two anchored edge kinds (`imports`, `implements`; resolved-or-dropped,
  never `inferred`), under `plugin_id rust` / `ontology_version 0.4.0`. Conformance
  against the Loomweave-hosted corpus graduates from the subset-consumer rule to
  the full-set ordered byte-for-byte rule, with eight new oracle rows vendored
  upstream this sprint and a corpus **drift alarm** (upstream blob byte-pin in the
  default suite + an opt-in `loomweave_drift` live recheck against a sibling
  checkout). The path-typed-generic-arg reserved-colon case and const-generic-arg
  spacing remain a pending cross-tool ADR-049 decision (drafted amendment-request
  letter in `docs/integration/`); the frozen identity corpus deliberately avoids
  both shapes.
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
- **Loomweave resolve client: ADR-036 plugin hint + hinted fail-soft.**
  `LoomweaveClient.resolve()` accepts an optional batch-scoped `plugin` hint
  (contract: `docs/integration/2026-06-11-wardline-resolve-plugin-hint-proposal.md`)
  and threads it from every call site that knows the producer: attest boundary
  enrichment and decorator coverage send `python` (Python-surface by
  construction); the Filigree identity-attach path derives the producer from
  the finding's rule family (`RS-WL-*` → `rust`), so a Rust finding now mints a
  `rust:function:` locator and a `rust:function` entity association instead of
  the previously hardcoded `python:function`. A 4xx on a *hinted* request
  degrades fail-soft to `unresolved` (an older Loomweave under
  `deny_unknown_fields` rejects the new field; identity enrichment must
  degrade, not crash); an unhinted 4xx stays loud. User-supplied dossier
  entities stay unhinted — the contract never fabricates a hint.
- **Rust qualname dialect: ADR-049 Amendments 6–9 (Loomweave lockstep, one
  batched re-vendor covering 4–9).** Closes the four Sprint-4 gold-blocker
  collision families at the dialect level, mirroring the authoritative
  Loomweave producer byte-for-byte (49-entity corpus + the new `module_mounts`
  section, blob `d81fb975…`):
  - **Amendments 6+7 — the residual-collision ladder** (`@cfg` → stage S
    self-type written path → stage T trait written path → method-`@cfg`):
    same-key impl twins split on their *written* self-type path
    (`impl T for a::X` / `b::X` → `a%3A%3AX.impl[T]` / `b%3A%3AX.impl[T]`) and
    then on their written trait path (`Compat<$0>.impl[a%3A%3AAsyncRead]`).
    Twin-gated end to end: only already-colliding ids change; a lone impl and
    every un-fired group render byte-identically to before (the frozen RS-WL
    identity corpus is unchanged).
  - **Amendment 8 — `#[path]` mount overlay** (`wardline.rust.mounts`): literal
    `#[path = "…"] mod name;` declarations now route mounted files/subtrees to
    their *logical* module path (rustc's relative-path rule; chains, cfg-twin
    `@cfg` composition, R5 first-wins determinism; macro-wrapped and
    `cfg_attr`-delivered mounts stay invisible by dialect rule). Mounted files
    re-key from their filesystem route — `rust_module_route` itself is
    unchanged and remains the no-mount default.
  - **Amendment 9 — `const _` skip-emission:** an unnamed `const _` is no
    longer an entity (unconditional — nothing can ever name it; findings inside
    one attribute to the enclosing module).
- **BREAKING (gate): parse failures are now gate-eligible.**
  `WLN-ENGINE-PARSE-ERROR` (a discovered file that could not be read/parsed) is
  promoted from a NONE FACT to an **ERROR DEFECT**: its sinks were never
  analyzed, so a default `--fail-on ERROR` reading green over it was a fail-open
  (e.g. a latin-1 coding cookie CPython runs but the UTF-8 reader rejects hid
  live code from the scan). Baseline/waiver still annotate it but cannot clear
  the secure gate; `--trust-suppressions` can (an explicit operator trust
  decision). A tree with unparseable files now trips `--fail-on ERROR` until the
  files are fixed or the suppression is explicitly trusted. (Python frontend;
  the Rust frontend's parse-error surfacing is unchanged — still a FACT.)
- **BREAKING (severity): `PY-WL-108` and `PY-WL-112` base severity WARN → ERROR.**
  Tainted command/program execution (always-shell APIs, argv exec/spawn,
  literal-`shell=True` subprocess) is the same blast-radius exploit class as
  SQLi (CWE-78 ≅ CWE-89), so both calibrate with `PY-WL-118`'s ERROR. Findings
  from these rules now trip a default `--fail-on ERROR` gate in fully-trusted
  functions; override per project via `rules.severity` if needed.
- **BREAKING (fingerprints): the boundary-integrity family now partitions
  four ways — bare `return p` boundaries re-key from `PY-WL-102` to `PY-WL-119`.**
  At most one of {102, 111, 113, 119} fires per boundary: 119 wins the bare
  degenerate shape (`return <param>`), 102 keeps every other no-rejection shape,
  111 keeps assert-only (including an assert inside a substituting `try` —
  documented precedence over 113), 113 fires only when a real rejection exists
  and a fail-open handler can swallow it. Because `rule_id` is part of the
  fingerprint, **baselined/waived/judged `PY-WL-102` entries for bare `return p`
  boundaries go stale** (the finding now carries `PY-WL-119`) — re-baseline /
  re-waive once after upgrade. The same boundary is no longer double-counted at
  ERROR in the gate population.
- **`PY-WL-102`/`PY-WL-111` recognise more genuine rejection shapes (fewer
  FPs on real validators):** a ONE-HOP same-module call to a raising helper
  (a factored-out validator, raising staticmethod, or delegation to another
  raising boundary — the helper must have a production-surviving rejection;
  assert-only helpers never count), curated **raising conversions**
  (`return int(p)` / `float`/`complex`/`Decimal`/`Fraction`/`UUID` over a
  non-constant argument, and non-constant subscript lookups `Color[p]` /
  `ALLOWED[p]` — validate-by-construction), and **conditional-expression falsy
  returns** (`return m.group(0) if m else None`).
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
- **Raw-receiver taint laundering via name-collision shadowing (wardline-f6a29ce23a).**
  In the L2 per-variable resolver (`_resolve_call`), the early `taint_map`
  short-circuits returned a MODULE-LEVEL symbol's clean return-taint without checking
  the call's receiver, so a local/parameter that **shadowed** a module/import name
  (`import ast; ast = read_raw(p); ast.literal_eval(p)`) laundered raw data through the
  shadowed-module's clean entry — an end-to-end soundness false negative (a tainted
  value reached an `os.system`/`PY-WL-108` sink unflagged). Each early short-circuit
  (the imported-fqn path, the direct dotted lookup, the bare-name call path, the
  context-encoder path, and the attribute-READ path in `_resolve_expr`) now defers
  when the call/read's chain-ROOT name is a tracked local/parameter currently in the
  RAW_ZONE — covering chained receivers (`a.b.method()`) and bare-name shadows
  (`foo()`) as well as the one-level case.
  `self`/`cls` roots are excluded so analyzer-injected cross-method summaries are
  preserved, and the var-types (`Type.method`) path is intentionally left ungated (a
  legitimately typed object carries a raw-ish value taint from an unmodeled
  constructor — gating it would false-positive `h = Helper(); h.get_assured()`).
  Genuine module sanitisers are untouched (the root is never tracked in `var_taints`);
  the Python default path stays identity-oracle byte-identical, with two discriminating
  corpus fixtures added.
- **Finding fingerprint is now invariant to taint-resolution drift (weft-4a9d0f863c).**
  The `fingerprint` — the cross-tool JOIN KEY into the baseline/waiver/judged stores
  and the Filigree tracker — folded engine-RESOLUTION outputs (resolved `TaintState`
  tiers and `via_callee`) into its `taint_path` component, so it moved across builds
  for byte-identical source as the rule suite was extended (a baselined finding
  escaped its baseline, tripped the gate, and minted a federation-wide duplicate).
  Every rule's `taint_path` now carries only a SOURCE-derived discriminator: rules
  emitting ≤1 finding per `(rule_id, path, line_start, qualname)` pass `taint_path=None`;
  call-site-anchored rules (PY-WL-105/106/108/115/116/117/118/120) discriminate by the
  sink/callee spelling plus the call's full lexical span (`col_offset:end_col_offset`,
  collision-free even for chained calls). PY-WL-114 is unchanged (its `name:token`
  path is already source-derived and load-bearing). The invariant is documented at
  `compute_finding_fingerprint` and enforced by a new identity-corpus collision gate
  (distinct-fingerprint-count == active-finding-count, exercised by a `sinks` fixture
  with same-line and chained sinks) plus a PY-WL-101 resolved-tier-swap invariance test.
  - **MIGRATION (one-time).** This is an intentional, reviewed fingerprint rekey
    (identity corpus `corpus_version` 1→2). It stabilises a key that was *already*
    drifting on every build, so it converts ongoing unbounded orphaning into a single
    bounded event. All four fingerprint-keyed stores must be refreshed once after
    upgrade: regenerate `baseline.yaml` (`wardline baseline update`) and re-run the
    LLM judge to repopulate `judged.yaml`; previously-waived findings will resurface
    (loudly — re-waive intentionally); and Filigree finding↔issue associations keyed
    on the old fingerprint orphan until re-associated. Perform across the federation in
    lockstep. After this, the key is stable across engine-precision changes.
- **Three PY-WL-118 false-negatives from the `scrub-2026-06-08` regression set
  (`scrub-regression`).** Surfaced by adversarial verification of the six P1 scrub
  fixes (`24b0a3e`); empirically reproduced and regression-tested.
  - **Tainted SQL via `**kwargs` dict-unpacking now fires** (`wardline-8c31463f9f`). The
    engine collapses a `**` unpack to a single taint under the `None` arg-key, which the
    narrowed `_SQL_STRING_KEYS` gate ignored. `_sql_string_taint` now treats the `None` key
    as the SQL-string slot when a `**` unpack could supply the `operation` — by inspecting the
    literal-dict keys (`**{"operation": …}` fires, `**{"parameters": …}` stays silent,
    preserving `wardline-e0e44852e7`) and failing closed on any opaque/non-static `**`. The
    snapshot's per-`**`-key taint collapse means a literal dict mixing a clean operation with a
    tainted parameter over-approximates (fires) — a deliberate fail-closed choice, never an FN.
  - **Nested defs now honor their OWN trust decorator** (`wardline-bb8396f96e`). The
    unconditional `.<locals>.` strip made a nested `@trusted` def inherit its parent's
    (suppressed) tier. The new shared `_sink_helpers.enclosing_declared_tier` walks outward
    through enclosing scopes and uses the nearest scope carrying an explicit declaration
    (`declared_qualnames`), so a nested def's own decorator governs while a genuinely
    undeclared nested def still inherits its enclosing trusted tier (`wardline-9b88ec5419`).
    Applied family-wide (PY-WL-106/107/108/115/116/117 share the base).
  - **PY-WL-118 now inspects sink calls inside lambda bodies** (`wardline-b8a94cf0ac`). The
    rule walked `own_nodes`, which treats `ast.Lambda` as a scope boundary, so a tainted
    `execute()` in a lambda escaped — while its sink-family siblings descend into lambdas. It
    now uses the shared lambda-descending `sink_method_calls`, attributing the finding to the
    enclosing entity as the siblings do.
- **Six P1 correctness defects from the pre-1.0 rule scrub (`scrub-2026-06-08`).** All
  empirically reproduced and regression-tested; a new shared fail-closed argument resolver
  (`_sink_helpers.resolved_arg_taints`) gives the sink rules per-argument taint with a single
  fail-closed implementation (`worst_arg_taint` is now a thin selector over it).
  - **PY-WL-118 no longer false-fires on parameterized queries** (`wardline-e0e44852e7`). SQLi
    is a property of the SQL-string argument only; untrusted data passed as a *bound parameter*
    (the OWASP-canonical mitigation) cannot alter query structure, so the rule now gates on the
    operation-string position and ignores the parameter position. A tainted SQL string still
    fires (fail-closed on a splatted operation).
  - **PY-WL-118 nested-def evasion closed** (`wardline-9b88ec5419`). The rule now applies the
    family-wide `.<locals>.` tier-strip, so a tainted `execute()` wrapped in a nested function
    inherits its enclosing trusted tier and fires — matching siblings 108/115/116/117.
  - **PY-WL-105 co-argument masking closed** (`wardline-836dcef5b4`). The rule fires when *any*
    resolved argument is provably untrusted, not the single `worst_arg_taint`: the
    `_PROVABLY_UNTRUSTED` predicate is not upward-closed (a hole at `UNKNOWN_RAW`), so a max-rank
    collapse let an `UNKNOWN_RAW` co-argument mask a provably-untrusted one.
  - **PY-WL-114 now gates on the resolved builtin FQN** (`wardline-0267c31cd8`), not the trailing
    identifier — fixing both the alias-blind false negative (`@t(level='ASURED')` where `t`
    aliases the builtin) and the foreign-same-name false positive (a non-wardline decorator
    merely spelled `trusted`). Mirrors PY-WL-110's resolver + builtin-prefix check.
  - **Engine fail-open: stale `var_types` no longer launders a raw receiver** (`wardline-5ba7ce0f98`).
    A name re-bound to an imprecisely-typed RHS (subscript / BinOp / f-string / …) now invalidates
    its recorded type, so a method call on a now-raw value can no longer resolve a clean `@trusted`
    summary past the RAW_ZONE receiver guard. Conservative direction (more FPs at worst, never an FN).
  - **Engine fail-open: summary cache key now binds the effective-scan-policy hash**
    (`wardline-9d6a81b9e7`). `compute_cache_key` folds in `attest.ruleset_hash(config)` — the same
    single policy identity `attest` signs — so seed-shaping config (`untrusted_sources`,
    `sanitisers`, `provenance_clash`) can no longer let a warm/persisted cache serve a stale-CLEAN
    summary that suppresses a real defect. Warm runs are byte-identical to cold runs across policy.
- **Six P2 correctness defects from the pre-1.0 rule scrub (`scrub-2026-06-08`).** All
  empirically reproduced with a control (the safe near-identical shape that must stay silent),
  regression-tested, and hardened across three adversarial review panels. Five make the engine
  fire MORE (4 false-negatives + 1 soundness + 1 coverage); one removes a false positive.
  - **PY-WL-109 with/`while True` fall-through** (`wardline-786a4ec647`). `_can_fall_through` now
    models `with`/`async with` (terminal iff body) and a constant `while True` with no break, so
    the None-leak rule no longer false-fires on returns wrapped in those constructs.
  - **PY-WL-113 assign-then-fall-through substitution** (`wardline-c314a7140b`). The fail-open
    rule now also matches an in-handler ASSIGNMENT of a value to a name the function returns by
    fall-through (not just an in-handler `return`). Gated on the handler having no *unconditional*
    top-level return (a conditional nested return does not stop fall-through) and excluding
    idempotent self-assignment, so a fail-CLOSED `result = p; return None` stays silent.
  - **PY-WL-110 nested-path false positive closed** (`wardline-09c09f14df`). Marker recognition
    now keys on the engine's exact-export predicate (`_is_builtin_decorator_fqn`), so a nested
    attribute path the engine never seeds is no longer counted as a contradictory-marker clash.
  - **Engine soundness: loop fixpoint iterates to convergence** (`wardline-e04db6e656`). The
    `range(8)` cap in `_handle_for`/`_handle_while` was lattice *height*, not propagation *depth*;
    a loop-carried rebind chain longer than 8 links left the head under-tainted (a fail-open). The
    walk now iterates to a genuine fixpoint with a `num_vars × lattice_height` backstop.
  - **Engine: branch-conditional dispatch resolved flow-sensitively** (`wardline-499c22bbdd`). A
    receiver assigned a project class in more than one branch arm is resolved to the SET of
    candidate callees via a flow-sensitive reaching-definitions pass (branch arms unioned at
    joins, straight-line reassignment replaces, loop body to a fixpoint, walrus replaces), so
    PY-WL-105 and PY-WL-120 fire on any anchored trusted-sink candidate regardless of AST order
    and emit one finding per call site. Replaces the AST-order-dependent flat last-write-wins.
  - **PY-WL-120 DB-cursor fetches now fire** (`wardline-e7c7cda31a`). `cursor.fetch{one,all,many}()`
    is seeded `EXTERNAL_RAW` (a curated method set), closing a dead matcher branch so DB reads
    trip the stored-taint rule exactly as `open()`/`read_text()` already do.
  - **Engine: container mutators contaminate the receiver** (`wardline-67c7498931`).
    `.append`/`.add`/`.extend`/`.update`/`.insert` with a tainted argument now write that taint
    back onto the receiver variable (matching the container-literal `box = [raw]`); `list.insert`'s
    index argument is excluded (position metadata, not stored content).
- **`agent_summary` display arrays now fully partition `total_findings` (W3 residual).** The
  pagination union was `active_defects + suppressed_findings + engine_facts`, which excluded
  non-defect findings that are not engine facts (metrics, classifications, suggestions, and
  non-engine facts). Those findings were counted in `summary.total_findings` / `informational`
  but occupied no display slot — an agent paginating `offset → next_offset` believed it had
  covered all findings while never seeing metrics or classifications. A new `informational`
  display array (parallel to `summary.informational`) captures this population. The union is
  now `active_defects + suppressed_findings + engine_facts + informational`, and
  `len(union) == truncation.findings_total == summary.total_findings` holds within the
  `display_findings` contract. The `engine_facts` display array is unchanged (engine facts
  only; non-engine facts go to `informational`). Closes the W3 pagination residual left open
  by `weft-f506e5f845`, which added the `informational` summary *count* but not the
  display-array complement.
- **Lambda taint: a sink-lambda bound in a non-last branch arm is no longer lost.**
  The Level-2 taint engine tracked lambda bindings one-per-name, so at a branch merge
  only the last arm's binding survived; a name rebound to a sink-lambda in a non-last
  `if`/`try`/`match` arm was overwritten by a later arm's benign lambda, and a tainted
  call after the branch resolved the wrong body — a silent false negative. Lambda
  bindings are now a per-name candidate set: a call resolves against every body the
  name may hold across arms (sink-agnostic; surfaces e.g. PY-WL-106/107/108 on the
  newly-covered shapes). May raise new findings on code matching this pattern under
  `--fail-on`. (`wardline-383f83fafe`; orthogonal loop zero-trip FN tracked separately)
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

[1.0.3]: https://github.com/foundryside-dev/wardline/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/foundryside-dev/wardline/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/foundryside-dev/wardline/compare/v0.3.0...v1.0.1
[0.3.0]: https://github.com/foundryside-dev/wardline/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/foundryside-dev/wardline/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/foundryside-dev/wardline/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/foundryside-dev/wardline/releases/tag/v0.1.0
