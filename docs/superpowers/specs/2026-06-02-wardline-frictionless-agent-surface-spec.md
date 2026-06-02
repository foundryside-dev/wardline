# Wardline — the frictionless agent surface (delivery spec)

**Date:** 2026-06-02
**Status:** Delivery spec — committed body of work. Derived from the
2026-06-02 senior-agent-operator dogfood gap analysis (the "serious user" pass).
Companion to the first-class body-of-work spec
(`2026-06-02-wardline-first-class-body-of-work-design.md`) and the SEI standard
(`2026-06-01-loom-stable-entity-identity-conformance.md`). Each workstream below
gets its own focused design→plan when reached; this spec fixes *what* we deliver
and the acceptance bar, not the *how* of each unit.
**Altitude:** Surface-completion program. It does not redesign the engine — the
recurring finding is that the engine and `core/`/CLI already compute what the
agent needs; the **MCP surface under-exposes it** and a few flows make the agent
do work the tool should do.

> **Governing thesis — remove all friction; leave only tools that work first
> time, every time.** A senior agent operates Wardline almost entirely over MCP,
> in a tight inner loop, inside a full Loom federation. Every tool it reaches for
> must: **(1)** complete its job in **one round-trip** (no N+1, no
> "scan-then-N-explains"); **(2)** return **structured data the agent acts on
> without re-parsing prose**; **(3)** require **zero hand-authored config to
> work** — discovery/activation, never configuration; **(4)** behave **identically
> over CLI and MCP** (the "identical by construction" tenet is an acceptance
> criterion here, not an aspiration); and **(5)** preserve **fail-closed
> honesty** — an honest `UNKNOWN_*` + `WLN-ENGINE-*` FACT *is* "working"; a silent
> false-green is the one failure mode that disqualifies a tool.

> **Thesis filter (unchanged).** Power via opt-in **activation**, never opt-in
> **configuration**. Zero-dependency base stays zero-dependency. Anything below
> that would make a tool "work only after the user hand-edits YAML" is a defect
> against this spec, not a feature.

---

## 1. Goal & the definition of "frictionless"

The senior-agent dogfood produced one through-line: **the gap is not engine
power, it's surface ergonomics.** Three of the five top gaps are MCP plumbing of
capabilities `core/`/the CLI already have. So "frictionless" has a precise,
testable meaning here:

A surface is frictionless when, for every move a senior agent makes in the inner
loop (scan → query → explain → fix → file → re-scan → prove), there is **one tool
call** that does it, returns **machine-actionable** output, works **the same on
MCP as on CLI**, and needs **no prior hand-config**. The program is done when no
move in that loop requires the agent to (a) shell out to the CLI for something
MCP can't do, (b) pull the whole corpus to read a slice, (c) issue N calls where
one should suffice, or (d) hand-edit `wardline.yaml` to make a federated tool
function.

**Program exit criterion (§8):** a single MCP-only dogfood session drives the
full loop on a real repo inside the federation — scan, filtered query, batched
explain, delta gate, file-and-link a finding to Filigree, prove coverage — with
**no CLI fallback and no manual config edit**, and warm/cold byte-identity holds.

---

## 2. Method & provenance

Source: the 2026-06-02 senior-user gap analysis (Opus persona, read-grounded
against `src/wardline/mcp/server.py`, `cli/{scan,judge,dossier,mcp}.py`,
`core/{explain,dossier,finding,filigree_emit,run}.py`, `loom_dossier.py`,
`install/detect.py`, and live `filigree list-issues`). Every "exists / weird"
claim below cites the file the analysis verified. Items already tracked as
Filigree issues are folded in **by reference with a shape critique** — this spec
does not re-file them, it constrains their delivered shape to the frictionless
bar.

---

## 3. The friction inventory (tiered)

Reality labels: **MISSING** · **WEIRD** (exists, wrong shape) · **PARTIAL** ·
**PLANNED** (tracked issue; shape critiqued) · **PLANNED-INERT** (sibling-gated).

| # | Friction removed | Surface | Tier | Reality | Workstream |
|---|------------------|---------|------|---------|------------|
| 1 | Can't emit findings → Filigree over MCP (CLI can) | MCP | **must** | WEIRD (`scan.py:82` yes / `server.py:315` no) | A |
| 2 | No "file & link & reconcile" one finding → issue | MCP+CLI | **must** | MISSING (`finding.py` drops `issue_id`) | A |
| 3 | `scan` returns whole corpus; no server-side slice | MCP | **must** | MISSING (`server.py:307`) | B |
| 4 | No delta gate (scan only what changed since ref) | CLI+MCP | **must** | PLANNED `wardline-cacf25bc9a` | C |
| 5 | Loop mandates N+1 explain (one per finding) | MCP | strong | WEIRD (`server.py:_LOOP_PROMPT`) | B |
| 6 | No coverage/assurance posture read | MCP+CLI | strong | PLANNED `wardline-5cdc7ba7b7` | D |
| 7 | Can't address dossier/query by Clarion **SEI** | MCP | strong | PARTIAL (`server.py:357` qualname-only) | E |
| 8 | No waiver/baseline debt rollup | MCP+CLI | strong | MISSING (fold into D) | D |
| 9 | No signed attestation of a trust state | CLI+MCP | nice | PLANNED `wardline-0635463846` | D |
| 10 | Can't activate a team's trust model w/o config | CLI | nice | PLANNED `wardline-6e4ac6c148` | F |
| 11 | Two baseline tools for one concept | MCP | nice | WEIRD (`server.py:238-251`) | G |
| 12 | No per-finding "new/persisted/reintroduced" lineage | MCP | nice | PARTIAL (falls out of C) | C |
| 13 | Federation URL degrades to hand-edited YAML | install | strong | WEIRD (`install/detect.py:30-47`) | F |
| 14 | Clarion dead-code boundary roots | (Clarion) | nice | PLANNED-INERT `wardline-1fb610b4fc` | — |

---

## 4. Workstreams (what we deliver)

Convention (matches the body-of-work spec): each unit lists **deliverable → DoD →
gate**. The DoD always includes the five frictionless criteria (one round-trip /
structured / no-config / CLI=MCP / fail-closed) where they apply.

### Workstream A — Federation writes reach MCP (close the asymmetry) · MUST

The defining federated move — turning a finding into tracked work — is CLI-only
today. This is a parity *bug* against "identical by construction."

- **A1 — Filigree emit over MCP** *(WEIRD → fix)*
  - **Deliverable:** the MCP `scan` handler emits to `self.filigree_url` when set
    (the CLI already does — `scan.py:74-83`), and returns a `filigree:{created,
    updated, failed}` block mirroring the existing `clarion` block
    (`server.py:96-101`). No new tool; close the gap at `server.py:315`.
  - **DoD:** an MCP scan with a configured Filigree URL produces byte-identical
    emission to the CLI path; return payload carries the structured counts.
  - **Gate:** CLI/MCP parity test (same findings → same Filigree writes).

- **A2 — `file_finding`: one finding → a linked, reconciling issue** *(MISSING)*
  - **Deliverable:** a new tool/command keyed on the stable fingerprint:
    `file_finding(fingerprint, priority?, assignee?) -> {issue_id, status,
    created|already_linked, fingerprint}`. Re-scan **reconciles** (close-on-fixed,
    reopen-on-regress) via the fingerprint. The bulk emitter
    (`filigree_emit.py:117-153`) stays for whole-gate population; this is the
    surgical single-finding move the bulk firehose can't express.
  - **Design note:** `Finding` deliberately omits `issue_id` (`finding.py:5-7`) —
    finding *identity* stays Wardline's, issue *lifecycle* stays Filigree's. The
    link lives in the reconciliation layer (fingerprint ↔ issue), **not** by
    mutating `Finding`. Preserve that boundary.
  - **DoD:** file once → get an id; re-scan with the finding fixed → issue
    auto-closes; finding regresses → issue reopens; all over both CLI and MCP.
  - **Gate:** reconciliation round-trip test against a live Filigree (the
    `clarion_e2e`-style opt-in marker pattern).

### Workstream B — Inner-loop reads stop wasting round-trips · MUST/strong

- **B1 — Server-side finding query** *(MISSING)*
  - **Deliverable:** filter params on `scan` (or sibling `find_findings`):
    `where:{rule_id?, qualname?, sink_qualname?, tier_in?, severity?, path_glob?,
    suppression?}` returning the same finding dicts, filtered **server-side**. All
    fields already exist on `Finding` (`finding.py:84-100`) and
    `properties.{actual,declared}_return`.
  - **Frictionless rationale:** agents think in slices; today the only knobs are
    `path`/`fail_on`/`config` (`server.py:307-314`), forcing a whole-corpus pull +
    client-side filter every loop. The "findings are never a resource" rule
    (correct, for staleness) must **not** also mean "no filtered read."
  - **DoD:** a filtered query returns only matching findings; no whole-corpus
    transfer required to read a slice.
  - **Gate:** parity — `where`-filtered result ≡ full scan filtered client-side.

- **B2 — Inline / batch explanation (kill the N+1)** *(WEIRD)*
  - **Deliverable:** `scan(..., explain:true)` inlines the cheap provenance slice
    (`immediate_tainted_callee`, `tier_in`/`tier_out`, `source_boundary_qualname`)
    onto each active finding; **or** `explain_taint(fingerprints:[...])` batch. The
    provenance is already computed during the scan and discarded
    (`explain.py:84` reads `context.function_return_callee`).
  - **Frictionless rationale:** the shipped loop prompt (`server.py:_LOOP_PROMPT`)
    literally instructs one `explain_taint` per finding — N+1 is the *documented*
    happy path. One scan should answer "what and why" together.
  - **DoD:** a single `scan(explain:true)` returns findings *with* provenance; the
    loop prompt is rewritten to the one-call shape. Deep N-hop chains stay on the
    existing `explain_chain` for the cases that need them.
  - **Gate:** inlined provenance ≡ per-finding `explain_taint` output.

- **B3 — Per-finding lineage** *(PARTIAL — companion to C)*
  - **Deliverable:** `lineage:{first_seen_ref, status:new|persisted|reintroduced}`
    on findings, falling out of the delta machinery (Workstream C).
  - **DoD/Gate:** delivered and tested as part of C.

### Workstream C — Delta gate, **MCP-first** · MUST · PLANNED `wardline-cacf25bc9a`

- **Deliverable:** `scan(base_ref:...)` (MCP) / `scan --new-since <ref>` (CLI),
  returning a structured `delta:{new, fixed, unchanged}` block — **not** just a CLI
  exit code.
- **Shape critique (binding):** the tracked issue is framed CLI-first; for an
  MCP-native agent the `base_ref` arg and the `delta` block are the primary
  surface, the exit code secondary. Honor it on **both** surfaces identically.
- **Correctness constraint (affirmed):** the affected-set must follow the **call
  graph**, not just touched files — a changed callee shifts a caller's resolved
  taint. Warm/cold `SummaryCache` byte-identity must hold.
- **DoD:** delta scan reports new-vs-fixed correctly across a call-graph-spanning
  change; structured block over MCP.
- **Gate:** call-graph delta correctness fixture + warm/cold byte-identity.

### Workstream D — Posture & evidence (structured, MCP-shaped) · strong/nice

- **D1 — `assure` coverage posture + waiver-debt rollup** *(PLANNED
  `wardline-5cdc7ba7b7`; folds in #8)*
  - **Deliverable:** a **structured MCP read** first, human report second: `{boundaries_total,
    proven, unknown:[{qualname, tier, location}], coverage_pct,
    unanalyzed_rule_ids, waiver_debt:[{fingerprint, expires, days_left, reason}],
    baselined_total, judged_total}`.
  - **Shape critique (binding):** the tracked issue reads report/CLI-first; invert
    it — the agent consults this *before deciding to trust a module*, so structured
    MCP output is primary. Most of it aggregates logic `dossier._build_trust`
    already computes per-entity (`dossier.py:480`, `:502` for suppressed-debt).
  - **DoD:** one call returns the posture object; coverage number is derived from
    real `UNKNOWN_*` tiers + `UNANALYZED_RULE_IDS`, not a heuristic.
  - **Gate:** posture object matches a hand-computed fixture; waiver-debt surfaces
    expiry.

- **D2 — `attest`: signed evidence, install-minted key** *(PLANNED
  `wardline-0635463846`)*
  - **Deliverable:** a signed, reproducible bundle ("at commit X, ruleset Y, these
    boundaries held, coverage N%"), SEI-keyed.
  - **Shape critique (binding — activation invariant):** the signing key must be
    **minted and recorded by `wardline install`** into `.wardline/` (as install
    already records Clarion bindings — `install/detect.py`). If `attest` requires
    the user to hand-provision/rotate a key, it is opt-in *configuration* and
    **fails this spec**. HMAC primitive exists (`clarion/_hmac.py`).
  - **Sequencing:** after D1 (it attests the coverage number) and after SEI wiring
    (E) so the bundle is SEI-keyed.
  - **DoD:** `install` mints the key; `attest` + verify run with **zero further
    config**; bundle reproduces.
  - **Gate:** attest→verify round-trip with no manual key step.

### Workstream E — SEI-native addressing · strong · PARTIAL

- **Deliverable:** `dossier` (and the B1 finding-query) accept `entity` (qualname)
  **or** `sei:"clarion:eid:…"` as the input key. Plumbing exists
  (`SeiResolver.resolve_sei`, `loom_dossier.py:43`); the tool just doesn't accept
  the SEI as the key (`server.py:357` is qualname-only).
- **Frictionless rationale:** the whole SEI value proposition is rename-stability —
  when Clarion hands me an entity *by SEI* after a rename moved its qualname, I
  must not have to reverse-map SEI→qualname first.
- **DoD:** `dossier(sei=…)` returns the same object as `dossier(entity=…)` for a
  matching entity; works after a rename that changed the qualname.
- **Gate:** rename-survival test (SEI key resolves post-rename; qualname key
  doesn't — that's the point).

### Workstream F — Activation hardening (no flow degrades to hand-config) · strong

- **F1 — Federation URL never gated on hand-editing YAML** *(WEIRD)*
  - **Deliverable:** `install/detect.py:30-47` writes a live `clarion:`/`filigree:`
    URL **only when the URL is in the env at install time**, else leaves a commented
    template the user must hand-uncomment — a silent degrade from activation to
    configuration. Add a **re-detect / wire-URL activation path** (e.g.
    `wardline install --wire-federation` or auto-detect on first scan) so a
    later-known port never forces a manual edit.
  - **DoD:** a federation whose URL becomes known *after* install can be wired with
    **one activation command**, no YAML hand-edit.
  - **Gate:** install-then-wire test produces a working federated scan with no
    manual file edit.

- **F2 — Portable trust-grammar packs** *(PLANNED `wardline-6e4ac6c148`)*
  - **Deliverable:** `wardline install <pack>` activates a team's trust model
    (boundary types + rules + config) on any repo — activation in its purest form.
    Shape is already right; the soundness-inheritance constraint (an unprovable
    custom boundary still yields `UNKNOWN_*` + `WLN-ENGINE-UNPROVABLE-BOUNDARY`
    FACT) is the load-bearing acceptance criterion. No critique beyond "ship it."

### Workstream G — Surface tidiness · nice

- **G1 — Collapse the two baseline tools** *(WEIRD)*: `baseline_create` /
  `baseline_update` differ only by a no-clobber flag (`server.py:238-251`). One
  `baseline` tool with `overwrite:bool` (default false). Frees a tools/list slot
  and removes a choice the agent shouldn't have to make.

### Not in this program

- **#14 Clarion dead-code boundary roots** (`wardline-1fb610b4fc`,
  PLANNED-INERT): Wardline exposes `@external_boundary`/`@trusted` entities as
  Clarion reachability roots. **Inert until Clarion builds its tag-emission
  pipeline** — off Wardline's critical path; no work here until the sibling picks
  a mechanism. Tracked, not scheduled.

---

## 5. Sequencing

Driven by "what unblocks the most inner-loop friction first," and by the
dependency D2→(D1,E), B3→C:

1. **A1** (parity bug, cheap) → **A2** (the missing federated move).
2. **B1** + **B2** (stop wasting round-trips — highest-frequency relief).
3. **C** (delta gate; carries **B3** lineage).
4. **E** (SEI addressing — unblocks D2's keying).
5. **D1** (posture) → **D2** (attest, needs D1+E).
6. **F1** (activation hardening) alongside; **F2**/**G1** as capacity allows.

A1, B1, B2, G1 are small surface-completion units shippable immediately; C and D
carry real design and get their own design→plan docs.

---

## 6. The activation-not-configuration ledger

Every unit is checked against the invariant. None requires new hand-authored
config; the two that *touch* config make it activation-shaped:

- **A1/A2/B1/B2/C/E/G1** — flags and reads over **existing** URL/fingerprint
  seams. Clean.
- **D2 (attest)** — **conditional**: clean **iff** `install` mints the key;
  fails the spec if it needs hand-provisioning. Made binding in D2's DoD.
- **F1** — explicitly *converts* a configuration degrade into an activation path.
- **F2 (packs)** — activation in its purest form.

---

## 7. Out of scope / non-goals

- No engine/lattice/rule-semantics changes — this is surface completion (the
  engine already computes what's needed).
- No new runtime dependencies in the base; federation writes use the existing
  stdlib-`urllib` emitter pattern.
- Findings remain **not** an MCP resource (staleness) — B1 adds a *filtered read*,
  not a cached resource.
- No re-filing of the planned issues (C, D1, D2, F2, #14) — this spec **constrains
  their shape**; they keep their Filigree IDs.

---

## 8. Definition of done

The program is done when:

1. **A single MCP-only dogfood** drives the full inner loop on a real federated
   repo — scan → filtered query (B1) → batched explain (B2) → delta gate (C) →
   `file_finding` to Filigree (A2) → `assure` coverage read (D1) → optional
   `attest` (D2) — **with no CLI fallback and no manual `wardline.yaml` edit**.
2. **Every delivered tool meets the five frictionless criteria** (one round-trip /
   structured / no-config / CLI=MCP / fail-closed), pinned by tests.
3. **CLI/MCP parity tests** cover A1, B1, B2, C (no surface can do something its
   twin can't).
4. **Warm/cold byte-identity** still holds (C must not break the `SummaryCache`
   contract).
5. **Fail-closed honesty** is preserved across all new surfaces — an honest
   `UNKNOWN_*` + `WLN-ENGINE-*` FACT, never a silent false-green, verified on the
   new query/explain/posture paths.
