# Priority Hardening Burndown Design

**Date:** 2026-07-11

**Scope:** The six implementation priorities and four tracker-reconciliation items in the user-approved priority list:
`wardline-da175547cf`, `wardline-2e6ad7772c`, `wardline-6f9eece880`,
`wardline-8a1399a8b5`, `wardline-7b4c550e21`, `wardline-550ea44e53`,
plus `wardline-80e457bc41`, `wardline-18499aaa2d`, `wardline-b40ad59ddb`,
and `wardline-c66f62894b`.

## Objective

Remove the highest-consequence false-green, destructive-input, federation-honesty,
framework-coverage, and agent-context risks in the live Wardline queue. Preserve one
independently reviewable Filigree lifecycle and commit per concrete ticket or split child.
Do not close umbrella or cleanup tickets until live source, tests, and ticket acceptance
criteria agree.

## Approaches Considered

### A. Ticket-isolated TDD burndown — selected

Each concrete risk gets a red reproduction, the smallest root-cause fix, focused and
repository-level verification, its own commit, and its own Filigree closeout. Broad tickets
are split when their invariants have different owners or proof surfaces.

This produces the clearest audit trail and prevents a gate-soundness change from being
reviewed together with unrelated MCP pagination or framework-source work. The trade-off is
more tracker and commit overhead.

### B. Security batch followed by product coverage

Combine gate soundness, confinement, MCP boolean validation, and authentication honesty
into one hardening change, then handle FastAPI and decorator coverage together. This reduces
setup overhead but creates a large diff whose tests cannot identify which independent change
caused a regression. It also weakens Filigree lineage.

### C. Broad architectural consolidation

Refactor gate state, path types, identity resolution, framework classification, and report
pagination behind new shared abstractions in one program. This could reduce long-term
duplication, but it is disproportionate to the confirmed failures and risks replacing
well-tested boundaries without ticket-specific red evidence.

## Delivery Architecture

The burndown is a sequence of independently testable work packets. Tracker reconciliation
runs first so completed work is not reimplemented. The remaining packets follow risk and
leverage order:

1. Reconcile technically completed and stale tracker records.
2. Make lineless defects fail closed.
3. Pin all current destructive MCP boolean controls in degraded validation mode.
4. Preserve Loomweave authentication truth through every identity-binding consumer.
5. Split and harden the three security invariants in `wardline-8a1399a8b5`.
6. Close the confirmed FastAPI input false negatives without broad over-tainting.
7. Bound and filter decorator coverage before remote enrichment.
8. Complete a requirement-by-requirement audit over the attachment and live tracker.

Every packet uses systematic debugging phases before implementation and TDD red/green proof.
No packet may absorb adjacent cleanup merely because the same file is open.

## Work Packet 0: Tracker Reconciliation

### `wardline-80e457bc41`

Accept and close without new production code after rerunning the federation-status parity
suite. Commit `9f0c4d18` introduced `core/federation_status.py`; MCP, CLI, scan jobs,
scan-file workflow, and agent summary delegate to its shared builders. Thin surface adapters
are presentation seams, not duplicate projectors.

### `wardline-18499aaa2d`

Accept and close without new production code after rerunning the shared HTTP contract and
federation client suites. Commit `5b0dcf24` introduced `WeftHttp`, and the originally cited
clients consume it while retaining client-specific authentication and signing.

### `wardline-b40ad59ddb`

Rescope rather than close. The root-relative configuration bug is tested, but
`_attach_legis_artifact()` still calls `config_mod.load()` after `run_scan()` loaded the
configuration. The implementation packet will thread the exact in-process `WardlineConfig`
used by the scan into artifact construction. The object remains in-process only and is never
serialized. Tests must prove one configuration load and object identity across explicit,
implicit, trusted-pack, local-pack, and strict-default modes.

### `wardline-c66f62894b`

Keep the program tracker open. Refresh its description so closed children
`wardline-c0563eee74` and `wardline-79ba05f464` are not presented as live. Retain the two
open P4 children and record that they are non-gating. Resolve the parent done definition from
live Weft program state rather than closing it as a code ticket.

## Work Packet 1: Lineless Defects Fail Closed

**Ticket:** `wardline-da175547cf`

`apply_suppressions()` currently converts every non-engine lineless `DEFECT` into a
non-gating `FACT`. Replace this generic downgrade with an explicit allowlist whose initial
membership is empty. An unallowlisted lineless source defect becomes a deterministic,
gate-eligible engine defect:

- use `WLN-ENGINE-LINELESS-DEFECT` as the diagnostic rule;
- retain the original severity so configured gate thresholds remain meaningful;
- anchor the diagnostic at `ENGINE_PATH` to avoid recursive rewriting;
- preserve the original rule, path, fingerprint, and kind in properties;
- derive a collision-resistant fingerprint from those original identity fields.

Do not fabricate a source line and do not crash the scan. Replace the tests that currently
assert the false-green behavior with regressions proving the diagnostic remains a `DEFECT`
and trips the appropriate gate. Add a registry-wide invariant that built-in source-rule
defects carry source lines.

## Work Packet 2: Destructive MCP Boolean Pins

**Ticket:** `wardline-2e6ad7772c`

Production `_bool_arg()` behavior is correct. The missing contract is degraded-mode dispatch
coverage when `jsonschema` is unavailable. Add a parameterized matrix that sends the string
`"false"` and proves a typed tool error before side effects for every current destructive or
write-enabling boolean:

- `fix.apply` and `fix.dry_run`;
- `judge.write`;
- `baseline.overwrite`;
- `scan_job_start.local_only`;
- `doctor.repair`;
- `rekey.apply`, `rekey.resume`, and `rekey.rollback`.

Use tool-specific minimal valid fixtures so execution reaches the named boolean guard. Spy on
side-effect functions where necessary and assert they were not called. Remove stale ticket
language about waiver booleans because current waiver tools expose no boolean control.

## Work Packet 3: Authentication-Honest Identity Resolution

**Ticket:** `wardline-6f9eece880`

Keep Loomweave optional and fail-soft, but stop collapsing authentication rejection into
ordinary entity absence. Introduce a frozen `BindingResolution` value in
`loomweave/dossier_sources.py` containing:

- `binding: EntityBinding | None`;
- `unavailable_reason: str | None`;
- `auth_status: int | None`.

Centralize status-aware wording. A 401 instructs the operator to align the federation/HMAC
credential and clock; a 403 identifies project, scope, or permission rejection without
claiming that setting a token is sufficient. Genuine unresolved entities retain the existing
no-binding language.

Thread the value through all consumers of the shared resolver:

- dossier linkage and work reasons;
- decorator-coverage identity/work reasons;
- attestation SEI enrichment diagnostics;
- Filigree legacy-locator attachment results.

Do not raise a generic exception, make Loomweave load-bearing, or add guessed identities.
Split the `DELTA_SKIP_REASON` / `NO_FACTS_REASON` comment and surface-test cleanup into a
separate small task; it is not the authentication root cause.

## Work Packet 4: Split Security Invariants

**Parent:** `wardline-8a1399a8b5`

Create three child tickets and close the parent only after each has an explicit disposition.

### 4A. Gate-population representation

Replace the independently optional `gate_findings` and `gate_honors_suppressions` state with
a frozen tagged `GatePopulation` value that carries the findings and one closed posture:
`UNSUPPRESSED` or `HONORS_SUPPRESSIONS`. `gate_decision()` consumes this value; low-level
`gate_trips()` remains population-agnostic. Tests reject illegal state, preserve secure
defaults, preserve explicit trusted-suppression behavior, and prove delta scans never narrow
the authoritative population.

### 4B. Two-stage confinement contract

Preserve both existing boundaries: direct MCP arguments are confined by
`resolve_under_root`, while config-derived paths and symlink traversal are confined during
discovery. Replace the ambiguous boolean at shared entry points with an explicit confinement
policy and document that a confined config path does not certify paths named inside its
contents. Tests cover direct escape, poisoned source roots, symlink escape, secure default,
and explicit legacy opt-out.

### 4C. Fingerprint determinism disposition

Do not refactor working fingerprint serialization merely to relocate ownership. Verify the
frozen identity corpus, `FINGERPRINT_SCHEME` enforcement, cross-interpreter CI matrix, and
producer-source seam record remain mandatory. If all proofs are current, close this child as
already enforced and document ownership; otherwise repair the missing enforcement only.

## Work Packet 5: FastAPI Input Coverage

**Parent:** `wardline-7b4c550e21`

Split simple request-member coverage from route-body classification.

### 5A. Precise request-source additions

- recognize `fastapi.requests.Request` alongside the existing FastAPI and Starlette names;
- recognize `req.url.query` and `req.scope["query_string"]` as raw nested sources;
- do not mark all of `url` or `scope` raw;
- retain clean controls for `url.path`, `scope["path"]`, `app`, `state`, and `client`;
- add regression pins for already-working async stream iteration, `multi_items()`,
  `getlist()`, and conservative `Depends()` handling without changing production behavior.

### 5B. Pydantic route-body parameters

Add a route-aware parameter classifier. Seed a Pydantic model parameter as attacker input
only when the function is a recognized FastAPI route and the annotation resolves to a
Pydantic model. Do not taint every `BaseModel` parameter in ordinary trusted functions.
Test direct models, imported aliases, nested fields, non-route controls, and validated
dependency-provider returns.

## Work Packet 6: Bounded Decorator Coverage

**Ticket:** `wardline-550ea44e53`

Separate local base-row classification from optional Loomweave and Filigree enrichment.
Compute the whole-project summary before filtering. Apply a shared core query over base rows,
then page, and enrich only the returned page.

The shared query supports conjunctive filters for:

- `qualname`;
- `path_glob`;
- `declared_tier`;
- `actual_tier`;
- `verdict`;
- `finding_state`;
- `has_active_findings`.

MCP and CLI expose the same `where`, `max_rows`, `offset`, and `full` semantics. The default
page is bounded; `full=true` is the explicit uncapped escape hatch. Output always includes:

- whole-project `summary`;
- `filtered_total`;
- the page of `rows`;
- `truncation` with `truncated`, `shown`, `total`, `page_size`, and advancing
  `next_offset`.

Invalid filters, negative offsets, negative page sizes, and zero-progress truncated pages
fail loudly. MCP schemas, structured output, CLI JSON, human output, and goldens change in
the same packet.

## Error-Handling Principles

- Security invariants fail closed without inventing source facts.
- Optional federation integrations remain fail-soft but name why data is unavailable.
- User-controlled filters and booleans reject invalid types before side effects.
- Pagination never silently truncates and never emits a non-advancing cursor.
- Existing explicit legacy opt-outs remain explicit; secure defaults do not weaken.

## Testing and Verification

Each work packet follows red/green TDD and runs its focused unit/conformance suites before
commit. Every production-code packet additionally runs:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
uv run wardline scan . --fail-on ERROR
git diff --check
```

Because a repository scan may report an inert gate when no trust boundaries are recognized,
ticket-specific regressions and live reproductions are the primary proof for the relevant
behavior. Generated scan artifacts are checked against repository status before commit.

## Filigree and Commit Discipline

For every code-bearing ticket or child:

1. Start work atomically with the verified actor and `--advance` when the workflow requires it.
2. Record the root cause before implementation.
3. Add the red reproduction, implement one root-cause fix, and verify.
4. Commit only that ticket's code, tests, and directly required docs.
5. Add verification evidence, advance through required review/verifying states, and close.

Tracker-only acceptance items receive live verification comments and closure without a code
commit. Umbrella parents close only when all children have terminal, evidence-backed
dispositions.

## Completion Criteria

The burndown is complete only when:

- all six requested implementation priorities have terminal evidence-backed dispositions;
- every child created by the required splits is closed or explicitly rejected with evidence;
- `wardline-80e457bc41` and `wardline-18499aaa2d` are reconciled against landed code;
- `wardline-b40ad59ddb` no longer performs a second policy load for the artifact;
- `wardline-c66f62894b` accurately names its live frontier and done definition;
- the full verification stack is green;
- the final live Filigree query shows none of the requested concrete work still open.
