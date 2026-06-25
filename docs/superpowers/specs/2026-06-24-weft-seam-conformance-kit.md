# Weft Seam Conformance Kit (design)

> The standard, mechanical recipe EVERY weft seam follows so applying conformance
> to a new seam is a checklist, not a bespoke project. Generalized from the SEI
> (Stable Entity Identity) conformance program, which is the GOLD STANDARD.

## 0. What a "seam" is and the bar it must clear

A **weft seam** is any interface where one Loom peer (wardline / loomweave /
filigree / legis / charter) produces or consumes data to/from another: HTTP
federation endpoints, HMAC-signed wire formats, shared identifier formats (SEI),
entity-associations, scan-artifact intake, taint-store blobs, the `weft.toml`
config contract, auth tokens (`WEFT_FEDERATION_TOKEN`), and cross-surface status
envelopes.

A seam is **AT THE SEI BAR** only when it has ALL of:

1. a frozen, machine-checkable **CONTRACT artifact** (not just prose docs);
2. an automated conformance **ORACLE** (golden-vector or scenario) that actually
   asserts the wire;
3. a **CI GATE** that FAILS CLOSED on drift — never a test that skips-clean when a
   peer/binary is absent;
4. (two-sided seams only) a **shared corpus both peers load** PLUS a **drift alarm**.

Default to judging a seam BELOW the bar unless you SEE all four in source.

The kit below specifies each of the four as a reusable pattern, citing the SEI
source it is derived from.

---

## 1. Lens: distributed two-sided contract & drift (federation lens)

One contract is defined ONCE and BOTH peers load/test the SAME bytes. Divergence
is impossible to merge green because the producer's live emit and the consumer's
loader are both coupled to one committed artifact, and an upstream byte-pin +
drift alarm catches silent divergence ACROSS repos.

The SEI program demonstrates the two seam shapes the kit must cover:

- **One-sided / cross-engine identity** — the producer freezes its own
  externally-observable surface so a *second producer of the same string* (the
  future Rust core) must reproduce it byte-for-byte.
  (`tests/golden/identity/test_identity_parity.py`,
  `tests/grammar/test_golden_oracle.py`.)
- **Two-sided / cross-repo contract** — producer and consumer load the SAME shared
  vector; an upstream byte-pin + opt-in live recheck catches divergence across
  repos.
  (`tests/conformance/test_legis_scan_wire_golden.py` (G1, commit `2441c1d0`);
  `tests/conformance/test_loomweave_rust_qualname_parity.py` (drift alarm, commit
  `36c8adcf`).)

The kit's INVERSION rule (who is authoritative) is set per-seam: for SEI/identity
Wardline is the producer-of-record; for the Rust qualname seam Loomweave is
authoritative and Wardline VENDORS its corpus and reproduces it as the second
producer. Header of `test_loomweave_rust_qualname_parity.py` states this inversion
explicitly — the kit requires every seam to name its authority and its second
producer/consumer.

---

## 2. Artifact layout (the CONTRACT artifact)

Derived from `tests/golden/identity/` and `tests/conformance/`.

Every seam `<seam>` gets a fixed directory shape under `tests/`:

```
tests/<area>/<seam>/
  README.md            # what the seam covers, inputs, determinism notes, regen procedure
  _capture.py          # the CANONICALIZER: produce the wire bytes, sorted/strict/host-free
  regen.py             # the ONLY sanctioned writer of the frozen artifact (requires --reason)
  conftest.py          # on-failure diff dump (real-regression vs intentional-rekey triage)
  test_<seam>_*.py     # the ORACLE(s) — assert live emit == frozen artifact
  fixtures/            # FIXED input corpus (no .weft/, no weft.toml, LF-pinned)
  corpus/              # the frozen artifact(s): <name>.json + META.json
```

For a two-sided seam, the single shared vector lives at
`tests/conformance/<seam>_wire.golden.json` and is loaded by BOTH repos (the
wardline half couples it to the live emit; the peer half loads the same file).
Cite: `tests/conformance/legis_scan_wire.golden.json` +
`test_legis_scan_wire_golden.py`.

Required properties of the CONTRACT artifact (from `_capture.py`):

- **Canonical JSON** — `json.dumps(..., indent=2, sort_keys=True, ensure_ascii=False)`
  with a `+ "\n"` trailer (`_capture.to_json`, lines 190-192).
- **Strict default hook** — a `default=` that RAISES on any non-serialisable type
  rather than `str()`-ing it, so hash/address-dependent nondeterminism cannot
  silently freeze (`_capture._strict_default`, lines 172-187; includes the
  documented float caveat).
- **No host data** — no absolute paths, no timestamps, no tool version. The
  *mutable* tool version is normalised to a sentinel (`_VERSION_SENTINEL =
  "<normalized>"`, applied to `driver.version` in `_capture._capture_sarif`,
  lines 92-94). Scans are rooted AT the fixture so paths are relative
  (`_capture.py` module docstring, lines 6-8).
- **Total order on every named array** — emission order is a Python-walker artifact
  a different engine won't reproduce, so every array gets a content-derived sort
  with a JSON-canonical tiebreaker because the natural key may collide
  (`_finding_sort_key`, lines 50-63; `_sarif_result_sort_key`, lines 107-113; the
  facts/spans sorts, lines 74-141). EXCEPTION: causal sequences (SARIF `codeFlows`,
  taint chains) are NEVER sorted (lines 99-102).
- **A `META.json` recording the scheme/version** the artifact was captured under,
  so a future scheme bump is a visible, accountable delta and is asserted against
  the live constant (`test_corpus_meta_has_engine_scheme`,
  `test_identity_parity.py` lines 37-45; `regen.py` writes
  `fingerprint_scheme` + `corpus_version` + `reason`).
- **A positive allowlist predicate** deciding what enters the frozen surface (NOT a
  denylist), so a future rule of a new family can't silently enter or be dropped
  (`is_identity_bearing`, `_capture.py` lines 40-47).

The artifact reuses the REAL wire serializer (`Finding.to_jsonl()`,
`build_taint_facts`, `build_sarif`, `build_legis_artifact`) and re-parses for
canonical re-serialization — so the oracle is sensitive to every wire field, not a
hand-mirrored schema (`_capture._capture_findings`, lines 66-71).

---

## 3. Oracle test shape

Derived from `test_identity_parity.py` and `test_golden_oracle.py`.

The oracle is a byte-for-byte equality of the live capture against the committed
artifact, PLUS a fixed set of non-vacuity and soundness guards that stop a silently
empty/shallow corpus from passing.

### 3a. The core equality (one-sided)

```python
def test_corpus_is_byte_identical(name):
    golden = (HERE / "corpus" / f"{name}.json").read_text("utf-8")
    actual = c.to_json(c.capture(INPUTS[name]))
    assert actual == golden, REGEN_HINT
```

(`test_identity_parity.py` lines 48-54; the grammar variant is
`test_golden_oracle.test_builtin_findings_match_golden`.) The `REGEN_HINT` names
the exact regen command and the `/tmp` diff path so the failure is
self-explaining (lines 30-34).

### 3b. The live-emit coupling (two-sided)

For a shared vector, the producer half asserts the LIVE signed emit carries
EXACTLY the vector's top-level and per-finding key-sets, and that the vector's one
active record routes as active:

- `test_live_emit_top_level_keys_match_the_vector` — `set(live) == set(vector)`
- `test_live_emit_per_finding_keys_match_the_vector` — every emitted record's
  key-set equals the vector's
- `test_golden_vector_is_a_valid_signed_artifact` — the vector round-trips under a
  documented fixed `GOLDEN_KEY` so the CONSUMER verifies it offline
- `test_vector_defect_routes_as_active` — the pinned record is the thing the
  consumer must route

(All from `test_legis_scan_wire_golden.py`.) The key strings are tied to SHARED
CONSTANTS imported from production (`FINDINGS_FIELD`, `FINGERPRINT_SCHEME_FIELD`,
`DIRTY_FIELD`) so a constant-VALUE rename reds
(`test_golden_vector_keys_are_the_named_constants`).

### 3b-bis. The scenario oracle (capability / protocol round-trips)

Some seams are not a single frozen wire but a *negotiation* or *protocol round-trip*
(SEI `_capabilities` advertisement, resolve/degrade behaviour). Byte-equality cannot
express "every named scenario the upstream standard defines is handled." For these,
the oracle is a SCENARIO ORACLE:

- Vendor an upstream-authored fixture of named scenarios
  (`tests/conformance/fixtures/sei-conformance-oracle.json`).
- One assertion per scenario id drives the LIVE consumer code path
  (`SeiResolver`) through that scenario and asserts the expected status.
- A module-level `COVERED_SCENARIOS` set is asserted EQUAL to the fixture's ids
  (`test_sei_oracle.test_every_oracle_scenario_is_covered`, lines 49/90-92) — so a
  NEW upstream scenario reds CI until it is explicitly covered.
- Plus a vendored == upstream-source drift check (the one acceptable skip, because
  the byte-pin of §4 Layer-1 is its hermetic backstop).

(`tests/conformance/test_sei_oracle.py` + `fixtures/sei-conformance-oracle.json`.)

So the kit has THREE sanctioned oracle shapes — pick by seam type:
**(1) byte-frozen golden** (engine-produced identity surfaces, §3a),
**(2) shared signed vector** (two-sided cross-repo wire, §3b),
**(3) scenario oracle** (capability negotiation / protocol round-trips, §3b-bis).
The non-vacuity guards of §3c and the determinism precondition of §3d apply to all three.

### 3c. Mandatory non-vacuity + soundness guards

Every seam oracle MUST carry, per input and per surface:

- **Non-vacuity** — each frozen surface is non-empty AND contains the load-bearing
  marker (`test_corpus_surface_non_vacuous`, lines 76-89: findings / entity_spans /
  facts / SARIF results / explain all non-empty; `PY-WL-101` present; every span
  has real line/col). This stops an empty Rust output from satisfying a vacuous
  oracle.
- **Edge-construct coverage** — the stress fixture's span-edge constructs (that
  produce NO finding) must appear in the frozen surface
  (`test_stress_freezes_span_edge_construct_spans`, lines 92-98).
- **Join-key collision-freedom** — distinct active records must have distinct
  fingerprints; the fingerprint is the cross-tool JOIN KEY, so a collision silently
  drops one record on the join (`test_corpus_fingerprints_are_collision_free`,
  lines 106-132 — the `sinks` fixture deliberately plants same-(rule,line,qualname)
  pairs to keep this non-vacuous).
- **Fixture hygiene** — fixtures carry no `.weft/` and no `weft.toml` (a
  baseline/waiver would date-poison the corpus via `date.today()`)
  (`test_fixture_has_no_local_config`, lines 148-152;
  `test_assure_corpus_has_no_waiver_debt`, lines 135-142).

### 3d. Determinism precondition

The captured surface must be verified deterministic BEFORE freezing: in-process
stable, path-independent, cross-process (`PYTHONHASHSEED`), cross-interpreter
(CPython 3.12 freeze ↔ 3.13 reproduce byte-identical) — so the gate runs on every
CI interpreter with NO skip (`test_identity_parity.py` docstring lines 5-8; README
"Determinism" section). A seam whose surface isn't deterministic is not yet
freezable; make it deterministic first (impose total order, normalise mutable
fields) — do not relax the equality.

---

## 4. Shared-corpus + drift-alarm mechanism (two-sided seams)

Derived from `test_loomweave_rust_qualname_parity.py` (commit `36c8adcf`) and the
G1 shared vector (commit `2441c1d0`).

The failure this prevents: two INDEPENDENT vendored mirrors (each side hand-copies
the schema) — the "hand-copied-both-sides" pattern that lets one side rename a
field and stay green while the other governs an empty payload under a `verified`
status (G1 / seam-S8 root cause, `test_legis_scan_wire_golden.py` docstring;
`2441c1d0` commit body).

The kit's two-layer drift alarm:

**Layer 1 — upstream byte-pin (runs in the DEFAULT suite, every PR):**
The vendored copy's git blob SHA is pinned as a module constant; any byte change to
the vendored file fails loudly, so re-vendors are deliberate, atomic, and update
the constant in the SAME commit.

```python
UPSTREAM_BLOB_SHA = "ed436c825861ad2b9e313f9211f5a55583b80c7c"

def test_vendored_corpus_matches_upstream_blob_pin():
    data = _CORPUS_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, "...deliberate re-vendor → update SHA in same commit"
```

(`test_loomweave_rust_qualname_parity.py` lines 100-189; the pin is computed as a
real git blob hash, `b"blob %d\x00" + data`, so `git hash-object` is the source of
truth.)

**Layer 2 — live recheck (OPT-IN marker, release-gate only):**
Byte-compares the vendored copy against the sibling checkout
(`WARDLINE_LOOMWEAVE_REPO`, default `/home/john/loomweave`); SKIPS when the checkout
is absent (CI PR runner has no sibling), FAILS on drift
(`test_vendored_corpus_matches_live_sibling_checkout`, marked
`@pytest.mark.loomweave_drift`, lines 191-204).

**The shared vector itself (the single source both load):**
For a two-sided wire, the ONE concrete signed instance lives in
`tests/conformance/<seam>_wire.golden.json`. It is deterministic and
self-consistent: volatile fields (`scanner_identity`, `rule_set_version`,
`commit_sha`, `tree_sha`) are FIXED sentinels and the signature is computed over
that body under a documented fixed key, so the consumer verifies it OFFLINE
(`test_legis_scan_wire_golden.py` docstring; `GOLDEN_KEY =
b"weft-shared-conformance-key"`). The wardline half couples it to the live emit;
the peer adds the matching loader as its half of the same test. Regenerating the
vector to match a rename on one side then REDS the other side's half — that
coupling is the whole point.

**Re-vendor procedure (a RELEASE-GATE item):** copy byte-verbatim → update
`UPSTREAM_BLOB_SHA` to `git hash-object <file>` + refresh provenance lines, all in
the SAME commit → re-run conformance and CONFORM the producer until byte-green
(never weaken the comparison). (`test_loomweave_rust_qualname_parity.py` header
RE-VENDOR PROCEDURE.)

---

## 5. CI gate spec (FAILS CLOSED)

Derived from `.github/workflows/ci.yml`, `tests/conftest.py`,
`src/wardline/_live_oracle.py` (commit `d87db0cd`).

The cardinal rule: **a live oracle that can't reach its peer must FAIL on the gated
job, never silently skip-clean.** The mechanism splits into PR-time (hermetic) and
scheduled (live), and a conftest hook converts SKIP→FAILURE when the gate is armed.

**5a. PR-time (hermetic pins, every push/PR):**
The byte-pin oracles, the shared-vector key-set tests, and the identity parity
corpus all run with no live peer — they rely on the committed artifacts, so they
gate every PR. (`ci.yml` jobs `Tests + Coverage`, `Self-Hosting Scan`; the
PR-vs-scheduled split is documented in the workflow comments,
`83d08aee75` commit body.) The self-scan itself is gated: `wardline scan src/
--format sarif --output results.sarif --fail-on ERROR` — with a NON-VACUOUS proof
fixture (`tests/test_self_hosting_violation.py` +
`tests/fixtures/.../trust_boundary_violation.py`) showing the pipeline CAN trip the
gate (`751a9ae71b`).

**5b. Scheduled / manual (live oracles, fail-closed):**
Live-peer tests run only on `schedule` / `workflow_dispatch` (a GitHub PR runner
can't host `loomweave serve` / live legis+filigree). They run with
`WARDLINE_LIVE_ORACLE_REQUIRED: "1"`, which arms the fail-close hook
(`ci.yml` jobs `live-judge`, `live-oracles` matrix over markers
`loomweave_e2e` / `legis_e2e` / `filigree_e2e` / `warpline_e2e`).

**5c. The SKIP→FAILURE hook (the fail-close primitive):**

```python
# tests/conftest.py
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if should_fail_live_oracle_skip((m.name for m in item.iter_markers()), report.outcome):
        report.outcome = "failed"
        report.longrepr = f"{LIVE_ORACLE_REQUIRED_ENV}=1 forbids skipped live oracle tests: ..."
```

`should_fail_live_oracle_skip` = `live_oracle_required() and outcome == "skipped"
and has_live_oracle_marker(...)` over `LIVE_ORACLE_MARKERS = {network,
loomweave_e2e, legis_e2e, filigree_e2e, warpline_e2e}`
(`src/wardline/_live_oracle.py`). So when the env is set, a live oracle that would
have skipped (peer unreachable) becomes a hard FAILURE — that is the fail-closed
guarantee.

**5d. Marker registration + default exclusion:**
Every live/drift marker is registered in `pyproject.toml [tool.pytest.ini_options]
markers` and excluded from the default `addopts` run (`-m 'not network and not
loomweave_e2e and not ... and not loomweave_drift and not warpline_e2e'`), so the
default `pytest` is hermetic and the live tier is opt-in by marker
(`pyproject.toml` lines 147-155). A new seam adds its `<seam>_e2e` marker to BOTH
`markers`, the `addopts` exclusion, AND `LIVE_ORACLE_MARKERS` (so the fail-close
hook covers it).

**5e. Rekey accountability:**
The frozen artifact changes ONLY via `regen.py --reason "<why>"` (stamps `reason`
into `META.json`); the parity test in CI fails any PR that changes `corpus/*`
without a matching production change; the recommended complement is a CODEOWNERS
entry on `corpus/**` so a rekey also needs maintainer review (`regen.py` docstring;
README "Regenerating" section).

**5f. Release ride-along (the gate must guard the publishable artifact):**
The conformance gate is worthless if it does not execute on the path that produces
a release. TODAY `.github/workflows/release.yml` (on tag `v*`) only `needs: build`
and guards the version tag + SHA256SUMS + PyPI Trusted Publishing — it does NOT
re-run the conformance suite or the `<seam>_drift` recheck, so a drifted seam can
ride a tag straight to PyPI because the gate lives only in `ci.yml`, which the tag
push does not depend on. The kit REQUIRES:

- the release `build`/publish job to `needs:`-depend on (or re-run) the §5a Tier-1
  HERMETIC conformance suite (byte-pins, shared-vector key-sets, identity parity,
  the gated `wardline scan src/ --fail-on ERROR` self-scan);
- the release runbook to run the §4 Layer-2 `-m <seam>_drift` live recheck against
  the sibling checkouts BEFORE tagging (the test header already declares this a
  RELEASE-GATE item);
- belt-and-braces: a branch-protection required-status-check on the conformance job
  (so the merge-to-main preceding the tag already gated it) AND a tag-time re-run
  (so a tag cut from an unprotected ref still gates).

(`release.yml` line 43 `needs: build` — the gap; `test_loomweave_rust_qualname_parity.py`
RE-VENDOR PROCEDURE header — the release-gate declaration.)

---

## 6. Per-seam checklist (mechanical application)

For a new seam `<seam>` between authority `A` and consumer/second-producer `B`:

1. **Name the seam's authority and the second producer/consumer.** State which
   side mints the bytes and which reproduces/consumes them; if `A` is a sibling
   repo, `B` (this repo) VENDORS `A`'s corpus. (Inversion rule, §1; cite header of
   `test_loomweave_rust_qualname_parity.py`.)
2. **Write the CONTRACT artifact** under `tests/<area>/<seam>/corpus/` (one-sided)
   or `tests/conformance/<seam>_wire.golden.json` (two-sided shared). Canonical
   JSON, strict default, host-free, totally ordered, with `META.json` recording
   the scheme/version. (§2.)
3. **Write `_capture.py`** that reuses the REAL production wire serializer, applies
   the positive allowlist predicate, and canonicalizes. (§2.)
4. **Write `regen.py`** requiring `--reason`, as the ONLY writer of the artifact.
   (§5e.)
5. **Write the ORACLE**, picking the shape by seam type: byte-equality (one-sided
   identity surface, §3a), live-emit key-set coupling + offline signature round-trip
   (two-sided shared vector, §3b), OR scenario oracle with `COVERED_SCENARIOS ==
   fixture ids` (capability negotiation / protocol round-trip, §3b-bis). (§3a/§3b/§3b-bis.)
6. **Add the non-vacuity + soundness guards**: per-surface non-empty, load-bearing
   marker present, edge-construct coverage, join-key collision-freedom, fixture
   hygiene. (§3c.)
7. **Prove determinism** (in-process / path / cross-process / cross-interpreter)
   BEFORE freezing; impose total order on any walker-order array. (§3d.)
8. **(Two-sided) Add the drift alarm**: Layer-1 `UPSTREAM_BLOB_SHA` git-blob pin in
   the default suite; Layer-2 opt-in `<seam>_drift` live recheck vs the sibling
   checkout (skip-when-absent, fail-on-drift). Document the RE-VENDOR PROCEDURE in
   the test header. (§4.)
9. **Register markers** `<seam>_e2e` (+ `<seam>_drift` if two-sided) in
   `pyproject.toml markers`, the `addopts` exclusion, AND
   `_live_oracle.LIVE_ORACLE_MARKERS`. (§5d.)
10. **Wire CI**: hermetic pins on every PR; live oracle on `schedule` /
    `workflow_dispatch` with `WARDLINE_LIVE_ORACLE_REQUIRED=1` so a peer-absent
    skip becomes a FAILURE. (§5a/§5b/§5c.)
11. **Add the on-failure diff conftest** (`conftest.py`) dumping the live capture to
    `/tmp` + a unified-diff head, so a real regression is distinguishable from an
    intentional rekey on a multi-KB artifact. (`tests/golden/identity/conftest.py`.)
12. **(Recommended) CODEOWNERS** on the artifact path so a rekey needs maintainer
    review. (§5e.)
13. **Wire the RELEASE ride-along**: make the release/publish workflow
    `needs:`-depend on (or re-run) the Tier-1 hermetic conformance suite, and run
    the `-m <seam>_drift` recheck in the release runbook before tagging — so a
    drifted seam cannot ride a tag to publish. (§5f.)
14. **Register the seam in the seam index** (§8) — add its row (authority,
    consumer/second-producer, oracle shape, marker, two-sided? Y/N, bar verdict) so
    the machine-checkable registry covers it.

A seam is AT THE BAR only when items 2, 5, 10 exist (contract + oracle + fail-closed
CI) and — for two-sided — item 8 (shared corpus + drift alarm). Anything less is
BELOW the bar regardless of how much prose documentation the seam carries.

---

## 8. Where the kit and the canonical seam index live

This kit GENERALIZES the SEI standard, and SEI set the precedent: the *standard*
was promoted out of the Wardline tree to the Weft federation hub
(`~/loom/sei-standard.md`, linked from `~/loom/doctrine.md`), leaving an in-repo
**pointer** at `docs/superpowers/specs/2026-06-01-loom-stable-entity-identity-conformance.md`.
The kit mirrors that split exactly, because a seam is a CROSS-PEER object — the
single canonical view can only be assembled where every peer is visible.

| Artifact | Canonical home | Notes |
|---|---|---|
| **Kit doctrine** (the standard all peers conform to) | hub: `~/loom/seam-conformance-kit.md`, linked from `~/loom/doctrine.md` | governs all peers, so the hub is canonical |
| **Wardline's executable reference** | this file (`docs/superpowers/specs/2026-06-24-weft-seam-conformance-kit.md`) | once promoted, reduce to pointer-to-hub + Wardline implementation notes, same shape as the SEI pointer |
| **Canonical seam INDEX** (cross-peer union: every seam, its authority/consumer, its bar verdict) | hub: `~/loom/seam-index.md` | only the hub sees all peers' halves, so the union index lives there |
| **Wardline's enforceable seam REGISTRY** | Wardline tree, adjacent to enforcement: `tests/conformance/seam_registry.json` (+ a `test_seam_registry.py` asserting it) | the machine-checkable, CI-asserted half that feeds the canonical index |

**The Wardline registry is itself gated, not prose.** A `test_seam_registry.py`
MUST assert that every seam listed in `seam_registry.json` actually has its oracle
test, its registered marker, and (two-sided) its drift alarm wired — so a
prose-only "index" entry with no enforcement is itself BELOW the bar. The registry
row schema is the §6 item 14 tuple: `{seam, authority, consumer_or_second_producer,
wire, two_sided, oracle_shape, marker, drift_alarm, bar_verdict, evidence_paths}`.

> Promotion note: `~/loom/` is the cross-repo federation hub and is NOT present in
> this checkout. Creating `~/loom/seam-conformance-kit.md` and `~/loom/seam-index.md`
> is a CROSS-REPO action (a hub PR); until then THIS file is authoritative-for-now
> and the Wardline `seam_registry.json` is the executable ground truth — exactly the
> posture the SEI pointer documents.

---

## 7. SEI source evidence (where each kit element was derived)

- Contract artifact / canonicalizer: `tests/golden/identity/_capture.py`
  (canonical JSON `to_json` L190-192; strict default `_strict_default` L172-187;
  version-sentinel normalisation L92-94; total-order sorts L50-141; allowlist
  predicate `is_identity_bearing` L40-47; real-wire reuse `_capture_findings`
  L66-71).
- Oracle shape: `tests/golden/identity/test_identity_parity.py` (byte equality
  L48-54; META scheme assert L37-45; non-vacuity L76-89; edge constructs L92-98;
  join-key collision-freedom L106-132; fixture hygiene L135-152) and
  `tests/grammar/test_golden_oracle.py` + `tests/grammar/golden_harness.py`
  (corpus-not-dogfood rationale).
- Shared corpus + drift alarm: `tests/conformance/test_loomweave_rust_qualname_parity.py`
  (byte-pin `UPSTREAM_BLOB_SHA` + `git hash-object` semantics; opt-in
  `loomweave_drift` live recheck; RE-VENDOR PROCEDURE) — commit `36c8adcf`; and
  `tests/conformance/test_legis_scan_wire_golden.py` +
  `tests/conformance/legis_scan_wire.golden.json` (single shared signed vector,
  live-emit key-set coupling, offline signature verify, named-constant key
  binding) — commit `2441c1d0` (G1).
- CI fail-closed gate: `.github/workflows/ci.yml` (PR-vs-scheduled split;
  self-scan `--fail-on ERROR`; `WARDLINE_LIVE_ORACLE_REQUIRED=1` matrix),
  `tests/conftest.py` (SKIP→FAILURE hook), `src/wardline/_live_oracle.py`
  (`LIVE_ORACLE_MARKERS`, `should_fail_live_oracle_skip`),
  `pyproject.toml` (marker registration + default `addopts` exclusion) — commit
  `d87db0cd`; non-vacuous self-scan proof `tests/test_self_hosting_violation.py`.
- Rekey accountability: `tests/golden/identity/regen.py` (`--reason`,
  `CORPUS_VERSION`, `META.json` stamp), `tests/golden/identity/README.md`
  (CI-enforces-no-silent-rekey + CODEOWNERS complement),
  `tests/golden/identity/conftest.py` (on-failure diff dump).

> Note on the canonical home: the SEI *standard* was promoted out of this tree to
> the Loom federation hub (`docs/superpowers/specs/2026-06-01-loom-stable-entity-identity-conformance.md`
> is now a pointer to `~/loom/sei-standard.md`). That hub file is NOT present in
> this checkout; this kit is derived from the LIVE, in-repo SEI implementation
> (tests + CI + tooling above), which is the executable ground truth.
