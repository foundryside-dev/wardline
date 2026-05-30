# Wardline SP4 — Outputs + Loom Integration (design)

**Date:** 2026-05-30
**Status:** approved-by-directive (user goal: "plan SP4 and implement it"; the single
gating decision — which finding kinds the Filigree emitter sends — was answered
**Everything**). Sibling contracts scouted live against filigree 2.1.0 and clarion 1.0.0.
**Supersedes nothing.** Builds on SP0–SP3 (all merged to main).

---

## 1. Goal

Give Wardline three *additive, non-load-bearing* output paths beyond the local
`findings.jsonl`:

1. **SARIF 2.1.0** — a standard interchange format for any SARIF consumer (CI
   annotations, code-scanning dashboards). Wired into the existing
   `wardline scan --format sarif` stub.
2. **Native Filigree emitter** — POST findings into Filigree's Loom scan-results
   lifecycle (`POST /api/loom/scan-results`), opt-in via `--filigree-url`.
3. **Clarion producer conformance** — pin Wardline's `metadata.wardline.qualname`
   producer byte-for-byte against Clarion's live normalization rules.

Charter discipline (`loom.md` §5): every path is enrichment. `wardline scan` boots,
analyzes, writes JSONL, and gates **with both siblings absent**. SARIF and Filigree
emission only happen when explicitly requested.

---

## 2. Sibling contract facts (scouted 2026-05-30, authoritative)

### Filigree 2.1.0 — `POST /api/loom/scan-results`
- Live and frozen. **No auth.** `Content-Type: application/json`. 200 on success,
  400 on validation error.
- **Envelope:** `{scan_source (req, non-empty), findings (req array)}` plus optional
  `scan_run_id`, `mark_unseen`, `create_observations`, `complete_scan_run`. The
  findings list key is **`findings`**.
- **Per-finding keys:** `path` (req — **NOT `file_path`**; `file_path` → 400),
  `rule_id` (req), `message` (req), `severity` (opt, lowercase 5-level), `line_start`/
  `line_end` (opt int ≥ 1 or null), `fingerprint` (opt **top-level** string),
  `suggestion` (opt), `metadata` (opt object), `language` (opt).
- **Severity set:** `critical | high | medium | low | info` (lowercase). Unknown →
  `info` fail-soft (we never hit it — our map is total).
- **Transforms we must respect:** `suggestion` truncated server-side at 10 000 chars;
  `metadata` preserved as semantic JSON (no key-order/dupe reliance); `line_start`
  beyond the on-disk file length is cleared to `null` (a warning is returned).
- **Response:** `ScanIngestResponseLoom` = `{succeeded: [ids], failed: [], stats:
  {files_created, files_updated, findings_created, findings_updated,
  observations_created, observations_failed}, warnings: [str]}`.

### Clarion 1.0.0 — qualname reconciliation (producer-side only)
- The reconciliation **consumer is not built** in 1.0.0 (`wardline_json` column
  reserved/all-None; `wardline_probe.py` proves only the import/version handshake;
  the NG-25 descriptor reader is deferred to v0.2). Clarion still imports
  `wardline.core.registry` directly.
- Therefore SP4 has **no live Clarion read-path to integrate against**. Wardline's
  only obligation is to keep emitting the correct pre-composed qualname (already done
  in `to_filigree_metadata`) and to **pin the producer** against Clarion's spec
  vectors so future reconciliation is lossless.
- `module_dotted_name` (`clarion/.../extractor.py:233-257`) and `reconstruct_qualname`
  (`.../qualname.py:34-48`) match Wardline's vendored `core/qualname.py` (validated
  in SP1a). **Note:** Wardline returns `None` where Clarion returns `""` for a
  top-level `__init__.py`; these are semantically equivalent at the emit boundary
  ("emit no entity"). The conformance test maps `None ↔ ""`.
- Spec vectors live at `clarion/docs/federation/fixtures/wardline-qualname-normalization.json`
  (12 module + 6 qualname vectors). Wardline vendors a **copy** (no read of `~/clarion`
  at test time).

---

## 3. Architecture

Three independent stages, each separately testable, none depending on a sibling at
runtime:

```
findings: list[Finding]   (already suppression-annotated by SP3)
   ├── SP4a  core/sarif.py     build_sarif(findings) -> dict     --format sarif → SarifSink
   ├── SP4b  core/filigree_emit.py
   │          build_scan_results_body(findings, *, scan_source) -> dict   (pure)
   │          FiligreeEmitter(url, transport).emit(findings) -> EmitResult --filigree-url
   └── SP4c  tests/conformance/  (no production code; producer pinning only)
```

`build_sarif` and `build_scan_results_body` are **pure functions of `findings`** —
same shape as `JsonlSink` / `to_filigree_metadata`, no registry coupling, no I/O.
This keeps every transform hermetically unit-testable against the contract fixtures.

---

## 4. SP4a — SARIF 2.1.0 emitter

**Files:** create `src/wardline/core/sarif.py`, `tests/unit/core/test_sarif.py`;
modify `src/wardline/cli/scan.py` (replace the stub).

`build_sarif(findings: Sequence[Finding]) -> dict[str, Any]` returns a SARIF 2.1.0
log: `{"version": "2.1.0", "$schema": <sarif-2.1.0 schema url>, "runs": [run]}` with a
single run.

- `run.tool.driver` = `{"name": "wardline", "informationUri": <repo url>,
  "version": <wardline __version__>, "rules": [...]}`.
- **`rules`** = the distinct `rule_id`s present in `findings`, in first-seen order,
  each as `{"id": rule_id}`. (Minimal valid ruleDescriptors; rich per-rule docs are
  out of scope — they'd couple SARIF to the registry and engine codes like
  `WLN-ENGINE-*` carry no `RuleMetadata`.) Results reference `ruleId` + `ruleIndex`.
- **`run.results`** = one SARIF result per finding:
  - `ruleId` = `finding.rule_id`; `ruleIndex` = index into `rules`.
  - `level` ← severity: `CRITICAL/ERROR → "error"`, `WARN → "warning"`,
    `INFO → "note"`, `NONE → "none"`.
  - `message.text` = `finding.message`.
  - `locations` = `[{"physicalLocation": {"artifactLocation": {"uri": location.path},
    "region": {...}}}]`; `region` carries `startLine`/`endLine`/`startColumn`/
    `endColumn` **only when non-None** (omit null keys — SARIF regions reject nulls).
    A finding with no `line_start` emits a `physicalLocation` with `artifactLocation`
    only (no `region`).
  - `partialFingerprints` = `{"wardlineFingerprint/v1": finding.fingerprint}`.
  - `properties` = `{"qualname"?, "kind", "internalSeverity", "confidence"?,
    "relatedEntities"?, "wardlineProperties"?}` (optionals omitted when absent —
    mirrors `to_filigree_metadata`'s discipline).
  - **Suppression:** when `finding.suppressed is not ACTIVE`, set
    `result.suppressions = [{"kind": "external", "status": "accepted"}]` and, for a
    waiver, include `"justification": finding.suppression_reason`. (SARIF's native
    suppression channel — baseline/waiver are external, not in-source.)

`SarifSink(path)` writes `json.dumps(build_sarif(findings), indent=2)`. CLI: when
`--format sarif`, default output path is `path / "findings.sarif"`; otherwise honor
`--output`. Suppression annotation and the `--fail-on` gate are unchanged (they run on
`findings` regardless of output format).

---

## 5. SP4b — native Filigree emitter

**Files:** create `src/wardline/core/filigree_emit.py`,
`tests/unit/core/test_filigree_emit.py`; modify `src/wardline/cli/scan.py`.

### Pure body builder
`build_scan_results_body(findings, *, scan_source: str = "wardline") -> dict` returns
`{"scan_source": scan_source, "findings": [_finding_to_wire(f) for f in findings]}`.

`_finding_to_wire(f)` →
```python
{
  "path": f.location.path,
  "rule_id": f.rule_id,
  "message": f.message,
  "severity": severity_to_filigree(f.severity),   # lowercase 5-level
  "line_start": f.location.line_start,             # may be null
  "line_end": f.location.line_end,                 # may be null
  "fingerprint": f.fingerprint,                    # TOP-LEVEL
  "suggestion": _cap_suggestion(f.suggestion),     # ≤ 10 000 chars; omit if None
  "metadata": to_filigree_metadata(f),             # {"wardline": {...}} incl. suppression
  "language": "python",
}
```
- **Emit ALL kinds** (user decision: *Everything*). No kind filter — DEFECT, FACT,
  CLASSIFICATION, METRIC, SUGGESTION all go. `metadata.wardline.kind` carries the kind;
  facts/metrics map `severity → info`. This matches `Finding` being a superset of
  Filigree's intake.
- `_cap_suggestion(s)`: `None → omit the key`; else truncate to ≤ 10 000 chars
  (avoids Filigree's server-side truncation warning). Key omitted entirely when None;
  `path`/`rule_id`/`message`/`fingerprint` always present; `severity`/`line_*`/
  `metadata`/`language` always present (nulls allowed for `line_*`).

### Transport + emitter
```python
class Transport(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response: ...
```
`Response = {status: int, body: str}`. The default `UrllibTransport` uses
`urllib.request` (stdlib only — no new dependency, federation-lightweight) with a
30 s timeout. Tests inject a fake transport; **no live server in the unit suite**
(a live e2e is optional, run only if a Filigree is already up).

`FiligreeEmitter(url, transport=UrllibTransport()).emit(findings) -> EmitResult`:
1. `body = json.dumps(build_scan_results_body(findings)).encode("utf-8")`.
2. POST to the **full user-supplied URL** (no path assembly, no ethereal-vs-server
   mode assumption — the user passes e.g.
   `http://localhost:8377/api/loom/scan-results`).
3. **Outcome split (load-bearing):**
   - **Sibling absent** — connection refused, DNS failure, timeout (`URLError`
     without an HTTP status): **warn and continue** (`EmitResult.reachable = False`).
     `wardline scan` proceeds to the gate; exit code is unaffected. Enrichment is
     non-load-bearing.
   - **Protocol error** — any HTTP status ≥ 400 (`HTTPError`): **loud failure**. This
     means Wardline built a bad payload — a Wardline bug, not a sibling outage. Echo
     the response body to stderr and raise so the CLI exits **2** (tool-error lane),
     *even if findings are otherwise clean*.
   - **Success** (2xx): parse `ScanIngestResponseLoom`; **surface `warnings[]` and
     `stats`** to the user (Filigree reports severity coercions and line clamps here —
     silence would hide on-wire mangling). Print a one-line summary
     (`emitted N finding(s) to <url> — C created / U updated[; W warning(s)]`).

### CLI wiring
`--filigree-url` (default None) on `wardline scan`. When set, after writing local
output and before the gate: construct `FiligreeEmitter`, call `.emit(findings)` inside
the existing `try/except WardlineError` boundary. A protocol error raises a new
`FiligreeEmitError(WardlineError)` → caught → exit 2. A sibling-absent path warns via
`click.echo(..., err=True)` and falls through. Order: scan → suppress → write output →
**emit (if url)** → print scan summary → gate.

---

## 6. SP4c — Clarion producer conformance

**Files:** create `tests/conformance/clarion_qualname_parity.json` (a vendored copy of
Clarion's fixture, with a header note recording provenance + sync instructions);
`tests/conformance/test_clarion_qualname_parity.py`.

The test drives every vector through Wardline's producer:
- **`module_normalization_vectors`:** assert `module_dotted_name(file_path)` equals
  `expected_module`, mapping `expected_module == "" ⟺ module_dotted_name(...) is None`
  (Wardline's "emit no entity" sentinel == Clarion's empty-and-rejected).
- **`qualified_name_vectors`** of `kind == "function"`: assert
  `f"{module_dotted_name(file_path)}.{qualname}"` equals `expected_qualified_name`
  (qualname copied verbatim — `<locals>` and nested-class chains untouched).
- The single `kind == "module"` vector (qualname null, `expected_qualified_name` ==
  the module dotted name) is asserted at the `module_dotted_name` half only — Wardline
  emits entities for functions/methods, not module entities (SP1a), so there is no
  module-qualname to compose; the prefix-reproduction is what the contract needs.

No production code changes — `to_filigree_metadata` already emits `qualname`, and the
qualname machinery is unchanged since SP1a. This stage converts byte-equality from
assumption to a committed CI test on Wardline's side.

---

## 7. Fingerprint line-stability — reconciled (no change)

The Loom brief's Filigree-side design refreshes `line_start` under a *stable*
fingerprint when code moves. Wardline's `compute_finding_fingerprint` **includes**
`line_start` by the user's explicit SP3 dial (strict line-sensitive matching).
Consequence: a line move re-keys the finding — Filigree sees a *new* fingerprint
(creates a new finding; the old one becomes `unseen_in_latest`), so Filigree's
`line_start`-refresh path is **inert for Wardline**. This is a *consequence* of an
already-made decision, not a fresh one: reopening fingerprint composition would break
SP3 baselines and waivers. **Decision: no change; documented here.** The taint-path
disambiguation (the actual Filigree ask-B constraint — two paths into one sink get
distinct fingerprints) is preserved.

---

## 8. Decomposition

- **SP4a** — SARIF emitter + `--format sarif` wiring + tests.
- **SP4b** — Filigree emitter (pure body builder + transport + emitter) +
  `--filigree-url` wiring + tests.
- **SP4c** — Clarion producer conformance fixture + test.

Order SP4a → SP4b → SP4c (SARIF is self-contained; Filigree reuses the SP0/SP2 wire
mappers; conformance is independent and can land anytime).

---

## 9. Testing

- **SP4a:** `build_sarif` shape/version; severity→level table; region omits null keys;
  no-line finding has no region; `partialFingerprints` carries the fingerprint;
  suppressed finding emits `result.suppressions` (waiver carries justification); rules
  array is first-seen-unique; `SarifSink` round-trips valid JSON; CLI `--format sarif`
  writes a `.sarif` file and the gate still fires.
- **SP4b:** body uses `path` not `file_path`; `fingerprint` top-level; severity
  lowercase-mapped; `suggestion` capped at 10 000 (and omitted when None);
  `metadata.wardline.*` present incl. suppression; all kinds emitted; injected
  transport — **success** surfaces stats/warnings; **HTTP 400** raises
  `FiligreeEmitError` → CLI exit 2 (loud, body echoed); **connection refused/timeout**
  warns, `reachable=False`, CLI continues to the gate (exit unaffected).
- **SP4c:** every vendored vector passes, including the `None ↔ ""` mapping and the
  divergence traps (`lib/` not stripped, `src` not at position 0, `<locals>` verbatim).

Full gate after every stage: `.venv/bin/python -m pytest -q`,
`.venv/bin/ruff check src tests`, `.venv/bin/mypy src`.

---

## 10. Non-goals

- No live Clarion reconciliation (consumer unbuilt in 1.0.0). No entity-association
  emission (ADR-029, deferred).
- No new runtime dependencies — SARIF and Filigree emission are stdlib-only
  (`json`, `urllib.request`).
- No `mark_unseen`/`scan_run_id`/`create_observations` control on the first cut —
  Filigree defaults stand; these can be exposed later if a workflow needs them.
- No SARIF rule-doc enrichment (descriptions/help) — minimal ruleDescriptors only.
- No fingerprint recomposition (see §7).

---

## 11. Risks

- **R1 — protocol/absent conflation.** Swallowing a 400 as "sibling absent" would hide
  emitter bugs. Mitigated by the explicit `HTTPError` (status) vs `URLError`
  (no status) split in §5; pinned by two distinct tests.
- **R2 — silent on-wire mangling.** Filigree clamps lines / coerces severity and
  reports it only in `warnings[]`. Mitigated by surfacing `warnings`/`stats` (§5).
- **R3 — fixture drift.** Clarion's vendored fixture can fall out of sync. Mitigated
  by a provenance header recording the source path + the one-line resync, and the test
  failing loudly on any divergence.
- **R4 — SARIF region nulls.** Emitting `startLine: null` produces invalid SARIF.
  Mitigated by omitting null region keys (§4) and a no-line test.
