# SP3 — Light-touch Baseline + Waivers (Design)

**Status:** Approved design (brainstormed with the default 7-lens panel 2026-05-30).
**Supersedes:** nothing. **Depends on:** SP2 (the `Finding.fingerprint` taint-path identity is the baseline/drift spine).
**Contract:** [Loom integration brief](../../integration/2026-05-29-wardline-loom-integration-brief.md) §3.B (the Wardline `fingerprint` is "the spine of SP3's baseline/drift detection").

---

## 1. Goal

Give a single user a **git-committable, human-readable** way to (a) accept the current set of findings as a *baseline* so future scans surface only new ones, and (b) *waive* specific findings with a written reason and optional expiry. Make the long-reserved `wardline scan --fail-on SEVERITY` gate go live, tripping only on findings that are neither baselined nor waived. **No HMAC, signing, counter-signatures, coverage/override gates, BAR, IRAP, or conformance — ever.** The mantra holds: enterprise functionality with single-person simplicity.

## 2. Design posture (fixed dials, user-chosen 2026-05-30)

1. **Strict full-fingerprint match.** The baseline matches a finding on its complete `Finding.fingerprint` (which folds in `line_start`), keeping identity consistent with Filigree's dedup key. Accepted cost: a line-shifting edit re-keys the finding (see §10, Limitation L1).
2. **Annotate-and-keep.** Suppressed findings are **not dropped**; they stay in `findings.jsonl` annotated with a typed marker, and `--fail-on` ignores them.
3. **Waiver = required reason + optional expiry.** An expired waiver stops suppressing (the finding resurfaces); a waiver with no expiry is permanent.
4. **Split layout.** The machine-generated baseline lives in `.wardline/baseline.yaml` (regenerated wholesale, committed); hand-authored waivers live inline in `wardline.yaml` under a `waivers:` block.

These four are not relitigated below. Everything else is the panel-shaped design.

## 3. Architecture & module boundaries

Three small, pure-ish `core/` modules plus a thin CLI wiring stage. **Suppression runs as a post-analyze stage in the CLI, never inside `WardlineAnalyzer.analyze`** — the analyzer keeps emitting the raw, Filigree-facing analysis *fact*; baseline/waiver is *policy* layered on top.

```
analyze (raw findings)
   → apply_suppressions(findings, baseline, waivers, today=…)   # annotate, don't drop
   → JsonlSink.write(annotated findings)                        # findings.jsonl always written
   → evaluate --fail-on gate over non-suppressed DEFECTs        # exit 0/1
```

- **`core/baseline.py`** — the baseline model + load/write.
- **`core/waivers.py`** — the waiver model + parse-from-config + match.
- **`core/suppression.py`** — the pure suppression function + the `--fail-on` gate predicate.
- **`core/finding.py`** (modified) — a typed top-level `suppressed` field on `Finding`.
- **`cli/scan.py`** (modified) — load baseline + waivers, apply, annotate, gate, summary line.
- **`cli/main.py`** (modified) — the `wardline baseline create|update` command group.

Rationale for the seam: `Finding` is documented as a superset of Filigree's intake, and Filigree owns *lifecycle*. Putting suppression inside the analyzer would contaminate the raw fact a Loom consumer wants; putting it in a `Sink` would conflate output-formatting with policy. A pure post-analyze function is the clean boundary.

## 4. The `suppressed` marker on `Finding` (typed, top-level)

Dial #2 said "annotate, e.g. `properties.suppressed`". The Python-engineering lens flagged that `properties` is serialized wholesale into both `to_jsonl` and `to_filigree_metadata` and is `Any`-typed — burying triage state there leaks it onto the Filigree wire (violating "lifecycle is Filigree's domain, deliberately absent here") and defeats `mypy --strict`. So the marker is a **typed top-level field** instead:

```python
class SuppressionState(StrEnum):
    ACTIVE = "active"        # not suppressed — the default
    BASELINED = "baselined"  # matched a baseline fingerprint
    WAIVED = "waived"        # matched an active waiver

@dataclass(frozen=True, slots=True)
class Finding:
    ...                                  # existing fields unchanged
    suppressed: SuppressionState = SuppressionState.ACTIVE   # additive, default-valued
    suppression_reason: str | None = None                    # the waiver reason, when WAIVED
```

Both new fields are additive with defaults — backward-compatible with every existing `Finding(...)` call and the frozen+slots contract. `to_jsonl` serializes `suppressed`/`suppression_reason` (annotate-and-keep: the JSONL record shows the disposition). `to_filigree_metadata` includes them under the already-namespaced `metadata.wardline` subtree (Wardline-local triage, clearly namespaced — *not* conflated with Filigree's own lifecycle columns); SP4 owns the final wire decision. **`suppressed` is NOT a fingerprint input** — suppression must never change identity.

Annotation is non-mutating: `apply_suppressions` builds annotated copies with `dataclasses.replace(f, suppressed=…, suppression_reason=…)` (valid with `slots=True`; `replace` calls `__init__`).

## 5. `core/baseline.py`

```python
BASELINE_VERSION: int = 1   # bumped on format change; validated on load (mirrors STDLIB_TAINT_VERSION)

@dataclass(frozen=True, slots=True)
class Baseline:
    fingerprints: frozenset[str]          # the match set — O(1) membership, immutable

    def contains(self, fingerprint: str) -> bool: ...
```

**File format** (`.wardline/baseline.yaml`, committed):

```yaml
version: 1
entries:
  - fingerprint: 9f3a…   # 64-hex; the ONLY matched field
    rule_id: PY-WL-101    # human-reference only (not matched)
    path: src/app/api.py  # human-reference only
    message: "app.handler declares … but returns …"  # human-reference only
```

The per-entry `rule_id`/`path`/`message` make the committed file auditable in a git diff (a bare hash list is unreviewable — the antithesis of "human-readable governance"); only `fingerprint` is loaded into the match set. Entries are written **sorted by (severity desc, rule_id, path, fingerprint)** so CRITICALs sit at the top of the diff and the file is git-stable across regenerations.

- `load_baseline(path: Path) -> Baseline` — `yaml.safe_load`; validate `version == BASELINE_VERSION`, `entries` is a list, each `fingerprint` a non-empty 64-hex str, **reject duplicate fingerprints** (a dup is silent in a set — detect at parse, raise; mirrors `stdlib_taint._build_table`). Malformed → `ConfigError`. **Missing file → empty `Baseline` (suppress nothing)**; empty/`{}` file → empty `Baseline`. *Never* silently treat malformed as empty (that would mass-unsuppress).
- `write_baseline(path: Path, findings: Iterable[Finding]) -> None` — write the sorted entries for the given findings; creates `.wardline/` if absent. IO separated from a pure `build_baseline_document(findings) -> dict` so validation/serialization is unit-testable without disk.

## 6. `core/waivers.py`

```python
@dataclass(frozen=True, slots=True)
class Waiver:
    fingerprint: str          # matched (copied from scan output / findings.jsonl)
    reason: str               # REQUIRED — the honesty floor
    expires: date | None = None   # optional; None = permanent

def parse_waivers(raw: Sequence[Mapping[str, Any]]) -> tuple[Waiver, ...]: ...

class WaiverSet:
    def match(self, fingerprint: str, today: date) -> Waiver | None:
        """The active (non-expired) waiver for this fingerprint, else None."""
```

Waivers are hand-authored in `wardline.yaml`:

```yaml
waivers:
  - fingerprint: 4b1c…
    reason: "false positive — validated upstream in middleware"
    expires: 2026-09-01        # optional ISO date
```

- **Parsing lives in `core/waivers.py`, not `config.load()`.** `config.load` stays a thin shape-loader; add `"waivers"` to its `_KNOWN_KEYS` and expose the raw list as `WardlineConfig.waivers: tuple[Mapping[str, Any], ...] = ()` (parallel to the existing reserved raw maps). `parse_waivers(config.waivers)` does the typed parse + date validation. This mirrors the load-raw / `_build_*`-validate split used by `stdlib_taint`.
- **Date handling.** `expires` may arrive from `safe_load` as a `date` (unquoted ISO), a `datetime` (if a time slipped in), or a `str` (quoted/other). Normalize: **check `datetime` before `date`** (`datetime` *is a subclass of* `date` — the order matters or a datetime silently passes as a date), else `date.fromisoformat(str)`. Unparseable → `ConfigError` (fail-loud: a typo'd date must never read as "never expires").
- **Validation (fail-loud, exit 2):** missing/empty `reason` → `ConfigError`; non-64-hex `fingerprint` → `ConfigError`; unparseable `expires` → `ConfigError`. A *past* `expires` is valid config (the waiver simply doesn't suppress).

## 7. `core/suppression.py`

```python
SEVERITY_ORDER: tuple[Severity, ...] = (Severity.INFO, Severity.WARN, Severity.ERROR, Severity.CRITICAL)
# NONE is absent — facts/metrics never participate in the gate.

def apply_suppressions(
    findings: Iterable[Finding], baseline: Baseline, waivers: WaiverSet, *, today: date,
) -> list[Finding]:
    """Annotate each DEFECT finding's `suppressed`/`suppression_reason`; copy others through.
    Precedence: an ACTIVE waiver wins over the baseline (it carries the reason + expiry, so
    expiry stays observable). Returns annotated copies; never mutates or drops."""

def gate_trips(findings: Iterable[Finding], fail_on: Severity) -> bool:
    """True iff any finding is kind=DEFECT, suppressed==ACTIVE, and severity >= fail_on
    in SEVERITY_ORDER. Non-DEFECT kinds and NONE-severity never trip."""
```

- Only `Kind.DEFECT` findings are subject to suppression and gating; FACT/METRIC/CLASSIFICATION/SUGGESTION pass through `ACTIVE` and never gate.
- **Expiry boundary:** a waiver is valid *through* its expiry date — `expired = today > expires` (so `expires == today` still suppresses). Pinned with a test at `today == expires`.
- **Precedence:** if a fingerprint is in both the baseline and an active waiver → `WAIVED` (reason-bearing), counted once. An *expired* waiver on a baselined fingerprint → the baseline still suppresses it as `BASELINED` (its expiry is a no-op; this is the documented consequence of dial #1+#4, surfaced only via the summary count, not changed).

## 8. CLI surface

### `wardline scan` (modified)

`--fail-on SEVERITY` goes **live**. Pipeline: analyze → `apply_suppressions(…, today=date.today())` → write annotated `findings.jsonl` → if `--fail-on` given and `gate_trips(...)`, exit **1**. `today` is sourced **once** here (`date.today()`) and threaded into the pure suppression layer, so everything below the CLI is hermetic.

**Exit lanes stay disjoint:** `0` = clean (or gate not tripped), `1` = `--fail-on` tripped on a non-suppressed DEFECT, `2` = tool error (`WardlineError`, already wired). The baseline is read **read-only** during `scan` — `scan` never mutates `.wardline/baseline.yaml` (mutation is only via the `baseline` verbs). An absent baseline file or absent `--fail-on` are both inert (suppress nothing / don't gate).

**Summary line** (extends the existing one at `scan.py:59`) — the one piece of always-on visibility that keeps the baseline honest (Meadows Level-6 information-flow leverage), no drift subsystem:

```
scanned N file(s); M finding(s) — S suppressed (B baseline / W waiver), A new
```

`A new` = non-suppressed DEFECT count. (Stale-baseline / dead-waiver / drift-report subsystems are deliberately **out** — `git diff` on the committed files is the audit/drift surface for a single user.)

### `wardline baseline` (replaces the SP0 stub)

- **`wardline baseline create [PATH]`** — runs the same scan as `wardline scan PATH` (identical discovery + config; `PATH` defaults to `.`), then writes `.wardline/baseline.yaml` from the resulting `Kind.DEFECT` findings **minus any fingerprint with an active waiver** (else the baseline swallows waived findings and their expiry never resurfaces — a real correctness bug). **Refuse (exit 2) if the file already exists** (use `update` to overwrite). Prints a severity breakdown of what it accepts (`baselining N findings: 1 CRITICAL, 3 ERROR, …`) so a CRITICAL can't be buried by one keystroke unseen. (Because the captured set is exactly the scanned scope, baselining a partial `PATH` writes a partial baseline — scan the whole project to capture the whole baseline.)
- **`wardline baseline update [PATH]`** — identical, but overwrites an existing baseline (a full re-derive over the scanned scope: drops fingerprints no longer produced, captures current). The git diff shows exactly what changed.

`list` and `prune` are **not** provided: `list` is `cat .wardline/baseline.yaml` / `git show` on a human-readable file; `prune` is folded into `update`'s re-derive. Waivers have no CLI verb — they are hand-authored in `wardline.yaml`, keyed by a fingerprint copied from the scan output.

## 9. Decomposition

| Stage | Scope | Acceptance |
|---|---|---|
| **SP3a** | Pure core: `Finding.suppressed`/`suppression_reason` fields (+ JSONL/Filigree serialization); `core/baseline.py` (`Baseline`, `BASELINE_VERSION`, `load_baseline`/`write_baseline`/`build_baseline_document`); `core/waivers.py` (`Waiver`, `parse_waivers`, `WaiverSet.match`); `core/suppression.py` (`apply_suppressions`, `gate_trips`, `SEVERITY_ORDER`). `WardlineConfig.waivers` raw field + `_KNOWN_KEYS`. | Round-trip `write`→`load`; suppression precedence (waiver-wins); expiry boundary (`== today` active, `> today` expired); `datetime`/`date` parse; fail-loud on malformed baseline / bad-expiry / missing-reason; `gate_trips` matrix (see §10); all pure, hermetic (`today` injected). |
| **SP3b** | `cli/scan.py`: load baseline (`.wardline/baseline.yaml`) + waivers (config), `apply_suppressions(today=date.today())`, annotated JSONL, **`--fail-on` live**, the summary line. | Suppressed DEFECT ≥ threshold → exit 0; non-suppressed DEFECT ≥ threshold → exit 1; expired waiver → finding resurfaces → exit 1; tool error → exit 2; missing baseline → inert; summary counts correct. |
| **SP3c** | `cli/main.py`: `wardline baseline create` / `update` (replace the stub), excluding active-waiver fingerprints, severity-breakdown print, refuse-if-exists on `create`. | `create` writes a sorted committed baseline; re-scan suppresses those findings; `create` refuses if file exists; `update` overwrites + re-derives; waived findings are excluded from the written baseline. |

Each stage is independently testable and shippable. SP3a's `apply_suppressions`/`build_baseline_document` contracts must bake in the "exclude active-waiver fingerprints" and "waiver-wins precedence" rules even though `create` (SP3c) is where exclusion is exercised — or the expiry bug ships latent.

## 10. Testing strategy

- **`gate_trips` matrix:** no findings (0); suppressed DEFECT ≥ threshold (0); non-suppressed DEFECT ≥ threshold (1); DEFECT below threshold (0); DEFECT == threshold exactly (1, confirms `>=`); FACT/METRIC at any severity (0); `Severity.NONE` (0); `--fail-on` absent (0); malformed config (2).
- **Highest-value fused test:** one DEFECT ≥ threshold → exit 0 with a live waiver, exit 1 once `today` advances past its expiry. Exercises fingerprint match + expiry boundary + annotate-and-keep + exit wiring in one shot, and catches the two likeliest defects (gate reading the pre-suppression set; expiry ignored).
- **Edge cases:** malformed `.wardline/baseline.yaml` → exit 2 (not silent-empty); baseline fingerprint no longer produced → silently ignored at match (surfaced only in git diff); waiver missing reason / unparseable expiry → exit 2; past expiry → resurfaces; empty vs missing baseline → both inert; repo-relative POSIX path normalization round-trips so fingerprints match cross-platform.
- **Limitation L1 pin:** a line-shifting edit (e.g. an added import above) changes a finding's `line_start` → new fingerprint → the baselined finding **resurfaces as new**. Pin this as expected behavior so it reads as a known property of dial #1, not a regression.
- **Self-hosting stays baseline-free:** `tests/test_self_hosting.py` keeps asserting 0 DEFECT with **no** baseline file, so it tests the analyzer, not the suppression layer.

## 11. Non-goals (explicit)

- **No** HMAC / signing / counter-signatures / coverage gates / override gates / BAR / IRAP / conformance — on anything.
- **No** stale-entry warnings, drift reports, dead-waiver detectors, `baseline list`/`prune` verbs, or `generated_at`/timestamp fields — ruled ceremony; `git diff` + the one summary line carry it.
- **No** waiver CLI authoring verb — hand-authored in `wardline.yaml`.
- **No** relaxation of the strict line-sensitive fingerprint (dial #1) and **no** change to the SP2c fingerprint composition.
- **No** SARIF / Filigree emission of the suppression state as authoritative — SP4 owns the wire.

## 12. Risks, limitations & forward-notes

- **L1 — line-sensitivity (accepted).** Per dial #1, a line move re-keys a finding (resurfaces-as-new + the old baseline entry goes inert). Documented + test-pinned. Hygiene is a cheap re-`update`, not a stale-detection subsystem.
- **Fingerprint collision (inherited, narrow).** The fingerprint coarsens `taint_path` (single best-callee), so two distinct findings sharing `(file, rule, line, qualname, taint_path)` collide — one waiver/baseline entry would suppress both. The fingerprint's inclusion of `qualname` + `line_start` makes this vanishingly rare for PY-WL-101 (rich taint_path) and structurally near-impossible for PY-WL-103/104 (a handler can't share a line with another). Mitigation: store `message` in baseline entries (visible in diff when it drifts); SP3a asserts DEFECT findings entering suppression carry a non-`None` `line_start`. Rate is unmeasured (greenfield) — do not quote a number.
- **CI rubber-stamp (loop guard).** The decay loop is "re-run `update` to make CI green," monotonically burying un-triaged findings. Guards: `update` prints what it accepts (severity breakdown) and the git diff is reviewable; **`scan` never mutates the baseline** (an explicit invariant — CI runs `scan`, never `baseline update`). Waivers carry the only built-in balancing loop (expiry); the baseline's only governor is the visible summary count.
- **Forward-note for SP4 — brief/implementation fingerprint tension (real).** The Loom brief's v17 design assumes the fingerprint is *line-stable* ("the update path must refresh `line_start` … since line can move while fingerprint holds"), but the SP2c fingerprint *includes* `line_start`, so a line move re-keys it. For SP3 this is moot (the user chose strict matching). But when SP4 builds the Filigree emitter, reconcile: either Filigree's `line_start`-refresh-on-fingerprint-match path is effectively dead (line moves change the fingerprint), or the fingerprint composition is revisited. Capture this in the SP4 spec; **out of scope for SP3.**
