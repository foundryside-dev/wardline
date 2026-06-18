# Warpline delta scan — implementation plan

- **Date:** 2026-06-18
- **Spec:** `docs/superpowers/specs/2026-06-18-warpline-delta-scan-design.md` (Approved)
- **Tracker:** `wardline-4e08ab9ce6` (B, this plan) · `wardline-c0563eee74` (A, follow-on — out of scope)
- **Baseline commit:** `4a24a032`
- **Label:** `warpline-delta-2026-06-18`
- **Branch discipline:** all work on the single in-flight `rcX` branch (per memory `feedback_single_rc_branch_no_scatter`); one PR `rcX → main`.

## 0. Orientation — what already exists vs. what is new

Read before writing code. Two distinct "delta" concepts coexist and **must not be conflated**:

| Concept | Existing? | What it scopes | Mechanism |
|---|---|---|---|
| `--new-since <gitref>` | **Yes** — `src/wardline/core/delta.py` (`get_changed_files_since`, `get_affected_entities`) + `run_scan(new_since=...)` | the **gate** (out-of-delta ACTIVE defects → BASELINED in both emitted + gate populations); **full analysis still runs** | git diff + caller-side call-graph closure over `last_context` |
| `--affected <file\|->` | **No — this plan** | **discovery/analysis** (engine analyzes only files containing an affected entity, **caller-closure-expanded**) + a **finding post-filter on the DISPLAYED set only** (the gate population is never narrowed — INV-4) | producer-supplied entity scope set (warpline worklist or bare entity list) — **untrusted/unauthenticated input** |

These are orthogonal **and mutually exclusive at the surface** (composing them is rejected loudly). `--new-since` keeps working byte-identically. The new `--affected` is a *pre-filter on which files reach `analyzer.analyze`* plus a *post-filter on the emitted findings* — but **NOT** on `gate_findings`: an attacker-influenceable scope must never forge a green (INV-4 / THREAT-001). The deferred `--since` (§Phase 8) is the only overlap — it *produces* an affected set from a gitref and then runs the `--affected` path; it does **not** reuse the `new_since` gate-scoping machinery.

Confirmed real symbols this plan builds on:

- `src/wardline/core/run.py` — `run_scan(...)`, `ScanResult`, `ScanSummary`, `gate_decision`, `GateDecision`. `run_scan` does `files = discover(...)` then `raw = list(analyzer.analyze(files, cfg, root=root))`. **The file-set scoping seam is between those two lines.** `analyzer.last_context` (`AnalysisContext`) carries `entities: Mapping[str, Entity]` and `project_edges`.
- `src/wardline/scanner/index.py` — `discover_file_entities(tree, *, module, path) -> list[Entity]`; `Entity.qualname`, `Entity.location` (`Location.path`). This is the **cheap structural pass** for the qualname→file index (no taint analysis needed).
- `src/wardline/core/qualname.py` — `module_dotted_name(rel_path)` for the module half of a qualname.
- `src/wardline/loomweave/identity.py` — `SeiResolver`, `SeiCapability`, `SeiResolver.resolve_sei`-style via `resolve_identity_status` / underlying client; `EntityBinding`. `src/wardline/core/sei_resolution.py` — `locator_to_qualname(locator)` (maps `python:function:pkg.mod.f` → `pkg.mod.f`) and the SEI-resolve pattern in `resolve_query_filters` (resolve `loomweave_client.resolve_sei(sei)["current_locator"]` → `locator_to_qualname`).
- `src/wardline/core/finding.py` — `Finding` (`qualname`, `location.path`, `fingerprint`, `kind`, `severity`); `compute_finding_fingerprint` (the **fingerprint invariant** — never touched by this plan); `_PROPERTY_ACCESSOR_QUALNAME_SUFFIXES` + `_to_wire_qualname` (suffix-stripping for `:setter`/`:deleter` — reuse for canonicalization, Phase 2/4).
- `src/wardline/core/filigree_emit.py` — `build_scan_results_body(..., mark_unseen=None)`; **auto-enables `mark_unseen` when findings/`scanned_paths` non-empty** — the INV-5 hazard; delta emit must force `mark_unseen=False`.
- `src/wardline/core/delta.py` — `get_affected_entities(changed_files, entities, project_edges)` builds the **reverse callee→caller** graph; **reused by Phase 2's caller-closure expansion** (taint findings anchor caller-side; warpline's worklist is downstream/callee).
- `src/wardline/core/sei_resolution.py` — `locator_to_qualname` prefix list **must gain `python:method:`** (Phase 2 bug fix; loomweave emits `kind="method"`, `index.py:95`).
- `src/wardline/core/sarif.py` — `SarifSink.write(findings, context=None)` + `build_sarif` — **gain an optional `run_properties` channel** for the SARIF scope block (Phase 7).
- `src/wardline/cli/scan.py` — the `scan` click command; pattern for fail-soft sibling blocks and `WardlineError → SystemExit(2)`.
- `src/wardline/mcp/server.py` — `_scan(args, root, ...)` handler (line ~792); `_SCAN_TOOL` inputSchema (line ~1739, properties incl. `new_since` at ~1832) and `_SCAN_OUTPUT_SCHEMA`.
- `src/wardline/mcp/tooling.py` — `ToolError`, `resolve_under_root`.
- `src/wardline/_live_oracle.py` — `LIVE_ORACLE_MARKERS` frozenset (currently `network, loomweave_e2e, legis_e2e, filigree_e2e`; **`rust_e2e` is deliberately NOT in it**).
- `pyproject.toml` `[tool.pytest.ini_options]` — `addopts` deselection string + `markers` list.
- `.github/workflows/ci.yml` — `live-oracles` job matrix (lines 149–187).
- `tests/conformance/` — golden-vector + faithful-vendor conventions (`test_legis_intake_contract.py`, `test_sei_oracle.py`); `tests/conftest.py` SKIP→FAIL hook.

---

## Invariants (assert with tests in Phase 9)

- **INV-1 — full-scan path unchanged.** When `affected` is not supplied, `run_scan` is byte-identical to today: same discovered files reach `analyzer.analyze`, same findings, same `ScanSummary`, same `gate_findings`. Proven by an existing-vs-new equivalence test.
- **INV-2 — fingerprints stable.** No code in this plan calls or alters `compute_finding_fingerprint` / `Finding.fingerprint`. The finding *filter* drops findings; it never re-mints identity. Proven by asserting filtered findings' fingerprints == the same findings' fingerprints in a full scan.
- **INV-3 — fail-closed honesty.** An `affected` input that resolves zero files (empty/malformed-but-parseable/all-unresolvable) → **full-fallback scan**, declared in the `scope` block; never a silent narrow.
- **INV-4 — an untrusted scope can never forge an authoritative green (THREAT-001).** `--affected` is attacker-influenceable input (a warpline worklist derived from filigree/loomweave state, or a hand-supplied/stale JSON blob with no signature, producer identity, or freshness binding — unlike `--new-since`, whose gitref is operator-supplied and computed locally). Therefore **the delta finding filter narrows only the EMITTED/displayed findings (`findings`), NEVER the gate population (`gate_findings`).** In delta mode the severity gate evaluates the *full unsuppressed population* exactly as a full scan would, so a worklist that surgically excludes the one file containing a real ERROR sink **cannot** produce `verdict="PASSED"` / exit 0. Fail-closed-on-empty (INV-3) does NOT cover this surgical-exclusion case (it only fires when ZERO files resolve, which a precise exclusion does not); INV-4 is the structural protection, not a deployment convention. Proven by a test: a worklist excluding a known-ERROR file MUST NOT yield a PASSED severity verdict and the verdict/exit must be identical to the full scan's.
- **INV-5 — Filigree reconciliation is never poisoned by a delta run (mark_unseen).** `FiligreeEmitter` auto-enables `mark_unseen` when findings/`scanned_paths` are non-empty (`filigree_emit.build_scan_results_body`), interpreting a fingerprint absent from a scanned path as "fixed" and closing the issue. A delta run emits the FULL discovery list as `scanned_paths` but a FILTERED `findings` list, so out-of-scope findings would be read as fixed → issues closed → irreversible signal loss. In delta mode the CLI emitter MUST be invoked with `mark_unseen=False` (a delta scan never reconciles closure); the `scope` block states that full reconciliation requires a full scan.

---

## Phase 1 — `delta_scope.py`: parse the affected-entity scope (§5.1)

**New file:** `src/wardline/core/delta_scope.py` (stdlib-only; base package stays zero-dep).

**Public interface:**

```python
@dataclass(frozen=True, slots=True)
class AffectedEntity:
    sei: str | None
    locator: str | None  # opaque-ish; warpline locator e.g. "python:function:pkg.mod.f"

@dataclass(frozen=True, slots=True)
class AffectedScope:
    entities: frozenset[AffectedEntity]
    source_kind: str        # "reverify_worklist_v1" | "entity_list" | "empty"
    item_count: int

class ScopeParseError(WardlineError):  # malformed payload — loud (exit 2), NOT a degrade
    ...

def parse_affected_scope(payload: object) -> AffectedScope: ...
def load_affected_scope(source: str) -> AffectedScope: ...
    # Internal helper: reads the JSON file at `source` (a real path) and delegates to
    # parse_affected_scope. It does NOT handle stdin — the CLI owns the stdin handle via
    # click.File('-') and passes already-read text to parse_affected_scope (see Phase 7).
    # parse_affected_scope(payload) is the sole public entry point.
```

Accepted shapes (§5.1) — **two structurally-distinct envelope variants** that must each have their own fixture/test:
1. `warpline.reverify_worklist.v1` **full success envelope** — `{"data": {"items": [...]}}` (the `data` wrapper present) — reads `data.items[].entity.{sei, locator}`.
2. `warpline.reverify_worklist.v1` **bare `data` payload** — `{"items": [...]}` (no outer envelope) — a producer that sends the inner object directly. **Distinct object from (1); must parse correctly via its own fixture.**
3. Bare entity list — `[{"sei"?: str, "locator"?: str}, ...]`.

**Payload size cap (DoS guard — §7):** `parse_affected_scope` rejects a payload whose byte length OR `item_count` exceeds a fixed cap with `ScopeParseError` (the stdin/inline ingress is new and uncapped per the SP8 known gap). Pick a generous cap (e.g. 4 MiB / 50_000 items) — large enough never to bite a real worklist, small enough to bound a hostile blob.

Rules: an entity with neither `sei` nor `locator` is dropped (counts toward neither). Empty/zero-entity input is **not** a `ScopeParseError` — it returns `AffectedScope(frozenset(), "empty", 0)` and the fail-closed rule (Phase 5) handles it. A structurally-malformed payload (not an object/array, `items` not a list, entity not an object) **is** `ScopeParseError` → loud (§7 "Malformed scope payload → exit 2").

**Test (proves it):** `tests/unit/core/test_delta_scope.py` — **three distinct shapes with distinct fixtures: full envelope (`{"data": {"items": …}}`), bare-data (`{"items": …}`), bare list**; malformed → `ScopeParseError`; over-cap (bytes and item_count) → `ScopeParseError`; empty → `source_kind="empty"`, `item_count=0`; entity with only `sei`, only `locator`, both, neither; `load_affected_scope` reads a file and raises `ScopeParseError` on bad JSON.

**Verify:** `uv run pytest tests/unit/core/test_delta_scope.py -q`

---

## Phase 2 — entity→file resolution (§5.2)

**New file:** `src/wardline/core/delta_resolve.py`.

**Public interface:**

```python
@dataclass(frozen=True, slots=True)
class ResolvedScope:
    files: frozenset[str]              # repo-relative POSIX paths to analyze (caller-expanded)
    affected_qualnames: frozenset[str] # BASE affected set (canonical), for the finding filter (Phase 4)
    resolved: tuple[AffectedEntity, ...]
    fell_back: tuple[AffectedEntity, ...]    # resolved via qualname index, not loomweave
    stale_sei: tuple[AffectedEntity, ...]    # SEI resolved but qualname absent from current index
    unresolved: tuple[AffectedEntity, ...]
    loomweave_used: bool

@dataclass(frozen=True, slots=True)
class QualnameIndex:
    by_qualname: dict[str, str]                 # canonical qualname -> repo-relative POSIX path
    project_edges: dict[str, frozenset[str]]    # caller -> callees, for the reverse-edge closure
    entities: dict[str, str]                    # canonical qualname -> repo-relative POSIX path (for get_affected_entities)

def build_qualname_index(files: Sequence[Path], root: Path) -> QualnameIndex:
    # via ast.parse (try/except SyntaxError|OSError -> skip file) + index.discover_file_entities
    # + qualname.module_dotted_name + structural call-edge extraction. Cheap structural pass;
    # NO taint analysis. Keys are CANONICAL (suffix-stripped) qualnames.

def resolve_affected_scope(
    scope: AffectedScope,
    *,
    index: QualnameIndex,
    sei_resolver: SeiResolver | None,
) -> ResolvedScope:
    # Resolves each entity to a base file; then caller-expands ResolvedScope.files via the
    # reverse call graph (get_affected_entities over index.project_edges/entities). The
    # filter set (affected_qualnames) stays the BASE set; only the analyzed files expand.
```

Resolution order per entity (§5.2). **All qualname comparisons use a canonical key** (see canonicalization below):
1. **SEI present and `sei_resolver` supported** → resolve SEI to a current locator (mirror `sei_resolution.resolve_query_filters`: `client.resolve_sei(sei)["current_locator"]` → `locator_to_qualname`) → canonicalize → match in the index → file. Authoritative; entity → `resolved`.
   - **SEI-drift guard (§5.2):** if the SEI resolves but the returned qualname is **absent** from the freshly-built qualname index (loomweave stale vs working tree — e.g. a rename since loomweave's last index), the SEI is treated as effectively stale: fall through to the supplied-locator path (step 2) rather than landing the entity in `unresolved`. Record this as `loomweave_stale_sei` resolution.
2. **SEI absent / loomweave unavailable / SEI did not resolve / SEI drifted** → fall back: `locator_to_qualname(locator)` → canonicalize → match in `qualname_index` → file; entity → `fell_back`.
3. **Neither path yields a file** → entity → `unresolved` (contributes no file; trips fail-closed only when the WHOLE set is unresolved, per Phase 5).

**Caller-closure expansion (load-bearing — §5.3a).** Warpline's worklist is a "changed + downstream (callee)" set, but taint findings anchor **caller-side**. After resolving the affected entities to a base file set, **expand once over the reverse call graph**: reuse `core.delta.get_affected_entities(changed_files=<resolved files>, entities=last_context.entities, project_edges=last_context.project_edges)` to pull in the **callers** of the affected entities, and add their files to `ResolvedScope.files`. This requires `last_context` (the analyzer context) — so the expansion runs as a second pass in `run_scan` (Phase 3) after a first cheap pass produces `project_edges`, OR `build_qualname_index` is extended to also return the structural call edges. Decision: build the edges in `build_qualname_index`'s structural pass (it already walks every file's AST) and expose them so the closure runs without a taint analysis. `affected_qualnames` for the filter is the **base** affected set (NOT the caller-expanded set) — the filter still only displays findings on requested entities, but the *analyzed file set* is caller-expanded so those findings are computed correctly.

**Qualname canonicalization (FN guard).** `Finding.qualname` carries property-accessor suffixes `:setter`/`:deleter` (see `finding.py` `_PROPERTY_ACCESSOR_QUALNAME_SUFFIXES`, normalized away only at the Filigree wire via `_to_wire_qualname`, NOT in the raw `Finding`) plus full class/method nesting. A locator `python:function:pkg.mod.Cls.prop` will NOT string-equal a finding qualname `pkg.mod.Cls.prop:setter`. **Both the index keys and the affected_qualnames set must be canonicalized through a single suffix-stripping helper** (reuse/lift `_to_wire_qualname`'s suffix logic) before membership tests, AND a worklist entry for a class scopes-in all its methods (a `python:class:` locator matches any finding qualname under that class prefix). This applies in `build_qualname_index`, in `resolve_affected_scope`, and in `filter_to_affected` (Phase 4).

**`locator_to_qualname` method bug (must fix in `sei_resolution.py`).** The current prefix list is `("python:function:", "python:class:", "python:")`. A `python:method:pkg.mod.Cls.m` locator (loomweave emits `kind="method"` for class members — confirmed `index.py:95`) hits the `python:` catch-all and returns `method:pkg.mod.Cls.m`, which never matches the index. **Add `"python:method:"` to the prefix list before the generic `python:` catch-all.** Phase 2 tests must cover a `python:method:` locator.

`build_qualname_index` uses `index.discover_file_entities(ast.parse(src), module=module_dotted_name(rel), path=rel)` over the **already-discovered** files — discovery still walks the whole tree (§5.3), so the index is complete and the loomweave path is optional. **Parse-error handling:** wrap `ast.parse(path.read_bytes())` in `try/except (SyntaxError, OSError)` and `continue` on failure (a parse-error file contributes no entries and does NOT raise out of `run_scan`). Return type is `dict[str, str]`: key = canonical bare dotted qualname (matching `Entity.qualname` post-canonicalization), value = repo-relative POSIX path (matching `Entity.location.path`). Use `cast`/`match` to narrow `ast.parse` to `ast.Module` for `mypy --strict`.

**Test:** `tests/unit/core/test_delta_resolve.py` — SEI path (fake `SeiResolver`/client double, mirroring `test_sei_oracle.py` doubles) returns a file; **`python:method:` locator** resolves correctly; **property setter/deleter finding vs base-name locator**, **method finding vs class-level locator**, **nested-class qualname** all match under canonicalization; qualname fallback (no resolver, or resolver unsupported) returns a file; **partial resolution** — two entities, one resolvable + one absent → `len(resolved.files) == 1`, `len(unresolved) == 1`, the unresolved locator appears in `unresolved`, and the result is NOT full-fallback; **SEI-drift** — SEI resolves to a qualname absent from the index → falls through to the locator path (or `unresolved`), recorded as `loomweave_stale_sei`; unresolved entity lands in `unresolved`; `loomweave_used` reflects whether the SEI path fired; `build_qualname_index` maps a known qualname to its file on a sample tree and **skips a `SyntaxError` file without raising**; **caller-closure** — a source entity in `b.py` whose caller (the sink) is in `a.py`: a worklist naming the `b.py` entity pulls `a.py` into `ResolvedScope.files` via the reverse-edge closure.

**Verify:** `uv run pytest tests/unit/core/test_delta_resolve.py -q`

---

## Phase 3 — scan scoping in `run_scan` (§5.3, §5.4)

**Edit:** `src/wardline/core/run.py`.

Add parameters (keyword-only, defaults preserve INV-1). **The SEI resolver is INJECTED, not self-constructed** — `run_scan` stays network-free and matches the existing caller-constructs-and-injects pattern (CLI scan.py and MCP server.py already build/inject the loomweave client; `run_scan` must not construct a second one inline):

```python
def run_scan(
    root: Path,
    *,
    ...,
    affected: AffectedScope | None = None,   # NEW
    sei_resolver: SeiResolver | None = None, # NEW — injected by the caller (CLI/MCP), never built here
    ...
) -> ScanResult: ...
```

Each caller builds the resolver if a loomweave URL is available (the CLI already resolves `loomweave_url` before calling `run_scan`; the MCP `_scan` already has the injected `loomweave` client) and passes it down. Any loomweave error at the call site → `sei_resolver=None` (fail-soft, recorded as "loomweave unavailable").

Wiring, **between** `files = discover(...)` and `analyzer.analyze(...)`:

1. **If `affected is None` → unchanged path (INV-1). Short-circuit BEFORE any new work:** `build_qualname_index` and `resolve_loomweave_url`/resolver use are NOT reached; the `scope` block is absent. (INV-1 test asserts via spy that these are not called when `affected is None`, so a future refactor can't make the full-scan path pay delta cost.)
2. **Mutual exclusion:** if `affected is not None and new_since is not None` → raise `ScopeParseError` (`--affected` and `--new-since` scope different things via different mechanisms; composing them is rejected loudly, never silently double-scoped). The CLI (Phase 7) and MCP (Phase 8) also reject the pair at their layer.
3. Else build `index = build_qualname_index(files, root)`; `resolved = resolve_affected_scope(affected, index=index, sei_resolver=sei_resolver)` (resolution + caller-closure expansion happen inside, per Phase 2).
4. **Fail-closed (INV-3, §5.4):** if `resolved.files` is empty → run the **full** analysis over all `files` (`scope_mode = "full-fallback"`); else analyze only `scoped_files = [p for p in files if relpath(p) in resolved.files]` (`scope_mode = "delta"`). Each scoped file is analyzed **in full** (whole-module context preserved — no intra-file soundness loss; the inter-file gap is declared, §5.3a).
5. After `apply_suppressions`, apply the **finding filter** (Phase 4) to `findings` (the EMITTED set) when `scope_mode == "delta"`. **Do NOT filter `gate_findings`** (INV-4 / THREAT-001): the gate evaluates the full unsuppressed population so an attacker-influenceable scope cannot forge a green. The `None` sentinel on `gate_findings` is preserved (never coerced to `[]`).
6. **`files_scanned` / discovery semantics:** keep `ScanResult.files_scanned = len(files)` as the **discovery** count (its existing meaning), and update the MCP `_SCAN_OUTPUT_SCHEMA` description (Phase 8) to read *"Number of files discovered (see scope.files_analyzed for the delta-mode analyzed count)."* The scope block carries both `files_discovered` (== `len(files)`) and `files_analyzed` (== `len(scoped_files)`; equal only in full-fallback), so no top-level field silently lies.
7. **Progress callback:** when `scope_mode == "delta"`, emit `{"files_discovered": len(files), "files_analyzed": len(scoped_files)}` (not `len(files)` for both) so a progress subscriber sees the real analyzed count.
8. Build the `scope` block (Phase 5) and attach it to `ScanResult`.

Add to `ScanResult` (default `None` ⇒ full scans serialize no scope block; `run_scan` constructs `ScanResult` by keyword so field order is call-safe — but **grep `tests/` for positional `ScanResult(` construction first** and fix any in this same commit):

```python
@dataclass(frozen=True, slots=True)
class ScanResult:
    ...
    scope: DeltaScopeReport | None = None
```

**Test:** covered by Phase 6 hermetic golden + a focused `tests/unit/core/test_run_affected.py` (scoped-file subset reaches the analyzer; full path when `affected is None`; **`affected` + `new_since` together → `ScopeParseError`**; **delta-mode `gate_findings` retains an out-of-scope finding** — i.e. the gate population is NOT narrowed; INV-1 spy asserts `build_qualname_index` is not called when `affected is None`).

**Verify:** `uv run pytest tests/unit/core/test_run_affected.py -q`

---

## Phase 4 — finding filter (§5.3)

**New function in** `src/wardline/core/delta_resolve.py` (keeps it pure/testable):

```python
def filter_to_affected(
    findings: list[Finding],
    affected_qualnames: frozenset[str],
    affected_files: frozenset[str],
) -> list[Finding]: ...
```

Keeps a finding iff `canonical(finding.qualname) in affected_qualnames` (or the finding's class matches a class-level affected locator — see Phase 2 canonicalization) **or** (`finding.qualname is None` and `finding.location.path in affected_files`) — so an anchored finding is kept by canonical qualname (matching `:setter`/`:deleter` and nested-class shapes); a file-level engine FACT (`WLN-ENGINE-*`, qualname `None`) on an analyzed affected file is kept as context. Findings on **other** entities in the same analyzed file are dropped from the *displayed* output (context, per §5.3). **Does not re-mint fingerprints (INV-2).**

**Apply ONLY to the emitted/displayed `findings`. Do NOT apply to `gate_findings`** (INV-4 / THREAT-001 — see Phase 3 step 5). The gate population must remain the full unsuppressed set so an attacker-influenceable scope can never produce an authoritative green. The `gate_findings is None` sentinel (secure-default / `--trust-suppressions`) is load-bearing security logic and is left untouched by this filter — `filter_to_affected` is never called with `None`.

**Test:** `tests/unit/core/test_delta_finding_filter.py` — a finding on an affected qualname is kept; a finding on a co-located non-affected qualname is dropped; **a `:setter`/`:deleter` finding whose base name is the affected locator is kept; a method finding under a class-level locator is kept; a nested-class qualname matches**; a qualname-`None` engine FACT on an affected file is kept; fingerprints of kept findings are unchanged vs input. Plus a `test_run_affected.py` assertion that **`result.gate_findings` after a delta scan still contains an out-of-scope ERROR finding** (gate population NOT narrowed) and the `gate_decision` verdict over it equals the full scan's.

**Verify:** `uv run pytest tests/unit/core/test_delta_finding_filter.py -q`

---

## Phase 5 — the `scope` block + fail-closed full-fallback (§5.4)

**New in** `src/wardline/core/delta_scope.py`:

```python
BOUNDARY_CAVEAT = (
    "Delta scan analyzes only files containing the affected entities. Findings here "
    "may be incomplete OR absent: cross-file taint whose source lies outside the "
    "analyzed set is not computed, so an in-scope entity can read clean without being "
    "clean. Advisory inner-loop signal, not a verdict — the full scan is the gate of record."
)

@dataclass(frozen=True, slots=True)
class DeltaScopeReport:
    mode: str               # "delta" | "full-fallback"
    gate_authority: str     # "advisory" (delta) | "gate-of-record" (full-fallback) — machine-readable
    entities_requested: int
    files_discovered: int   # == ScanResult.files_scanned
    files_analyzed: int     # scoped subset; == files_discovered only in full-fallback
    in_scope_findings: int
    fell_back_count: int     # entities resolved via the spoofable qualname locator path, not SEI
    stale_sei_count: int     # entities whose SEI resolved to a now-absent qualname (loomweave stale)
    unresolved_entities: tuple[dict[str, str | None], ...]  # [{locator, sei}, ...]
    loomweave_used: bool
    boundary_caveat: str = BOUNDARY_CAVEAT

    def to_dict(self) -> dict[str, object]: ...   # dict[str, object] (not Any) for mypy --strict
```

Built in `run_scan` from the `ResolvedScope` + post-filter counts. `mode == "full-fallback"` (and `gate_authority == "gate-of-record"`) when `resolved.files` was empty (empty scope, all-unresolvable, or loomweave-absent-and-qualname-miss); otherwise `mode == "delta"`, `gate_authority == "advisory"`. `unresolved_entities` lists every entity that did not resolve even in `delta` mode (§7 "Some entities unresolved → scan the resolved subset; list unresolved"); `fell_back_count`/`stale_sei_count` surface how much of the scope rests on the spoofable/stale path so a consumer can judge trust without treating fell-back entities as SEI-equivalent. `to_dict` returns `dict[str, object]` (the inner `unresolved_entities` dicts are `dict[str, str | None]`, not assignable to `dict[str, Any]` under strict).

**Test:** `tests/unit/core/test_delta_scope_report.py` — `to_dict` keys/shape incl. `gate_authority`, `files_discovered`, `fell_back_count`, `stale_sei_count`; `boundary_caveat` is the fixed (stronger) string and names the in-scope-correctness hazard; full-fallback mode → `gate_authority == "gate-of-record"`; delta mode → `gate_authority == "advisory"`.

**Verify:** `uv run pytest tests/unit/core/test_delta_scope_report.py -q`

---

## Phase 6 — hermetic golden (§8, every PR, no sibling)

**New file:** `tests/conformance/test_warpline_delta_scope.py` + fixtures under `tests/conformance/fixtures/warpline_delta/` (a small sample tree + a fixed `warpline.reverify_worklist.v1` JSON fixture). Mirror the faithful-vendor / golden conventions of `test_legis_intake_contract.py` and `test_sei_oracle.py` (no import from warpline; the worklist shape is vendored from §9 of the spec).

Assertions (the spec's three golden axes plus the two honesty paths):
1. **Scoped file set** — for a worklist naming entity X in `a.py`, only `a.py` is analyzed (assert via `result.scope.files_analyzed` and that a known finding in `b.py` is *absent*).
2. **Filtered finding set** — a finding on a co-located non-affected entity in `a.py` is filtered out; the affected entity's finding is present.
3. **`scope` block** — `mode="delta"`, `entities_requested`, `files_analyzed`, `in_scope_findings`, `boundary_caveat` exact string.
4. **Fallback path** — an all-unresolvable worklist → `mode="full-fallback"`, `gate_authority="gate-of-record"`, all files analyzed.
5. **Unresolved-entity path** — a worklist with one resolvable + one bogus entity → `delta` mode, `unresolved_entities` lists the bogus one, `len(resolved.files) >= 1` (NOT fallback).
6. **Caller-closure / inter-file taint axis** — a tainted source in `b.py` feeds a sink in affected `a.py` (the worklist names `b.py`'s entity, the changed callee). Assert `a.py` is pulled into the analyzed set via the reverse-edge closure so the sink finding IS computed — and pin the behavior (this documents the inter-file gap as covered, not latent). A companion negative case: with caller-closure DISABLED the finding would be missing — assert the closure is what saves it.
7. **gate-not-narrowed axis** — a finding on a co-located non-affected entity is absent from displayed `findings` but PRESENT in `gate_findings` (mirrors INV-4 at the golden level).

No loomweave needed: SEI-less entities exercise the qualname fallback; the SEI path is covered by the Phase 2 unit double and the Phase 11 live oracle.

**Verify:** `uv run pytest tests/conformance/test_warpline_delta_scope.py -q`

---

## Phase 7 — CLI `--affected` with stdin (§6)

**Edit:** `src/wardline/cli/scan.py`.

Add option using `click.File('r')` so `-` is handled natively by Click and is testable through `CliRunner.invoke(..., input=...)` (reading `sys.stdin` directly does NOT work under `CliRunner` — it patches Click's stdin, not `sys.stdin`):

```python
@click.option(
    "--affected",
    "affected_file",
    type=click.File("r"),
    default=None,
    help="Scan only entities in this warpline reverify-worklist / entity-list "
         "(file path, or '-' for stdin). Speed, not truth: out-of-scope cross-file "
         "flows are not analyzed (see the scope block). Empty/unresolvable → full scan. "
         "Mutually exclusive with --since.",
)
```

In the handler:
- If `affected_file` is set, read `payload_text = affected_file.read()` and `affected = parse_affected_scope(json.loads(payload_text))` inside the existing `try` so `ScopeParseError`/`json.JSONDecodeError` → the existing `SystemExit(2)` path (§7 malformed → exit 2). (Do NOT use `sys.stdin.read()`; `click.File('-')` already resolved the stream.)
- **Mutual exclusion:** if both `--affected` and `--since` (Phase 12) are supplied → loud error (exit 2).
- **Build and inject the SEI resolver** (Phase 3 injection contract): if a loomweave URL resolves, construct it here (the CLI already resolves `loomweave_url`) and pass `sei_resolver=...` into `run_scan`; else `None`. Pass `affected=affected`.
- **Filigree emit guard (INV-5 / mark_unseen):** when `result.scope is not None and result.scope.mode == "delta"`, invoke the `FiligreeEmitter` with `mark_unseen=False` (a delta scan emits the FULL discovery list as `scanned_paths` but a FILTERED `findings` list — auto-`mark_unseen` would read out-of-scope findings as fixed and close their issues). Full-fallback scans reconcile normally.
- When `result.scope is not None`, echo a one-line scope summary to stderr (mode, gate_authority, files_analyzed/files_discovered, in_scope_findings, unresolved count) and include the block in every `--format` output: `scope` block in `agent-summary` JSON; SARIF run-level `properties` (see SARIF interface below); jsonl unaffected (findings only) but the stderr line still prints. Full-scan path (no `--affected`) prints nothing new (INV-1).

**SARIF interface (must be spelled out, not invented at implementation time):** `build_sarif` and `SarifSink.write` currently take `(findings, context=None)` with no run-properties channel. Add `run_properties: dict[str, object] | None = None` to `build_sarif` and thread it into `runs[0].properties`; `SarifSink.write` gains the same optional param and forwards it. The CLI passes `run_properties={"wardline_delta_scope": result.scope.to_dict()}` when `result.scope is not None`. Keep the param optional/defaulted so the existing dogfood self-scan and other `SarifSink` callers are unaffected.

**Test:** `tests/unit/cli/test_scan_affected_cli.py` — mirror `tests/unit/cli/test_scan_rust.py` (`CliRunner` + `from wardline.cli.scan import scan`). Cases: `--affected <fixture-file>` scopes; **`--affected -` via `CliRunner(mix_stderr=False).invoke(scan, [..., "--affected", "-"], input=json.dumps([...]))`** — a valid entity list → `mode="delta"` + non-null `scope.files_analyzed`; **empty `--affected -` (`input="[]"`) → `mode="full-fallback"`**; malformed payload → exit code 2; `--affected` + `--since` together → exit 2; **`--format sarif` output contains `runs[0].properties.wardline_delta_scope`**; **a delta CLI emit does NOT trigger `mark_unseen`** (assert the emitter body is built with `mark_unseen=False` — mock the emitter or assert on the request body).

**Verify:** `uv run pytest tests/unit/cli/test_scan_affected_cli.py -q` and manual: `printf '[]' | uv run wardline scan src --affected -`

---

## Phase 8 — MCP `scan` gains `affected` (§6)

**Edit:** `src/wardline/mcp/server.py`.

1. `_scan` handler (~line 805, beside `new_since = args.get("new_since")`): read `affected_arg = args.get("affected")`. Accept (a) an object/array (worklist/entity-list inline) → `parse_affected_scope(affected_arg)`; (b) a string path under root → `load_affected_scope(_resolve_under_root(root, affected_arg))`. `ScopeParseError` → `ToolError(str(exc))` (isError result, matching the §7 loud-malformed posture). **Reject `affected` + `new_since` together with a `ToolError`** (mutual exclusion, matching the CLI). **Build/pass `sei_resolver`** from the already-injected `loomweave` client (Phase 3 injection contract). Pass `affected=...` into `run_scan`. The inline form bypasses `_resolve_under_root` confinement (it is the MCP-primary ergonomic) — that is acceptable because INV-4 makes the scope's trust level moot for the gate; record `source_kind` + `item_count` in the scope echo so the inline provenance is at least logged.
2. `_SCAN_TOOL` inputSchema (~line 1832, next to `new_since`): add

```python
"affected": {
    "type": ["object", "array", "string"],
    "description": "Scan only entities in this warpline reverify-worklist (warpline."
    "reverify_worklist.v1) or bare entity list, or a path to one. Speed, not truth: "
    "cross-file flows outside the affected set are not analyzed (see scope block). "
    "Empty/unresolvable input falls back to a full scan.",
},
```
3. `_SCAN_OUTPUT_SCHEMA`: add an optional `scope` object property (mode/`gate_authority`/entities_requested/`files_discovered`/files_analyzed/in_scope_findings/`fell_back_count`/`stale_sei_count`/unresolved_entities/loomweave_used/boundary_caveat) so the structured-content emission stays schema-valid (pinned by `tests/conformance/test_mcp_structured_output.py`). Emit `result.scope.to_dict()` when present. **Also update the `files_scanned` property description** to "Number of files discovered (see scope.files_analyzed for the delta-mode analyzed count)" so the schema does not lie in delta mode (per Phase 3 step 6).

**Test:** extend `tests/unit/mcp/test_*scan*.py` (or a new `tests/unit/mcp/test_scan_affected_mcp.py`) — inline array `affected` scopes; path-string `affected`; malformed inline → `ToolError`/isError; `affected` + `new_since` → `ToolError`; **the returned `structuredContent` with `affected` supplied and `scope` non-null VALIDATES against `_SCAN_OUTPUT_SCHEMA`** (this is the only end-to-end pin of the scope shape; an optional property stays green even when malformed unless a delta invocation actually exercises it). Add a delta invocation to `tests/conformance/test_mcp_structured_output.py` (or assert the scope-present validation in the new MCP test) so the scope shape is pinned with `scope` present, not just absent. Re-run `tests/conformance/test_mcp_structured_output.py` (`EXPECTED_TOOLS`/tool-count unchanged — `affected` is a new param on an existing tool, not a new tool).

**Verify:** `uv run pytest tests/unit/mcp/ tests/conformance/test_mcp_structured_output.py -q`

---

## Phase 9 — invariant tests (INV-1/2/3)

**New file:** `tests/unit/core/test_affected_invariants.py`.

- **INV-1:** scan a fixture tree with `run_scan(affected=None)` vs the pre-change behavior — assert findings, `ScanSummary`, `gate_findings`, `scanned_paths` identical (frozen expected set). Plus a spy assertion that `build_qualname_index` and the loomweave-resolver path are NOT invoked when `affected is None` (the full-scan path pays no delta cost / probes no loomweave).
- **INV-2:** for an entity scoped by `--affected`, assert each kept finding's `fingerprint` equals the same finding's fingerprint from a full scan of the same tree (filter drops, never re-mints).
- **INV-3:** `affected` with all-unresolvable entities → `result.scope.mode == "full-fallback"`, `gate_authority == "gate-of-record"`, and the finding set equals the full scan's.
- **INV-4 (THREAT-001 — the load-bearing security test):** a fixture tree with a known ERROR sink in `evil.py`. A worklist that resolves >0 files but **surgically excludes `evil.py`** → `scope.mode == "delta"` (NOT full-fallback — fail-closed does not catch this), the displayed `findings` omit the `evil.py` finding, BUT `gate_decision(result, fail_on=ERROR)` returns `verdict == "FAILED"` / `tripped is True` / `exit_class == 1` — **identical to the full scan's verdict**. Assert the delta gate cannot green a real ERROR.
- **INV-5 (mark_unseen):** a delta scan's CLI emit path builds the Filigree request body with `mark_unseen=False` (assert via the body builder / a mocked emitter), so out-of-scope findings are never read as fixed.

**Verify:** `uv run pytest tests/unit/core/test_affected_invariants.py -q`

---

## Phase 10 — wire the `warpline_e2e` marker (pyproject + `_live_oracle`)

1. **`src/wardline/_live_oracle.py`:** add `"warpline_e2e"` to `LIVE_ORACLE_MARKERS` (so the conftest SKIP→FAIL hook covers it, exactly like `loomweave_e2e`/`legis_e2e`/`filigree_e2e`; **not** like `rust_e2e`, which is intentionally excluded).
2. **`pyproject.toml` `[tool.pytest.ini_options]`:**
   - `addopts`: append ` and not warpline_e2e` to the deselection string (currently `-m 'not network and not loomweave_e2e and not legis_e2e and not filigree_e2e and not rust_e2e and not loomweave_drift'`).
   - `markers`: add `"warpline_e2e: live \`warpline reverify | wardline scan --affected -\` round-trip (delta scope; weekly/manual)"`.

**Test:** `tests/unit/test_live_oracle.py` (extend if present, else add) — `warpline_e2e` is in `LIVE_ORACLE_MARKERS`; **`rust_e2e` is still ABSENT** from `LIVE_ORACLE_MARKERS` (guards an accidental copy-paste); `should_fail_live_oracle_skip(["warpline_e2e"], "skipped")` is True iff the env var is set; a `rust_e2e`-only skip is NOT failed even when `WARDLINE_LIVE_ORACLE_REQUIRED=1`. Plus a meta-assert that the marker is registered (no `PytestUnknownMarkWarning`).

**Verify:** `uv run pytest -q` (full suite still green; new marker deselected by default) and `WARDLINE_LIVE_ORACLE_REQUIRED=1 uv run pytest -m warpline_e2e -q` (skips clean when no `warpline` binary → **fails** because the env var is set, proving the fail-closed wiring).

---

## Phase 11 — the `warpline_e2e` live oracle + CI matrix

1. **New file:** `tests/conformance/test_warpline_e2e.py`, marked `@pytest.mark.warpline_e2e`, gated on a `warpline` binary (`WARDLINE_WARPLINE_BIN` override, skip clean otherwise — same auto-skip shape as `loomweave_e2e`/`legis_e2e`). It runs the real round-trip: `warpline reverify` → pipe its `reverify_worklist.v1` into `wardline scan --affected -`, assert exit code and a `scope` block with `mode in {"delta","full-fallback"}`, and that the analyzed file set is a subset of discovery.
2. **`.github/workflows/ci.yml`:** add to the `live-oracles` matrix `include:` (after `filigree_e2e`):
   ```yaml
   - name: Warpline
     marker: warpline_e2e
   ```
   Add `WARDLINE_WARPLINE_BIN: ${{ secrets.WARDLINE_WARPLINE_BIN }}` to the job `env:` alongside the existing `WARDLINE_LOOMWEAVE_BIN`/`WARDLINE_LEGIS_URL`/`WARDLINE_FILIGREE_URL`. The job already passes `WARDLINE_LIVE_ORACLE_REQUIRED: "1"` (fail-closed) and runs only on `schedule`/`workflow_dispatch`.
3. **Extend the CI meta-guard `tests/unit/test_ci_live_oracles.py` (MUST — it will go RED otherwise).** `test_ci_exposes_scheduled_and_manual_live_oracles` asserts an EXACT env-var set `{WARDLINE_OPENROUTER_API_KEY, WARDLINE_LOOMWEAVE_BIN, WARDLINE_LEGIS_URL, WARDLINE_FILIGREE_URL}` and an EXACT marker set `{loomweave_e2e, legis_e2e, filigree_e2e}` against `ci.yml`'s text. Adding the warpline matrix row + `WARDLINE_WARPLINE_BIN` env makes the CI text contain new entries, but this meta-test pins the *current* set; once Phase 11 lands the file must be updated to include `WARDLINE_WARPLINE_BIN` in the env-var loop and `warpline_e2e` in the marker loop, AND assert both `'warpline_e2e' in workflow` and `'WARDLINE_WARPLINE_BIN' in workflow`. Without this, the new oracle can be omitted/misconfigured in CI while the default suite stays green (the fail-closed wiring would never be validated until a scheduled run).

**Verify (local, optional):** `WARDLINE_LIVE_ORACLE_REQUIRED=1 WARDLINE_WARPLINE_BIN=<path> uv run pytest -m warpline_e2e -q`. CI: confirm the matrix row renders in a `workflow_dispatch` run. Run `uv run pytest tests/unit/test_ci_live_oracles.py -q` to confirm the meta-guard is green AFTER the edit (it goes red before).

---

## Phase 12 — deferred-optional `--since <gitref>` (§6, may slip to a later increment)

Built **on top of** `--affected`, not on the `new_since` gate path. **New function** `delta_scope.affected_scope_from_gitref(ref, root) -> AffectedScope` (reuse `core/delta.get_changed_files_since`, then map changed files → entity locators via the same qualname index) → feeds the identical `run_scan(affected=...)` path. CLI `--since` is mutually exclusive with `--affected`. Marked **optional**; ship Phases 1–11 first. If cut, it carries forward as a labelled follow-up — not deferred *defect* work.

**Test:** `tests/unit/core/test_delta_since.py` (only if Phase 12 lands).

**Verify:** `uv run pytest tests/unit/core/test_delta_since.py -q`

---

## Definition of done

- [ ] `delta_scope.py` parses three distinct shapes (full envelope / bare-data / bare-list); malformed → `ScopeParseError`; over-cap → `ScopeParseError`; empty → non-error (Phase 1 tests green).
- [ ] `delta_resolve.py` resolves SEI (loomweave) and qualname-fallback with **canonicalized** qualnames (`:setter`/`:deleter`/method/nested-class); `python:method:` locators resolve; **SEI-drift → locator fallback**; **caller-closure expansion** pulls in callers; `build_qualname_index` is taint-free + skips `SyntaxError` files (Phase 2 tests green).
- [ ] `locator_to_qualname` gains `python:method:` prefix (bug fix).
- [ ] `run_scan(affected=..., sei_resolver=...)` scopes analysis to affected-entity files (caller-expanded); SEI resolver is **injected, not self-constructed**; `--affected`+`--new-since` → `ScopeParseError`; full files analyzed whole-module (Phase 3 + golden).
- [ ] Finding filter applies to `findings` only, keeps in-scope + qualname-`None` engine facts, drops co-located others, no re-mint; **`gate_findings` NOT narrowed; `None` sentinel preserved** (Phase 4 + INV-2 + INV-4).
- [ ] **INV-4 (THREAT-001):** a surgical-exclusion worklist over a known-ERROR file CANNOT produce a PASSED severity verdict — delta gate == full gate. **INV-5 (mark_unseen):** delta CLI emit forces `mark_unseen=False`.
- [ ] Fail-closed full-fallback on empty/all-unresolvable; `scope` block with the **stronger** `boundary_caveat` + `gate_authority`/`files_discovered`/`fell_back_count`/`stale_sei_count`; mode/counts/unresolved correct (Phase 5 + golden).
- [ ] Hermetic golden green every PR, no sibling — incl. **inter-file caller-closure axis** and **gate-not-narrowed axis** (Phase 6).
- [ ] CLI `--affected <file|->` via `click.File` (CliRunner `input=` testable); malformed → exit 2; `--affected`+`--since` → exit 2; scope in human/json/**sarif (`run_properties` channel)**; delta emit `mark_unseen=False` (Phase 7).
- [ ] MCP `scan` `affected` param (object/array/path); `affected`+`new_since` → `ToolError`; `scope` in structured content **validated with scope PRESENT**; `_SCAN_OUTPUT_SCHEMA` + `files_scanned` description updated; `test_mcp_structured_output.py` green (Phase 8).
- [ ] **INV-1** full-scan path byte-identical (+ spy: no delta work / no loomweave probe when `affected is None`); **INV-2** fingerprints stable; **INV-3** fail-closed; **INV-4** gate unforgeable; **INV-5** no false mark_unseen (Phase 9).
- [ ] CI meta-guard `test_ci_live_oracles.py` extended for `WARDLINE_WARPLINE_BIN` + `warpline_e2e` (Phase 11).
- [ ] `warpline_e2e` in `LIVE_ORACLE_MARKERS` + `pyproject` `addopts`/`markers`; fail-closed verified (Phase 10).
- [ ] `warpline_e2e` live oracle + `ci.yml` `live-oracles` matrix row + `WARDLINE_WARPLINE_BIN` env, wired exactly like loomweave/legis/filigree (Phase 11).
- [ ] `ruff` + `mypy --strict` clean; base package still zero-dep (no new runtime import of blake3/extras in `delta_scope.py`/`delta_resolve.py`).
- [ ] Full suite green by default: `uv run pytest -q`.
- [ ] CHANGELOG `[Unreleased] Added` notes `wardline scan --affected` + MCP `affected` + `warpline_e2e`.

## Out of scope — deferred to spec A (`wardline-c0563eee74`)

- **Published, drift-checked contract.** Emitting a `wardline.delta_scope.v1` provenance block and pinning it in CI against warpline's *published* `warpline.reverify_worklist.v1` artifact (a golden vector vs the producer's live artifact). This plan vendors the worklist shape hermetically from spec §9; it does **not** consume a published artifact or drift-check against the producer.
- **Fixing the stale-vendored-golden gap** (`test_sei_oracle.py::test_vendored_oracle_matches_loomweave_source` skipping unless `LOOMWEAVE_REPO` is set). That is A's remit.
- **Any wardline→warpline outbound transport.** Spec §3 non-goal: wardline never calls warpline (HTTP/MCP/CLI). The scope set is producer-agnostic input only.
- **`--since` git-driven convenience** is *optional within this plan* (Phase 12), not part of A; if cut it carries forward under the `warpline-delta-2026-06-18` label.
