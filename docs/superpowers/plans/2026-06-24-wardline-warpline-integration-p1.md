# Wardline ↔ Warpline Integration (Item 4, P1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring online the wardline-side surfaces warpline needs for (a) scoped-rescan provenance and (b) per-SEI proven-clean-at-commit reads — *without* wardline ever calling warpline or ever declaring a change clean on warpline's behalf.

**Architecture:** Two independent capabilities on existing surfaces. (a) extends the already-shipped `--affected` delta scan's honesty block (`DeltaScopeReport`) with the *scope source* and the producer's *unverified* `generated_at` staleness proxy. (b) reframes the proposal's literal "resolved-finding read" into the property it actually names — "wardline cleared entity E at commit X" — by extending the already-shipped `attest` bundle (full-scan, commit-pinned, SEI-keyed, fail-closed 3-valued verdict) with a per-boundary `content_hash` binding key, bumped to schema `wardline-attest-2`. Warpline *pulls* the published bundle and does only mechanical `(commit, content_hash)` equality; wardline owns the trust verdict. Both are versioned cross-tool contracts.

**Tech Stack:** Python 3.12+, stdlib-only base, pytest (`.venv/bin/pytest`), ruff, mypy --strict. JSON Schema for the MCP output contract. HMAC-SHA256 (stdlib) for attest signing.

## Global Constraints

- **Zero-dependency base.** Stdlib only in `core`/`mcp`; no new third-party deps. `blake3` stays an opt-in extra, lazy-imported. (verbatim from `attest.py`/`dossier.py` module docstrings)
- **wardline NEVER calls warpline.** All warpline input arrives as a *pushed, untrusted, unauthenticated* payload (`delta_scope.py:8-16`). Do not add any `warpline_*_get` MCP/HTTP call from wardline. Producer claims (`generated_at`, future `completeness`) are unverified — namespace them and never let them feed `mode`, `gate_authority`, or any verdict.
- **Fail-closed; `unknown` ≠ `clean`.** Never report unproven code as clean. The attest verdict stays 3-valued (`clean`/`defect`/`unknown`); absence-of-proof maps to warpline `risk=unavailable`, never clean.
- **INV-4 holds.** The delta filter narrows only displayed findings, never the gate population. `--affected` stays incompatible with `--fail-on`. Do not touch `gate_findings`.
- **No back-compat shims for the unreleased contract.** `wardline-attest-1` has no external consumer yet (warpline is the first, built against v2); bump cleanly to `wardline-attest-2`, no dual-version support.
- **mypy --strict and ruff clean** after every task: `.venv/bin/mypy src` and `.venv/bin/ruff check src tests`.
- **Single-branch discipline.** Do all of this on ONE branch (e.g. `feat/warpline-p1` or the active `rcX` branch); one PR to `main`; merge back when green — never orphan the branch.
- **Glossary line-anchor lock (GOTCHA).** `tests/docs/test_glossary_vocabulary.py` binds doc citations to exact line numbers in `run.py`/`scan.py`/`server.py`. Editing `run.py` (Task A3) or `server.py` (Task A4) shifts lines and may break it — if it fails, re-anchor BOTH the test's `_ANCHORS` and the cited lines in `docs/reference/finding-lifecycle-vocabulary.md`. `delta_scope.py`/`attest.py` edits are not anchored.

---

## File Structure

| File | Responsibility | Touched by |
|---|---|---|
| `src/wardline/core/delta_scope.py` | `AffectedScope` (carry `producer_generated_at`); `DeltaScopeReport` (carry `scope_source` + `producer_generated_at`) + `to_dict()` | A1, A2 |
| `src/wardline/core/run.py` | Thread `source_kind`/`generated_at` from `AffectedScope` into the `DeltaScopeReport` it builds (`~L340`, `~L564`) | A3 |
| `src/wardline/mcp/server.py` | Mirror the two new fields into the hand-maintained `_SCAN_OUTPUT_SCHEMA` scope block (`~L1398`) | A4 |
| `src/wardline/core/attest.py` | Add per-boundary `content_hash`; bump `ATTEST_SCHEMA` to `wardline-attest-2` | B1 |
| `tests/unit/core/test_delta_scope_report.py` | Unit tests for the new report fields + parser capture | A1, A2 |
| `tests/unit/core/test_run_affected.py` | Integration: `run_scan(affected=)` surfaces the new fields | A3 |
| `tests/unit/mcp/test_scan_output_schema_parity.py` (new) | Key-parity drift guard: `DeltaScopeReport.to_dict()` keys == MCP scope schema keys (80e457bc41-class) | A4 |
| `tests/unit/core/test_attest.py` | Attest unit tests (schema string + `content_hash`) | B1 |
| `docs/contracts/wardline-attest-2.md` (new) | Published consumer contract: boundary shape, commit-as-temporal-pin, `enrichment_reasons` triple, boundary rule | B2 |
| `tests/conformance/test_attest_contract_freeze.py` (new) | Freeze the attest producer shape + schema tag | B2 |
| `tests/conformance/wardline_delta_scope_contract.v1.json` (new) | Published `wardline.delta_scope.v1` producer artifact | C1 |
| `tests/conformance/test_wardline_delta_scope_contract.py` (new) | Drift-check `DeltaScopeReport.to_dict()` against the published artifact | C1 |
| `tests/conformance/test_warpline_delta_scope.py` | Extend: assert `producer_generated_at` captured from fixtures + gated live-drift marker | C2 |
| `CHANGELOG.md` | `[Unreleased] Added` entries | A4, B1 |

---

## Phase A — (a) scoped-rescan provenance (UNBLOCKED, ship now)

### Task A1: `AffectedScope` captures the producer's `generated_at`

**Files:**
- Modify: `src/wardline/core/delta_scope.py` (`AffectedScope` ~L55-69; `_parse_worklist` ~L170-196)
- Test: `tests/unit/core/test_delta_scope_report.py`

**Interfaces:**
- Produces: `AffectedScope.producer_generated_at: str | None` — the worklist's `data.generated_at` (unverified producer claim), `None` for a bare entity-list or when absent.

- [ ] **Step 1: Write the failing test**

In `tests/unit/core/test_delta_scope_report.py` add:

```python
from wardline.core.delta_scope import parse_affected_scope


def test_worklist_captures_generated_at():
    payload = {
        "schema": "warpline.reverify_worklist.v1",
        "data": {
            "generated_at": "2026-06-18T00:00:00Z",
            "items": [{"entity": {"locator": "python:function:a.alpha", "sei": None}}],
        },
    }
    scope = parse_affected_scope(payload)
    assert scope.source_kind == "reverify_worklist_v1"
    assert scope.producer_generated_at == "2026-06-18T00:00:00Z"


def test_entity_list_has_no_generated_at():
    scope = parse_affected_scope([{"locator": "python:function:a.alpha"}])
    assert scope.source_kind == "entity_list"
    assert scope.producer_generated_at is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_delta_scope_report.py::test_worklist_captures_generated_at -v`
Expected: FAIL — `AttributeError: 'AffectedScope' object has no attribute 'producer_generated_at'`

- [ ] **Step 3: Add the field to `AffectedScope`**

In `delta_scope.py`, extend the dataclass (keep existing docstring):

```python
@dataclass(frozen=True, slots=True)
class AffectedScope:
    entities: frozenset[AffectedEntity]
    source_kind: str
    item_count: int
    producer_generated_at: str | None = None
```

- [ ] **Step 4: Capture `generated_at` in `_parse_worklist`**

In `_parse_worklist`, immediately after the `data` mapping is validated (after the `if not isinstance(data, dict): raise ...` block), add:

```python
    generated_at = _coerce_str(data.get("generated_at"))
```

Then thread it into all three `AffectedScope(...)` returns in that function:

```python
    if items is None:
        return AffectedScope(frozenset(), "empty", 0, producer_generated_at=generated_at)
```
```python
    if not entities:
        return AffectedScope(frozenset(), "empty", len(items), producer_generated_at=generated_at)
    return AffectedScope(
        frozenset(entities), "reverify_worklist_v1", len(items), producer_generated_at=generated_at
    )
```

(`_parse_entity_list` is unchanged — a bare list carries no `generated_at`, so the `None` default applies.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/core/test_delta_scope_report.py -v`
Expected: PASS (both new tests + all existing report tests)

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/delta_scope.py tests/unit/core/test_delta_scope_report.py
git commit -m "feat(delta): capture warpline worklist generated_at on AffectedScope"
```

---

### Task A2: `DeltaScopeReport` carries `scope_source` + `producer_generated_at`

**Files:**
- Modify: `src/wardline/core/delta_scope.py` (`DeltaScopeReport` ~L242-289)
- Test: `tests/unit/core/test_delta_scope_report.py`

**Interfaces:**
- Consumes: `AffectedScope.source_kind`, `AffectedScope.producer_generated_at` (Task A1).
- Produces: `DeltaScopeReport.scope_source: str`, `DeltaScopeReport.producer_generated_at: str | None`, both in `to_dict()`. The serialized key set grows from 11 to 13.

- [ ] **Step 1: Write the failing test**

In `tests/unit/core/test_delta_scope_report.py` add:

```python
from wardline.core.delta_scope import DeltaScopeReport


def _report(**overrides):
    base = dict(
        mode="delta",
        gate_authority="advisory",
        scope_source="reverify_worklist_v1",
        entities_requested=1,
        files_discovered=1,
        files_analyzed=1,
        in_scope_findings=0,
        fell_back_count=0,
        stale_sei_count=0,
        unresolved_entities=(),
        loomweave_used=False,
        producer_generated_at="2026-06-18T00:00:00Z",
    )
    base.update(overrides)
    return DeltaScopeReport(**base)


def test_report_serializes_scope_source_and_generated_at():
    d = _report().to_dict()
    assert d["scope_source"] == "reverify_worklist_v1"
    assert d["producer_generated_at"] == "2026-06-18T00:00:00Z"
    assert set(d) >= {"scope_source", "producer_generated_at"}


def test_report_generated_at_defaults_none():
    d = _report(producer_generated_at=None, scope_source="entity_list").to_dict()
    assert d["producer_generated_at"] is None
    assert d["scope_source"] == "entity_list"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_delta_scope_report.py::test_report_serializes_scope_source_and_generated_at -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'scope_source'`

- [ ] **Step 3: Add the fields + serialize them**

In `DeltaScopeReport`, add `scope_source` among the no-default fields and `producer_generated_at` among the defaulted ones (ordering rule: defaulted fields last):

```python
@dataclass(frozen=True, slots=True)
class DeltaScopeReport:
    mode: str
    gate_authority: str
    scope_source: str
    entities_requested: int
    files_discovered: int
    files_analyzed: int
    in_scope_findings: int
    fell_back_count: int
    stale_sei_count: int
    unresolved_entities: tuple[dict[str, str | None], ...]
    loomweave_used: bool
    producer_generated_at: str | None = None
    boundary_caveat: str = field(default=BOUNDARY_CAVEAT)
```

Extend `to_dict()` (add the two keys; keep the rest):

```python
        return {
            "mode": self.mode,
            "gate_authority": self.gate_authority,
            "scope_source": self.scope_source,
            "entities_requested": self.entities_requested,
            "files_discovered": self.files_discovered,
            "files_analyzed": self.files_analyzed,
            "in_scope_findings": self.in_scope_findings,
            "fell_back_count": self.fell_back_count,
            "stale_sei_count": self.stale_sei_count,
            "unresolved_entities": [dict(e) for e in self.unresolved_entities],
            "loomweave_used": self.loomweave_used,
            "producer_generated_at": self.producer_generated_at,
            "boundary_caveat": self.boundary_caveat,
        }
```

Also extend the dataclass docstring with one line: `scope_source` records the parsed producer shape (`reverify_worklist_v1` / `entity_list` / `empty`); `producer_generated_at` is the worklist's UNVERIFIED `data.generated_at` staleness proxy, never wardline-vouched.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/core/test_delta_scope_report.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/delta_scope.py tests/unit/core/test_delta_scope_report.py
git commit -m "feat(delta): add scope_source + producer_generated_at to DeltaScopeReport"
```

---

### Task A3: Thread the new fields through `run_scan`

**Files:**
- Modify: `src/wardline/core/run.py` (locals ~L340-347; affected block ~L349-356; report build ~L562-575)
- Test: `tests/unit/core/test_run_affected.py`

**Interfaces:**
- Consumes: `AffectedScope.source_kind`, `AffectedScope.producer_generated_at` (A1); `DeltaScopeReport(scope_source=, producer_generated_at=)` (A2).
- Produces: `ScanResult.scope.scope_source` and `ScanResult.scope.producer_generated_at` populated for every `--affected` run (delta and full-fallback).

- [ ] **Step 1: Write the failing test**

In `tests/unit/core/test_run_affected.py` add (mirror the file's existing `run_scan(..., affected=...)` setup; this asserts the new fields):

```python
from wardline.core.delta_scope import parse_affected_scope


def test_run_scope_block_declares_source_and_generated_at(tmp_path):
    (tmp_path / "a.py").write_text("def alpha():\n    return 1\n", encoding="utf-8")
    affected = parse_affected_scope(
        {
            "schema": "warpline.reverify_worklist.v1",
            "data": {
                "generated_at": "2026-06-18T00:00:00Z",
                "items": [{"entity": {"locator": "python:function:a.alpha", "sei": None}}],
            },
        }
    )
    result = run_scan(tmp_path, affected=affected)
    assert result.scope is not None
    assert result.scope.scope_source == "reverify_worklist_v1"
    assert result.scope.producer_generated_at == "2026-06-18T00:00:00Z"
```

(If `run_scan` is not already imported at the top of this file, add `from wardline.core.run import run_scan`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_run_affected.py::test_run_scope_block_declares_source_and_generated_at -v`
Expected: FAIL — `AttributeError: 'DeltaScopeReport' object has no attribute 'scope_source'` is already fixed by A2, so this fails instead on `scope_source == ""` (the default local) until wired.

- [ ] **Step 3: Add the locals**

In `run.py`, alongside the other scope locals (~L340-347, near `scope_mode: str | None = None`), add:

```python
    scope_source: str = ""
    producer_generated_at: str | None = None
```

- [ ] **Step 4: Populate them inside the `if affected is not None:` block**

Immediately after `entities_requested = affected.item_count` (~L350), add:

```python
        scope_source = affected.source_kind
        producer_generated_at = affected.producer_generated_at
```

- [ ] **Step 5: Pass them into the `DeltaScopeReport(...)` constructor**

In the `scope = DeltaScopeReport(...)` block (~L564), add the two kwargs:

```python
        scope = DeltaScopeReport(
            mode=scope_mode,
            gate_authority="advisory" if scope_mode == "delta" else "gate-of-record",
            scope_source=scope_source,
            entities_requested=entities_requested,
            files_discovered=len(files),
            files_analyzed=len(analyze_files),
            in_scope_findings=len(findings),
            fell_back_count=fell_back_count,
            stale_sei_count=stale_sei_count,
            unresolved_entities=unresolved_entities,
            loomweave_used=loomweave_used,
            producer_generated_at=producer_generated_at,
        )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/core/test_run_affected.py tests/unit/core/test_affected_invariants.py -v`
Expected: PASS (the new test + INV-1..INV-5 still green)

- [ ] **Step 7: Verify SARIF + CLI auto-propagation and the glossary lock**

The CLI agent-summary (`scan.py:458`), SARIF (`scan.py:343` → `core/sarif.py`), and MCP response (`server.py:1048`) all consume `result.scope.to_dict()`, so they pick up the new keys with no code change. Confirm + catch the line-anchor lock:

Run: `.venv/bin/pytest tests/unit/cli/test_scan_affected_cli.py tests/conformance/test_warpline_delta_scope.py tests/docs/test_glossary_vocabulary.py -v`
Expected: PASS. If `test_glossary_vocabulary.py` FAILS, re-anchor its `_ANCHORS` line numbers and the citations in `docs/reference/finding-lifecycle-vocabulary.md` to the new `run.py` lines, then re-run.

- [ ] **Step 8: Commit**

```bash
git add src/wardline/core/run.py tests/unit/core/test_run_affected.py
git commit -m "feat(delta): thread scope_source + producer_generated_at into run_scan scope block"
```

---

### Task A4: Mirror the new fields into the MCP output schema + add the key-parity drift guard

**Files:**
- Modify: `src/wardline/mcp/server.py` (`_SCAN_OUTPUT_SCHEMA` scope block ~L1405-1480)
- Create: `tests/unit/mcp/test_scan_output_schema_parity.py`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `DeltaScopeReport.to_dict()` key set (A2).
- Produces: a structural invariant — the MCP scope schema's `properties` + `required` exactly equal `DeltaScopeReport.to_dict()` keys.

- [ ] **Step 1: Write the failing parity test**

Create `tests/unit/mcp/test_scan_output_schema_parity.py`:

```python
"""Guard the 80e457bc41-class drift: the hand-maintained MCP scope schema must stay
key-identical to DeltaScopeReport.to_dict(). A field added to one but not the other
silently desyncs structuredContent from the payload."""

from __future__ import annotations

from wardline.core.delta_scope import DeltaScopeReport
from wardline.mcp.server import _SCAN_OUTPUT_SCHEMA


def _sample_report() -> DeltaScopeReport:
    return DeltaScopeReport(
        mode="delta",
        gate_authority="advisory",
        scope_source="reverify_worklist_v1",
        entities_requested=1,
        files_discovered=1,
        files_analyzed=1,
        in_scope_findings=0,
        fell_back_count=0,
        stale_sei_count=0,
        unresolved_entities=(),
        loomweave_used=False,
        producer_generated_at="2026-06-18T00:00:00Z",
    )


def test_scope_schema_properties_match_report_keys():
    report_keys = set(_sample_report().to_dict().keys())
    schema_keys = set(_SCAN_OUTPUT_SCHEMA["properties"]["scope"]["properties"].keys())
    assert schema_keys == report_keys


def test_scope_schema_required_matches_report_keys():
    report_keys = set(_sample_report().to_dict().keys())
    required = set(_SCAN_OUTPUT_SCHEMA["properties"]["scope"]["required"])
    assert required == report_keys
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/mcp/test_scan_output_schema_parity.py -v`
Expected: FAIL — schema is missing `scope_source` and `producer_generated_at`.

- [ ] **Step 3: Add the two properties to the scope schema**

In `server.py`, inside the scope block's `"properties": {...}`, add (place `scope_source` after `gate_authority`, `producer_generated_at` after `loomweave_used`):

```python
                "scope_source": {
                    "type": "string",
                    "enum": ["reverify_worklist_v1", "entity_list", "empty"],
                    "description": "Which producer scope shape was parsed: a warpline.reverify_worklist.v1 "
                    "worklist, a bare entity_list, or empty (zero usable entities). Declares the scope SOURCE.",
                },
```
```python
                "producer_generated_at": {
                    "type": ["string", "null"],
                    "description": "UNVERIFIED producer claim, echoed verbatim: the warpline worklist's "
                    "data.generated_at (ISO-8601), a staleness proxy. Unauthenticated and never wardline-vouched; "
                    "it never feeds mode, gate_authority, or any verdict. Null for a bare entity_list or when omitted.",
                },
```

- [ ] **Step 4: Add both keys to the scope `required` list**

```python
            "required": [
                "mode",
                "gate_authority",
                "scope_source",
                "entities_requested",
                "files_discovered",
                "files_analyzed",
                "in_scope_findings",
                "fell_back_count",
                "stale_sei_count",
                "unresolved_entities",
                "loomweave_used",
                "producer_generated_at",
                "boundary_caveat",
            ],
```

- [ ] **Step 5: Run the parity + MCP structured-output tests**

Run: `.venv/bin/pytest tests/unit/mcp/test_scan_output_schema_parity.py tests/unit/mcp/test_scan_affected_mcp.py tests/conformance/test_mcp_structured_output.py tests/docs/test_glossary_vocabulary.py -v`
Expected: PASS. If the glossary lock fails (server.py lines shifted), re-anchor as in Task A3 Step 7.

- [ ] **Step 6: Add a CHANGELOG entry**

In `CHANGELOG.md` under `## [Unreleased]` → `### Added`:

```markdown
- Delta-scan scope block now declares its `scope_source` and echoes warpline's unverified `producer_generated_at` (staleness proxy) across CLI/SARIF/MCP; MCP scope schema is key-parity-tested against `DeltaScopeReport`.
```

- [ ] **Step 7: Commit**

```bash
git add src/wardline/mcp/server.py tests/unit/mcp/test_scan_output_schema_parity.py CHANGELOG.md
git commit -m "feat(mcp): mirror scope_source/producer_generated_at into scan schema + key-parity guard"
```

---

## Phase B — (b) per-SEI proven-clean-at-commit via `wardline-attest-2` (UNBLOCKED, ship now)

### Task B1: Add per-boundary `content_hash` and bump the attest schema

**Files:**
- Modify: `src/wardline/core/attest.py` (`ATTEST_SCHEMA` L62; boundary build L215-222; `_enrich_seis` L150-163)
- Modify: `tests/unit/core/test_attest.py`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `EntityBinding.content_hash` (already populated by `SeiResolver.resolve_locator`, `identity.py:139-146`; resolved-and-discarded today in `_enrich_seis`).
- Produces: `ATTEST_SCHEMA == "wardline-attest-2"`; each `payload.boundaries[]` entry is `{qualname, sei, content_hash, verdict, tier}`. `content_hash` is `None` when no Loomweave client resolved it (honest) — whole-file blake3 granularity, never entity-span.

- [ ] **Step 1: Write the failing tests**

In `tests/unit/core/test_attest.py` add (the file already defines `_annotated_tree`, `_KEY`, `_PINNED`):

```python
import types


class _FakeLoomweave:
    """Minimal client for SEI enrichment: SEI-capable, resolves every locator to an
    ALIVE binding carrying a content_hash. Satisfies the capabilities()/resolve()/
    resolve_identity()/resolve_sei() surface _enrich_seis exercises."""

    def capabilities(self):
        return {"sei": {"supported": True, "version": 1}}

    def resolve(self, qualnames, *, plugin=None):
        return types.SimpleNamespace(resolved={q: f"python:function:{q}" for q in qualnames})

    def resolve_identity(self, locator):
        return {
            "alive": True,
            "sei": "loomweave:eid:" + "a" * 32,
            "current_locator": locator,
            "content_hash": "blake3:deadbeef",
        }

    def resolve_sei(self, sei):
        return {"alive": True}


def test_schema_is_attest_2(tmp_path):
    bundle = build_attestation(_annotated_tree(tmp_path), _KEY, today=_PINNED)
    assert bundle["schema"] == "wardline-attest-2"


def test_boundaries_carry_content_hash_key_without_client(tmp_path):
    bundle = build_attestation(_annotated_tree(tmp_path), _KEY, today=_PINNED)
    boundaries = bundle["payload"]["boundaries"]
    assert boundaries  # src / clean / leak are declared boundaries
    for b in boundaries:
        assert "content_hash" in b
        assert b["content_hash"] is None  # no loomweave client → honest None


def test_boundaries_carry_resolved_content_hash_with_client(tmp_path):
    bundle = build_attestation(
        _annotated_tree(tmp_path), _KEY, today=_PINNED, loomweave_client=_FakeLoomweave()
    )
    clean = next(b for b in bundle["payload"]["boundaries"] if b["qualname"].endswith(".clean"))
    assert clean["content_hash"] == "blake3:deadbeef"
    assert clean["sei"] == "loomweave:eid:" + "a" * 32
    assert bundle["payload"]["sei_source"] == "loomweave"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/core/test_attest.py::test_schema_is_attest_2 tests/unit/core/test_attest.py::test_boundaries_carry_content_hash_key_without_client -v`
Expected: FAIL — schema is `"wardline-attest-1"`; boundaries have no `content_hash` key.

- [ ] **Step 3: Bump the schema constant**

In `attest.py`:

```python
ATTEST_SCHEMA = "wardline-attest-2"
```

- [ ] **Step 4: Add `content_hash` to the boundary dict**

In `_build_payload`, in the boundary append (L215-222):

```python
            boundaries.append(
                {
                    "qualname": qualname,
                    "sei": None,  # filled by _enrich_seis behind a lazy Loomweave import
                    "content_hash": None,  # filled by _enrich_seis from the resolved binding (whole-file blake3)
                    "verdict": verdict.verdict,
                    "tier": verdict.declared_tier,
                }
            )
```

- [ ] **Step 5: Capture `content_hash` in `_enrich_seis`**

In `_enrich_seis`, in the per-boundary resolved block (L156-158):

```python
            if binding is not None and binding.sei:
                boundary["sei"] = binding.sei
                boundary["content_hash"] = binding.content_hash
                resolved_any = True
```

(`binding.content_hash` may be `None` even when the SEI resolves — that is honest; do not synthesize one.)

- [ ] **Step 6: Update remaining hardcoded `wardline-attest-1` references**

Run: `rg -n "wardline-attest-1" src tests docs`
For each hit (existing assertions, docstrings, CHANGELOG, the `verify_attestation` cross-schema test if any), update to `wardline-attest-2`. The `_sign`/`verify_attestation` logic needs no change — they read `ATTEST_SCHEMA`; a `wardline-attest-1` bundle now correctly reports `signature_valid=False` (clean break, no external consumer).

- [ ] **Step 7: Run the full attest suite**

Run: `.venv/bin/pytest tests/unit/core/test_attest.py tests/conformance -k attest -v`
Expected: PASS. Reproduction tests stay green (re-derivation now includes `content_hash` on both sides). If any test pins exact boundary bytes/shape, update its expectation to include `content_hash`.

- [ ] **Step 8: Add a CHANGELOG entry**

In `CHANGELOG.md` under `## [Unreleased]`:

```markdown
### Changed
- **BREAKING (unreleased contract):** attest bundle schema bumped `wardline-attest-1` → `wardline-attest-2`; each boundary now carries `content_hash` (whole-file blake3 binding key, null when unresolved). `wardline-attest-1` bundles no longer verify.
```

- [ ] **Step 9: Commit**

```bash
git add src/wardline/core/attest.py tests/unit/core/test_attest.py CHANGELOG.md
git commit -m "feat(attest): add per-boundary content_hash; bump schema to wardline-attest-2"
```

---

### Task B2: Publish the `wardline-attest-2` consumer contract + freeze the producer shape

**Files:**
- Create: `docs/contracts/wardline-attest-2.md`
- Create: `tests/conformance/test_attest_contract_freeze.py`

**Interfaces:**
- Consumes: the attest bundle shape from B1.
- Produces: a frozen producer contract (boundary keys + schema tag) and the documented consumer rules (commit-as-temporal-pin; `enrichment_reasons` triple; the boundary rule that warpline never declares clean).

- [ ] **Step 1: Write the freeze test (failing on the doc absence is fine; assert the shape)**

Create `tests/conformance/test_attest_contract_freeze.py`:

```python
"""Freeze the wardline-attest-2 PRODUCER contract: the boundary key set and schema tag
warpline's risk-as-verification consumer keys on. A change here is a deliberate contract
bump (and must update docs/contracts/wardline-attest-2.md + warpline's consumer)."""

from __future__ import annotations

from pathlib import Path

from wardline.core.attest import ATTEST_SCHEMA, build_attestation

_KEY = "0" * 64

_MODULE = (
    "from wardline.decorators.trust import trusted, external_boundary\n"
    "@external_boundary\n"
    "def src():\n"
    "    return object()\n"
    "@trusted(level='INTEGRAL')\n"
    "def clean():\n"
    "    return 1\n"
)

_FROZEN_BOUNDARY_KEYS = {"qualname", "sei", "content_hash", "verdict", "tier"}
_FROZEN_VERDICTS = {"clean", "defect", "unknown"}


def test_attest_schema_tag_frozen():
    assert ATTEST_SCHEMA == "wardline-attest-2"


def test_boundary_shape_frozen(tmp_path):
    from datetime import date

    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")
    bundle = build_attestation(tmp_path, _KEY, today=date(2026, 6, 24))
    for b in bundle["payload"]["boundaries"]:
        assert set(b.keys()) == _FROZEN_BOUNDARY_KEYS
        assert b["verdict"] in _FROZEN_VERDICTS


def test_consumer_contract_doc_exists():
    doc = Path(__file__).resolve().parents[2] / "docs" / "contracts" / "wardline-attest-2.md"
    assert doc.is_file(), "publish the wardline-attest-2 consumer contract"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/conformance/test_attest_contract_freeze.py -v`
Expected: FAIL on `test_consumer_contract_doc_exists` (doc not yet written); the shape tests PASS (B1 done).

- [ ] **Step 3: Write the consumer contract doc**

Create `docs/contracts/wardline-attest-2.md`:

```markdown
# Contract: `wardline-attest-2` (producer: wardline · consumer: warpline)

Wardline publishes a signed, full-scan, commit-pinned attest bundle. Warpline's
risk-as-verification ("Rung 2") consumes it to decide whether an entity was *proven
clean at a commit*. **Wardline is the trust authority; warpline never declares clean.**

## Bundle shape (verbatim)

`payload.boundaries[]`: `{qualname, sei, content_hash, verdict, tier}`
- `verdict` ∈ `{clean, defect, unknown}` — fail-closed 3-valued. `unknown` (undeclared /
  under-scanned / unprovable) is **never** `clean`.
- `sei`: opaque Loomweave SEI, or `null` when no Loomweave client resolved it.
- `content_hash`: whole-file blake3 binding key, or `null` when unresolved. **File
  granularity, not entity-span** — do not key on it as entity-precise.
- `payload.commit`: the git HEAD the full scan ran against (`dirty` refused at build).
- `payload.attested_at`: the BUILD date (analysis freshness) — **NOT** a resolution time.

## Consumer rules (warpline)

1. **Temporal pin is `commit`** (+ `content_hash`), never `attested_at`. To claim
   "proven clean at commit X", match `payload.commit == X` AND the entity's current
   `content_hash` byte-equals the boundary's. This is a mechanical equality check, not a
   trust judgement.
2. **Only `verdict == "clean"` AND a matched `(commit, content_hash)` → proven-good.**
   Anything else → `risk=unavailable`.
3. **`enrichment_reasons` triple** — the three codes warpline reports when it cannot
   assert proven-good:
   - `not_attested` — no bundle for this commit (absent / commit mismatch).
   - `sei_unkeyed` — bundle present but `sei_source == "unavailable"`, so no boundary
     matches this SEI.
   - `verdict_unknown` — entity SEI-matched but `verdict == "unknown"`.
4. **Signature caveat:** HMAC-SHA256 with a shared project key is tamper-evidence within
   a key-holding domain, NOT non-repudiable proof of *who* produced the bundle.

## Versioning

A change to the boundary key set or `verdict` vocabulary is a schema bump (e.g.
`wardline-attest-3`) and must update this doc, `test_attest_contract_freeze.py`, and
warpline's consumer. Tracked under `wardline-c0563eee74`.
```

- [ ] **Step 4: Run the freeze test to verify it passes**

Run: `.venv/bin/pytest tests/conformance/test_attest_contract_freeze.py -v`
Expected: PASS (all three).

- [ ] **Step 5: Commit**

```bash
git add docs/contracts/wardline-attest-2.md tests/conformance/test_attest_contract_freeze.py
git commit -m "docs(contract): publish wardline-attest-2 consumer contract + freeze test"
```

---

## Phase C — Published versioned contracts + drift checks (overlaps `wardline-c0563eee74`)

> These close the cross-tool contract-integrity gap so warpline can build on stable,
> drift-checked artifacts. They also satisfy `wardline-c0563eee74`'s "publish
> `wardline.delta_scope.v1`" and "verify the worklist consumer vs a published artifact"
> acceptance — track the work there.

### Task C1: Publish + freeze the `wardline.delta_scope.v1` producer artifact

**Files:**
- Create: `tests/conformance/wardline_delta_scope_contract.v1.json`
- Create: `tests/conformance/test_wardline_delta_scope_contract.py`

**Interfaces:**
- Consumes: `DeltaScopeReport.to_dict()` (A2).
- Produces: a versioned, drift-checked producer artifact (mirrors `filigree_suppression_filter_contract.json`).

- [ ] **Step 1: Write the drift test**

Create `tests/conformance/test_wardline_delta_scope_contract.py`:

```python
"""Drift-check DeltaScopeReport.to_dict() against the published wardline.delta_scope.v1
contract. A new/removed field here is a deliberate contract change — bump the artifact."""

from __future__ import annotations

import json
from pathlib import Path

from wardline.core.delta_scope import DeltaScopeReport

_CONTRACT = Path(__file__).resolve().parent / "wardline_delta_scope_contract.v1.json"


def _sample() -> dict:
    return DeltaScopeReport(
        mode="delta",
        gate_authority="advisory",
        scope_source="reverify_worklist_v1",
        entities_requested=1,
        files_discovered=1,
        files_analyzed=1,
        in_scope_findings=0,
        fell_back_count=0,
        stale_sei_count=0,
        unresolved_entities=(),
        loomweave_used=False,
        producer_generated_at="2026-06-18T00:00:00Z",
    ).to_dict()


def test_delta_scope_matches_published_contract():
    contract = json.loads(_CONTRACT.read_text(encoding="utf-8"))
    assert contract["schema"] == "wardline.delta_scope.v1"
    assert set(_sample().keys()) == set(contract["fields"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/conformance/test_wardline_delta_scope_contract.py -v`
Expected: FAIL — contract file missing.

- [ ] **Step 3: Publish the contract artifact**

Create `tests/conformance/wardline_delta_scope_contract.v1.json`:

```json
{
  "schema": "wardline.delta_scope.v1",
  "description": "The --affected delta-scan honesty/provenance block (DeltaScopeReport.to_dict()). Producer: wardline. gate_authority='advisory' in delta mode is never a gate-of-record pass. producer_generated_at is an UNVERIFIED warpline claim.",
  "fields": [
    "mode",
    "gate_authority",
    "scope_source",
    "entities_requested",
    "files_discovered",
    "files_analyzed",
    "in_scope_findings",
    "fell_back_count",
    "stale_sei_count",
    "unresolved_entities",
    "loomweave_used",
    "producer_generated_at",
    "boundary_caveat"
  ]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/conformance/test_wardline_delta_scope_contract.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/conformance/wardline_delta_scope_contract.v1.json tests/conformance/test_wardline_delta_scope_contract.py
git commit -m "feat(contract): publish + drift-check wardline.delta_scope.v1 artifact"
```

---

### Task C2: Strengthen the `warpline.reverify_worklist.v1` consumer drift check

**Files:**
- Modify: `tests/conformance/test_warpline_delta_scope.py`

**Interfaces:**
- Consumes: the vendored `tests/conformance/fixtures/warpline_delta/*.v1.json` fixtures + `parse_affected_scope` (A1).
- Produces: a hermetic assertion that the consumer captures `generated_at`, plus a gated marker for verifying against warpline's *published* artifact (mirrors the SEI oracle's `LOOMWEAVE_REPO` gating).

- [ ] **Step 1: Write the failing assertion**

In `tests/conformance/test_warpline_delta_scope.py` add:

```python
import json
import os
from pathlib import Path

import pytest

from wardline.core.delta_scope import parse_affected_scope

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "warpline_delta"


def test_consumer_captures_worklist_generated_at():
    payload = json.loads((_FIXTURES / "worklist_alpha.v1.json").read_text(encoding="utf-8"))
    scope = parse_affected_scope(payload)
    assert scope.source_kind == "reverify_worklist_v1"
    assert scope.producer_generated_at == "2026-06-18T00:00:00Z"


@pytest.mark.skipif(
    not os.environ.get("WARPLINE_REPO"),
    reason="set WARPLINE_REPO to drift-check the vendored fixtures vs warpline's published "
    "warpline.reverify_worklist.v1 artifact (gated on warpline publishing it)",
)
def test_vendored_worklist_matches_published_artifact():
    published = Path(os.environ["WARPLINE_REPO"]) / "contracts" / "reverify_worklist.v1.schema.json"
    assert published.is_file(), "warpline has not published the worklist contract artifact yet"
    # When warpline publishes, assert each vendored fixture validates against `published`.
    # Until then this is the documented integration point (skips clean).
```

- [ ] **Step 2: Run test to verify it fails then passes the hermetic part**

Run: `.venv/bin/pytest tests/conformance/test_warpline_delta_scope.py::test_consumer_captures_worklist_generated_at -v`
Expected: PASS (A1 shipped). The gated test SKIPS without `WARPLINE_REPO`.

- [ ] **Step 3: Commit**

```bash
git add tests/conformance/test_warpline_delta_scope.py
git commit -m "test(contract): assert worklist generated_at capture + gated published-artifact drift marker"
```

---

## Phase D — Deferred / Out of scope (documented, not implemented)

These are intentionally NOT built now. Each names its trigger so it can be picked up later.

- **D1 — warpline declared `completeness` propagation (GATED on warpline).** The proposal's
  acceptance asks wardline to declare warpline's *completeness*. No `completeness` field
  exists in `warpline.reverify_worklist.v1` today. **Do not add a wardline-side placeholder
  with a default** — emit absence; warpline reports `risk=unavailable(completeness_not_declared)`
  at its own layer. **Trigger:** warpline publishes a `completeness` field in the worklist
  contract. Then mirror A1/A2/A4 for one more field (`producer_completeness`).
- **D2 — `warpline.impact_radius.v1` / `blast_radius` consumption (REJECTED).** The schema
  does not exist, and "Read `warpline_impact_radius_get`" violates the never-call invariant.
  The worklist already carries `depth`/`why`/`enrichment` that the parser drops. **If a
  blast-radius signal is wanted later,** un-drop those existing worklist fields inside the
  current consumer (a pushed shape), rather than standing up a second schema + parser + DoS
  caps + drift contract.
- **D3 — live-pull of warpline (CONSTRAINT CONFLICT, confirm before any build).** If the
  requester genuinely wants wardline to *call* `warpline_*_get`, that reverses the shipped
  `delta_scope.py:8-16` invariant and adds a liveness/SSRF/trust surface. Surface it as a
  decision, do not implement silently.

---

## Self-Review

**Spec coverage (against the evaluation):**
- (a) declare scope source → A2/A3/A4 (`scope_source`). ✓
- (a) declare warpline staleness → A1/A3 (`producer_generated_at`). ✓
- (a) completeness → D1 (gated, correctly deferred). ✓
- (a) impact_radius → D2 (rejected with rationale). ✓
- (a) full scan stays authoritative → unchanged; INV-4 + `--affected`/`--fail-on` rejection asserted green (A3 Step 6). ✓
- (b) per-SEI clean-at-commit via attest, not Finding lifecycle → B1 (`content_hash`, schema bump). ✓
- (b) timestamp = commit pin, not build date → documented in B2 contract. ✓
- (b) `enrichment_reasons` triple → defined in B2. ✓
- (b) 3-valued fidelity / boundary → frozen in B2 (`_FROZEN_VERDICTS`) + contract rules. ✓
- Versioned, drift-checked contracts → C1 (delta_scope.v1), C2 (worklist consumer), B2 (attest-2). ✓
- Security guards: GUARD-1 (clean only from full attest, never delta) — attest runs full by construction; GUARD-2 (content_hash binding) — B1; GUARD-3 (stale/orphaned can't transfer) — warpline equality check on `content_hash`, documented B2. ✓

**Placeholder scan:** every code/test step contains complete, runnable code; no TBD/"similar to". ✓

**Type consistency:** field names are identical across tasks — `producer_generated_at` (A1 `AffectedScope` → A2 `DeltaScopeReport` → A3 `run_scan` → A4 schema/required → C1 contract), `scope_source` (A2→A3→A4→C1), `content_hash` (B1→B2 frozen key set). The `_FROZEN_BOUNDARY_KEYS` in B2 == the boundary dict built in B1. ✓
