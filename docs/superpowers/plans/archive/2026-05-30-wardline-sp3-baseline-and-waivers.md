# SP3 — Light-touch Baseline + Waivers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a git-committable baseline + human-readable waivers so `wardline scan` annotates known/waived findings (keeping them in output) and `--fail-on` trips only on findings that are neither baselined nor waived; plus `wardline baseline create|update` to manage the baseline.

**Architecture:** Three pure `core/` modules (`baseline.py`, `waivers.py`, `suppression.py`) plus a typed `Finding.suppressed` field. Suppression runs as a post-analyze CLI stage, never inside the analyzer (the analyzer keeps emitting the raw Filigree-facing fact). `today` is injected so the suppression layer is hermetic; the CLI sources `date.today()` once. No HMAC/signing/governance — plain YAML in git.

**Tech Stack:** Python 3.12, frozen+slots dataclasses, `StrEnum`, PyYAML (`safe_load`/`safe_dump`), `datetime.date`, `click` CLI.

**Spec:** `docs/superpowers/specs/2026-05-30-wardline-sp3-baseline-and-waivers-design.md`. Read §4–§8 before starting.

**Gate (every task):** `.venv/bin/python -m pytest -q`, `.venv/bin/ruff check src tests`, `.venv/bin/mypy src`. ALWAYS the venv binaries — never bare `python`/`pytest`/`ruff`/`mypy`.

---

## File Structure

- **Modify** `src/wardline/core/finding.py` — add `SuppressionState` StrEnum + `Finding.suppressed`/`suppression_reason` fields + serialization (Task 1).
- **Create** `src/wardline/core/baseline.py` — `Baseline` model, `BASELINE_VERSION`, `build_baseline_document`, `write_baseline`, `load_baseline` (Task 2).
- **Create** `src/wardline/core/waivers.py` — `Waiver`, `parse_waivers`, `WaiverSet` (Task 3).
- **Modify** `src/wardline/core/config.py` — `waivers` raw field + `_KNOWN_KEYS` (Task 3).
- **Create** `src/wardline/core/suppression.py` — `SEVERITY_ORDER`, `apply_suppressions`, `gate_trips` (Task 4).
- **Modify** `src/wardline/cli/scan.py` — load + apply + annotate + summary + live `--fail-on` (Task 5).
- **Modify** `src/wardline/cli/main.py` — `wardline baseline create|update` group (Task 6).
- **Tests:** `tests/unit/core/test_finding.py` (extend), `tests/unit/core/test_baseline.py` (new), `tests/unit/core/test_waivers.py` (new), `tests/unit/core/test_config.py` (extend), `tests/unit/core/test_suppression.py` (new), `tests/unit/cli/test_cli.py` (extend).

---

## SP3a — Pure core (Tasks 1–4)

### Task 1: `Finding.suppressed` typed field + serialization

**Files:**
- Modify: `src/wardline/core/finding.py`
- Test: `tests/unit/core/test_finding.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/core/test_finding.py`:

```python
def test_finding_defaults_to_active_suppression() -> None:
    from wardline.core.finding import SuppressionState

    assert _finding().suppressed is SuppressionState.ACTIVE
    assert _finding().suppression_reason is None


def test_suppressed_serializes_in_jsonl() -> None:
    from wardline.core.finding import SuppressionState

    f = _finding(suppressed=SuppressionState.WAIVED, suppression_reason="reviewed")
    obj = json.loads(f.to_jsonl())
    assert obj["suppressed"] == "waived"
    assert obj["suppression_reason"] == "reviewed"


def test_active_suppression_serializes_too() -> None:
    obj = json.loads(_finding().to_jsonl())
    assert obj["suppressed"] == "active"
    assert obj["suppression_reason"] is None


def test_suppressed_not_in_fingerprint_inputs() -> None:
    # suppression must never change identity.
    from wardline.core.finding import SuppressionState
    from dataclasses import replace

    f = _finding()
    g = replace(f, suppressed=SuppressionState.BASELINED)
    assert f.fingerprint == g.fingerprint  # fingerprint is a stored field, unaffected


def test_filigree_metadata_includes_suppression_only_when_suppressed() -> None:
    from wardline.core.finding import SuppressionState, to_filigree_metadata

    active = to_filigree_metadata(_finding())["wardline"]
    assert "suppressed" not in active
    waived = to_filigree_metadata(
        _finding(suppressed=SuppressionState.WAIVED, suppression_reason="ok")
    )["wardline"]
    assert waived["suppressed"] == "waived"
    assert waived["suppression_reason"] == "ok"
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/core/test_finding.py -q`
Expected: FAIL — `ImportError: cannot import name 'SuppressionState'` / unexpected keyword `suppressed`.

- [ ] **Step 3: Add the enum and fields**

In `src/wardline/core/finding.py`, after the `Kind` StrEnum (around line 33), add:

```python
class SuppressionState(StrEnum):
    ACTIVE = "active"        # not suppressed — the default
    BASELINED = "baselined"  # matched a baseline fingerprint
    WAIVED = "waived"        # matched an active waiver
```

In the `Finding` dataclass, add two fields at the END of the field list (after `properties`):

```python
    suppressed: SuppressionState = SuppressionState.ACTIVE
    suppression_reason: str | None = None
```

In `Finding.to_jsonl`, add to the `payload` dict (before the `return`):

```python
            "suppressed": self.suppressed.value,
            "suppression_reason": self.suppression_reason,
```

- [ ] **Step 4: Serialize in `to_filigree_metadata`**

In `to_filigree_metadata`, after the `properties` block and before `return`, add:

```python
    if finding.suppressed is not SuppressionState.ACTIVE:
        wardline["suppressed"] = finding.suppressed.value
        if finding.suppression_reason is not None:
            wardline["suppression_reason"] = finding.suppression_reason
```

- [ ] **Step 5: Run to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/core/test_finding.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/finding.py tests/unit/core/test_finding.py
git commit -m "feat(sp3a): typed Finding.suppressed field + serialization"
```

---

### Task 2: `core/baseline.py`

**Files:**
- Create: `src/wardline/core/baseline.py`
- Test: `tests/unit/core/test_baseline.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/core/test_baseline.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from wardline.core.baseline import (
    BASELINE_VERSION,
    Baseline,
    build_baseline_document,
    load_baseline,
    write_baseline,
)
from wardline.core.errors import ConfigError
from wardline.core.finding import Finding, Kind, Location, Severity

_FP_A = "a" * 64
_FP_B = "b" * 64


def _finding(fp: str, *, rule: str = "PY-WL-101", sev: Severity = Severity.ERROR, path: str = "src/m.py") -> Finding:
    return Finding(
        rule_id=rule, message=f"msg {fp[:4]}", severity=sev, kind=Kind.DEFECT,
        location=Location(path=path, line_start=1), fingerprint=fp,
    )


def test_build_document_shape_and_version() -> None:
    doc = build_baseline_document([_finding(_FP_A)])
    assert doc["version"] == BASELINE_VERSION
    assert doc["entries"][0]["fingerprint"] == _FP_A
    assert doc["entries"][0]["rule_id"] == "PY-WL-101"
    assert "path" in doc["entries"][0] and "message" in doc["entries"][0]


def test_build_document_dedups_and_sorts_severity_first() -> None:
    findings = [
        _finding(_FP_A, sev=Severity.WARN, rule="PY-WL-103"),
        _finding(_FP_B, sev=Severity.CRITICAL, rule="PY-WL-101"),
        _finding(_FP_A, sev=Severity.WARN, rule="PY-WL-103"),  # dup fingerprint
    ]
    entries = build_baseline_document(findings)["entries"]
    assert [e["fingerprint"] for e in entries] == [_FP_B, _FP_A]  # CRITICAL first; dup collapsed


def test_write_then_load_round_trips(tmp_path: Path) -> None:
    p = tmp_path / ".wardline" / "baseline.yaml"
    write_baseline(p, [_finding(_FP_A), _finding(_FP_B)])
    bl = load_baseline(p)
    assert bl.fingerprints == frozenset({_FP_A, _FP_B})
    assert bl.contains(_FP_A) and not bl.contains("c" * 64)


def test_missing_file_is_empty_baseline(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "nope.yaml").fingerprints == frozenset()


def test_empty_file_is_empty_baseline(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text("", encoding="utf-8")
    assert load_baseline(p).fingerprints == frozenset()


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text("entries: [1, 2\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_version_mismatch_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(yaml.safe_dump({"version": 999, "entries": []}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_bad_fingerprint_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(yaml.safe_dump({"version": BASELINE_VERSION, "entries": [{"fingerprint": "short"}]}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(p)


def test_duplicate_fingerprint_in_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "b.yaml"
    p.write_text(
        yaml.safe_dump({"version": BASELINE_VERSION, "entries": [{"fingerprint": _FP_A}, {"fingerprint": _FP_A}]}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_baseline(p)
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/core/test_baseline.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.core.baseline'`.

- [ ] **Step 3: Write `baseline.py`**

Create `src/wardline/core/baseline.py`:

```python
# src/wardline/core/baseline.py
"""The git-committable finding baseline (SP3).

A ``.wardline/baseline.yaml`` is a snapshot of accepted findings keyed on the
full ``Finding.fingerprint`` (strict match — see spec §2 dial 1). The committed
file carries ``rule_id``/``path``/``message`` per entry for human auditability in
a git diff; only ``fingerprint`` is loaded into the match set. No governance.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from wardline.core.errors import ConfigError
from wardline.core.finding import Finding, Severity

BASELINE_VERSION: int = 1
"""Bumped on a format change; validated on load (mirrors STDLIB_TAINT_VERSION)."""

# CRITICAL sorts first so high-severity entries sit at the top of the git diff.
_SEVERITY_SORT: dict[Severity, int] = {
    Severity.CRITICAL: 0, Severity.ERROR: 1, Severity.WARN: 2, Severity.INFO: 3, Severity.NONE: 4,
}
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class Baseline:
    fingerprints: frozenset[str]

    def contains(self, fingerprint: str) -> bool:
        return fingerprint in self.fingerprints


def build_baseline_document(findings: Iterable[Finding]) -> dict[str, Any]:
    """Pure: the YAML-shaped dict for the given findings (deduped, severity-sorted)."""
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.fingerprint, f)
    ordered = sorted(
        unique.values(),
        key=lambda f: (_SEVERITY_SORT[f.severity], f.rule_id, f.location.path, f.fingerprint),
    )
    return {
        "version": BASELINE_VERSION,
        "entries": [
            {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "path": f.location.path, "message": f.message}
            for f in ordered
        ],
    }


def write_baseline(path: Path, findings: Iterable[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        build_baseline_document(findings), sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    path.write_text(text, encoding="utf-8")


def load_baseline(path: Path) -> Baseline:
    if not path.exists():
        return Baseline(frozenset())
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    return _build_baseline(raw, path.name)


def _build_baseline(raw: Any, name: str = "baseline.yaml") -> Baseline:
    if not isinstance(raw, dict):
        raise ConfigError(f"{name}: must be a mapping at top level")
    if not raw:
        return Baseline(frozenset())
    if raw.get("version") != BASELINE_VERSION:
        raise ConfigError(f"{name}: version mismatch — expected {BASELINE_VERSION}, got {raw.get('version')!r}")
    entries = raw.get("entries")
    if entries is None:
        return Baseline(frozenset())
    if not isinstance(entries, list):
        raise ConfigError(f"{name}: 'entries' must be a list")
    fingerprints: set[str] = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"{name} entries[{idx}] must be a mapping")
        fp = entry.get("fingerprint")
        if not isinstance(fp, str) or len(fp) != 64 or not set(fp) <= _HEX:
            raise ConfigError(f"{name} entries[{idx}].fingerprint must be a 64-char hex string")
        if fp in fingerprints:
            raise ConfigError(f"{name} entries[{idx}]: duplicate fingerprint {fp!r}")
        fingerprints.add(fp)
    return Baseline(frozenset(fingerprints))
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/core/test_baseline.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/baseline.py tests/unit/core/test_baseline.py
git commit -m "feat(sp3a): baseline model — load/write/build, validated"
```

---

### Task 3: `core/waivers.py` + config `waivers` field

**Files:**
- Create: `src/wardline/core/waivers.py`
- Modify: `src/wardline/core/config.py`
- Test: `tests/unit/core/test_waivers.py`, `tests/unit/core/test_config.py`

- [ ] **Step 1: Write the failing waiver tests**

Create `tests/unit/core/test_waivers.py`:

```python
from __future__ import annotations

from datetime import date

import pytest

from wardline.core.errors import ConfigError
from wardline.core.waivers import Waiver, WaiverSet, parse_waivers

_FP = "a" * 64


def test_parse_minimal_waiver() -> None:
    (w,) = parse_waivers([{"fingerprint": _FP, "reason": "false positive"}])
    assert w == Waiver(fingerprint=_FP, reason="false positive", expires=None)


def test_parse_expiry_from_date_object() -> None:
    (w,) = parse_waivers([{"fingerprint": _FP, "reason": "r", "expires": date(2026, 9, 1)}])
    assert w.expires == date(2026, 9, 1)


def test_parse_expiry_from_iso_string() -> None:
    (w,) = parse_waivers([{"fingerprint": _FP, "reason": "r", "expires": "2026-09-01"}])
    assert w.expires == date(2026, 9, 1)


def test_missing_reason_raises() -> None:
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _FP}])
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _FP, "reason": "   "}])


def test_bad_fingerprint_raises() -> None:
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": "short", "reason": "r"}])


def test_unparseable_expiry_raises() -> None:
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _FP, "reason": "r", "expires": "soon"}])


def test_duplicate_fingerprint_raises() -> None:
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _FP, "reason": "a"}, {"fingerprint": _FP, "reason": "b"}])


def test_match_active_when_no_expiry() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP, "reason": "r"}]))
    assert ws.match(_FP, date(2026, 5, 30)) is not None
    assert ws.match("b" * 64, date(2026, 5, 30)) is None


def test_expiry_boundary_inclusive_then_expires() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP, "reason": "r", "expires": "2026-05-30"}]))
    assert ws.match(_FP, date(2026, 5, 30)) is not None   # valid THROUGH expiry day
    assert ws.match(_FP, date(2026, 5, 31)) is None        # expired the day after
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/core/test_waivers.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.core.waivers'`.

- [ ] **Step 3: Write `waivers.py`**

Create `src/wardline/core/waivers.py`:

```python
# src/wardline/core/waivers.py
"""Human-authored finding waivers (SP3).

Waivers live inline in ``wardline.yaml`` under a ``waivers:`` list, each keyed on
a finding's full ``fingerprint`` (copied from scan output), with a REQUIRED reason
and an OPTIONAL ISO expiry date. An expired waiver stops suppressing (the finding
resurfaces). No governance.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from wardline.core.errors import ConfigError

_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class Waiver:
    fingerprint: str
    reason: str
    expires: date | None = None

    def is_active(self, today: date) -> bool:
        """Active through the expiry day; expired strictly after (today > expires)."""
        return self.expires is None or today <= self.expires


def _parse_expiry(raw: Any, idx: int) -> date | None:
    if raw is None:
        return None
    if isinstance(raw, datetime):  # datetime IS-A date — check it FIRST
        return raw.date()
    if isinstance(raw, date):
        return raw
    if isinstance(raw, str):
        try:
            return date.fromisoformat(raw)
        except ValueError as exc:
            raise ConfigError(f"waivers[{idx}].expires {raw!r} is not an ISO date (YYYY-MM-DD)") from exc
    raise ConfigError(f"waivers[{idx}].expires must be a date or ISO string, got {type(raw).__name__}")


def parse_waivers(raw: Sequence[Mapping[str, Any]]) -> tuple[Waiver, ...]:
    if not raw:
        return ()
    waivers: list[Waiver] = []
    seen: set[str] = set()
    for idx, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ConfigError(f"waivers[{idx}] must be a mapping")
        fp = item.get("fingerprint")
        if not isinstance(fp, str) or len(fp) != 64 or not set(fp) <= _HEX:
            raise ConfigError(f"waivers[{idx}].fingerprint must be a 64-char hex string")
        if fp in seen:
            raise ConfigError(f"waivers[{idx}]: duplicate fingerprint {fp!r}")
        seen.add(fp)
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ConfigError(f"waivers[{idx}].reason is required (non-empty string)")
        waivers.append(Waiver(fingerprint=fp, reason=reason, expires=_parse_expiry(item.get("expires"), idx)))
    return tuple(waivers)


class WaiverSet:
    """Fingerprint → waiver lookup with expiry-aware matching."""

    def __init__(self, waivers: Iterable[Waiver]) -> None:
        self._by_fp: dict[str, Waiver] = {w.fingerprint: w for w in waivers}

    def match(self, fingerprint: str, today: date) -> Waiver | None:
        waiver = self._by_fp.get(fingerprint)
        if waiver is None or not waiver.is_active(today):
            return None
        return waiver
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/core/test_waivers.py -q`
Expected: PASS.

- [ ] **Step 5: Write the failing config test**

Append to `tests/unit/core/test_config.py`:

```python
def test_waivers_block_is_parsed_raw(tmp_path) -> None:
    from wardline.core import config as config_mod

    p = tmp_path / "wardline.yaml"
    p.write_text(
        "waivers:\n  - fingerprint: " + ("a" * 64) + "\n    reason: ok\n",
        encoding="utf-8",
    )
    cfg = config_mod.load(p)
    assert cfg.waivers == ({"fingerprint": "a" * 64, "reason": "ok"},)


def test_waivers_key_does_not_warn(recwarn, tmp_path) -> None:
    from wardline.core import config as config_mod

    p = tmp_path / "wardline.yaml"
    p.write_text("waivers: []\n", encoding="utf-8")
    config_mod.load(p)
    assert not [w for w in recwarn.list if "waivers" in str(w.message)]
```

- [ ] **Step 6: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/core/test_config.py -q -k waivers`
Expected: FAIL — `WardlineConfig` has no attribute `waivers` (and a spurious unknown-key warning).

- [ ] **Step 7: Add the `waivers` field to config**

In `src/wardline/core/config.py`:

Add `"waivers"` to `_KNOWN_KEYS`:

```python
_KNOWN_KEYS = frozenset(
    {"source_roots", "exclude", "rules", "baseline", "waivers", "judge", "filigree", "clarion"}
)
```

Add a field to `WardlineConfig` (after `rules_severity`, alongside the reserved raw maps):

```python
    waivers: tuple[Mapping[str, Any], ...] = ()
```

In `load(...)`, add to the `WardlineConfig(...)` constructor call:

```python
        waivers=tuple(raw.get("waivers") or ()),
```

- [ ] **Step 8: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/core/test_config.py -q`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/wardline/core/waivers.py src/wardline/core/config.py tests/unit/core/test_waivers.py tests/unit/core/test_config.py
git commit -m "feat(sp3a): waiver model + parse + config waivers field"
```

---

### Task 4: `core/suppression.py` — `apply_suppressions` + `gate_trips`

**Files:**
- Create: `src/wardline/core/suppression.py`
- Test: `tests/unit/core/test_suppression.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/core/test_suppression.py`:

```python
from __future__ import annotations

from datetime import date

from wardline.core.baseline import Baseline
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.suppression import apply_suppressions, gate_trips
from wardline.core.waivers import WaiverSet, parse_waivers

_FP_A = "a" * 64
_FP_B = "b" * 64
_TODAY = date(2026, 5, 30)


def _defect(fp: str, *, sev: Severity = Severity.ERROR, kind: Kind = Kind.DEFECT) -> Finding:
    return Finding(
        rule_id="PY-WL-101", message="m", severity=sev, kind=kind,
        location=Location(path="src/m.py", line_start=1), fingerprint=fp,
    )


def _empty_baseline() -> Baseline:
    return Baseline(frozenset())


def _no_waivers() -> WaiverSet:
    return WaiverSet(())


def test_baselined_finding_is_annotated() -> None:
    out = apply_suppressions([_defect(_FP_A)], Baseline(frozenset({_FP_A})), _no_waivers(), today=_TODAY)
    assert out[0].suppressed is SuppressionState.BASELINED


def test_waived_finding_is_annotated_with_reason() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP_A, "reason": "fp"}]))
    out = apply_suppressions([_defect(_FP_A)], _empty_baseline(), ws, today=_TODAY)
    assert out[0].suppressed is SuppressionState.WAIVED
    assert out[0].suppression_reason == "fp"


def test_waiver_wins_over_baseline() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP_A, "reason": "fp"}]))
    out = apply_suppressions([_defect(_FP_A)], Baseline(frozenset({_FP_A})), ws, today=_TODAY)
    assert out[0].suppressed is SuppressionState.WAIVED  # waiver precedence keeps expiry observable


def test_expired_waiver_falls_back_to_active_or_baseline() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP_A, "reason": "fp", "expires": "2026-05-29"}]))
    # expired, not baselined -> stays ACTIVE (resurfaces)
    out = apply_suppressions([_defect(_FP_A)], _empty_baseline(), ws, today=_TODAY)
    assert out[0].suppressed is SuppressionState.ACTIVE
    # expired, but baselined -> baseline still suppresses
    out2 = apply_suppressions([_defect(_FP_A)], Baseline(frozenset({_FP_A})), ws, today=_TODAY)
    assert out2[0].suppressed is SuppressionState.BASELINED


def test_non_defect_passes_through_active() -> None:
    out = apply_suppressions([_defect(_FP_A, kind=Kind.METRIC)], Baseline(frozenset({_FP_A})), _no_waivers(), today=_TODAY)
    assert out[0].suppressed is SuppressionState.ACTIVE  # only DEFECT is suppressed


def test_gate_trips_only_on_active_defect_at_or_above_threshold() -> None:
    # non-suppressed ERROR defect, fail-on ERROR -> trips
    assert gate_trips([_defect(_FP_A, sev=Severity.ERROR)], Severity.ERROR) is True
    # below threshold
    assert gate_trips([_defect(_FP_A, sev=Severity.WARN)], Severity.ERROR) is False
    # exactly at threshold (>=)
    assert gate_trips([_defect(_FP_A, sev=Severity.CRITICAL)], Severity.CRITICAL) is True


def test_gate_ignores_suppressed_and_nondefect_and_none() -> None:
    baselined = apply_suppressions([_defect(_FP_A)], Baseline(frozenset({_FP_A})), _no_waivers(), today=_TODAY)
    assert gate_trips(baselined, Severity.ERROR) is False           # suppressed ignored
    assert gate_trips([_defect(_FP_A, kind=Kind.FACT)], Severity.INFO) is False  # non-defect ignored
    assert gate_trips([_defect(_FP_A, sev=Severity.NONE)], Severity.INFO) is False  # NONE never gates
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/core/test_suppression.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.core.suppression'`.

- [ ] **Step 3: Write `suppression.py`**

Create `src/wardline/core/suppression.py`:

```python
# src/wardline/core/suppression.py
"""Apply baseline + waivers to findings, and the ``--fail-on`` gate predicate (SP3).

Pure functions: ``today`` is injected so the whole layer is hermetic. Only
``Kind.DEFECT`` findings are suppressed or gated; an ACTIVE waiver wins over the
baseline (it carries the reason + expiry, keeping expiry observable).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import date

from wardline.core.baseline import Baseline
from wardline.core.finding import Finding, Kind, Severity, SuppressionState
from wardline.core.waivers import WaiverSet

# Ascending trust-cost order for the --fail-on threshold. NONE is absent — facts
# and metrics never participate in the gate.
SEVERITY_ORDER: tuple[Severity, ...] = (Severity.INFO, Severity.WARN, Severity.ERROR, Severity.CRITICAL)
_RANK: dict[Severity, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def apply_suppressions(
    findings: Iterable[Finding], baseline: Baseline, waivers: WaiverSet, *, today: date
) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        if f.kind is not Kind.DEFECT:
            out.append(f)
            continue
        waiver = waivers.match(f.fingerprint, today)
        if waiver is not None:
            out.append(replace(f, suppressed=SuppressionState.WAIVED, suppression_reason=waiver.reason))
        elif baseline.contains(f.fingerprint):
            out.append(replace(f, suppressed=SuppressionState.BASELINED))
        else:
            out.append(f)
    return out


def gate_trips(findings: Iterable[Finding], fail_on: Severity) -> bool:
    """True iff any ACTIVE Kind.DEFECT finding has severity >= fail_on."""
    threshold = _RANK[fail_on]
    for f in findings:
        if f.kind is not Kind.DEFECT or f.suppressed is not SuppressionState.ACTIVE:
            continue
        rank = _RANK.get(f.severity)
        if rank is not None and rank >= threshold:
            return True
    return False
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/core/test_suppression.py -q`
Expected: PASS.

- [ ] **Step 5: Run the SP3a gate**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: all pass; ruff + mypy clean. (`gate_trips` is called with `Severity`; the CLI will convert the `--fail-on` string in Task 5.)

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/suppression.py tests/unit/core/test_suppression.py
git commit -m "feat(sp3a): suppression engine — apply_suppressions + gate_trips"
```

---

## SP3b — Scan integration (Task 5)

### Task 5: `wardline scan` applies suppressions, summary line, live `--fail-on`

**Files:**
- Modify: `src/wardline/cli/scan.py`
- Test: `tests/unit/cli/test_cli.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/cli/test_cli.py` (note: existing top imports already include `from click.testing import CliRunner`, `from wardline.cli.scan import scan`, `import json as _json`):

```python
def _write(project, name, src):
    p = project / name
    p.write_text(src, encoding="utf-8")
    return p


# A @trusted function returning raw data fires PY-WL-101 (a real DEFECT).
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def test_scan_fail_on_trips_on_unsuppressed_defect(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)
    out = tmp_path / "f.jsonl"
    res = CliRunner().invoke(scan, [str(proj), "--output", str(out), "--fail-on", "ERROR"])
    assert res.exit_code == 1, res.output  # PY-WL-101 is ERROR, unsuppressed


def test_scan_fail_on_inert_without_flag(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)
    out = tmp_path / "f.jsonl"
    res = CliRunner().invoke(scan, [str(proj), "--output", str(out)])
    assert res.exit_code == 0, res.output  # no --fail-on -> never gates


def test_scan_baseline_suppresses_and_clears_gate(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)
    out = tmp_path / "f.jsonl"
    # First scan: capture the PY-WL-101 fingerprint.
    CliRunner().invoke(scan, [str(proj), "--output", str(out)])
    findings = [_json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    fp = next(f["fingerprint"] for f in findings if f["rule_id"] == "PY-WL-101")
    # Write a baseline accepting it.
    bl = proj / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text(
        "version: 1\nentries:\n  - fingerprint: " + fp + "\n    rule_id: PY-WL-101\n    path: svc.py\n    message: m\n",
        encoding="utf-8",
    )
    # Second scan: the defect is baselined -> annotated + gate clears.
    res = CliRunner().invoke(scan, [str(proj), "--output", str(out), "--fail-on", "ERROR"])
    assert res.exit_code == 0, res.output
    findings2 = [_json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    leak = next(f for f in findings2 if f["rule_id"] == "PY-WL-101")
    assert leak["suppressed"] == "baselined"  # annotate-and-keep
    assert "1 suppressed" in res.output


def test_scan_malformed_baseline_exits_2(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", "def f(p):\n    return p\n")
    bl = proj / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text("version: 1\nentries: [1, 2\n", encoding="utf-8")  # malformed
    res = CliRunner().invoke(scan, [str(proj), "--output", str(tmp_path / "f.jsonl")])
    assert res.exit_code == 2  # never silently empty -> mass-unsuppress
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q -k "fail_on or baseline_suppresses or malformed_baseline"`
Expected: FAIL — `--fail-on ERROR` currently exits 0 (inert); no `suppressed` key; malformed baseline not yet read.

- [ ] **Step 3: Rewrite the body of `scan`**

In `src/wardline/cli/scan.py`, update the imports block to add:

```python
from datetime import date

from wardline.core.baseline import load_baseline
from wardline.core.finding import Kind, Severity, SuppressionState
from wardline.core.suppression import apply_suppressions, gate_trips
from wardline.core.waivers import WaiverSet, parse_waivers
```

Replace the body from `output = output if ...` through the final `click.echo(...)` with:

```python
    output = output if output is not None else (path / "findings.jsonl")
    try:
        cfg_path = config_path or (path / "wardline.yaml")
        cfg = config_mod.load(cfg_path)
        cache = None
        if cache_dir is not None:
            cache = SummaryCache(cache_dir=cache_dir)
            cache.load()
        files = discover(path, cfg)
        findings = WardlineAnalyzer(summary_cache=cache).analyze(files, cfg, root=path)
        if cache is not None:
            cache.save()
        baseline = load_baseline(path / ".wardline" / "baseline.yaml")
        waivers = WaiverSet(parse_waivers(cfg.waivers))
        findings = apply_suppressions(findings, baseline, waivers, today=date.today())
        JsonlSink(output).write(findings)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    baselined = sum(1 for f in defects if f.suppressed is SuppressionState.BASELINED)
    waived = sum(1 for f in defects if f.suppressed is SuppressionState.WAIVED)
    new = sum(1 for f in defects if f.suppressed is SuppressionState.ACTIVE)
    click.echo(
        f"scanned {len(files)} file(s); {len(findings)} finding(s) — "
        f"{baselined + waived} suppressed ({baselined} baseline / {waived} waiver), {new} new -> {output}"
    )
    if fail_on is not None and gate_trips(findings, Severity(fail_on)):
        raise SystemExit(1)
```

(Leave the SARIF guard and the function signature unchanged. The existing `from wardline.core.errors import WardlineError` import stays.)

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q`
Expected: PASS (including the pre-existing scan tests — the summary-line text changed, so confirm no pre-existing test asserts the OLD exact summary string; if one does, update it to match the new format).

- [ ] **Step 5: Run the SP3b gate**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: all pass. Confirm `tests/test_self_hosting.py` stays green (own code is undecorated → no DEFECT → nothing suppressed, no baseline file).

- [ ] **Step 6: Commit**

```bash
git add src/wardline/cli/scan.py tests/unit/cli/test_cli.py
git commit -m "feat(sp3b): scan applies baseline+waivers, live --fail-on, drift summary"
```

---

## SP3c — Baseline CLI (Task 6)

### Task 6: `wardline baseline create|update`

**Files:**
- Modify: `src/wardline/cli/main.py`
- Test: `tests/unit/cli/test_cli.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/cli/test_cli.py`:

```python
import yaml as _yaml

from wardline.cli.main import cli as _cli

_LEAKY_FOR_BASELINE = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def test_baseline_create_writes_file_and_suppresses_next_scan(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_FOR_BASELINE, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(_cli, ["baseline", "create", str(proj)])
    assert res.exit_code == 0, res.output
    bl = proj / ".wardline" / "baseline.yaml"
    assert bl.exists()
    doc = _yaml.safe_load(bl.read_text())
    assert doc["version"] == 1 and len(doc["entries"]) >= 1
    assert "baselined" in res.output
    # Next scan: the captured defect is now baselined, gate clears.
    out = tmp_path / "f.jsonl"
    res2 = runner.invoke(scan, [str(proj), "--output", str(out), "--fail-on", "ERROR"])
    assert res2.exit_code == 0, res2.output


def test_baseline_create_refuses_if_exists(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_FOR_BASELINE, encoding="utf-8")
    runner = CliRunner()
    runner.invoke(_cli, ["baseline", "create", str(proj)])
    res = runner.invoke(_cli, ["baseline", "create", str(proj)])
    assert res.exit_code == 2  # already exists -> use update


def test_baseline_update_overwrites(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_FOR_BASELINE, encoding="utf-8")
    runner = CliRunner()
    runner.invoke(_cli, ["baseline", "create", str(proj)])
    res = runner.invoke(_cli, ["baseline", "update", str(proj)])
    assert res.exit_code == 0, res.output


def test_baseline_create_excludes_active_waivers(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_FOR_BASELINE, encoding="utf-8")
    runner = CliRunner()
    # Discover the fingerprint first.
    out = tmp_path / "f.jsonl"
    runner.invoke(scan, [str(proj), "--output", str(out)])
    fp = next(
        _json.loads(ln)["fingerprint"]
        for ln in out.read_text().splitlines() if ln.strip() and _json.loads(ln)["rule_id"] == "PY-WL-101"
    )
    # Waive it, then create the baseline -> the waived fingerprint must be EXCLUDED.
    (proj / "wardline.yaml").write_text(
        "waivers:\n  - fingerprint: " + fp + "\n    reason: handled\n", encoding="utf-8"
    )
    res = runner.invoke(_cli, ["baseline", "create", str(proj)])
    assert res.exit_code == 0, res.output
    doc = _yaml.safe_load((proj / ".wardline" / "baseline.yaml").read_text()) or {}
    fps = {e["fingerprint"] for e in (doc.get("entries") or [])}
    assert fp not in fps  # active-waiver fingerprint excluded from the baseline
```

Also UPDATE the pre-existing stub test `test_baseline_and_judge_stubs_exit_2` — `baseline` is no longer a stub. Change it to assert only `judge` exits 2, and that bare `wardline baseline` (no subcommand) prints help:

```python
def test_judge_stub_exits_2_and_baseline_is_a_group() -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["judge"]).exit_code == 2
    # `baseline` is now a command group; invoking it with no subcommand shows help.
    res = runner.invoke(cli, ["baseline"])
    assert res.exit_code == 0
    assert "create" in res.output and "update" in res.output
```

(Delete the old `test_baseline_and_judge_stubs_exit_2`.)

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q -k baseline`
Expected: FAIL — `baseline` is currently a stub command that exits 2; no `create`/`update` subcommands.

- [ ] **Step 3: Replace the `baseline` stub with a command group**

In `src/wardline/cli/main.py`, add imports:

```python
from datetime import date
from pathlib import Path

import click

from wardline.core import config as config_mod
from wardline.core.baseline import write_baseline
from wardline.core.discovery import discover
from wardline.core.errors import WardlineError
from wardline.core.finding import Kind
from wardline.core.waivers import WaiverSet, parse_waivers
from wardline.scanner.analyzer import WardlineAnalyzer
```

Delete the existing `@cli.command() def baseline(): ...` stub and replace with:

```python
def _generate_baseline(path: Path, *, overwrite: bool) -> None:
    baseline_path = path / ".wardline" / "baseline.yaml"
    if baseline_path.exists() and not overwrite:
        click.echo(
            f"{baseline_path} already exists; use `wardline baseline update` to overwrite.", err=True
        )
        raise SystemExit(2)
    try:
        cfg = config_mod.load(path / "wardline.yaml")
        waivers = WaiverSet(parse_waivers(cfg.waivers))
        today = date.today()
        files = discover(path, cfg)
        findings = WardlineAnalyzer().analyze(files, cfg, root=path)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    # Capture current DEFECTs, EXCLUDING any with an active waiver (else the
    # baseline swallows them and their expiry never resurfaces — spec §8).
    to_baseline = [
        f for f in findings
        if f.kind is Kind.DEFECT and waivers.match(f.fingerprint, today) is None
    ]
    write_baseline(baseline_path, to_baseline)
    from collections import Counter

    counts = Counter(f.severity.value for f in to_baseline)
    breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items()))
    click.echo(f"baselined {len(to_baseline)} finding(s) -> {baseline_path}" + (f": {breakdown}" if breakdown else ""))


@cli.group()
def baseline() -> None:
    """Manage the finding baseline (.wardline/baseline.yaml)."""


@baseline.command("create")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def baseline_create(path: Path) -> None:
    """Write a new baseline from current findings (refuses if one exists)."""
    _generate_baseline(path, overwrite=False)


@baseline.command("update")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def baseline_update(path: Path) -> None:
    """Re-derive and overwrite the baseline from current findings."""
    _generate_baseline(path, overwrite=True)
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q`
Expected: PASS.

- [ ] **Step 5: Run the full gate**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: all pass; ruff + mypy clean; `tests/test_self_hosting.py` green.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/cli/main.py tests/unit/cli/test_cli.py
git commit -m "feat(sp3c): wardline baseline create|update"
```

---

## Self-Review

- **Spec §4 (typed `suppressed` field):** Task 1. **§5 (baseline model/file/load-write):** Task 2. **§6 (waiver model + config field + dates):** Task 3. **§7 (apply_suppressions/gate_trips/SEVERITY_ORDER/precedence/expiry boundary):** Task 4. **§8 scan integration (load+apply+annotate+summary+`--fail-on`):** Task 5. **§8 CLI `create`/`update` (exclude-active-waivers, refuse-if-exists, severity breakdown):** Task 6. **§10 tests** (gate matrix, fused expiry test, edge cases, L1 line-shift, self-hosting baseline-free): covered across Tasks 4–6 + the self-hosting note.
- **Limitation L1 (line-shift resurfaces)** is implicit in strict matching; the §10 pin is the `test_scan_baseline_suppresses_and_clears_gate` round-trip (unchanged code → suppressed). An explicit line-shift test is optional polish; not blocking.
- **Type consistency:** `SuppressionState` (Task 1) used identically in Tasks 4–6; `apply_suppressions(findings, baseline, waivers, *, today)` and `gate_trips(findings, fail_on: Severity)` signatures match between Task 4 and Task 5; `parse_waivers`/`WaiverSet`/`load_baseline`/`write_baseline` names consistent across tasks; `cfg.waivers` raw shape (Task 3) consumed by Tasks 5 + 6.
- **No placeholders:** every code step is complete. **No governance** anywhere.
