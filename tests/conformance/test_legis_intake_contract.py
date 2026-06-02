"""T5.2 — legis intake conformance (hermetic, always-on).

legis (the Loom governance plugin) ingests a Wardline scan response and governs;
it NEVER re-analyzes. This test pins the wire contract Wardline *emits* against
legis's documented ingest shape — `legis/src/legis/wardline/ingest.py`, faithfully
**vendored below** as a local spec so this test imports nothing from legis (lane:
legis is a fixed external contract).

It is the always-on guard behind the opt-in live `legis_e2e` oracle: if a Wardline
finding field is dropped, or a value drifts (e.g. severity emitted lowercase, or
`kind`/`suppressed` values renamed), `_LegisFinding.from_wire` / `_active_defects`
below break and this test reds — catching the drift in default CI, between live
oracle runs.

One judge: Wardline analyses (decides active vs suppressed, defect vs fact); legis
governs from that verdict. The conformance equality
`len(_active_defects(scan)) == result.summary.active` proves legis reproduces
Wardline's OWN gate population without re-deriving it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.run import run_scan

# ---------------------------------------------------------------------------
# Vendored legis ingest contract — a faithful copy of legis/src/legis/wardline/
# ingest.py (TRUST_TIERS, WardlineSeverity, WardlineFinding.from_wire,
# active_defects). NOT imported from legis. If legis changes its contract, the
# live legis_e2e oracle catches it; this copy is the always-on shape guard.
# ---------------------------------------------------------------------------

_LEGIS_TRUST_TIERS: frozenset[str] = frozenset(
    {
        "INTEGRAL",
        "ASSURED",
        "GUARDED",
        "EXTERNAL_RAW",
        "UNKNOWN_RAW",
        "UNKNOWN_GUARDED",
        "UNKNOWN_ASSURED",
        "MIXED_RAW",
    }
)

# legis's WardlineSeverity member NAMES — from_wire does `WardlineSeverity[name]`.
_LEGIS_SEVERITY_NAMES: frozenset[str] = frozenset({"CRITICAL", "ERROR", "WARN", "INFO", "NONE"})


@dataclass(frozen=True)
class _LegisFinding:
    """Mirror of legis WardlineFinding — the fields legis actually reads."""

    rule_id: str
    message: str
    severity: str
    kind: str
    fingerprint: str
    qualname: str | None
    properties: Mapping[str, Any]
    suppressed: str

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> _LegisFinding:
        # legis does WardlineSeverity[d["severity"]] (a NAME subscript) — replicate
        # the strictness: an unknown/absent severity name is a hard ingest failure.
        sev = d["severity"]
        if sev not in _LEGIS_SEVERITY_NAMES:
            raise KeyError(sev)
        return cls(
            rule_id=d["rule_id"],
            message=d["message"],
            severity=sev,
            kind=d["kind"],
            fingerprint=d["fingerprint"],
            qualname=d.get("qualname"),
            properties=dict(d.get("properties", {})),
            suppressed=d.get("suppressed", "active"),
        )


def _active_defects(scan: Mapping[str, Any]) -> list[_LegisFinding]:
    """legis's gate population: active (non-suppressed) DEFECT findings."""
    out: list[_LegisFinding] = []
    for raw in scan.get("findings", []):
        f = _LegisFinding.from_wire(raw)
        if f.kind == "defect" and f.suppressed == "active":
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# The Wardline side: build the scan response exactly as mcp/server.py:_scan does
# (findings = json.loads(Finding.to_jsonl()) per finding).
# ---------------------------------------------------------------------------

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _scan_response(root: Path) -> tuple[dict[str, Any], Any]:
    """The wire `scan` object legis ingests, plus the ScanResult for cross-checks."""
    result = run_scan(root)
    scan = {"findings": [json.loads(f.to_jsonl()) for f in result.findings]}
    return scan, result


def _proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def test_every_emitted_finding_satisfies_legis_from_wire(tmp_path: Path) -> None:
    # Every finding Wardline emits must ingest into legis's from_wire without error
    # — that proves the field names AND value shapes (severity name, etc.) conform.
    scan, result = _scan_response(_proj(tmp_path))
    assert result.findings  # the fixture produces at least the PY-WL-101 defect
    ingested_all = []
    for raw in scan["findings"]:
        ingested = _LegisFinding.from_wire(raw)  # raises if a field is missing/drifted
        assert ingested.severity in _LEGIS_SEVERITY_NAMES
        # legis stores `kind` as an opaque string (it only special-cases "defect"
        # for the gate population), so any Wardline kind ingests cleanly — Wardline
        # emits defect/fact/classification/metric/suggestion.
        assert isinstance(ingested.kind, str) and ingested.kind
        ingested_all.append(ingested)
    # qualname must round-trip: legis resolves it (api/app.py resolve(qualname)) to
    # capture the Clarion lineage snapshot, so a silently-dropped qualname would route
    # every finding under the "unknown" locator. Both sides read it via .get(), so
    # nothing else here would red on its loss — pin it explicitly.
    assert any(i.qualname == "svc.leaky" for i in ingested_all)


def test_legis_gate_population_equals_wardline_active_count(tmp_path: Path) -> None:
    # One judge: legis's independently-applied active-defect selection reproduces
    # Wardline's OWN gate population (summary.active) exactly — legis reads the
    # verdict, never re-derives it.
    scan, result = _scan_response(_proj(tmp_path))
    assert len(_active_defects(scan)) == result.summary.active
    assert result.summary.active >= 1  # svc.leaky is an active PY-WL-101 defect


def test_active_selection_excludes_suppressed_and_facts() -> None:
    # Control with hand-built findings: legis's selection must drop a baselined
    # defect AND a NONE fact, keeping only the active defect. Uses the real
    # Finding.to_jsonl shape so the contract — not a mock — is exercised.
    loc = Location(path="svc.py", line_start=6, line_end=7, col_start=0, col_end=0)
    active = Finding(
        rule_id="PY-WL-101",
        message="leak",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=loc,
        fingerprint="a" * 64,
        qualname="svc.leaky",
        suppressed=SuppressionState.ACTIVE,
    )
    baselined = Finding(
        rule_id="PY-WL-101",
        message="leak2",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=loc,
        fingerprint="b" * 64,
        qualname="svc.other",
        suppressed=SuppressionState.BASELINED,
    )
    fact = Finding(
        rule_id="WLN-ENGINE-FUNCTION-SKIPPED",
        message="skipped",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=loc,
        fingerprint="c" * 64,
        qualname="svc.skipped",
        suppressed=SuppressionState.ACTIVE,
    )
    scan = {"findings": [json.loads(f.to_jsonl()) for f in (active, baselined, fact)]}
    selected = _active_defects(scan)
    assert [f.fingerprint for f in selected] == ["a" * 64]


def test_wardline_trust_tiers_match_legis_vocabulary() -> None:
    # One vocabulary: the 8 tiers legis carries verbatim must equal Wardline's.
    from wardline.core.taints import TaintState

    assert {t.value for t in TaintState} == set(_LEGIS_TRUST_TIERS)
