"""legis intake conformance (hermetic, always-on) — the FAITHFUL contract guard.

legis (the Weft governance plugin) ingests a Wardline scan and governs; it NEVER
re-analyses, and it is a FIXED external contract. This test pins the wire Wardline
*emits* against legis's documented ingest — `legis/src/legis/wardline/ingest.py` and
`enforcement/signing.py` / `canonical.py`, faithfully **vendored below** so this test
imports nothing from legis (legis is the fixed external lane; the opt-in live
`legis_e2e` oracle exercises the real server).

Earlier this mirror was a *simplified* copy: it skipped `_validate_trust_properties`,
the suppression-proof requirement, and the raise-on-unsupported-state. That made it
green on the thin leak fixture while the real legis would 422 a realistic scan — a
false-green. The mirror below is now faithful to legis's actual `from_wire` /
`active_defects`, so it reds on exactly the drift the live server would reject.

The Wardline side emits the signed artifact via `build_legis_artifact`, which projects
the whole scan onto legis's accepted vocabulary (tier-only properties, mapped
suppression states, proof in `properties`). The conformance equality
`len(active_defects(scan)) == result.summary.active` proves legis reproduces
Wardline's OWN gate population without re-deriving it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from wardline.core import legis as wl_legis
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.run import run_scan

# ---------------------------------------------------------------------------
# Vendored legis contract — faithful copies of legis/src/legis/{canonical.py,
# enforcement/signing.py, wardline/ingest.py}. NOT imported from legis.
# ---------------------------------------------------------------------------
_TRUST_TIERS: frozenset[str] = frozenset(
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
_SUPPRESSION_PROOF_KEYS: frozenset[str] = frozenset({"suppression_proof", "suppression_ticket", "suppression_reason"})
_SEVERITY_NAMES: frozenset[str] = frozenset({"CRITICAL", "ERROR", "WARN", "INFO", "NONE"})
_MAX_FINDINGS = 500
_ARTIFACT_SIGNATURE_FIELD = "artifact_signature"
_ARTIFACT_PROVENANCE_FIELDS = ("scanner_identity", "rule_set_version", "commit_sha", "tree_sha")
_SIG_PREFIX_V2 = "hmac-sha256:v2:"


class _LegisPayloadError(ValueError):
    """Mirror of legis WardlinePayloadError."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _legis_sign(fields: dict, key: bytes) -> str:
    mac = hmac.new(key, _canonical_json(fields).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{_SIG_PREFIX_V2}{mac}"


def _legis_verify(fields: dict, signature: str, key: bytes) -> bool:
    if signature.startswith(_SIG_PREFIX_V2):
        return hmac.compare_digest(_legis_sign(fields, key), signature)
    return False


def _validate_trust_properties(properties: Mapping[str, Any]) -> None:
    for key, value in properties.items():
        if key in _SUPPRESSION_PROOF_KEYS:
            if not isinstance(value, str) or not value.strip():
                raise _LegisPayloadError(f"finding {key} must be a non-empty suppression proof string")
            continue
        if not isinstance(value, str) or value not in _TRUST_TIERS:
            raise _LegisPayloadError(f"finding property {key} has invalid trust tier: {value!r}")


def _has_suppression_proof(properties: Mapping[str, Any]) -> bool:
    return any(
        isinstance(properties.get(key), str) and bool(properties[key].strip()) for key in _SUPPRESSION_PROOF_KEYS
    )


@dataclass(frozen=True)
class _LegisFinding:
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
        missing = [k for k in ("rule_id", "message", "severity", "kind", "fingerprint") if k not in d]
        if missing:
            raise _LegisPayloadError(f"finding missing required field(s): {', '.join(missing)}")
        sev = d["severity"]
        if not isinstance(sev, str) or sev not in _SEVERITY_NAMES:
            raise _LegisPayloadError(f"unknown Wardline severity: {sev}")
        properties = d.get("properties", {})
        if not isinstance(properties, Mapping):
            raise _LegisPayloadError("finding properties must be an object")
        _validate_trust_properties(properties)
        qualname = d.get("qualname")
        if qualname is not None and not isinstance(qualname, str):
            raise _LegisPayloadError("finding qualname must be a string or null")
        suppressed = d.get("suppressed", "active")
        if not isinstance(suppressed, str):
            raise _LegisPayloadError("finding suppressed must be a string")
        for key in ("rule_id", "message", "kind", "fingerprint"):
            if not isinstance(d[key], str) or not d[key]:
                raise _LegisPayloadError(f"finding {key} must be a non-empty string")
        return cls(
            rule_id=d["rule_id"],
            message=d["message"],
            severity=sev,
            kind=d["kind"],
            fingerprint=d["fingerprint"],
            qualname=qualname,
            properties=dict(properties),
            suppressed=suppressed,
        )


def active_defects(scan: Mapping[str, Any]) -> list[_LegisFinding]:
    raw_findings = scan.get("findings", [])
    if not isinstance(raw_findings, list):
        raise _LegisPayloadError("scan findings must be a list")
    if len(raw_findings) > _MAX_FINDINGS:
        raise _LegisPayloadError(f"scan findings exceeds maximum batch size {_MAX_FINDINGS}")
    out: list[_LegisFinding] = []
    for raw in raw_findings:
        f = _LegisFinding.from_wire(raw)
        if f.kind != "defect":
            continue
        if f.suppressed == "active":
            out.append(f)
            continue
        if f.suppressed in {"waived", "suppressed"}:
            if not _has_suppression_proof(f.properties):
                raise _LegisPayloadError("suppressed defect must carry suppression proof")
            continue
        raise _LegisPayloadError(f"unsupported suppression state for defect: {f.suppressed}")
    return out


def verify_wardline_artifact(scan: Mapping[str, Any], artifact_key: bytes | None) -> dict[str, Any]:
    """Faithful mirror of legis verify_wardline_artifact (the key-required path)."""
    fields = {k: v for k, v in scan.items() if k != _ARTIFACT_SIGNATURE_FIELD}
    if artifact_key is None:
        return {"artifact_status": "unverified"}
    missing = [k for k in _ARTIFACT_PROVENANCE_FIELDS if not isinstance(scan.get(k), str) or not scan[k]]
    if missing:
        raise _LegisPayloadError(f"Wardline artifact missing required field(s): {', '.join(missing)}")
    signature = scan.get(_ARTIFACT_SIGNATURE_FIELD)
    if not isinstance(signature, str) or not signature:
        raise _LegisPayloadError("Wardline artifact signature is required")
    if not _legis_verify(fields, signature, artifact_key):
        raise _LegisPayloadError("Wardline artifact signature does not verify")
    return {"artifact_status": "verified"}


# ---------------------------------------------------------------------------
# Wardline side — the signed artifact via build_legis_artifact.
# ---------------------------------------------------------------------------
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)
# PY-WL-110 contradictory-trust: a real defect whose properties carry a NON-tier
# value ({"markers": "external_boundary+trusted"}) — the case that 422s legis raw.
_CONTRADICTORY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n@trusted\ndef both(p):\n    return p\n"
)


def _proj(tmp_path: Path, source: str = _LEAKY) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(source, encoding="utf-8")
    return proj


def _artifact(root: Path, *, key: bytes | None = None) -> tuple[dict[str, Any], Any]:
    from wardline.core.config import load as load_config

    result = run_scan(root)
    cfg = load_config(root / "wardline.yaml")
    scan = wl_legis.build_legis_artifact(result, root=root, config=cfg, key=key)
    return scan, result


def test_projected_artifact_satisfies_faithful_legis_from_wire(tmp_path: Path) -> None:
    # Every finding the artifact emits ingests into the FAITHFUL legis from_wire
    # without error — field names, severity name, AND trust-tier-only properties.
    scan, result = _artifact(_proj(tmp_path))
    assert scan["findings"]  # the leak defect
    for raw in scan["findings"]:
        _LegisFinding.from_wire(raw)  # raises on any drift / non-tier property


def test_contradictory_defect_nontier_property_is_projected_away(tmp_path: Path) -> None:
    # The raw PY-WL-110 finding carries a non-tier `markers` property that real legis
    # rejects; the projection drops it so the artifact ingests cleanly. This proves
    # BOTH that the mirror is now strict and that the projection closes the gap.
    root = _proj(tmp_path, _CONTRADICTORY)
    scan, result = _artifact(root)
    raw_findings = [json.loads(f.to_jsonl()) for f in result.findings if f.kind is Kind.DEFECT]
    assert raw_findings, "expected a PY-WL-110 defect"
    assert any("markers" in r.get("properties", {}) for r in raw_findings)
    # raw → real legis would 422
    with pytest.raises(_LegisPayloadError):
        for r in raw_findings:
            _LegisFinding.from_wire(r)
    # projected → ingests
    for raw in scan["findings"]:
        _LegisFinding.from_wire(raw)


def test_legis_gate_population_equals_wardline_active_count(tmp_path: Path) -> None:
    # One judge: legis's independently-applied active-defect selection reproduces
    # Wardline's OWN gate population (summary.active) exactly.
    scan, result = _artifact(_proj(tmp_path))
    assert len(active_defects(scan)) == result.summary.active
    assert result.summary.active >= 1


def test_signed_artifact_verifies_against_legis(tmp_path: Path) -> None:
    # Build a committed repo so signing has honest provenance; the signed artifact
    # must verify through legis's verify_wardline_artifact with the same key.
    import subprocess

    root = _proj(tmp_path)
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@example.com"],
        ["git", "config", "user.name", "t"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "init"],
    ):
        subprocess.run(cmd, cwd=root, check=True, capture_output=True)
    key = b"shared-secret"
    scan, _ = _artifact(root, key=key)
    assert verify_wardline_artifact(scan, key)["artifact_status"] == "verified"
    # tamper detection: flip a finding message → signature no longer verifies
    tampered = json.loads(json.dumps(scan))
    tampered["findings"][0]["message"] += "X"
    with pytest.raises(_LegisPayloadError):
        verify_wardline_artifact(tampered, key)


def test_baselined_defect_ingests_after_projection() -> None:
    # A hand-built BASELINED defect: legis has no `baselined` state and would 422
    # the raw finding; the projection maps it to `suppressed` + injects proof.
    loc = Location(path="svc.py", line_start=6, line_end=7, col_start=0, col_end=0)
    baselined = Finding(
        rule_id="PY-WL-101",
        message="leak",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=loc,
        fingerprint="b" * 64,
        qualname="svc.other",
        suppressed=SuppressionState.BASELINED,
    )
    raw = json.loads(baselined.to_jsonl())
    with pytest.raises(_LegisPayloadError):  # raw baselined → unsupported state
        active_defects({"findings": [raw]})
    projected = wl_legis.project_finding(baselined)
    # projected → ingests, and is NOT in the active gate population
    assert active_defects({"findings": [projected]}) == []


def test_wardline_trust_tiers_match_legis_vocabulary() -> None:
    # One vocabulary: the 8 tiers legis carries verbatim must equal Wardline's.
    from wardline.core.taints import TaintState

    assert {t.value for t in TaintState} == set(_TRUST_TIERS)
    assert set(_TRUST_TIERS) == wl_legis.TRUST_TIERS
