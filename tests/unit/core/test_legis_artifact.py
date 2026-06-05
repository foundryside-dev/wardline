"""B4 — the Wardline→legis signed scan artifact (sign + conformant projection).

legis governs a Wardline scan it receives over ``POST /wardline/scan-results``; it
NEVER re-analyses and it is a FIXED external contract. Its ingest validator
(``legis/src/legis/wardline/ingest.py``) is strict in three ways the rich Wardline
finding wire violates:

1. every ``properties`` VALUE must be one of the 8 trust tiers (or a suppression
   proof) — Wardline also stores analysis diagnostics there (``sink``/``callee``/
   ``markers``/``reason``);
2. a non-active defect must carry its suppression proof IN ``properties`` —
   Wardline carries ``suppression_reason`` at the top level;
3. the only suppressed states legis knows are ``waived``/``suppressed`` — Wardline
   also emits ``baselined``/``judged``.

All three were reproduced against the real legis before this test was written
(``unsupported suppression state``, ``invalid trust tier``, ``must carry
suppression proof``). The signed artifact is therefore a *typed projection* of the
defect population onto legis's accepted vocabulary; the rich MCP/SARIF/Loomweave wire
is unchanged. This module pins the projection and the byte-exact signature.
"""

from __future__ import annotations

import pytest

from wardline.core import legis
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState

# ---------------------------------------------------------------------------
# Golden vector — the literal hex was produced by the REAL legis signer
# (`from legis.enforcement.signing import sign`) over the fields below with the
# key below. Vendoring the canonical_json+HMAC *formula* cannot catch a shared
# misreading of the contract; a hardcoded hex captured from legis can. The live
# `legis_e2e` oracle re-confirms the verify path against a running legis.
# ---------------------------------------------------------------------------
_GOLDEN_KEY = b"test-shared-secret-key"
_GOLDEN_FIELDS = {
    "scanner_identity": "wardline@1.0.0rc1",
    "rule_set_version": "sha256:deadbeef",
    "commit_sha": "c" * 40,
    "tree_sha": "t" * 40,
    "findings": [
        {
            "rule_id": "PY-WL-101",
            "message": "leak",
            "severity": "ERROR",
            "kind": "defect",
            "fingerprint": "a" * 64,
            "qualname": "svc.leaky",
            "properties": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW"},
            "suppressed": "active",
        }
    ],
}
_GOLDEN_SIG = "hmac-sha256:v2:73eb9f0c8b7ba898aa4b5fd62fa56ade0cbd9755d2c42eee209012675537f81d"


def test_golden_signature_matches_real_legis() -> None:
    # The authoritative cross-impl pin: Wardline's signer must reproduce legis's
    # byte-for-byte over the same key + fields.
    assert legis.sign_artifact(_GOLDEN_FIELDS, _GOLDEN_KEY) == _GOLDEN_SIG


def test_sign_strips_existing_signature() -> None:
    # legis verifies over scan-minus-artifact_signature; signing must be stable
    # whether or not a stale signature is already present in the dict.
    with_sig = {**_GOLDEN_FIELDS, "artifact_signature": "hmac-sha256:v2:stale"}
    assert legis.sign_artifact(with_sig, _GOLDEN_KEY) == _GOLDEN_SIG


def test_canonical_json_is_sorted_tight_unicode() -> None:
    # Exact replica of legis/src/legis/canonical.py — sorted keys, tight
    # separators, non-ASCII preserved, no NaN.
    assert legis.canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'


# ---------------------------------------------------------------------------
# Projection — properties, suppression mapping, defect-only selection
# ---------------------------------------------------------------------------
def _finding(**over: object) -> Finding:
    base: dict[str, object] = {
        "rule_id": "PY-WL-101",
        "message": "leak",
        "severity": Severity.ERROR,
        "kind": Kind.DEFECT,
        "location": Location(path="svc.py", line_start=1, line_end=1, col_start=0, col_end=0),
        "fingerprint": "a" * 64,
        "qualname": "svc.leaky",
        "suppressed": SuppressionState.ACTIVE,
    }
    base.update(over)
    return Finding(**base)  # type: ignore[arg-type]


def test_projection_keeps_only_trust_tier_properties() -> None:
    # A real PY-WL-106 sink finding carries diagnostics (sink/callee/arg_taint) in
    # properties; legis rejects any non-tier value. The projection keeps the tier
    # values, drops the diagnostics.
    f = _finding(properties={"sink": "os.system", "arg_taint": "EXTERNAL_RAW", "tier": "INTEGRAL"})
    out = legis.project_finding(f)
    assert out["properties"] == {"arg_taint": "EXTERNAL_RAW", "tier": "INTEGRAL"}


def test_projection_drops_non_string_property_values() -> None:
    # contradictory_trust emits {"markers": [list]}; legis requires string tiers.
    f = _finding(properties={"markers": ["external_boundary", "trusted"], "body_taint": "GUARDED"})
    out = legis.project_finding(f)
    assert out["properties"] == {"body_taint": "GUARDED"}


def test_projection_minimal_legis_read_surface() -> None:
    # The wire finding is exactly legis's read surface — no location/suggestion/
    # confidence/maturity leak into the signed bytes.
    out = legis.project_finding(_finding(properties={}))
    assert set(out) == {
        "rule_id",
        "message",
        "severity",
        "kind",
        "fingerprint",
        "qualname",
        "properties",
        "suppressed",
    }


def test_baselined_maps_to_suppressed_with_synthesized_proof() -> None:
    # legis has no `baselined` state and requires a non-empty proof for any
    # non-active defect. A baselined finding with no reason must still carry proof.
    f = _finding(suppressed=SuppressionState.BASELINED, suppression_reason=None)
    out = legis.project_finding(f)
    assert out["suppressed"] == "suppressed"
    assert isinstance(out["properties"].get("suppression_reason"), str)
    assert out["properties"]["suppression_reason"].strip()


def test_judged_maps_to_suppressed_and_carries_reason() -> None:
    f = _finding(suppressed=SuppressionState.JUDGED, suppression_reason="LLM: false positive")
    out = legis.project_finding(f)
    assert out["suppressed"] == "suppressed"
    assert out["properties"]["suppression_reason"] == "LLM: false positive"


def test_waived_keeps_state_and_injects_proof_into_properties() -> None:
    f = _finding(suppressed=SuppressionState.WAIVED, suppression_reason="WAIVE-123")
    out = legis.project_finding(f)
    assert out["suppressed"] == "waived"
    assert out["properties"]["suppression_reason"] == "WAIVE-123"


def test_active_finding_carries_no_suppression_proof() -> None:
    out = legis.project_finding(_finding(properties={"tier": "INTEGRAL"}))
    assert out["suppressed"] == "active"
    assert "suppression_reason" not in out["properties"]


# ---------------------------------------------------------------------------
# build_legis_artifact — provenance, defect-only, signing, dirty-tree refusal
# ---------------------------------------------------------------------------
import subprocess  # noqa: E402

from wardline.core.config import load as load_config  # noqa: E402
from wardline.core.errors import LegisArtifactError  # noqa: E402
from wardline.core.run import run_scan  # noqa: E402

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _git(repo: object, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # type: ignore[call-overload]


def _committed_repo(tmp_path: object, source: str = _LEAKY):
    repo = tmp_path / "proj"  # type: ignore[operator]
    repo.mkdir()
    (repo / "svc.py").write_text(source, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


def _build(repo, *, key: bytes | None = None, allow_dirty: bool = False) -> dict:
    result = run_scan(repo)
    cfg = load_config(repo / "wardline.yaml")
    return legis.build_legis_artifact(result, root=repo, config=cfg, key=key, allow_dirty=allow_dirty)


def test_signed_artifact_has_all_four_provenance_fields_and_signature(tmp_path) -> None:
    scan = _build(_committed_repo(tmp_path), key=b"k")
    for field in ("scanner_identity", "rule_set_version", "commit_sha", "tree_sha"):
        assert isinstance(scan[field], str) and scan[field], field
    assert scan["scanner_identity"].startswith("wardline@")
    assert scan["rule_set_version"].startswith("sha256:")
    assert scan["artifact_signature"].startswith("hmac-sha256:v2:")


def test_signed_artifact_signature_verifies_over_minus_signature(tmp_path) -> None:
    scan = _build(_committed_repo(tmp_path), key=b"k")
    sig = scan["artifact_signature"]
    assert legis.sign_artifact(scan, b"k") == sig  # re-sign of the posted body matches


def test_artifact_includes_all_findings_projected(tmp_path) -> None:
    # legis records finding_count over the WHOLE list (service/wardline.py), so the
    # artifact carries every finding — including engine FACTs — each projected so its
    # non-tier diagnostics (here {"source_root": "pkg"}) can't 422 legis. Non-defect
    # kinds simply aren't routed; they still count.
    from wardline.core.run import ScanResult, ScanSummary

    loc = Location(path="svc.py", line_start=1, line_end=1, col_start=0, col_end=0)
    defect = _finding(properties={"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW"})
    fact = Finding(
        rule_id="WLN-ENGINE-SOURCE-ROOT-MISSING",
        message="source root does not exist: pkg",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=loc,
        fingerprint="f" * 64,
        qualname=None,
        properties={"source_root": "pkg"},  # a non-tier value legis would reject raw
    )
    result = ScanResult(
        findings=[defect, fact],
        summary=ScanSummary(total=2, active=1, baselined=0, waived=0, judged=0, unanalyzed=1),
        files_scanned=1,
        context=None,
    )
    repo = tmp_path / "norepo"
    repo.mkdir()
    cfg = load_config(repo / "wardline.yaml")
    scan = legis.build_legis_artifact(result, root=repo, config=cfg, key=None)
    assert {f["kind"] for f in scan["findings"]} == {"defect", "fact"}
    assert len(scan["findings"]) == 2
    # the fact's non-tier property is projected away so it ingests cleanly
    fact_wire = next(f for f in scan["findings"] if f["kind"] == "fact")
    assert fact_wire["properties"] == {}


def test_unsigned_artifact_omits_signature(tmp_path) -> None:
    scan = _build(_committed_repo(tmp_path), key=None)
    assert "artifact_signature" not in scan
    # best-effort provenance is still present for a committed repo
    assert scan["commit_sha"]
    assert scan["tree_sha"]


def test_signing_refuses_dirty_tree(tmp_path) -> None:
    repo = _committed_repo(tmp_path)
    (repo / "svc.py").write_text(_LEAKY + "\n# dirty\n", encoding="utf-8")  # uncommitted edit
    with pytest.raises(LegisArtifactError):
        _build(repo, key=b"k")


def test_allow_dirty_signs_anyway(tmp_path) -> None:
    repo = _committed_repo(tmp_path)
    (repo / "svc.py").write_text(_LEAKY + "\n# dirty\n", encoding="utf-8")
    scan = _build(repo, key=b"k", allow_dirty=True)
    assert scan["artifact_signature"].startswith("hmac-sha256:v2:")


def test_signing_non_repo_refuses(tmp_path) -> None:
    repo = tmp_path / "norepo"
    repo.mkdir()
    (repo / "svc.py").write_text(_LEAKY, encoding="utf-8")
    result = run_scan(repo)
    cfg = load_config(repo / "wardline.yaml")
    with pytest.raises(LegisArtifactError):
        legis.build_legis_artifact(result, root=repo, config=cfg, key=b"k")
