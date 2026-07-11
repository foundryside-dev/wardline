"""Executable checks for the authoritative finding-identity documentation.

The accepted ADR, operator suppression guide, and seam registry describe a live
cross-tool join key.  Bind their headline claims to the runtime producers so a
future scheme or SARIF-key change cannot leave authoritative prose behind.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from wardline.core.finding import FINGERPRINT_SCHEME, Finding, Kind, Location, Severity, compute_finding_fingerprint
from wardline.core.sarif import build_sarif

_ROOT = Path(__file__).parents[2]
_ADR = _ROOT / "docs/decisions/2026-06-05-wardline-finding-identity-frozen-contract.md"
_SUPPRESSION_GUIDE = _ROOT / "docs/guides/suppression.md"
_SEAM_REGISTRY = _ROOT / "tests/conformance/seam_registry.json"
_REKEY_SOURCE = _ROOT / "src/wardline/core/rekey.py"


def test_authoritative_identity_docs_match_live_scheme_and_formula() -> None:
    adr = _ADR.read_text(encoding="utf-8")
    guide = _SUPPRESSION_GUIDE.read_text(encoding="utf-8")
    rekey_source = _REKEY_SOURCE.read_text(encoding="utf-8")

    assert FINGERPRINT_SCHEME == "wlfp2"
    assert tuple(inspect.signature(compute_finding_fingerprint).parameters) == (
        "rule_id",
        "path",
        "qualname",
        "taint_path",
    )
    assert "`wlfp2`" in adr
    assert "sha256(rule_id \\0 path \\0 qualname \\0 taint_path)" in adr
    assert "`line_start` is deliberately not hashed" in adr
    assert "line-insensitive" in guide
    assert "line_start-sensitive" not in rekey_source


def test_authoritative_identity_docs_match_live_sarif_surface() -> None:
    adr = _ADR.read_text(encoding="utf-8")
    finding = Finding(
        rule_id="PY-WL-999",
        message="identity contract",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/example.py", line_start=7),
        fingerprint="a" * 64,
    )
    sarif = build_sarif([finding])

    assert sarif["version"] == "2.1.0"
    partials = sarif["runs"][0]["results"][0]["partialFingerprints"]
    assert set(partials) == {"wardlineFingerprint/v2"}
    assert "SARIF 2.1.0" in adr
    assert "`partialFingerprints.wardlineFingerprint/v2`" in adr


def test_identity_seam_registry_names_the_live_enforcement_owner_and_corpus() -> None:
    rows = json.loads(_SEAM_REGISTRY.read_text(encoding="utf-8"))
    row = next(r for r in rows if r["seam"].startswith("Finding identity & wire contract"))

    assert row["authority"] == "wardline"
    assert "wlfp2" in row["wire"]
    assert "line_start is excluded" in row["wire"]
    assert "tests/golden/identity/test_identity_parity.py" in row["evidence_paths"]
    assert "tests/golden/identity/rust/test_rust_identity_parity.py" in row["evidence_paths"]
    assert ".github/workflows/ci.yml" in row["evidence_paths"]
