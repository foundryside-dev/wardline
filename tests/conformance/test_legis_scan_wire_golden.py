"""Shared cross-member golden vector for the wardline → legis scan wire (G1).

``legis_scan_wire.golden.json`` is the ONE concrete instance of the legis scan
artifact that BOTH wardline (producer) and legis (consumer) load and assert
against — replacing the two *independent vendored mirrors*
(``test_legis_artifact_contract_freeze.py`` here, legis's own vendored ``from_wire``)
whose hand-copied drift is the federation-interface-audit **G1 / seam-S8** finding:
wardline could rename ``findings`` and stay green while legis silently governs an
EMPTY scan under a ``verified`` status (the consumer reads ``scan.get("findings", [])``).

The vector is a deterministic, self-consistent **signed** artifact: its volatile
fields (``scanner_identity``, ``rule_set_version``, ``commit_sha``, ``tree_sha``) are
fixed sentinels and its ``artifact_signature`` is computed over that body with
:data:`GOLDEN_KEY`, so a consumer can verify it offline with no live scan. legis loads
the SAME file in its CI (its half of G1) and asserts its real ingest routes the one
active defect — so a required-field drift on EITHER side reds.

This file is the wardline (producer) half: it pins the vector to wardline's LIVE emit
(:func:`build_legis_artifact`). Rename/drop/add a wire key and the structural
conformance below reds; regenerating the vector to match would then red legis's half.
That coupling is the whole point — it is the shared executable test the 2026-06-10
federation remediation requires to ship WITH the contract, not a vendored copy.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from wardline.core.config import load as load_config
from wardline.core.legis import (
    DIRTY_FIELD,
    FINDINGS_FIELD,
    FINGERPRINT_SCHEME_FIELD,
    build_legis_artifact,
    sign_artifact,
)
from wardline.core.run import run_scan

# The fixed key the shared vector is signed under. Documented and stable so the
# consumer (legis) can verify the vector's signature offline. NOT a production secret.
GOLDEN_KEY = b"weft-shared-conformance-key"

_VECTOR_PATH = Path(__file__).parent / "legis_scan_wire.golden.json"

# Same leaky boundary→sink fixture the freeze test uses: yields one real PY-WL-101
# defect carrying every per-finding wire key.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _vector() -> dict:
    return json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))


def _signed_clean_artifact(tmp_path: Path) -> dict:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@example.com"],
        ["git", "config", "user.name", "t"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "init"],
    ):
        subprocess.run(cmd, cwd=proj, check=True, capture_output=True)
    result = run_scan(proj)
    cfg = load_config(proj / "weft.toml")
    return build_legis_artifact(result, root=proj, config=cfg, key=GOLDEN_KEY)


def test_golden_vector_is_a_valid_signed_artifact() -> None:
    # The consumer verifies the vector offline; prove it round-trips under GOLDEN_KEY.
    vector = _vector()
    assert vector["artifact_signature"] == sign_artifact(vector, GOLDEN_KEY)


def test_golden_vector_keys_are_the_named_constants() -> None:
    # Ties the vector's literal key strings to the shared constants: a constant VALUE
    # change (the silent-rename vector) reds here.
    vector = _vector()
    assert FINDINGS_FIELD in vector
    assert FINGERPRINT_SCHEME_FIELD in vector
    assert DIRTY_FIELD not in vector  # clean signed artifact carries no dirty marker
    assert isinstance(vector[FINDINGS_FIELD], list) and vector[FINDINGS_FIELD]


def test_live_emit_top_level_keys_match_the_vector(tmp_path: Path) -> None:
    # The dangerous case: wardline renames/drops a top-level key. The live signed emit
    # must carry EXACTLY the vector's top-level key-set.
    live = _signed_clean_artifact(tmp_path)
    assert set(live) == set(_vector())


def test_live_emit_per_finding_keys_match_the_vector(tmp_path: Path) -> None:
    # Every finding wardline emits must carry exactly the per-finding key-set the
    # vector pins (so a per-finding key rename can't route a finding to a defaulted key).
    expected_keys = set(_vector()[FINDINGS_FIELD][0])
    live = _signed_clean_artifact(tmp_path)
    for finding in live[FINDINGS_FIELD]:
        assert set(finding) == expected_keys


def test_vector_defect_routes_as_active(tmp_path: Path) -> None:
    # The vector's one finding is an active defect — the thing legis must route. A
    # producer that emitted it under a renamed state value (legis 422s an unknown
    # state) or dropped it would diverge from this pinned instance.
    vector = _vector()
    defect = vector[FINDINGS_FIELD][0]
    assert defect["kind"] == "defect"
    assert defect["suppression_state"] == "active"
