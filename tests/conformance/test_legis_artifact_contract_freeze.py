"""FROZEN cross-member wire contract — the exact key-set ``build_legis_artifact`` emits.

⚠️  EDITING THE EXPECTED KEY-SETS BELOW IS A CROSS-REPO BREAKING CHANGE. ⚠️

The legis consumer (the Weft governance plugin) reads these keys, and it reads
several of them with a DEFAULT rather than a hard requirement — most importantly
``findings`` (``scan.get("findings", [])``) and ``dirty``. So a silent rename or
drop on *this* (producer) side routes ZERO defects into legis under a green
``verified`` status: the consumer never errors, it just governs an empty scan.
That fail-open is the weft foundation seam-S8 / G1 finding (the ``dirty``-key
analog is the hub's ``dirty``-freeze issue); the consumer-side validation gap is
legis's to close, but the *trigger* — a producer key drifting — is ours to prevent.

The invariant this file freezes: **a producer that pins its WHOLE emitted key-set
protects the consumer regardless of which keys the consumer validates vs defaults.**
We do not have to know legis's required-field set; we promise never to silently
change our wire. ``build_legis_artifact`` is the sole producer of this wire — the
CLI (``scan --format legis``) and MCP (``legis_artifact``) both emit its dict
verbatim (``json.dumps(artifact)`` / ``response["legis_artifact"] = artifact``),
adding and stripping nothing — so freezing it here covers every emit path.

This test failing on an UNPLANNED diff is the contract doing its job. If you are
changing the wire on purpose, change it here in LOCKSTEP with the legis hub, and
update the matching constants in ``wardline/core/legis.py``.

What is frozen: the top-level key-set per emit mode; the per-finding top-level
key-set; AND the two legis-routing-critical sub-fields that live INSIDE a finding
and below the top-level freeze — the ``suppression_state`` VALUE (legis routes its
gate population on the exact strings ``active``/``waived``/``suppressed`` and 422s
an unrecognised one) and the nested proof key in ``properties`` (legis requires a
non-empty proof for any non-active defect). Those last two only ride the wire under
the opt-in ``--trust-suppressions`` posture (under the secure default every defect
rides as ``active``), so a drift there fails LOUD at legis rather than routing to
zero — but it still breaks the hop in the field, so it is frozen here too.

Documented out-of-scope (low, cannot route-to-zero, intentionally not frozen): a
scalar value-TYPE change on an ignored-unknown envelope field (e.g. a non-string
``fingerprint_scheme``), and the degenerate commit-present-but-tree-unreadable path
(emits ``commit_sha`` without ``tree_sha`` — a strict SUBSET of a frozen mode on an
already-unsigned artifact, reachable only on a corrupt repo).

The expected sets hardcode the literal key STRINGS (not the ``*_FIELD`` constants
in ``legis.py``) on purpose: a change to a constant's *value* must still trip this.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from wardline.core.config import load as load_config
from wardline.core.errors import LegisArtifactError
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.legis import build_legis_artifact, project_finding
from wardline.core.run import run_scan

# A leaky boundary→sink module: yields a real PY-WL defect so every mode under test
# carries at least one projected finding to freeze the per-finding key-set against.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)

# --- The frozen contract -----------------------------------------------------
# Always present, in every mode.
_BASE = frozenset({"scanner_identity", "rule_set_version", "fingerprint_scheme", "findings", "scan_scope"})
# No git repo: no commit/tree provenance to read.
_NON_REPO = _BASE
# A clean committed repo, no signing key: best-effort committed provenance.
_REPO_CLEAN_UNSIGNED = _BASE | {"commit_sha", "tree_sha"}
# A clean committed repo + signing key: the verified artifact carries its signature.
_SIGNED_CLEAN = _BASE | {"commit_sha", "tree_sha", "artifact_signature"}
# A dirty repo (key absent, or present under allow_dirty): committed provenance plus
# the ``dirty`` marker — and NEVER a signature (the false-provenance guard).
_REPO_DIRTY_UNSIGNED = _BASE | {"commit_sha", "tree_sha", "dirty"}
# Every projected finding carries exactly these keys (project_finding).
_FINDING_KEYS = frozenset(
    {"rule_id", "message", "severity", "kind", "fingerprint", "qualname", "properties", "suppression_state"}
)
_SCOPE_KEYS = frozenset(
    {"schema", "scan_root", "is_git_root", "source_roots", "resolved_source_roots", "scanned_paths"}
)


def _proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _git_commit(root: Path) -> None:
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@example.com"],
        ["git", "config", "user.name", "t"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "init"],
    ):
        subprocess.run(cmd, cwd=root, check=True, capture_output=True)


def _build(root: Path, *, key: bytes | None = None, allow_dirty: bool = False) -> dict:
    result = run_scan(root)
    cfg = load_config(root / "weft.toml")
    return build_legis_artifact(result, root=root, config=cfg, key=key, allow_dirty=allow_dirty)


def test_non_repo_unsigned_key_set_is_frozen(tmp_path: Path) -> None:
    scan = _build(_proj(tmp_path), key=None)
    assert set(scan) == _NON_REPO


def test_repo_clean_unsigned_key_set_is_frozen(tmp_path: Path) -> None:
    root = _proj(tmp_path)
    _git_commit(root)
    scan = _build(root, key=None)
    assert set(scan) == _REPO_CLEAN_UNSIGNED


def test_signed_clean_key_set_is_frozen(tmp_path: Path) -> None:
    root = _proj(tmp_path)
    _git_commit(root)
    scan = _build(root, key=b"shared-secret")
    assert set(scan) == _SIGNED_CLEAN


def test_repo_dirty_unsigned_key_set_is_frozen(tmp_path: Path) -> None:
    root = _proj(tmp_path)
    _git_commit(root)
    (root / "svc.py").write_text(_LEAKY + "# uncommitted edit\n", encoding="utf-8")
    scan = _build(root, key=None)
    assert set(scan) == _REPO_DIRTY_UNSIGNED


def test_dirty_tree_with_key_under_allow_dirty_is_unsigned_and_frozen(tmp_path: Path) -> None:
    # key present + dirty + allow_dirty: the false-provenance guard means this is
    # NEVER signed — it must produce the same dirty key-set as the unsigned path,
    # and must carry no signature.
    root = _proj(tmp_path)
    _git_commit(root)
    (root / "svc.py").write_text(_LEAKY + "# uncommitted edit\n", encoding="utf-8")
    scan = _build(root, key=b"shared-secret", allow_dirty=True)
    assert set(scan) == _REPO_DIRTY_UNSIGNED
    assert "artifact_signature" not in scan


def test_projected_finding_key_set_is_frozen(tmp_path: Path) -> None:
    scan = _build(_proj(tmp_path), key=None)
    assert scan["findings"], "fixture must yield at least one defect to freeze finding keys"
    for finding in scan["findings"]:
        assert set(finding) == _FINDING_KEYS


def test_scan_scope_key_set_and_values_are_frozen(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "svc.py").write_text(_LEAKY, encoding="utf-8")
    (root / "weft.toml").write_text('[wardline]\nsource_roots = ["src"]\n', encoding="utf-8")

    scan = _build(root, key=None)
    scope = scan["scan_scope"]

    assert set(scope) == _SCOPE_KEYS
    assert scope["schema"] == "wardline-legis-scan-scope-1"
    assert scope["scan_root"] == "."
    assert scope["is_git_root"] is False
    assert scope["source_roots"] == ["src"]
    assert scope["resolved_source_roots"] == ["src"]
    assert scope["scanned_paths"] == ["src/svc.py"]


def test_signed_artifact_refuses_subdirectory_scan_root(tmp_path: Path) -> None:
    root = _proj(tmp_path)
    subdir = root / "safe"
    subdir.mkdir()
    (subdir / "svc.py").write_text(_LEAKY, encoding="utf-8")
    _git_commit(root)
    result = run_scan(subdir)
    cfg = load_config(subdir / "weft.toml")

    with pytest.raises(LegisArtifactError, match="git repository root"):
        build_legis_artifact(result, root=subdir, config=cfg, key=b"shared-secret")


def test_findings_is_a_list(tmp_path: Path) -> None:
    # Guard the container TYPE, not just the key name: legis iterates findings; a
    # key whose value silently became a dict would route nothing the same way a
    # rename does. (json round-trip mirrors the on-wire shape the CLI writes.)
    scan = json.loads(json.dumps(_build(_proj(tmp_path), key=None)))
    assert isinstance(scan["findings"], list)


# --- The legis-routing-critical sub-fields inside a non-active finding ---------
# The mode/per-finding freezes above only ever exercise ACTIVE findings (the scan
# fixture yields no suppressions), so they never reach project_finding's non-active
# branch: the suppression_state VALUE mapping and the proof injected into properties.
# legis routes on those exact strings and requires the proof, so a silent drift there
# breaks the hop (loud 422) under --trust-suppressions. We build the non-active states
# directly (no git/baseline setup needed) and freeze both. The proof key literal
# "suppression_reason" is hardcoded so a change to SUPPRESSION_PROOF_KEY's value trips.
_SUPPRESSION_STATE_WIRE = {
    SuppressionState.WAIVED: "waived",
    SuppressionState.BASELINED: "suppressed",
    SuppressionState.JUDGED: "suppressed",
}
_PROOF_KEY = "suppression_reason"


def _defect(state: SuppressionState) -> Finding:
    return Finding(
        rule_id="PY-WL-101",
        message="leak",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=6, line_end=7, col_start=0, col_end=0),
        fingerprint="b" * 64,
        qualname="svc.leaky",
        suppressed=state,
        suppression_reason="ticket-123",
    )


@pytest.mark.parametrize(("state", "wire"), list(_SUPPRESSION_STATE_WIRE.items()))
def test_nonactive_suppression_state_value_and_proof_key_are_frozen(state: SuppressionState, wire: str) -> None:
    proj = project_finding(_defect(state))
    assert set(proj) == _FINDING_KEYS  # top-level key-set is branch-invariant
    assert proj["suppression_state"] == wire  # the legis routing value
    assert _PROOF_KEY in proj["properties"]  # the nested proof KEY name legis reads
    assert proj["properties"][_PROOF_KEY]  # non-empty (legis 422s on empty proof)


def test_active_defect_injects_no_proof() -> None:
    # The complement: proof is injected ONLY for non-active defects, so an active
    # finding must NOT carry the proof key (else legis would see spurious proof and
    # the active/suppressed split would blur).
    proj = project_finding(_defect(SuppressionState.ACTIVE))
    assert proj["suppression_state"] == "active"
    assert _PROOF_KEY not in proj["properties"]
