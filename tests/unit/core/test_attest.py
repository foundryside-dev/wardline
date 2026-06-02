# tests/unit/core/test_attest.py
"""The signed evidence bundle (``attest``) — build / sign / verify.

Determinism is a hard requirement: the bundle's own canonical bytes are BOTH the
signed material and the reproducibility target, and the suite runs under
``pytest-randomly``. Two builds of the same unchanged tree at the same pinned date
must produce byte-identical canonical payloads.

Threat model under test: HMAC-SHA256 with a SHARED key is tamper-evidence within a
key-holding trust domain, NOT asymmetric/non-repudiable proof — verification REQUIRES
the key. The wrong-key and tamper assertions pin that the signature actually binds the
payload bytes.
"""

from __future__ import annotations

import subprocess
from datetime import date
from pathlib import Path

from wardline.core import config as config_mod
from wardline.core.assure import build_posture
from wardline.core.attest import (
    _canonical_bytes,
    build_attestation,
    git_state,
    ruleset_hash,
    verify_attestation,
)
from wardline.core.errors import AttestError, WardlineError

_KEY = "0" * 64
_PINNED = date(2026, 6, 3)

# Real trust boundaries: `src` is an @external_boundary (EXTERNAL_RAW), `clean`
# conforms (INTEGRAL), `leak` declares INTEGRAL but returns the EXTERNAL_RAW value
# → a PY-WL-101 defect. Mirrors the test_assure.py pattern so there are real anchors.
_MODULE = (
    "from wardline.decorators.trust import trusted, external_boundary\n"
    "\n"
    "@external_boundary\n"
    "def src():\n"
    "    return _read()\n"
    "\n"
    "def _read():\n"
    "    return object()\n"
    "\n"
    "@trusted(level='INTEGRAL')\n"
    "def clean():\n"
    "    return 1\n"
    "\n"
    "@trusted(level='INTEGRAL')\n"
    "def leak():\n"
    "    return src()\n"
)


def _annotated_tree(tmp_path: Path) -> Path:
    """A clean, NON-git annotated tree (no waivers → payload is date-independent)."""
    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")
    return tmp_path


def _write_config(path: Path, *, severity: str) -> None:
    path.write_text(
        f"rules:\n  enable:\n    - PY-WL-101\n  severity:\n    PY-WL-101: {severity}\n",
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# 1. ruleset_hash determinism
# --------------------------------------------------------------------------- #
def test_ruleset_hash_deterministic_and_severity_sensitive(tmp_path: Path) -> None:
    cfg_a = tmp_path / "a.yaml"
    cfg_b = tmp_path / "b.yaml"
    _write_config(cfg_a, severity="ERROR")
    _write_config(cfg_b, severity="WARNING")

    config_a1 = config_mod.load(cfg_a)
    config_a2 = config_mod.load(cfg_a)
    config_b = config_mod.load(cfg_b)

    h_a1 = ruleset_hash(config_a1)
    h_a2 = ruleset_hash(config_a2)
    h_b = ruleset_hash(config_b)

    assert h_a1.startswith("sha256:")
    assert h_a1 == h_a2, "same config must hash identically"
    assert h_a1 != h_b, "a changed severity must change the ruleset hash"


# --------------------------------------------------------------------------- #
# 2. git_state
# --------------------------------------------------------------------------- #
def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )


def test_git_state_repo_clean_dirty_and_non_git(tmp_path: Path) -> None:
    # Non-git directory first.
    non_git = tmp_path / "plain"
    non_git.mkdir()
    (non_git / "f.py").write_text("x = 1\n", encoding="utf-8")
    assert git_state(non_git) == (None, False)

    # A throwaway git repo IN tmp_path (the FEATURE under test on a tmp repo — NOT
    # version-controlling the wardline repo).
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "f.py").write_text("x = 1\n", encoding="utf-8")
    _git(["init"], repo)
    _git(["add", "-A"], repo)
    _git(
        [
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "init",
        ],
        repo,
    )

    commit, dirty = git_state(repo)
    assert commit is not None
    assert len(commit) == 40 and all(c in "0123456789abcdef" for c in commit)
    assert dirty is False

    # An untracked file flips dirty True.
    (repo / "new.py").write_text("y = 2\n", encoding="utf-8")
    commit2, dirty2 = git_state(repo)
    assert commit2 == commit
    assert dirty2 is True


# --------------------------------------------------------------------------- #
# 3. build_attestation + signature round-trip / wrong-key / tamper
# --------------------------------------------------------------------------- #
def test_build_attestation_shape_and_signature(tmp_path: Path) -> None:
    tree = _annotated_tree(tmp_path)

    bundle = build_attestation(tree, _KEY, today=_PINNED)

    assert bundle["schema"] == "wardline-attest-1"
    payload = bundle["payload"]

    # Non-git tree → commit None, dirty False.
    assert payload["commit"] is None
    assert payload["dirty"] is False
    assert payload["sei_source"] == "unavailable"
    assert payload["ruleset_hash"].startswith("sha256:")

    # Posture equals the standalone build_posture at the same pinned date.
    expected_posture = build_posture(tree, today=_PINNED).to_dict()
    assert payload["posture"] == expected_posture

    # Boundaries sorted by qualname, every sei None.
    boundaries = payload["boundaries"]
    quals = [b["qualname"] for b in boundaries]
    assert quals == sorted(quals)
    assert quals  # there ARE anchored boundaries
    assert all(b["sei"] is None for b in boundaries)
    assert {"qualname", "sei", "verdict", "tier"} == set(boundaries[0])

    # Signature round-trips with the right key.
    assert bundle["signature"]["alg"] == "HMAC-SHA256"
    assert len(bundle["signature"]["key_id"]) == 8
    result = verify_attestation(bundle, _KEY)
    assert result["signature_valid"] is True
    assert result["reproduced"] is None  # reproduce=False default

    # Wrong key → invalid.
    assert verify_attestation(bundle, "f" * 64)["signature_valid"] is False

    # Tamper with a payload field → invalid under the RIGHT key.
    import copy

    tampered = copy.deepcopy(bundle)
    tampered["payload"]["dirty"] = True
    assert verify_attestation(tampered, _KEY)["signature_valid"] is False


# --------------------------------------------------------------------------- #
# 4. Reproducibility / determinism (waiver-free tree → date-independent payload)
# --------------------------------------------------------------------------- #
def test_build_is_byte_identical_and_reproduces(tmp_path: Path) -> None:
    tree = _annotated_tree(tmp_path)

    b1 = build_attestation(tree, _KEY, today=_PINNED)
    b2 = build_attestation(tree, _KEY, today=_PINNED)
    assert _canonical_bytes(b1["payload"]) == _canonical_bytes(b2["payload"])
    assert b1["signature"]["value"] == b2["signature"]["value"]

    # Reproduce against the unchanged tree (no waivers → no today-sensitive field).
    verified = verify_attestation(b1, _KEY, root=tree, reproduce=True)
    assert verified["signature_valid"] is True
    assert verified["reproduced"] is True
    assert verified["mismatches"] == []
    assert "RECORDED commit" in verified["note"]


def test_reproduce_detects_a_moved_tree(tmp_path: Path) -> None:
    """The headline feature: when the tree MOVES after signing, the signature stays
    valid (the recorded bytes are intact) but ``reproduced`` is False and ``mismatches``
    names the top-level payload keys that diverged — demonstrating the note's exact
    scenario (tree moved on, not tamper)."""
    tree = _annotated_tree(tmp_path)
    bundle = build_attestation(tree, _KEY, today=_PINNED)

    # Add a new anchored boundary → shifts both ``boundaries`` and the posture's
    # boundaries_total.
    (tree / "m.py").write_text(
        _MODULE + "\n@trusted(level='INTEGRAL')\ndef extra():\n    return 2\n",
        encoding="utf-8",
    )

    verified = verify_attestation(bundle, _KEY, root=tree, reproduce=True)
    assert verified["signature_valid"] is True  # recorded bytes untouched
    assert verified["reproduced"] is False
    assert "boundaries" in verified["mismatches"]
    assert "posture" in verified["mismatches"]
    assert "RECORDED commit" in verified["note"]


# --------------------------------------------------------------------------- #
# 5. Dirty refusal
# --------------------------------------------------------------------------- #
def test_dirty_tree_refusal(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text(_MODULE, encoding="utf-8")
    _git(["init"], repo)
    _git(["add", "-A"], repo)
    _git(
        [
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "init",
        ],
        repo,
    )
    # Introduce an uncommitted change.
    (repo / "m.py").write_text(_MODULE + "\n# touched\n", encoding="utf-8")

    commit, dirty = git_state(repo)
    assert dirty is True

    try:
        build_attestation(repo, _KEY, allow_dirty=False, today=_PINNED)
    except AttestError as exc:
        assert isinstance(exc, WardlineError)
        assert "dirty" in str(exc)
    else:  # pragma: no cover - failure path
        raise AssertionError("expected AttestError on a dirty tree with allow_dirty=False")

    # allow_dirty=True succeeds and records dirty: true.
    bundle = build_attestation(repo, _KEY, allow_dirty=True, today=_PINNED)
    assert bundle["payload"]["dirty"] is True
    assert bundle["payload"]["commit"] == commit
    assert verify_attestation(bundle, _KEY)["signature_valid"] is True
