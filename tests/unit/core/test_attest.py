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
from types import ModuleType

import pytest

from wardline.core import config as config_mod
from wardline.core.assure import build_posture
from wardline.core.attest import (
    _canonical_bytes,
    build_attestation,
    git_state,
    ruleset_hash,
    verify_attestation,
)
from wardline.core.config import WardlineConfig
from wardline.core.errors import AttestError, WardlineError
from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, TrustGrammar
from wardline.scanner.taint.provider import FunctionTaint

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


@pytest.mark.parametrize(
    ("field", "base", "changed"),
    [
        ("source_roots", WardlineConfig(), WardlineConfig(source_roots=("src",))),
        ("exclude", WardlineConfig(), WardlineConfig(exclude=("vendor/**",))),
        ("rules_enable", WardlineConfig(), WardlineConfig(rules_enable=("PY-WL-101",))),
        ("rules_severity", WardlineConfig(), WardlineConfig(rules_severity={"PY-WL-101": "CRITICAL"})),
        ("untrusted_sources", WardlineConfig(), WardlineConfig(untrusted_sources=("pkg.io.read_raw",))),
        ("sanitisers", WardlineConfig(), WardlineConfig(sanitisers=("pkg.clean.safe",))),
        ("provenance_clash", WardlineConfig(), WardlineConfig(provenance_clash=True)),
    ],
)
def test_ruleset_hash_changes_for_effective_scan_policy_fields(
    field: str,
    base: WardlineConfig,
    changed: WardlineConfig,
) -> None:
    assert ruleset_hash(base) != ruleset_hash(changed), f"{field} must be signed policy identity"


def test_ruleset_hash_changes_for_trusted_pack_identity_and_grammar() -> None:
    def seed(levels: object) -> FunctionTaint:
        return FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.GUARDED)

    class RuleA:
        rule_id = "PY-WL-950"

    class RuleB:
        rule_id = "PY-WL-951"

    boundary = BoundaryType("policy_boundary", "policy_pack", 1, (), seed)
    pack_a = ModuleType("policy_pack")
    pack_a.__version__ = "1.0"
    pack_a.config = {"rules": {"severity": {"PY-WL-950": "WARN"}}}  # type: ignore[attr-defined]
    pack_a.grammar = TrustGrammar(boundary_types=(boundary,), rules=(RuleA,))  # type: ignore[attr-defined]

    pack_b = ModuleType("policy_pack")
    pack_b.__version__ = "1.1"
    pack_b.config = {"rules": {"severity": {"PY-WL-951": "ERROR"}}}  # type: ignore[attr-defined]
    pack_b.grammar = TrustGrammar(boundary_types=(boundary,), rules=(RuleB,))  # type: ignore[attr-defined]

    cfg_a = WardlineConfig(packs=("policy_pack",), pack_modules={"policy_pack": pack_a})
    cfg_b = WardlineConfig(packs=("policy_pack",), pack_modules={"policy_pack": pack_b})

    assert ruleset_hash(cfg_a) != ruleset_hash(cfg_b)


def test_attestation_reproduce_threads_trusted_pack_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_root = Path(__file__).resolve().parents[3]
    monkeypatch.syspath_prepend(str(project_root))
    tree = tmp_path / "proj"
    tree.mkdir()
    (tree / "wardline.yaml").write_text("packs:\n  - tests.unit.install.mock_pack\n", encoding="utf-8")
    (tree / "m.py").write_text(
        "from tests.unit.install.mock_pack import mock_boundary\n\n@mock_boundary\ndef violator():\n    pass\n",
        encoding="utf-8",
    )

    bundle = build_attestation(
        tree,
        _KEY,
        today=_PINNED,
        trust_local_packs=True,
        trusted_packs=("tests.unit.install.mock_pack",),
    )
    assert bundle["payload"]["posture"]["defect_total"] >= 1

    verified = verify_attestation(
        bundle,
        _KEY,
        root=tree,
        reproduce=True,
        trust_local_packs=True,
        trusted_packs=("tests.unit.install.mock_pack",),
    )
    assert verified["signature_valid"] is True
    assert verified["reproduced"] is True
    assert verified["mismatches"] == []


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

    tampered_alg = copy.deepcopy(bundle)
    tampered_alg["signature"]["alg"] = "none"
    assert verify_attestation(tampered_alg, _KEY)["signature_valid"] is False

    tampered_key_id = copy.deepcopy(bundle)
    tampered_key_id["signature"]["key_id"] = "deadbeef"
    assert verify_attestation(tampered_key_id, _KEY)["signature_valid"] is False

    tampered_schema = copy.deepcopy(bundle)
    tampered_schema["schema"] = "wardline-attest-2"
    assert verify_attestation(tampered_schema, _KEY)["signature_valid"] is False


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
# 4b. attested_at recorded + date-stable / config-correct reproduce
# --------------------------------------------------------------------------- #
def test_attested_at_records_the_build_date(tmp_path: Path) -> None:
    """The bundle states its own build date in the SIGNED payload (an evidence primitive
    must be self-describing). It equals the ``today`` passed in, as an ISO string."""
    tree = _annotated_tree(tmp_path)
    bundle = build_attestation(tree, _KEY, today=_PINNED)
    assert bundle["payload"]["attested_at"] == _PINNED.isoformat()


def _waiver_tree(tmp_path: Path) -> Path:
    """A clean annotated tree WITH an active waiver (``expires`` set) → the payload's
    posture carries a date-sensitive ``days_left``, so re-derivation on a different day
    diverges UNLESS verify reads the recorded ``attested_at``."""
    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")
    (tmp_path / "wardline.yaml").write_text(
        f'waivers:\n  - fingerprint: "{"a" * 64}"\n    reason: "third-party shim"\n    expires: "2026-12-31"\n',
        encoding="utf-8",
    )
    return tmp_path


def test_reproduce_is_date_stable_for_a_waiver_tree(tmp_path: Path) -> None:
    """A waiver tree built on a PAST date (distinct from the real clock) reproduces True:
    verify reads the recorded ``attested_at`` instead of ``date.today()``, so the
    date-sensitive ``days_left`` re-derives identically. (Before this fix, verify used the
    real today and ``reproduced`` would be False the day after the build.)"""
    tree = _waiver_tree(tmp_path)
    built = date(2025, 1, 1)  # deliberately NOT the real date.today()
    bundle = build_attestation(tree, _KEY, today=built)

    verified = verify_attestation(bundle, _KEY, root=tree, reproduce=True)
    assert verified["signature_valid"] is True
    assert verified["reproduced"] is True, verified["mismatches"]
    assert verified["mismatches"] == []


def test_reproduce_threads_config_path(tmp_path: Path) -> None:
    """A bundle built with a NON-default ``config_path`` (living outside ``root`` and with
    a non-default severity → distinct ``ruleset_hash``) reproduces True only when the SAME
    ``config_path`` is threaded into verify. (Before this fix verify hardcoded
    ``config_path=None`` → it rediscovered the default config → ``ruleset_hash`` mismatch.)"""
    tree = _annotated_tree(tmp_path)
    cfg = tmp_path / "custom" / "wardline.yaml"
    cfg.parent.mkdir()
    _write_config(cfg, severity="WARN")  # non-default severity → distinct ruleset_hash

    bundle = build_attestation(tree, _KEY, config_path=cfg, today=_PINNED)

    verified = verify_attestation(bundle, _KEY, root=tree, reproduce=True, config_path=cfg)
    assert verified["signature_valid"] is True
    assert verified["reproduced"] is True, verified["mismatches"]
    assert verified["mismatches"] == []


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


# --------------------------------------------------------------------------- #
# 6. SEI enrichment (optional, behind a lazy Clarion import)
# --------------------------------------------------------------------------- #
from wardline.clarion.client import ResolveResult  # noqa: E402 — kept with the SEI tests it serves

_SEI = "clarion:eid:00112233445566778899aabbccddeeff"


class _FakeClarion:
    """A Clarion double that resolves exactly ONE qualname to an SEI.

    Mirrors ``tests/unit/core/test_loom_dossier.py``'s fake but is SELECTIVE: only the
    ``hit`` qualname resolves to a locator (others land in ``unresolved`` → no binding →
    ``sei=None``), so the "other boundaries stay None" assertion is real."""

    def __init__(self, *, hit: str = "m.leak", sei: str = _SEI) -> None:
        self._hit = hit
        self._sei = sei

    def capabilities(self) -> dict[str, object]:
        return {"sei": {"supported": True, "version": 1}}

    def resolve(self, qualnames: list[str]) -> ResolveResult:
        resolved = {q: f"python:function:{q}" for q in qualnames if q == self._hit}
        unresolved = [q for q in qualnames if q != self._hit]
        return ResolveResult(resolved=resolved, unresolved=unresolved)

    def resolve_identity(self, locator: str) -> dict[str, object]:
        return {"sei": self._sei, "current_locator": locator, "content_hash": "ch", "alive": True}

    def resolve_sei(self, sei: str) -> dict[str, object]:
        return {"alive": True}


class _RaisingClarion(_FakeClarion):
    """capabilities() raises → the WHOLE enrichment degrades to unavailable, never crashes."""

    def capabilities(self) -> dict[str, object]:
        raise RuntimeError("clarion unreachable")


def test_sei_keyed_bundle_fills_resolved_boundary_only(tmp_path: Path) -> None:
    tree = _annotated_tree(tmp_path)
    bundle = build_attestation(tree, _KEY, clarion_client=_FakeClarion(hit="m.leak"), today=_PINNED)

    payload = bundle["payload"]
    assert payload["sei_source"] == "clarion"
    by_qn = {b["qualname"]: b for b in payload["boundaries"]}
    assert by_qn["m.leak"]["sei"] == _SEI  # the one resolvable qualname is keyed
    assert by_qn["m.clean"]["sei"] is None  # unresolved → honestly None
    assert by_qn["m.src"]["sei"] is None
    assert verify_attestation(bundle, _KEY)["signature_valid"] is True


def test_sei_enrichment_is_fail_soft(tmp_path: Path) -> None:
    """Attestation must never fail because Clarion is unreachable: a raising client
    degrades to every ``sei=None`` and ``sei_source == "unavailable"``."""
    tree = _annotated_tree(tmp_path)
    bundle = build_attestation(tree, _KEY, clarion_client=_RaisingClarion(), today=_PINNED)

    payload = bundle["payload"]
    assert payload["sei_source"] == "unavailable"
    assert all(b["sei"] is None for b in payload["boundaries"])
    assert verify_attestation(bundle, _KEY)["signature_valid"] is True


def test_no_clarion_client_is_unavailable(tmp_path: Path) -> None:
    tree = _annotated_tree(tmp_path)
    bundle = build_attestation(tree, _KEY, today=_PINNED)

    payload = bundle["payload"]
    assert payload["sei_source"] == "unavailable"
    assert all(b["sei"] is None for b in payload["boundaries"])


def test_sei_keyed_bundle_reproducibility(tmp_path: Path) -> None:
    """A SEI-keyed bundle reproduces with the SAME client (same tree → same SEIs); without
    a client the boundaries re-derive with ``sei=None`` so ``reproduced`` is honestly False,
    while ``signature_valid`` stays True (the signature is over the recorded payload)."""
    tree = _annotated_tree(tmp_path)
    bundle = build_attestation(tree, _KEY, clarion_client=_FakeClarion(hit="m.leak"), today=_PINNED)

    with_client = verify_attestation(bundle, _KEY, root=tree, reproduce=True, clarion_client=_FakeClarion(hit="m.leak"))
    assert with_client["signature_valid"] is True
    assert with_client["reproduced"] is True
    assert with_client["mismatches"] == []

    without_client = verify_attestation(bundle, _KEY, root=tree, reproduce=True)
    assert without_client["signature_valid"] is True
    assert without_client["reproduced"] is False
    assert "boundaries" in without_client["mismatches"]
    assert "sei_source" in without_client["mismatches"]
