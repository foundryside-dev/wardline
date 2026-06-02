# src/wardline/core/attest.py
"""Signed, reproducible evidence bundle (``attest``) — build / sign / verify.

THREAT MODEL — read before trusting a bundle. The signature is **HMAC-SHA256 with
a SHARED PROJECT KEY**. That makes it *tamper-evidence within a key-holding trust
domain* (a CI runner, a team that all hold the same key) — NOT public, asymmetric,
non-repudiable proof. Verification REQUIRES possessing the same secret used to sign;
anyone with the key can both produce and verify a bundle, so it does not bind the
bundle to a specific signer. Asymmetric signing (Ed25519 / RSA) would prove authorship
without sharing a secret, but it needs a non-stdlib dependency, which Wardline's
zero-dependency base forbids — so HMAC is **forced, not chosen**. Do not present a
bundle as cryptographic proof of *who* produced it; it proves only that the holder of
the project key has not been tampered with since signing.

DETERMINISM is a hard requirement. The canonical bytes of ``payload``
(:func:`_canonical_bytes`) are BOTH the signed material and the reproducibility target.
Two builds of the same unchanged tree at the same ``today`` must produce byte-identical
canonical payloads — the only date-sensitive field is the posture's waiver-debt
``days_left``, so a waiver-free tree's payload is fully date-independent. Every list in
the payload is sorted on a stable key (boundaries by qualname; the posture sorts its own
lists) so the suite's ``pytest-randomly`` ordering cannot perturb the bytes.

Zero-dependency: stdlib ``hmac`` / ``hashlib`` / ``subprocess`` / ``json`` only. This
module never imports ``wardline.clarion`` (an optional extra) at module level; SEI
enrichment of the ``boundaries`` entries is opt-in via a ``clarion_client`` and happens
behind a LAZY import inside :func:`_enrich_seis`. Without a client every ``sei`` stays
None and ``sei_source`` is ``"unavailable"``.

SEI values live in the SIGNED payload, so reproducibility threads the same
``clarion_client`` through BOTH build and verify: re-verifying a SEI-keyed bundle WITH
the same client (and unchanged tree) reproduces; re-verifying WITHOUT a client honestly
reports ``reproduced=False`` (the SEIs cannot be re-derived) while the signature — which
is over the recorded payload — stays valid.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from datetime import date
from pathlib import Path
from typing import Any

from wardline._version import __version__
from wardline.core import config as config_mod
from wardline.core.assure import _empty_posture, posture_from_scan
from wardline.core.attest_key import key_id
from wardline.core.config import WardlineConfig
from wardline.core.dossier import classify_entity_trust
from wardline.core.errors import AttestError
from wardline.core.run import run_scan
from wardline.core.waivers import parse_waivers


def git_state(root: Path) -> tuple[str | None, bool]:
    """Return ``(commit, dirty)`` for the working tree at ``root``.

    ``commit`` is the stripped stdout of ``git rev-parse HEAD`` (cwd=root), or None if
    ``root`` is not a git repo, git is not installed, or the command exits non-zero.
    ``dirty`` is True iff ``git status --porcelain`` (cwd=root) emits any output.

    Read-only: no network, no mutation. A missing-git / non-repo state is reported as
    ``(None, False)``, never raised — attestation of a non-git tree is legitimate.
    """
    try:
        rev = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None, False
    if rev.returncode != 0:
        return None, False
    commit = rev.stdout.strip() or None
    if commit is None:
        return None, False

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:  # pragma: no cover - git existed for rev-parse
        return commit, False
    if status.returncode != 0:  # pragma: no cover - unusual
        return commit, False
    dirty = bool(status.stdout.strip())
    return commit, dirty


def ruleset_hash(config: WardlineConfig) -> str:
    """A deterministic ``"sha256:<hex>"`` over the config's rule surface.

    Canonicalises ``sorted(rules_enable)``, ``sorted(rules_severity.items())`` and the
    Wardline ``__version__`` into a stable JSON string, then SHA-256s it. The same config
    always hashes identically; changing any enabled rule, any severity override, or the
    analyzer version changes the hash — so a bundle's ruleset is pinned to the policy that
    produced it.
    """
    canonical = json.dumps(
        [sorted(config.rules_enable), sorted(config.rules_severity.items()), __version__],
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """THE canonical serialization of a payload — used for signing AND reproducibility.

    Compact, key-sorted UTF-8 JSON. Any change to this function silently invalidates
    every previously signed bundle, so treat it as a wire contract.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(payload: dict[str, Any], key: str) -> dict[str, str]:
    """HMAC-SHA256 the canonical payload bytes under the shared ``key``.

    Returns ``{"alg", "value", "key_id"}``. ``key_id`` is a non-secret 8-hex short id
    (see :func:`wardline.core.attest_key.key_id`) that lets bundles signed with different
    keys be told apart without revealing the key. See the module threat model: this is
    shared-secret tamper-evidence, not asymmetric proof.
    """
    value = hmac.new(key.encode(), _canonical_bytes(payload), hashlib.sha256).hexdigest()
    return {"alg": "HMAC-SHA256", "value": value, "key_id": key_id(key)}


def _enrich_seis(boundaries: list[dict[str, Any]], clarion_client: Any) -> str:
    """Fill each boundary's ``sei`` from Clarion, fail-soft per boundary.

    Returns the ``sei_source``: ``"clarion"`` if a client was supplied AND at least one
    SEI resolved, else ``"unavailable"``. The Clarion seam is an optional extra, so it is
    imported LAZILY here (the module base stays zero-dependency). Any failure leaves
    ``sei=None`` and never crashes attestation: an outer ``try`` degrades the WHOLE
    enrichment (a capabilities / resolver-construction outage → ``"unavailable"``), and a
    per-qualname ``try`` keeps one unresolvable boundary from aborting the rest.
    """
    if clarion_client is None:
        return "unavailable"

    try:
        from wardline.clarion.dossier_sources import resolve_entity_binding
        from wardline.clarion.identity import SeiCapability, SeiResolver

        capabilities = clarion_client.capabilities()
        resolver = SeiResolver(clarion_client, SeiCapability.from_capabilities(capabilities))

        resolved_any = False
        for boundary in boundaries:
            try:
                binding = resolve_entity_binding(clarion_client, resolver, boundary["qualname"])
            except Exception:  # noqa: BLE001 — per-boundary fail-soft, see docstring
                continue
            if binding is not None and binding.sei:
                boundary["sei"] = binding.sei
                resolved_any = True
    except Exception:  # noqa: BLE001 — whole-enrichment fail-soft, see docstring
        return "unavailable"

    return "clarion" if resolved_any else "unavailable"


def _build_payload(
    root: Path,
    *,
    config_path: Path | None,
    confine_to_root: bool,
    today: date,
    clarion_client: Any = None,
) -> dict[str, Any]:
    """Derive the (unsigned) attestation payload from the tree at ``root``.

    The PURE derivation shared by :func:`build_attestation` and
    :func:`verify_attestation` so a re-derivation is apples-to-apples. It runs
    ``run_scan`` exactly ONCE and applies NO policy (the dirty-tree refusal lives in
    :func:`build_attestation`, never here — verify must not raise on a dirty tree).
    """
    cfg_path = config_path or (root / "wardline.yaml")
    config = config_mod.load(cfg_path)
    waivers = parse_waivers(config.waivers)

    result = run_scan(root, config_path=config_path, confine_to_root=confine_to_root)
    commit, dirty = git_state(root)

    if result.context is None:
        posture = _empty_posture(waivers, today)
        boundaries: list[dict[str, Any]] = []
        sei_source = "unavailable"  # no boundaries → nothing to key
    else:
        posture = posture_from_scan(result, result.context, waivers=waivers, today=today)
        boundaries = []
        for qualname in sorted(result.context.declared_qualnames):
            verdict = classify_entity_trust(result, result.context, qualname)
            boundaries.append(
                {
                    "qualname": qualname,
                    "sei": None,  # filled by _enrich_seis below behind a lazy Clarion import
                    "verdict": verdict.verdict,
                    "tier": verdict.declared_tier,
                }
            )
        sei_source = _enrich_seis(boundaries, clarion_client)

    return {
        "wardline_version": __version__,
        "commit": commit,
        "dirty": dirty,
        "ruleset_hash": ruleset_hash(config),
        "posture": posture.to_dict(),
        "boundaries": boundaries,
        "sei_source": sei_source,
    }


def build_attestation(
    root: Path,
    key: str,
    *,
    config_path: Path | None = None,
    confine_to_root: bool = False,
    clarion_client: Any = None,
    allow_dirty: bool = True,
    today: date | None = None,
) -> dict[str, Any]:
    """Build a signed evidence bundle for the tree at ``root``.

    Runs the scan ONCE (via :func:`_build_payload`), then HMAC-signs the canonical
    payload bytes under the shared ``key``. With ``allow_dirty=False`` a working tree
    with uncommitted changes is refused (:class:`AttestError`) so a bundle's ``commit``
    truthfully pins its source.

    With a ``clarion_client``, each boundary's ``sei`` is resolved from Clarion (opt-in,
    fail-soft, behind a lazy import — see :func:`_enrich_seis`) and ``sei_source`` becomes
    ``"clarion"`` if any SEI resolved; without one every ``sei`` stays None and
    ``sei_source`` is ``"unavailable"``. See the module threat model: the signature is
    shared-secret tamper-evidence, not asymmetric proof.
    """
    if today is None:
        today = date.today()

    payload = _build_payload(
        root,
        config_path=config_path,
        confine_to_root=confine_to_root,
        today=today,
        clarion_client=clarion_client,
    )
    if payload["dirty"] and not allow_dirty:
        raise AttestError("refusing to attest a dirty working tree (uncommitted changes); pass allow_dirty to override")

    signature = _sign(payload, key)
    return {"schema": "wardline-attest-1", "payload": payload, "signature": signature}


def verify_attestation(
    bundle: dict[str, Any],
    key: str,
    *,
    root: Path | None = None,
    reproduce: bool = False,
    clarion_client: Any = None,
) -> dict[str, Any]:
    """Verify a bundle's signature (always, offline) and optionally its reproducibility.

    The signature check recomputes the HMAC over the recorded payload and compares it in
    constant time (:func:`hmac.compare_digest`) against the stored value — it never scans
    and works fully offline with the shared ``key``. A wrong key or any tampered payload
    field yields ``signature_valid=False``.

    When ``reproduce=True`` and ``root`` is given, the payload is re-derived at the
    CURRENT tree and its canonical bytes compared to the recorded payload's; equal →
    ``reproduced=True``, otherwise ``mismatches`` lists the differing top-level payload
    keys. ``reproduced`` is None when ``reproduce=False``. NOTE: reproducibility holds
    against the RECORDED commit — a mismatch may mean the tree moved on, not tamper.

    Since SEI values are part of the signed payload, reproducing a SEI-keyed bundle
    requires the SAME ``clarion_client`` used to build it: pass it here so the
    re-derivation resolves SEIs identically. Without it, a SEI-keyed bundle re-derives
    with ``sei=None`` and honestly reports ``reproduced=False`` (the binding cannot be
    reproduced), while ``signature_valid`` is unaffected (it is over the recorded bytes).
    """
    recorded_payload: dict[str, Any] = bundle["payload"]
    expected = _sign(recorded_payload, key)["value"]
    signature_valid = hmac.compare_digest(expected, bundle["signature"]["value"])

    note = "reproducibility holds against the RECORDED commit; a mismatch may mean the tree moved, not tamper."

    if not reproduce or root is None:
        return {
            "signature_valid": signature_valid,
            "reproduced": None,
            "mismatches": [],
            "note": note,
        }

    rederived = _build_payload(
        root,
        config_path=None,
        confine_to_root=False,
        today=date.today(),
        clarion_client=clarion_client,
    )
    if _canonical_bytes(rederived) == _canonical_bytes(recorded_payload):
        return {
            "signature_valid": signature_valid,
            "reproduced": True,
            "mismatches": [],
            "note": note,
        }

    keys = sorted(set(recorded_payload) | set(rederived))
    mismatches = [k for k in keys if recorded_payload.get(k) != rederived.get(k)]
    return {
        "signature_valid": signature_valid,
        "reproduced": False,
        "mismatches": mismatches,
        "note": note,
    }
