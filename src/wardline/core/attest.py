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
(:func:`_canonical_bytes`) are the reproducibility target; the HMAC additionally binds
the outer envelope ``schema`` so a future schema relabel cannot verify against the wrong
wire contract. Two builds of the same unchanged tree at the same ``today`` must produce
byte-identical canonical payloads — the only date-sensitive field is the posture's
waiver-debt ``days_left``, so a waiver-free tree's payload is fully date-independent.
Every list in the payload is sorted on a stable key (boundaries by qualname; the posture
sorts its own lists) so the suite's ``pytest-randomly`` ordering cannot perturb the
bytes.

Zero-dependency: stdlib ``hmac`` / ``hashlib`` / ``subprocess`` / ``json`` only. This
module never imports a third-party EXTRA package (e.g. ``blake3``) at module level —
``import wardline.core.attest`` pulls in no extra dependency. (It DOES reach
``wardline.loomweave.identity`` transitively via ``core.dossier``, but that module is
stdlib-only, so the zero-dependency base holds.) The live Loomweave CLIENT used for SEI
enrichment of the ``boundaries`` entries is opt-in via a ``loomweave_client`` and is
LAZY-imported inside :func:`_enrich_seis`. Without a client every ``sei`` stays None and
``sei_source`` is ``"unavailable"``.

SEI values live in the SIGNED payload, so reproducibility threads the same
``loomweave_client`` through BOTH build and verify: re-verifying a SEI-keyed bundle WITH
the same client (and unchanged tree) reproduces; re-verifying WITHOUT a client honestly
reports ``reproduced=False`` (the SEIs cannot be re-derived) while the signature — which
is over the recorded payload — stays valid.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import date
from enum import Enum
from pathlib import Path
from types import ModuleType
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

ATTEST_SCHEMA = "wardline-attest-1"


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
    except OSError:
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
    except OSError:  # pragma: no cover
        return commit, False
    if status.returncode != 0:  # pragma: no cover - unusual
        return commit, False
    dirty = bool(status.stdout.strip())
    return commit, dirty


def _file_sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _module_origin(module: ModuleType) -> Path | None:
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None) or getattr(module, "__file__", None)
    if not isinstance(origin, str) or origin in {"built-in", "frozen"}:
        return None
    return Path(origin)


def _callable_policy_identity(value: Any) -> dict[str, Any]:
    code = getattr(value, "__code__", None)
    code_hash = None
    if code is not None:
        digest = hashlib.sha256()
        digest.update(code.co_code)
        digest.update(repr(code.co_consts).encode("utf-8", "backslashreplace"))
        digest.update(repr(code.co_names).encode("utf-8", "backslashreplace"))
        digest.update(repr(code.co_varnames).encode("utf-8", "backslashreplace"))
        code_hash = digest.hexdigest()
    return {
        "module": getattr(value, "__module__", None),
        "qualname": getattr(value, "__qualname__", getattr(value, "__name__", repr(value))),
        "code_sha256": code_hash,
    }


def _class_policy_identity(value: type) -> dict[str, Any]:
    source_path = None
    try:
        import inspect

        source = inspect.getsourcefile(value)
        source_path = Path(source) if source is not None else None
    except (OSError, TypeError):
        source_path = None
    return {
        "module": getattr(value, "__module__", None),
        "qualname": getattr(value, "__qualname__", value.__name__),
        "rule_id": getattr(value, "rule_id", None),
        "source_sha256": _file_sha256(source_path),
    }


def _jsonable_policy_value(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _jsonable_policy_value(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, tuple | list):
        return [_jsonable_policy_value(v) for v in value]
    if isinstance(value, set | frozenset):
        rendered = [_jsonable_policy_value(v) for v in value]
        return sorted(rendered, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if isinstance(value, type):
        return _class_policy_identity(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _jsonable_policy_value(getattr(value, field.name)) for field in fields(value)}
    if callable(value):
        return _callable_policy_identity(value)
    return repr(value)


def _pack_policy_identity(name: str, module: Any) -> dict[str, Any]:
    if not isinstance(module, ModuleType):
        return {"name": name, "loaded": False, "module_repr": repr(module)}
    origin = _module_origin(module)
    return {
        "name": name,
        "loaded": True,
        "module": getattr(module, "__name__", name),
        "version": getattr(module, "__version__", None),
        "source_sha256": _file_sha256(origin),
        "config": _jsonable_policy_value(getattr(module, "config", None)),
        "grammar": _jsonable_policy_value(getattr(module, "grammar", None)),
    }


def _effective_scan_policy(config: WardlineConfig) -> dict[str, Any]:
    return {
        "schema": "wardline-effective-scan-policy-v1",
        "wardline_version": __version__,
        "source_roots": list(config.source_roots),
        "exclude": list(config.exclude),
        "rules": {
            "enable": sorted(config.rules_enable),
            "severity": {str(k): str(v) for k, v in sorted(config.rules_severity.items())},
        },
        "provenance_clash": config.provenance_clash,
        "untrusted_sources": sorted(config.untrusted_sources),
        "sanitisers": sorted(config.sanitisers),
        "packs": [_pack_policy_identity(name, config.pack_modules.get(name)) for name in config.packs],
    }


def ruleset_hash(config: WardlineConfig) -> str:
    """A deterministic ``"sha256:<hex>"`` over the effective scan policy.

    The signed identity covers the analyzer version, source scope, excludes, rule
    enablement/severity, provenance policy, custom source/sanitiser trust semantics,
    and trusted pack identity/config/grammar. Two attestations with the same hash are
    therefore comparable evidence bundles under the policy inputs that materially shape
    scan results.
    """
    canonical = json.dumps(_effective_scan_policy(config), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """THE canonical serialization used for payload reproducibility.

    Compact, key-sorted UTF-8 JSON. The signer wraps the payload with the outer schema
    before calling this function so the schema tag is bound too.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(payload: dict[str, Any], key: str, *, schema: str = ATTEST_SCHEMA) -> dict[str, str]:
    """HMAC-SHA256 the canonical envelope bytes under the shared ``key``.

    Returns ``{"alg", "value", "key_id"}``. ``key_id`` is a non-secret 8-hex short id
    (see :func:`wardline.core.attest_key.key_id`) that lets bundles signed with different
    keys be told apart without revealing the key. See the module threat model: this is
    shared-secret tamper-evidence, not asymmetric proof.
    """
    signed_material = {"schema": schema, "payload": payload}
    value = hmac.new(key.encode(), _canonical_bytes(signed_material), hashlib.sha256).hexdigest()
    return {"alg": "HMAC-SHA256", "value": value, "key_id": key_id(key)}


def _enrich_seis(boundaries: list[dict[str, Any]], loomweave_client: Any) -> str:
    """Fill each boundary's ``sei`` from Loomweave, fail-soft per boundary.

    Returns the ``sei_source``: ``"loomweave"`` if a client was supplied AND at least one
    SEI resolved, else ``"unavailable"``. The Loomweave seam is an optional extra, so it is
    imported LAZILY here (the module base stays zero-dependency). Any failure leaves
    ``sei=None`` and never crashes attestation: an outer ``try`` degrades the WHOLE
    enrichment (a capabilities / resolver-construction outage → ``"unavailable"``), and a
    per-qualname ``try`` keeps one unresolvable boundary from aborting the rest.
    """
    if loomweave_client is None:
        return "unavailable"

    try:
        from wardline.loomweave.dossier_sources import resolve_entity_binding
        from wardline.loomweave.identity import SeiCapability, SeiResolver

        capabilities = loomweave_client.capabilities()
        resolver = SeiResolver(loomweave_client, SeiCapability.from_capabilities(capabilities))

        resolved_any = False
        for boundary in boundaries:
            try:
                binding = resolve_entity_binding(loomweave_client, resolver, boundary["qualname"])
            except Exception:  # noqa: BLE001 — per-boundary fail-soft, see docstring
                continue
            if binding is not None and binding.sei:
                boundary["sei"] = binding.sei
                resolved_any = True
    except Exception:  # noqa: BLE001 — whole-enrichment fail-soft, see docstring
        return "unavailable"

    return "loomweave" if resolved_any else "unavailable"


def _build_payload(
    root: Path,
    *,
    config_path: Path | None,
    cache_dir: Path | None = None,
    confine_to_root: bool = True,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
    today: date,
    loomweave_client: Any = None,
) -> dict[str, Any]:
    """Derive the (unsigned) attestation payload from the tree at ``root``.

    The PURE derivation shared by :func:`build_attestation` and
    :func:`verify_attestation` so a re-derivation is apples-to-apples. It runs
    ``run_scan`` exactly ONCE and applies NO policy (the dirty-tree refusal lives in
    :func:`build_attestation`, never here — verify must not raise on a dirty tree).
    """
    cfg_path = config_path or (root / "wardline.yaml")
    config = config_mod.load(
        cfg_path,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    waivers = parse_waivers(config.waivers)

    result = run_scan(
        root,
        config_path=config_path,
        cache_dir=cache_dir,
        confine_to_root=confine_to_root,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
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
                    "sei": None,  # filled by _enrich_seis below behind a lazy Loomweave import
                    "verdict": verdict.verdict,
                    "tier": verdict.declared_tier,
                }
            )
        sei_source = _enrich_seis(boundaries, loomweave_client)

    return {
        "wardline_version": __version__,
        "attested_at": today.isoformat(),
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
    cache_dir: Path | None = None,
    confine_to_root: bool = True,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
    loomweave_client: Any = None,
    allow_dirty: bool = True,
    today: date | None = None,
) -> dict[str, Any]:
    """Build a signed evidence bundle for the tree at ``root``.

    Runs the scan ONCE (via :func:`_build_payload`), then HMAC-signs the canonical
    payload bytes under the shared ``key``. With ``allow_dirty=False`` a working tree
    with uncommitted changes is refused (:class:`AttestError`) so a bundle's ``commit``
    truthfully pins its source.

    With a ``loomweave_client``, each boundary's ``sei`` is resolved from Loomweave (opt-in,
    fail-soft, behind a lazy import — see :func:`_enrich_seis`) and ``sei_source`` becomes
    ``"loomweave"`` if any SEI resolved; without one every ``sei`` stays None and
    ``sei_source`` is ``"unavailable"``. See the module threat model: the signature is
    shared-secret tamper-evidence, not asymmetric proof.
    """
    if today is None:
        today = date.today()

    payload = _build_payload(
        root,
        config_path=config_path,
        cache_dir=cache_dir,
        confine_to_root=confine_to_root,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
        today=today,
        loomweave_client=loomweave_client,
    )
    if payload["dirty"] and not allow_dirty:
        raise AttestError("refusing to attest a dirty working tree (uncommitted changes); pass allow_dirty to override")

    signature = _sign(payload, key, schema=ATTEST_SCHEMA)
    return {"schema": ATTEST_SCHEMA, "payload": payload, "signature": signature}


def verify_attestation(
    bundle: dict[str, Any],
    key: str,
    *,
    root: Path | None = None,
    reproduce: bool = False,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    loomweave_client: Any = None,
    confine_to_root: bool = True,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
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

    The re-derivation uses the bundle's own recorded ``attested_at`` as ``today`` (so a
    tree with active waiver-debt reproduces on a later day — the bundle states its own
    date) and the supplied ``config_path`` (so a bundle built with a custom ``--config``
    re-derives under that same config rather than silently defaulting to ``None``).

    Since SEI values are part of the signed payload, reproducing a SEI-keyed bundle
    requires the SAME ``loomweave_client`` used to build it: pass it here so the
    re-derivation resolves SEIs identically. Without it, a SEI-keyed bundle re-derives
    with ``sei=None`` and honestly reports ``reproduced=False`` (the binding cannot be
    reproduced), while ``signature_valid`` is unaffected (it is over the recorded bytes).
    """
    if not isinstance(bundle, dict):
        raise AttestError("attestation bundle must be a JSON object")
    schema = bundle.get("schema")
    recorded_payload_raw = bundle["payload"]
    if not isinstance(recorded_payload_raw, dict):
        raise AttestError("attestation payload must be a JSON object")
    recorded_payload: dict[str, Any] = recorded_payload_raw
    expected = _sign(recorded_payload, key, schema=schema if isinstance(schema, str) else "")["value"]
    signature = bundle.get("signature") or {}
    signature_valid = (
        isinstance(signature, dict)
        and schema == ATTEST_SCHEMA
        and signature.get("alg") == "HMAC-SHA256"
        and signature.get("key_id") == key_id(key)
        and hmac.compare_digest(expected, str(signature.get("value") or ""))
    )

    note = "reproducibility holds against the RECORDED commit; a mismatch may mean the tree moved, not tamper."

    if not reproduce or root is None:
        return {
            "signature_valid": signature_valid,
            "reproduced": None,
            "mismatches": [],
            "note": note,
        }

    today = date.fromisoformat(recorded_payload["attested_at"]) if recorded_payload.get("attested_at") else date.today()
    rederived = _build_payload(
        root,
        config_path=config_path,
        cache_dir=cache_dir,
        confine_to_root=confine_to_root,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
        today=today,
        loomweave_client=loomweave_client,
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
