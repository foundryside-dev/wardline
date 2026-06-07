# src/wardline/core/legis.py
"""B4 — the signed Wardline→legis scan-artifact (the cross-repo authenticated hop).

An agent posts a Wardline scan to legis (the Weft governance plugin) at
``POST /wardline/scan-results``; legis governs it and NEVER re-analyses. legis is a
FIXED external contract: when its deployment sets ``LEGIS_WARDLINE_ARTIFACT_KEY`` it
*requires* a valid ``artifact_signature`` plus signed provenance and rejects unsigned
or non-conformant bodies. This module produces the artifact legis accepts.

Two things have to be exact for the hop to hold in production:

* **Byte-for-byte signing.** HMAC-SHA256 over ``canonical_json(scan-minus-signature)``
  with the ``hmac-sha256:v2:`` prefix — a faithful replica of
  ``legis/src/legis/{canonical,enforcement/signing}.py``. Pinned by a golden vector
  captured from the real legis signer.
* **A conformant projection.** legis's ingest validator
  (``legis/src/legis/wardline/ingest.py``) is strict where the rich Wardline finding
  wire is loose: every ``properties`` value must be a trust tier (Wardline also stores
  analysis diagnostics there), a non-active defect must carry its suppression proof IN
  ``properties`` (Wardline carries it at the top level), and the only suppressed states
  legis knows are ``waived``/``suppressed`` (Wardline also emits ``baselined``/
  ``judged``). So the legis wire is a *typed projection* of the whole scan onto
  legis's accepted vocabulary — the trust grammar carried verbatim, the diagnostics
  dropped. The rich MCP/SARIF/Loomweave finding wire is unchanged.

Wardline never calls legis (it has no HTTP client to it); it produces the signed scan
and the agent posts it. ``build_legis_artifact`` returns the single, verbatim-postable
``scan`` object — sign it last, over the otherwise-complete scan, and post exactly
those bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline._version import __version__
from wardline.core.attest import git_state, ruleset_hash
from wardline.core.errors import LegisArtifactError
from wardline.core.finding import Finding, SuppressionState
from wardline.core.safe_paths import safe_project_file
from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig
    from wardline.core.run import ScanResult

LEGIS_ARTIFACT_KEY_ENV = "WARDLINE_LEGIS_ARTIFACT_KEY"
SIG_PREFIX = "hmac-sha256:v2:"
ARTIFACT_SIGNATURE_FIELD = "artifact_signature"

# The one shared vocabulary — legis carries these 8 tiers verbatim (TRUST_TIERS in
# legis ingest.py). Sourced from the lattice so the two can never drift.
TRUST_TIERS: frozenset[str] = frozenset(t.value for t in TaintState)

# legis records a non-active defect's proof from one of these property keys. Wardline
# stores it top-level as ``suppression_reason``; the projection injects it here.
SUPPRESSION_PROOF_KEY = "suppression_reason"

# legis's ingest only accepts ``active``/``waived``/``suppressed`` for a defect and
# raises on anything else. Wardline's richer states map onto that set; ``baselined``
# and ``judged`` are both non-active suppressions, so both ride legis's generic
# ``suppressed`` bucket (each still carries a proof). Active stays active, so legis's
# independently-derived gate population still equals Wardline's.
_SUPPRESSED_STATE_MAP: dict[SuppressionState, str] = {
    SuppressionState.ACTIVE: "active",
    SuppressionState.WAIVED: "waived",
    SuppressionState.BASELINED: "suppressed",
    SuppressionState.JUDGED: "suppressed",
}

# Non-empty proof for a non-active defect that arrived without a ``suppression_reason``
# (legis 422s on an empty proof). A baseline match / judge verdict is itself the proof.
_DEFAULT_PROOF: dict[SuppressionState, str] = {
    SuppressionState.BASELINED: "baselined: matched a baseline fingerprint",
    SuppressionState.JUDGED: "judged: triage classified this a false positive",
    SuppressionState.WAIVED: "waived",
}


def canonical_json(value: Any) -> str:
    """Sorted-key, tight-separator, non-ASCII-preserving, NaN-rejecting JSON.

    A faithful replica of ``legis/src/legis/canonical.py``. The signature is taken
    over these exact bytes, so any divergence here breaks the hop.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sign_artifact(fields: dict[str, Any], key: bytes) -> str:
    """``hmac-sha256:v2:<hexdigest>`` over ``canonical_json(fields-minus-signature)``.

    Matches legis ``enforcement.signing.sign``. Any existing ``artifact_signature``
    is stripped before signing (legis verifies over the same minus-signature view),
    so signing is stable whether or not a stale signature is present.
    """
    signed = {k: v for k, v in fields.items() if k != ARTIFACT_SIGNATURE_FIELD}
    mac = hmac.new(key, canonical_json(signed).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{SIG_PREFIX}{mac}"


def key_id(key: str) -> str:
    """A non-secret short id (first 8 hex of ``sha256(key)``) for rotation logs.

    Mirrors :func:`wardline.core.attest_key.key_id` — lets two deployments confirm
    they hold the same shared secret without revealing it.
    """
    return hashlib.sha256(key.encode()).hexdigest()[:8]


def load_legis_artifact_key(root: Path) -> str | None:
    """Return the shared HMAC secret from the environment, or a
    ``WARDLINE_LEGIS_ARTIFACT_KEY=<value>`` line in ``root/.env``, or None.

    An already-set environment value always wins. Mirrors
    :func:`wardline.core.attest_key.load_attest_key`. The secret must equal whatever
    legis reads from ``LEGIS_WARDLINE_ARTIFACT_KEY`` for the signature to verify.
    """
    value = os.environ.get(LEGIS_ARTIFACT_KEY_ENV)
    if value:
        return value
    env_path = safe_project_file(root, root / ".env", label=".env")
    if not env_path.is_file():
        return None
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{LEGIS_ARTIFACT_KEY_ENV}="):
            parsed = line.split("=", 1)[1].strip().strip('"').strip("'")
            return parsed or None
    return None


def _tier_properties(properties: dict[str, Any]) -> dict[str, str]:
    """Keep only trust-grammar properties — entries whose VALUE is one of the 8
    tiers. Diagnostics (``sink``/``callee``/``markers``/``reason``/...) are dropped.

    Self-maintaining: any future tier-valued property flows through; any new
    diagnostic does not — so a rule cannot silently emit a legis-rejected value.
    """
    return {k: v for k, v in properties.items() if isinstance(v, str) and v in TRUST_TIERS}


def project_finding(finding: Finding) -> dict[str, Any]:
    """Project one Wardline finding onto legis's exact read surface.

    The wire shape is the canonical ``Finding.to_jsonl`` projection restricted to the
    fields legis reads, with ``properties`` filtered to trust tiers, the suppressed
    state mapped onto legis's vocabulary, and a non-active defect's proof injected
    into ``properties`` (legis requires it there, non-empty).
    """
    wire = json.loads(finding.to_jsonl())
    properties = _tier_properties(wire.get("properties", {}))
    suppressed = _SUPPRESSED_STATE_MAP[finding.suppressed]
    if suppressed != "active":
        reason = (finding.suppression_reason or "").strip()
        properties[SUPPRESSION_PROOF_KEY] = reason or _DEFAULT_PROOF[finding.suppressed]
    return {
        "rule_id": wire["rule_id"],
        "message": wire["message"],
        "severity": wire["severity"],
        "kind": wire["kind"],
        "fingerprint": wire["fingerprint"],
        "qualname": wire["qualname"],
        "properties": properties,
        "suppressed": suppressed,
    }


def _git_tree_sha(root: Path) -> str | None:
    """The committed tree object SHA (``git rev-parse HEAD^{tree}``), or None.

    Read-only; never raises. Paired with :func:`git_state`'s ``dirty`` flag so a
    dirty tree's committed ``tree_sha`` is never signed as if it described the
    scanned content.
    """
    try:
        rev = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=root,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if rev.returncode != 0:
        return None
    return rev.stdout.strip() or None


def build_legis_artifact(
    result: ScanResult,
    *,
    root: Path,
    config: WardlineConfig,
    key: bytes | None = None,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    """Build the verbatim-postable ``scan`` object for ``POST /wardline/scan-results``.

    The findings are the GATE population — the SAME population Wardline's own
    ``--fail-on`` gate evaluates (``gate_decision``), each projected onto legis's
    accepted vocabulary. Under the secure default that is ``result.gate_findings``
    (the unsuppressed population: a committed baseline/waiver/judged annotates the
    emitted ``findings`` but does NOT clear the gate), so a defect a malicious PR
    self-suppresses still rides as ``active`` and legis enforces it — the one-judge
    property. Under ``--trust-suppressions`` ``gate_findings`` is None and the
    artifact honours the repo suppressions (``result.findings``), exactly as the
    gate does. Both populations are ``apply_suppressions`` over the same raw list, so
    ``len(gate_findings) == len(findings)`` and the ``finding_count`` legis records
    over the whole list (``service/wardline.py``) stays honest.

    legis routes only the active defects but records ``finding_count`` over the whole
    list; the projection makes facts and diagnostics ingest cleanly (non-tier
    properties filtered, non-defect kinds simply not routed). Wardline does NOT cap
    the list — legis enforces its own 500-finding limit and a larger scan is rejected
    loudly rather than silently truncated.

    When ``key`` is given AND the tree is clean the scan is signed and MUST carry
    honest provenance (``scanner_identity``, ``rule_set_version``, ``commit_sha``,
    ``tree_sha``); signing a non-repo is refused (:class:`LegisArtifactError`). Signing
    is clean-tree-only: a dirty tree with a key is refused (:class:`LegisArtifactError`)
    UNLESS ``allow_dirty=True``, which does NOT sign — it emits the unsigned dev
    artifact instead (a ``tree_sha`` that does not match dirty working content is false
    provenance). When ``key`` is None — or a dirty tree under ``allow_dirty`` — the scan
    is emitted unsigned with best-effort provenance and a ``dirty: true`` marker on a
    dirty tree; legis records it as ``unverified`` (the trust-the-agent posture before a
    key is set, and the dev/tour loop without a commit).

    Sign last, over the otherwise-complete scan: ``artifact_signature`` is added after
    the rest is in place, exactly as legis verifies (scan-minus-signature).
    """
    # Mirror gate_decision's exact fallback so the artifact tracks the operator's
    # posture: secure-default -> gate_findings (baselined/judged/waived ride as
    # active -> legis enforces them, the one-judge property); --trust-suppressions
    # -> gate_findings is None -> honour the repo suppressions in ``findings``.
    gate_population = result.gate_findings if result.gate_findings is not None else result.findings
    findings = [project_finding(f) for f in gate_population]
    scan: dict[str, Any] = {
        "scanner_identity": f"wardline@{__version__}",
        "rule_set_version": ruleset_hash(config),
        "findings": findings,
    }
    commit, dirty = git_state(root)

    # Signing is CLEAN-TREE-ONLY. A key + clean tree produces the signed, verified
    # artifact. A key + dirty tree is refused loudly UNLESS ``allow_dirty`` — and even
    # then we do NOT sign: the only ``tree_sha`` we can read is the *committed* tree,
    # which does not describe dirty working content, so signing it would be false
    # provenance (see :func:`_git_tree_sha`). Instead ``allow_dirty`` falls through to
    # the unsigned dev artifact below, clearly marked ``dirty: true`` (legis records it
    # ``unverified``). This lets the dev/tour loop exercise the full Wardline→legis
    # handshake without a commit, while keeping signature *verification* clean-tree-only.
    if key is not None and not dirty:
        if commit is None:
            raise LegisArtifactError(
                "cannot sign legis artifact: not a git repository, so commit/tree provenance is unavailable"
            )
        tree = _git_tree_sha(root)
        if tree is None:
            raise LegisArtifactError("cannot sign legis artifact: tree SHA unavailable")
        scan["commit_sha"] = commit
        scan["tree_sha"] = tree
        scan[ARTIFACT_SIGNATURE_FIELD] = sign_artifact(scan, key)
        return scan
    if key is not None and dirty and not allow_dirty:
        raise LegisArtifactError(
            "refusing to sign a legis artifact for a dirty working tree "
            "(uncommitted changes); commit first or pass allow_dirty for an unsigned dev artifact"
        )

    # Unsigned (no key, or key + allow_dirty on a dirty tree): supply whatever
    # provenance we can honestly read; legis marks it unverified. Never fabricate a
    # tree_sha — omit it if unreadable. A dirty tree is flagged so neither the agent
    # nor a human mistakes the committed provenance for the scanned working content.
    if commit is not None:
        scan["commit_sha"] = commit
        tree = _git_tree_sha(root)
        if tree is not None:
            scan["tree_sha"] = tree
    if dirty:
        scan["dirty"] = True
    return scan


@dataclass(frozen=True, slots=True)
class LegisArtifactOutcome:
    """The signed/dirty status of a built artifact, read from what the producer
    actually emitted. ``signed`` ⟺ the artifact carries a signature field (so it can
    never disagree with the producer); ``dirty`` ⟺ the ``dirty`` marker is set;
    ``unverified_reason`` is the agent-facing note for the unsigned dev-artifact case."""

    signed: bool
    dirty: bool
    unverified_reason: str | None


_DIRTY_UNVERIFIED_REASON = (
    "dirty working tree — emitted an UNSIGNED legis dev artifact (legis records it "
    "unverified); never gate CI on it. Commit for a signed artifact."
)


def legis_artifact_outcome(artifact: Mapping[str, Any]) -> LegisArtifactOutcome:
    """Single authority for an artifact's signed/dirty status, shared by the CLI and
    MCP surfaces so neither re-derives it from raw keys (which could drift from the
    producer). ``signed`` is read from the presence of the signature field — the
    authoritative record of what :func:`build_legis_artifact` did — not re-computed
    from key presence."""
    dirty = bool(artifact.get("dirty"))
    signed = ARTIFACT_SIGNATURE_FIELD in artifact
    return LegisArtifactOutcome(
        signed=signed,
        dirty=dirty,
        unverified_reason=_DIRTY_UNVERIFIED_REASON if dirty else None,
    )
