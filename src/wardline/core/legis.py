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
from wardline.core.attest import git_state
from wardline.core.errors import LegisArtifactError
from wardline.core.finding import FINGERPRINT_SCHEME, Finding, SuppressionState
from wardline.core.ruleset import ruleset_hash
from wardline.core.safe_paths import safe_project_file
from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig
    from wardline.core.run import ScanResult

LEGIS_ARTIFACT_KEY_ENV = "WARDLINE_LEGIS_ARTIFACT_KEY"
SIG_PREFIX = "hmac-sha256:v2:"
ARTIFACT_SIGNATURE_FIELD = "artifact_signature"

# Cross-member scan-artifact keys that legis reads with a DEFAULT, not a hard
# requirement (``findings`` -> empty list, ``dirty`` -> false). A silent rename of one
# of these routes zero defects into legis under a green ``verified`` status — the
# consumer never errors, it just governs an empty scan (weft foundation seam S8 / G1;
# the ``dirty``-key analog is the hub's dirty-freeze issue). The fail-open is legis's to
# close, but the trigger — a producer key drifting — is ours to prevent: the full
# emitted key-set is frozen by tests/conformance/test_legis_artifact_contract_freeze.py.
# Change a value here ONLY in lockstep with the legis hub. ``fingerprint_scheme`` is an
# ignored-unknown envelope field today, frozen alongside so it cannot silently become a
# drifted required key tomorrow.
FINDINGS_FIELD = "findings"
DIRTY_FIELD = "dirty"
FINGERPRINT_SCHEME_FIELD = "fingerprint_scheme"
SCAN_SCOPE_FIELD = "scan_scope"
SCAN_SCOPE_SCHEMA = "wardline-legis-scan-scope-1"

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
        "suppression_state": suppressed,
    }


_SAFE_GIT_CONFIG = ("-c", "core.fsmonitor=false")


def _git_tree_sha(root: Path) -> str | None:
    """The committed tree object SHA (``git rev-parse HEAD^{tree}``), or None.

    Read-only; never raises. Paired with :func:`git_state`'s ``dirty`` flag so a
    dirty tree's committed ``tree_sha`` is never signed as if it described the
    scanned content.
    """
    try:
        rev = subprocess.run(
            ["git", *_SAFE_GIT_CONFIG, "rev-parse", "HEAD^{tree}"],
            cwd=root,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if rev.returncode != 0:
        return None
    return rev.stdout.strip() or None


def _git_repo_root(root: Path) -> Path | None:
    """The containing git repository root, or None when unavailable."""
    try:
        rev = subprocess.run(
            ["git", *_SAFE_GIT_CONFIG, "rev-parse", "--show-toplevel"],
            cwd=root,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if rev.returncode != 0:
        return None
    value = rev.stdout.strip()
    if not value:
        return None
    try:
        return Path(value).resolve()
    except OSError:
        return None


def _relative_posix(path: Path, base: Path) -> str:
    """Return *path* relative to *base* in stable POSIX form, allowing ``..``."""
    try:
        rel = path.relative_to(base)
    except ValueError:
        rel = Path(os.path.relpath(path, base))
    return rel.as_posix() if rel.parts else "."


def _scan_scope(result: ScanResult, *, root: Path, config: WardlineConfig) -> dict[str, Any]:
    """Signed description of the exact scan scope carried by the artifact."""
    resolved_root = root.resolve()
    repo_root = _git_repo_root(root)
    scope_base = repo_root if repo_root is not None else resolved_root
    resolved_source_roots = [
        _relative_posix((resolved_root / source_root).resolve(), scope_base) for source_root in config.source_roots
    ]
    return {
        "schema": SCAN_SCOPE_SCHEMA,
        "scan_root": _relative_posix(resolved_root, scope_base),
        "is_git_root": repo_root is not None and resolved_root == repo_root,
        "source_roots": list(config.source_roots),
        "resolved_source_roots": resolved_source_roots,
        "scanned_paths": list(result.scanned_paths),
    }


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
    accepted vocabulary. Under the secure default that is the tagged unsuppressed
    population: a committed baseline/waiver/judged annotates the emitted ``findings``
    but does NOT clear the gate, so a defect a malicious PR self-suppresses still rides
    as ``active`` and legis enforces it — the one-judge property. Under
    ``--trust-suppressions`` the tagged population honours repository suppressions,
    exactly as the gate does.

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

    Two refusals guard the wire's honesty regardless of ``key``/``allow_dirty``:
    an ``--affected`` delta scan (``result.scope`` advisory) is refused outright — the
    frozen legis wire cannot mark partial scope, so the artifact would over-claim
    coverage (:class:`LegisArtifactError`); and an INDETERMINATE working tree
    (``git status`` failed → ``dirty is None``) is never treated as clean — with a key
    it is refused unless ``allow_dirty`` routes to the unsigned dev artifact, marked
    ``dirty: true``.
    """
    # An ``--affected`` delta scan analyzes only the affected subset while
    # ``scanned_paths`` (and thus ``scan_scope``) records the FULL discovery, and the
    # contract-frozen legis wire carries no scope-mode/advisory field to say so. Emitting
    # would hand legis a partial finding population cryptographically indistinguishable
    # from a full-repository scan of the same commit — a (potentially signed) false green
    # under an attacker-influenceable worklist (INV-4 / THREAT-001). Refuse loudly,
    # mirroring the ``--affected`` cannot-drive ``--fail-on`` rejection: a delta scan is
    # advisory and cannot back the legis hop. ``full-fallback`` IS the gate of record (the
    # whole tree was analyzed), so it passes; any future non-gate-of-record mode fails
    # closed here rather than over-claiming scope on the wire.
    if result.scope is not None and result.scope.gate_authority != "gate-of-record":
        raise LegisArtifactError(
            "refusing to build a legis artifact for an --affected delta scan: only the affected "
            "subset was analyzed, but the artifact would claim the full discovered scope with no "
            "advisory marker on the frozen legis wire; run a full scan for the legis hop"
        )

    # Consume the same mandatory tagged population as gate_decision. It is always the
    # unfiltered analyzed population — never the delta display set (INV-4 / THREAT-001).
    gate_population = result.gate_population.findings
    findings = [project_finding(f) for f in gate_population]
    scan: dict[str, Any] = {
        "scanner_identity": f"wardline@{__version__}",
        "rule_set_version": ruleset_hash(config),
        # Envelope scheme signal (legis ignores unknown top-level fields; it is part
        # of the signed body so the artifact_signature covers it). Per-finding
        # fingerprints stay BARE — legis reads them from to_jsonl (SARIF-style value).
        FINGERPRINT_SCHEME_FIELD: FINGERPRINT_SCHEME,
        FINDINGS_FIELD: findings,
        # Bind the artifact to the requested and realized scope. This prevents a
        # signed subdirectory or narrowed-source-root scan from being indistinguishable
        # from a full-repository scan carrying the same commit/tree provenance.
        SCAN_SCOPE_FIELD: _scan_scope(result, root=root, config=config),
    }
    commit, dirty = git_state(root)
    repo_root = _git_repo_root(root)

    # Signing is CLEAN-TREE-ONLY, and "clean" must be POSITIVELY ESTABLISHED. ``dirty``
    # is a tri-state (:func:`git_state`): ``dirty is None`` means git could not enumerate
    # the working tree (corrupted index, .git permission failure), so cleanliness is
    # indeterminate — signing the committed ``tree_sha`` for content git could not even
    # read would be false provenance, exactly like the dirty case, so it fails CLOSED
    # (refused with a key, or falls through to the unsigned dev artifact under
    # ``allow_dirty``, marked ``dirty: true`` because we cannot vouch otherwise).
    # A key + clean tree produces the signed, verified artifact. A key + dirty tree is
    # refused loudly UNLESS ``allow_dirty`` — and even then we do NOT sign: the only
    # ``tree_sha`` we can read is the *committed* tree, which does not describe dirty
    # working content, so signing it would be false provenance (see
    # :func:`_git_tree_sha`). Instead ``allow_dirty`` falls through to the unsigned dev
    # artifact below, clearly marked ``dirty: true`` (legis records it ``unverified``).
    # This lets the dev/tour loop exercise the full Wardline→legis handshake without a
    # commit, while keeping signature *verification* clean-tree-only.
    if key is not None and dirty is None and not allow_dirty:
        raise LegisArtifactError(
            "cannot sign legis artifact: working-tree cleanliness is indeterminate "
            "(`git status` failed); repair the repository, or pass allow_dirty for an "
            "unsigned dev artifact"
        )
    if key is not None and dirty is False:
        if commit is None:
            raise LegisArtifactError(
                "cannot sign legis artifact: not a git repository, so commit/tree provenance is unavailable"
            )
        if repo_root is None or root.resolve() != repo_root:
            raise LegisArtifactError(
                "cannot sign legis artifact: scan root is not the git repository root; "
                "scan the repository root so commit/tree provenance and scan scope match"
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

    # Unsigned (no key, or key + allow_dirty on a dirty/indeterminate tree): supply
    # whatever provenance we can honestly read; legis marks it unverified. Never
    # fabricate a tree_sha — omit it if unreadable. A dirty tree is flagged so neither
    # the agent nor a human mistakes the committed provenance for the scanned working
    # content; an INDETERMINATE tree (``dirty is None`` — commit resolved but ``git
    # status`` failed) is flagged the same way, because we cannot vouch that the
    # committed provenance describes the scanned content. A non-repo tree is
    # ``(None, False)`` and carries no marker.
    if commit is not None:
        scan["commit_sha"] = commit
        tree = _git_tree_sha(root)
        if tree is not None:
            scan["tree_sha"] = tree
    if dirty or dirty is None:
        scan[DIRTY_FIELD] = True
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
    dirty = bool(artifact.get(DIRTY_FIELD))
    signed = ARTIFACT_SIGNATURE_FIELD in artifact
    return LegisArtifactOutcome(
        signed=signed,
        dirty=dirty,
        unverified_reason=_DIRTY_UNVERIFIED_REASON if dirty else None,
    )
