"""`wardline rekey` — one-shot scan-driven fingerprint migration (P4).

Carries baseline/judged/waiver verdicts (+ best-effort Filigree) across the
wlfp1->wlfp2 value-rekey. From a SINGLE scan it computes, per finding, both the OLD
fingerprint (the frozen wlfp1 formula, ``line_start`` IN + the old ``taint_path``
surfaced as ``Finding.taint_path_v0``) and the NEW fingerprint (the live wlfp2
engine output, ``finding.fingerprint``). The resulting ``old_fp -> new_fp`` remap is
what re-keys the stores.

This module is the migration brain; the CLI (`cli/rekey.py`) is a thin shell over
it. It never touches the production hash, the analyzer, or the rules.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wardline.core import paths
from wardline.core.baseline import BASELINE_VERSION
from wardline.core.errors import ConfigError, FiligreeEmitError, WardlineError
from wardline.core.finding import FINGERPRINT_SCHEME, Finding, Kind
from wardline.core.fingerprint_v0 import compute_finding_fingerprint_v0
from wardline.core.judged import JUDGED_VERSION
from wardline.core.optional_deps import require_yaml
from wardline.core.safe_paths import read_bytes_no_follow, safe_project_file, write_text_no_follow
from wardline.core.waivers import WAIVERS_VERSION

SNAPSHOT_DIR_NAME = ".rekey_snapshot"
# Why a verdict can orphan (NOT only a source move) — the one explanation both
# surfaces (CLI rekey output, MCP rekey payload) attach to every dropped verdict.
ORPHAN_CAUSE = "source moved/deleted, or a custom multi-emit rule not surfacing taint_path_v0"
# Why a CURRENT-scheme entry can fail to match (NOT a migration orphan): the store is
# already at the live scheme, so a rekey would not touch it — a non-matching entry is
# baseline drift (the source changed since it was recorded), surfaced separately so a
# healthy-but-drifted store is never misread as a dead one (A7, weft-dda1a6d8dd).
STALE_CAUSE = "already at the current scheme but matches no current finding — baseline drift, not a rekey orphan"
# Bounded-by-default display: surfaces emit COUNTS plus at most this many example
# fingerprints with an explicit remainder marker (a bounded page never reads as the
# full set — agent_summary's convention). The full orphan list still lands verbatim
# in the migration journal on apply; the probe is advisory.
ORPHAN_SAMPLE_LIMIT = 10
# (store filename, list-key inside the YAML doc, version constant) — the three YAML
# legs, in gate-criticality order (baseline first restores the local --fail-on gate).
_STORES: tuple[tuple[str, str, int], ...] = (
    ("baseline.yaml", "entries", BASELINE_VERSION),
    ("judged.yaml", "findings", JUDGED_VERSION),
    ("waivers.yaml", "waivers", WAIVERS_VERSION),
)

# Mirror of scanner.rules._POLICY_CONFIG_RULE_ID (core must not import scanner — layering).
# A drift test (test_rekey_population.py) asserts the two stay equal. POLICY-CONFIG is the
# ONE engine rule whose fingerprint is compute_finding_fingerprint-based (line_start-sensitive
# under wlfp1), so it is v0-reconstructed, NOT identity-mapped, unlike the other engine
# diagnostics. Verified mechanically: no other WLN-ENGINE-*/WLN-L3-* DEFECT uses
# compute_finding_fingerprint (they use diagnostics._fingerprint, which is scheme-independent).
_POLICY_CONFIG_RULE_ID = "WLN-ENGINE-POLICY-CONFIG"


def is_join_population(f: Finding) -> bool:
    """The findings the stores can key on. ``collect_and_write_baseline`` stores EVERY
    ``Kind.DEFECT`` (no rule_id filter), and waivers/judged are bare-fingerprint-keyed,
    so the remap MUST cover every DEFECT — not just ``PY-WL-*`` — or a stored engine
    DEFECT (e.g. ``WLN-ENGINE-POLICY-CONFIG``, ``WLN-L3-MONOTONICITY-VIOLATION``, both
    gating ERROR DEFECTs at ENGINE_PATH) silently orphans on migration and resurfaces
    ACTIVE (the P4-review gate regression).

    ``RS-WL-*`` (Rust) is INCLUDED — P5-REVISIT decided 2026-06-10 (identity keystone):
    Rust identity graduated to baseline-eligible, so an RS-WL DEFECT enters the stores
    like any other and a stored RS-WL verdict must migrate, not orphan. (The former
    hard exclusion was a no-op pre-merge but a live orphaning path post-graduation.)"""
    return f.kind is Kind.DEFECT


def _is_scheme_independent(rule_id: str) -> bool:
    """True iff the finding's fingerprint did NOT change across the wlfp1->wlfp2 rekey,
    i.e. it was hashed by the engine's local ``diagnostics._fingerprint`` (which never
    folded ``line_start``), so its ``old_fp == new_fp``. That is the engine-diagnostic
    family (``WLN-ENGINE-*`` / ``WLN-L3-*``) EXCEPT ``WLN-ENGINE-POLICY-CONFIG``, which —
    alone among engine rules — is hashed via ``compute_finding_fingerprint`` and so is
    v0-reconstructed like the policy rules."""
    if rule_id == _POLICY_CONFIG_RULE_ID:
        return False
    return rule_id.startswith("WLN-ENGINE-") or rule_id.startswith("WLN-L3-")


def _old_fingerprint(f: Finding) -> str:
    """The finding's pre-rekey (wlfp1) fingerprint. Scheme-independent engine
    diagnostics kept their fingerprint, so ``old_fp == new_fp``; everything else
    (``PY-WL-*``, ``WLN-ENGINE-POLICY-CONFIG``, and custom-grammar rules) was hashed via
    ``compute_finding_fingerprint`` with ``line_start`` IN, so it is reconstructed from
    ``finding.location.line_start`` (P3 preserved it as exactly the hashed line) +
    ``finding.taint_path_v0`` (the old taint_path, ``None`` where it was ``None``).

    LIMITATION: a CUSTOM-grammar *multi-emit* rule that set a non-empty ``taint_path``
    but did NOT surface ``taint_path_v0`` will reconstruct the wrong ``old_fp`` and its
    verdict will orphan. Built-in rules all set ``taint_path_v0`` at their non-None
    sites; custom multi-emit rules must do likewise to be move-stable across a rekey."""
    if _is_scheme_independent(f.rule_id):
        return f.fingerprint
    return compute_finding_fingerprint_v0(
        rule_id=f.rule_id,
        path=f.location.path,
        line_start=f.location.line_start,
        qualname=f.qualname,
        taint_path=f.taint_path_v0,
    )


@dataclass(frozen=True, slots=True)
class FingerprintRemap:
    """One finding's identity across the rekey. ``old_fp`` is what the pre-rekey
    stores recorded; ``new_fp`` is what the live engine now emits."""

    old_fp: str
    new_fp: str
    rule_id: str
    path: str
    qualname: str | None


def compute_old_new_fingerprints(findings: Iterable[Finding]) -> list[FingerprintRemap]:
    """The dual-fingerprint contract from one scan, over the join population (every
    DEFECT). ``old_fp`` is ``_old_fingerprint(f)`` (v0 reconstruction for
    scheme-sensitive rules, identity for scheme-independent engine diagnostics); ``new_fp``
    is the live ``finding.fingerprint``. The v0 reconstruction is validated NON-CIRCULARLY
    against the real pre-P3 corpus in ``tests/unit/core/test_rekey_dual_fp.py``.
    """
    remaps: list[FingerprintRemap] = []
    for f in findings:
        if not is_join_population(f):
            continue
        remaps.append(
            FingerprintRemap(
                old_fp=_old_fingerprint(f),
                new_fp=f.fingerprint,
                rule_id=f.rule_id,
                path=f.location.path,
                qualname=f.qualname,
            )
        )
    return remaps


# --- S3: injectivity — per-collision orphan-and-report (NOT a whole-run abort) ----


@dataclass(frozen=True, slots=True)
class RekeyCollision:
    """Two findings DISTINCT under wlfp1 (different ``old_fp``) that collapse to one
    ``new_fp`` under wlfp2. P2/P3 guarantee no two CURRENT findings share a ``new_fp``,
    so this can only mean a discriminator bug — it is reported LOUD (shares the
    WLN-ENGINE-FINGERPRINT-COLLISION invariant) and BOTH old_fps are orphaned (neither
    verdict is carried), but the rest of the migration proceeds. A whole-run abort
    would brick a real project permanently, so we never abort."""

    new_fp: str
    old_fps: tuple[str, ...]

    @property
    def message(self) -> str:
        return (
            f"WLN-ENGINE-FINGERPRINT-COLLISION: {len(self.old_fps)} pre-rekey fingerprints collapse to "
            f"{self.new_fp} under wlfp2 ({', '.join(self.old_fps)}); both verdicts orphaned, not carried."
        )


@dataclass(frozen=True, slots=True)
class RemapResult:
    """The old_fp -> new_fp lookup the carry legs consume, plus any collisions."""

    old_to_new: dict[str, str]
    collisions: tuple[RekeyCollision, ...]


def build_remap(remaps: Iterable[FingerprintRemap]) -> RemapResult:
    """Build the ``old_fp -> new_fp`` map. ``old_fp`` is a function of the finding's
    inputs (incl. line_start), so it never maps to two new_fps. The inverse CAN
    collide (wlfp2 dropped line_start): if >1 distinct old_fp shares a new_fp, ALL
    those old_fps are excluded from the map and recorded as a collision."""
    new_to_olds: dict[str, set[str]] = {}
    old_to_new: dict[str, str] = {}
    for r in remaps:
        new_to_olds.setdefault(r.new_fp, set()).add(r.old_fp)
        old_to_new[r.old_fp] = r.new_fp
    collisions = tuple(
        RekeyCollision(new_fp=nf, old_fps=tuple(sorted(olds)))
        for nf, olds in sorted(new_to_olds.items())
        if len(olds) > 1
    )
    for c in collisions:
        for of in c.old_fps:
            old_to_new.pop(of, None)
    return RemapResult(old_to_new=old_to_new, collisions=collisions)


# --- S4: pre-flight snapshot (the SOLE provenance source on resume) ---------------


def snapshot_dir(root: Path) -> Path:
    return paths.weft_state_dir(root) / SNAPSHOT_DIR_NAME


def snapshot_stores(root: Path) -> tuple[str, ...]:
    """Copy each EXISTING YAML store into ``.rekey_snapshot/`` byte-identical. The
    snapshot is the immutable provenance source the carry legs read — resume NEVER
    re-reads the (already-rewritten) live store. Idempotent: an existing snapshot is
    the pre-migration truth and is NEVER clobbered (a second invocation keeps it)."""
    sdir = snapshot_dir(root)
    state = paths.weft_state_dir(root)
    present: list[str] = []
    for name, _key, _ver in _STORES:
        live = state / name
        # Read the live store WITHOUT following a symlink: an untrusted checkout could
        # plant `.weft/wardline/<store>.yaml` as a symlink to a user-readable file outside
        # the repo, and a naive read would copy that target into the in-project snapshot
        # (arbitrary file disclosure). A symlinked/non-regular/missing store is simply not
        # snapshot-eligible.
        data = read_bytes_no_follow(live)
        if data is None:
            continue
        present.append(name)
        dest = safe_project_file(root, sdir / name, label=name)
        if dest.exists():
            continue  # never clobber the pre-migration snapshot
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return tuple(present)


# --- S5: carry verdicts from the SNAPSHOT, preserving ALL provenance --------------


@dataclass(frozen=True, slots=True)
class CarryResult:
    """A re-keyed store document plus the old_fps carried / orphaned producing it."""

    document: dict[str, Any]
    carried: tuple[str, ...]
    orphaned: tuple[str, ...]


def _read_old_store(path: Path) -> dict[str, Any]:
    """Read an OLD-scheme (wlfp1) store RAW — bypassing the scheme-enforcing loaders,
    which would (correctly) reject the pre-rekey snapshot. The migration is the one
    place that reads an old-scheme store on purpose."""
    if not path.is_file():
        return {}
    yaml = require_yaml("reading the rekey snapshot")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        raise ConfigError(f"malformed snapshot {path.name}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"snapshot {path.name} is not a mapping")
    return loaded


def _carry_store(snapshot_path: Path, list_key: str, version: int, old_to_new: dict[str, str]) -> CarryResult:
    """Remap one store: swap each entry's ``fingerprint`` old->new while byte-preserving
    every OTHER field (rationale/reason/expires/rule_id/path/message/...), drop entries
    whose old_fp is not in the remap (orphans), and re-stamp the wlfp2 scheme header.
    Deterministic order: (rule_id, path, new fingerprint)."""
    loaded = _read_old_store(snapshot_path)
    raw_entries = loaded.get(list_key) or []
    # A snapshot store ALREADY at the live scheme needs no remap: its fingerprints are
    # wlfp2 keys, and pushing them through the wlfp1->wlfp2 map would orphan every one
    # (the mixed-scheme leg of A7, weft-dda1a6d8dd). Identity-carry it untouched.
    already_current = loaded.get("fingerprint_scheme") == FINGERPRINT_SCHEME
    carried: list[str] = []
    orphaned: list[str] = []
    new_entries: list[dict[str, Any]] = []
    for entry in raw_entries:
        old_fp = entry.get("fingerprint") if isinstance(entry, dict) else None
        if not isinstance(old_fp, str):
            continue  # not a valid entry — nothing to carry or orphan
        new_fp = old_fp if already_current else old_to_new.get(old_fp)
        if new_fp is None:
            orphaned.append(old_fp)
            continue
        carried.append(old_fp)
        new_entries.append({**entry, "fingerprint": new_fp})  # byte-preserve all provenance
    new_entries.sort(key=lambda e: (str(e.get("rule_id") or ""), str(e.get("path") or ""), e["fingerprint"]))
    document = {"fingerprint_scheme": FINGERPRINT_SCHEME, "version": version, list_key: new_entries}
    return CarryResult(document=document, carried=tuple(carried), orphaned=tuple(orphaned))


def carry_baseline_forward(snapshot_path: Path, old_to_new: dict[str, str]) -> CarryResult:
    return _carry_store(snapshot_path, "entries", BASELINE_VERSION, old_to_new)


def carry_judged_forward(snapshot_path: Path, old_to_new: dict[str, str]) -> CarryResult:
    return _carry_store(snapshot_path, "findings", JUDGED_VERSION, old_to_new)


def carry_waivers_forward(snapshot_path: Path, old_to_new: dict[str, str]) -> CarryResult:
    return _carry_store(snapshot_path, "waivers", WAIVERS_VERSION, old_to_new)


# --- S6: journal — remap + per-leg done-flags ONLY (snapshot is the content source) -

JOURNAL_SCHEMA_VERSION = 1
# Legs in apply order: YAML first (gate-critical — baseline restores the local gate),
# Filigree last (reconciliation debt, no remap endpoint).
LEG_NAMES: tuple[str, ...] = ("baseline", "judged", "waivers", "filigree")
# Maps a YAML leg to (carry fn, snapshot filename, live-store path fn).
_YAML_LEGS: dict[str, tuple[Any, str, Any]] = {
    "baseline": (carry_baseline_forward, "baseline.yaml", paths.baseline_path),
    "judged": (carry_judged_forward, "judged.yaml", paths.judged_path),
    "waivers": (carry_waivers_forward, "waivers.yaml", paths.waivers_path),
}


@dataclass
class Leg:
    name: str
    done: bool = False
    carried: list[str] = field(default_factory=list)
    orphaned: list[str] = field(default_factory=list)
    # Filigree-only: recorded reconciliation debt when the leg soft-fails.
    debt: str | None = None


@dataclass
class Journal:
    """Resumable migration state. Holds the remap + per-leg done-flags + orphan/collision
    lists ONLY — NOT the carried verdict content (the snapshot is the sole provenance
    source; duplicating content here would let two copies diverge). Resume reads
    ``remap`` from here + content from the snapshot, and NEVER re-scans."""

    remap: dict[str, str]
    collisions: list[RekeyCollision] = field(default_factory=list)
    legs: list[Leg] = field(default_factory=lambda: [Leg(n) for n in LEG_NAMES])
    schema_version: int = JOURNAL_SCHEMA_VERSION
    fingerprint_scheme_from: str = "wlfp1"
    fingerprint_scheme_to: str = FINGERPRINT_SCHEME
    # The snapshotted stores carried no scheme stamp (pre-P1) — orphans here MAY be a
    # fingerprint-formula change (pre-705acfe), not source churn. Surfaced as a caution.
    snapshot_prescheme: bool = False

    def leg(self, name: str) -> Leg:
        return next(leg for leg in self.legs if leg.name == name)

    def next_pending_leg(self) -> str | None:
        return next((leg.name for leg in self.legs if not leg.done), None)

    @property
    def complete(self) -> bool:
        return all(leg.done for leg in self.legs)


def new_journal(remaps: Iterable[FingerprintRemap]) -> Journal:
    """Build a fresh journal from a single scan's dual-fingerprints."""
    result = build_remap(remaps)
    return Journal(remap=result.old_to_new, collisions=list(result.collisions))


def journal_to_doc(journal: Journal) -> dict[str, Any]:
    return {
        "schema_version": journal.schema_version,
        "fingerprint_scheme_from": journal.fingerprint_scheme_from,
        "fingerprint_scheme_to": journal.fingerprint_scheme_to,
        "snapshot_prescheme": journal.snapshot_prescheme,
        "remap": dict(journal.remap),
        "collisions": [{"new_fp": c.new_fp, "old_fps": list(c.old_fps)} for c in journal.collisions],
        "legs": [
            {"name": leg.name, "done": leg.done, "carried": leg.carried, "orphaned": leg.orphaned, "debt": leg.debt}
            for leg in journal.legs
        ],
    }


def write_journal(path: Path, journal: Journal, *, root: Path) -> None:
    # ``root`` is REQUIRED (confinement is non-optional, matching _write_store_doc).
    yaml = require_yaml("writing the rekey journal")
    path = safe_project_file(root, path, label=path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: a crash mid-write must leave the OLD journal intact (or none) — never
    # a truncated doc that load_journal rejects, which would brick --resume.
    tmp = path.with_name(path.name + ".tmp")
    # safe_project_file guarded `path` but NOT `tmp`; write the temp file no-follow so a
    # pre-planted `<journal>.tmp` symlink cannot redirect the write to an arbitrary
    # user-writable target before os.replace runs.
    write_text_no_follow(
        tmp, yaml.safe_dump(journal_to_doc(journal), sort_keys=False, allow_unicode=True), label=tmp.name
    )
    os.replace(tmp, path)


def load_journal(path: Path) -> Journal:
    yaml = require_yaml("loading the rekey journal")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict) or "remap" not in loaded:
        raise ConfigError(f"malformed migration journal {path.name}")
    legs = [
        Leg(
            name=str(d["name"]),
            done=bool(d.get("done", False)),
            carried=list(d.get("carried") or []),
            orphaned=list(d.get("orphaned") or []),
            debt=d.get("debt"),
        )
        for d in loaded.get("legs") or []
    ]
    collisions = [
        RekeyCollision(new_fp=str(c["new_fp"]), old_fps=tuple(c.get("old_fps") or []))
        for c in loaded.get("collisions") or []
    ]
    return Journal(
        remap=dict(loaded["remap"]),
        collisions=collisions,
        legs=legs or [Leg(n) for n in LEG_NAMES],
        schema_version=int(loaded.get("schema_version", JOURNAL_SCHEMA_VERSION)),
        fingerprint_scheme_from=str(loaded.get("fingerprint_scheme_from", "wlfp1")),
        fingerprint_scheme_to=str(loaded.get("fingerprint_scheme_to", FINGERPRINT_SCHEME)),
        snapshot_prescheme=bool(loaded.get("snapshot_prescheme", False)),
    )


# --- S7: per-leg-atomic, idempotent application (crash-safe; snapshot is the source) -


def _write_store_doc(root: Path, live_path: Path, document: dict[str, Any]) -> None:
    yaml = require_yaml("writing a rekeyed store")
    safe = safe_project_file(root, live_path, label=live_path.name)
    safe.parent.mkdir(parents=True, exist_ok=True)
    safe.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False, allow_unicode=True), encoding="utf-8"
    )


def apply_pending_legs(
    root: Path, journal: Journal, *, findings: Sequence[Finding] | None = None, filigree: Any = None
) -> Journal:
    """Apply each not-done leg, crash-safely: carry from the SNAPSHOT -> write the live
    store -> persist the done-flag. A crash after the write but before the flag leaves
    the leg not-done, so resume re-carries from the (untouched) snapshot and reproduces
    identical content — never an empty store, because carry NEVER reads the live store.
    YAML legs are idempotent; the Filigree leg soft-fails into recorded debt and never
    aborts the (already-complete) YAML migration."""
    jpath = paths.migration_journal_path(root)
    sdir = snapshot_dir(root)
    for leg in journal.legs:
        if leg.done:
            continue
        if leg.name == "filigree":
            _apply_filigree_leg(leg, findings, filigree)
            write_journal(jpath, journal, root=root)
            continue
        carry_fn, snap_name, live_path_fn = _YAML_LEGS[leg.name]
        snap = sdir / snap_name
        if not snap.is_file():
            # The store never existed pre-migration — nothing to carry, create nothing.
            leg.done = True
            write_journal(jpath, journal, root=root)
            continue
        result = carry_fn(snap, journal.remap)
        _write_store_doc(root, live_path_fn(root), result.document)
        leg.carried = list(result.carried)
        leg.orphaned = list(result.orphaned)
        leg.done = True
        write_journal(jpath, journal, root=root)  # persist the flag AFTER the store write
    return journal


# --- S8: Filigree leg — LAST, reconciliation debt, soft-fail, never aborts ----------


def _apply_filigree_leg(leg: Leg, findings: Sequence[Finding] | None, filigree: Any) -> None:
    """Re-emit the current scan's join-population findings under their NEW (wlfp2)
    fingerprints; Filigree's ``mark_unseen`` sweep closes the now-absent old_fp
    associations (there is no remap endpoint, so this is reconciliation debt, honestly).
    Soft-fail: an unreachable / 401 / 5xx / bad-payload sibling records debt and leaves
    the leg not-done — it NEVER aborts the already-complete YAML migration."""
    if findings is None:
        # Pure --resume without a scan: cannot re-emit. Defer (debt), do not re-scan.
        # This check is FIRST: a pending Filigree leg on resume must NOT be silently
        # completed (the forward run already no-op-completes it when no URL was set).
        leg.done = False
        leg.debt = "Filigree reconciliation deferred — re-run `wardline rekey` (not --resume) to re-emit."
        return
    if filigree is None:
        # No Filigree configured (forward run, no --filigree-url) — nothing to reconcile.
        leg.done = True
        leg.debt = None
        return
    population = [f for f in findings if is_join_population(f)]
    scanned = sorted({f.location.path for f in population})
    try:
        result = filigree.emit(population, scanned_paths=scanned)
    except FiligreeEmitError as exc:
        leg.done = False
        leg.debt = f"Filigree rejected the re-emit (bad payload/endpoint): {exc}"
        return
    if result.reachable and not result.failed and not result.warnings:
        leg.done = True
        leg.debt = None
        leg.carried = [f.fingerprint for f in population]
    elif result.reachable:
        # 2xx but the server rejected some findings (failed>0) or warned — NOT a clean
        # reconciliation. Record debt and leave the leg pending so a re-run retries.
        leg.done = False
        leg.debt = (
            f"Filigree accepted the re-emit with {result.failed} rejected"
            + (f" and warnings: {'; '.join(result.warnings)}" if result.warnings else "")
            + " — re-run `wardline rekey` to reconcile the remainder."
        )
    else:
        leg.done = False
        leg.debt = (
            f"Filigree unreachable (status={result.status}); old fingerprint associations may orphan. "
            "Re-run `wardline rekey` to reconcile."
        )


# --- S9: --probe (read-only cross-check; writes NOTHING) --------------------------


def _store_fingerprints(root: Path) -> dict[str, tuple[str | None, set[str]]]:
    """Per live store: its ``fingerprint_scheme`` header (None when pre-scheme) and the
    fingerprints it records, read RAW (a pre-migration store would SCHEME_MISMATCH the
    enforcing loaders). The scheme is load-bearing: a store ALREADY at the live scheme
    holds wlfp2 fingerprints, and judging it against the wlfp1-reconstructed remap keys
    misreads every healthy entry as orphaned (A7, weft-dda1a6d8dd). Read-only."""
    out: dict[str, tuple[str | None, set[str]]] = {}
    state = paths.weft_state_dir(root)
    for name, key, _ver in _STORES:
        p = state / name
        if not p.is_file():
            continue
        loaded = _read_old_store(p)
        scheme = loaded.get("fingerprint_scheme")
        fps = {
            e["fingerprint"]
            for e in (loaded.get(key) or [])
            if isinstance(e, dict) and isinstance(e.get("fingerprint"), str)
        }
        if fps:
            out[name] = (scheme if isinstance(scheme, str) else None, fps)
    return out


def _dir_has_prescheme_store(dir_path: Path) -> bool:
    """True iff a store in ``dir_path`` holds entries but carries NO ``fingerprint_scheme``
    header — i.e. it predates P1's scheme stamp. Such a store MAY also predate the
    taint-resolution-drift fix (705acfe), in which case its fingerprints fold resolved-taint
    values that v0 reconstruction cannot reproduce — so its verdicts orphan from a
    fingerprint-FORMULA change, not source churn. The header alone can't distinguish the two
    eras, so callers surface the possibility rather than mislabel every orphan a source move."""
    for name, key, _ver in _STORES:
        p = dir_path / name
        if not p.is_file():
            continue
        loaded = _read_old_store(p)
        if loaded.get(key) and not loaded.get("fingerprint_scheme"):
            return True
    return False


@dataclass(frozen=True, slots=True)
class ProbeReport:
    scanned_findings: int
    matched: int
    orphaned: tuple[str, ...]
    collisions: tuple[RekeyCollision, ...]
    per_store: dict[str, int]  # store name -> count of its old_fps with no current finding
    prescheme: bool = False  # a live store predates the scheme stamp (possible formula drift)
    # Stores ALREADY stamped with the live scheme (sorted). A rekey is a no-op for
    # them; their entries are matched against the CURRENT fingerprints, never the
    # wlfp1 remap keys (A7, weft-dda1a6d8dd).
    current_scheme_stores: tuple[str, ...] = ()
    # Current-scheme entries with no current finding — baseline drift (STALE_CAUSE),
    # not migration orphans; they do not dirty the probe.
    stale: tuple[str, ...] = ()
    # True when every populated store already carries the live scheme (vacuously when
    # none holds fingerprints): no fingerprint migration is pending.
    no_op: bool = False

    @property
    def clean(self) -> bool:
        return not self.orphaned and not self.collisions


def probe(root: Path, findings: Sequence[Finding]) -> ProbeReport:
    """Read-only dry run: which stored verdicts will carry, which orphan, any collisions.
    Each store is judged against ITS OWN scheme: a store still at wlfp1 (or pre-scheme)
    against the reconstructed old-fingerprint remap keys, a store already at the live
    scheme against the current scan's fingerprints (a rekey would not touch it, so a
    healthy wlfp2 baseline reports matched=N / orphaned=0 / clean — A7,
    weft-dda1a6d8dd). Writes nothing — no snapshot, no journal, no store rewrite."""
    remaps = compute_old_new_fingerprints(findings)
    result = build_remap(remaps)
    keys = set(result.old_to_new)
    new_fps = {r.new_fp for r in remaps}
    matched: set[str] = set()
    orphaned: set[str] = set()
    stale: set[str] = set()
    per_store: dict[str, int] = {}
    current_scheme_stores: list[str] = []
    migration_pending = False
    for name, (scheme, fps) in sorted(_store_fingerprints(root).items()):
        if scheme == FINGERPRINT_SCHEME:
            current_scheme_stores.append(name)
            matched |= fps & new_fps
            stale |= fps - new_fps
            continue
        migration_pending = True
        store_orphans = fps - keys
        matched |= fps & keys
        orphaned |= store_orphans
        if store_orphans:
            per_store[name] = len(store_orphans)
    return ProbeReport(
        scanned_findings=len(remaps),
        matched=len(matched),
        orphaned=tuple(sorted(orphaned)),
        # Collisions stay LOUD even when no migration is pending: >1 old_fp collapsing
        # to one new_fp means two CURRENT findings share a fingerprint — a discriminator
        # bug (WLN-ENGINE-FINGERPRINT-COLLISION), not a migration artifact. A healthy
        # baseline has none, so this never dirties the A7 clean-no-op verdict.
        collisions=result.collisions,
        per_store=per_store,
        prescheme=_dir_has_prescheme_store(paths.weft_state_dir(root)),
        current_scheme_stores=tuple(current_scheme_stores),
        stale=tuple(sorted(stale)),
        no_op=not migration_pending,
    )


# --- Orchestrators (scan-free: the CLI runs the scan and passes findings) ----------


def run_rekey(root: Path, findings: Sequence[Finding], *, filigree: Any = None) -> Journal:
    """Fresh migration: snapshot FIRST (pre-migration provenance), plan the remap from
    the single scan, write the journal, then apply the legs. Idempotent via the snapshot."""
    # Refuse a forward re-run over an ALREADY-COMPLETE migration. The snapshot (wlfp1) and
    # journal persist after success (only --rollback clears them), and the live stores are
    # now wlfp2; re-snapshot never clobbers, so a second forward run would re-carry from the
    # STALE wlfp1 snapshot and DROP any verdict added since the migration. (Incomplete — e.g.
    # a deferred Filigree leg — still re-runs, preserving the converge/retry path.)
    jpath = paths.migration_journal_path(root)
    existing_journal = load_journal(jpath) if jpath.is_file() else None
    if existing_journal is not None and existing_journal.complete:
        raise WardlineError(
            "this project's fingerprint migration is already complete — "
            "use `wardline rekey --rollback` to undo it, or delete "
            f"{snapshot_dir(root)} + {jpath} to migrate afresh."
        )
    if existing_journal is not None:
        return apply_pending_legs(root, existing_journal, findings=findings, filigree=filigree)
    # Refuse a rekey when every populated store ALREADY carries the live scheme: there
    # is nothing to migrate, and re-keying wlfp2 entries through the wlfp1 remap would
    # orphan every healthy verdict (the destructive twin of the A7 probe misread,
    # weft-dda1a6d8dd). Checked BEFORE the snapshot — a refused run writes nothing.
    populated_schemes = [scheme for scheme, _fps in _store_fingerprints(root).values()]
    if populated_schemes and all(s == FINGERPRINT_SCHEME for s in populated_schemes):
        raise WardlineError(
            f"every store is already at the {FINGERPRINT_SCHEME} fingerprint scheme — "
            "no fingerprint migration is pending; a rekey would only orphan healthy "
            "verdicts. Nothing to do (run `wardline rekey --probe` for the per-store view)."
        )
    snapshot_stores(root)  # must precede any store write
    journal = new_journal(compute_old_new_fingerprints(findings))
    # Detect from the immutable snapshot (byte-identical to the pre-migration live stores)
    # so the caution persists onto the journal for --resume display too.
    journal.snapshot_prescheme = _dir_has_prescheme_store(snapshot_dir(root))
    write_journal(jpath, journal, root=root)
    return apply_pending_legs(root, journal, findings=findings, filigree=filigree)


def resume_rekey(root: Path, *, findings: Sequence[Finding] | None = None, filigree: Any = None) -> Journal:
    """Resume from the journal — applies only not-done legs, NEVER re-scans. YAML legs
    re-carry from the snapshot; the Filigree leg defers (debt) if no findings are given."""
    jpath = paths.migration_journal_path(root)
    if not jpath.is_file():
        raise WardlineError("no migration journal to resume — run `wardline rekey` first")
    journal = load_journal(jpath)
    return apply_pending_legs(root, journal, findings=findings, filigree=filigree)


# --- S10: forward-only rollback (YAML clean+complete; Filigree may orphan) ---------


@dataclass(frozen=True, slots=True)
class RollbackResult:
    restored: tuple[str, ...]


def rollback(root: Path) -> RollbackResult:
    """Restore the YAML stores byte-identical from the snapshot and remove the journal +
    snapshot. YAML rollback is clean and complete. Filigree associations created by the
    forward run are NOT reversed (no remap endpoint; re-emitting would need the old scan)
    — the caller warns about that orphan risk."""
    sdir = snapshot_dir(root)
    snap_files = [name for name, _k, _v in _STORES if (sdir / name).is_file()]
    jpath = paths.migration_journal_path(root)
    if not snap_files and not jpath.is_file():
        raise WardlineError(f"no rekey snapshot under {sdir} — nothing to roll back")
    state = paths.weft_state_dir(root)
    restored: list[str] = []
    for name in snap_files:
        live = safe_project_file(root, state / name, label=name)
        live.parent.mkdir(parents=True, exist_ok=True)
        live.write_bytes((sdir / name).read_bytes())
        restored.append(name)
    # Remove the journal, then the snapshot files + dir (best-effort cleanup).
    jpath.unlink(missing_ok=True)
    for name, _k, _v in _STORES:
        (sdir / name).unlink(missing_ok=True)
    if sdir.is_dir() and not any(sdir.iterdir()):
        sdir.rmdir()
    return RollbackResult(restored=tuple(restored))
