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
from wardline.core.fingerprint_v0 import FINGERPRINT_SCHEME_V0, compute_finding_fingerprint_v0
from wardline.core.judge_types import JudgeTransport
from wardline.core.judged import JUDGED_VERSION, validate_judged_document
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


def _require_rekey_store_scheme(raw: object, *, store_name: str) -> str | None:
    """Validate the only store schemes this one-step migration can interpret.

    A missing header is the explicitly supported pre-scheme case.  Any named
    scheme other than the frozen source scheme or this build's live scheme has
    no trustworthy remap and must fail before a verdict is carried or orphaned.
    """
    if raw is None:
        return None
    if isinstance(raw, str) and raw in {FINGERPRINT_SCHEME_V0, FINGERPRINT_SCHEME}:
        return raw
    raise ConfigError(
        f"{store_name}: unsupported fingerprint scheme {raw!r}; rekey can only route "
        f"missing/pre-scheme, {FINGERPRINT_SCHEME_V0!r}, or {FINGERPRINT_SCHEME!r} stores"
    )


# Mirror of scanner.rules._POLICY_CONFIG_RULE_ID (core must not import scanner — layering).
# A drift test (test_rekey_population.py) asserts the two stay equal. POLICY-CONFIG is the
# ONE engine rule whose legacy wlfp1 fingerprint used compute_finding_fingerprint and
# therefore included line_start. It is v0-reconstructed, NOT identity-mapped, unlike
# the other engine diagnostics. The live wlfp2 producer excludes absolute line_start.
# Verified mechanically: no other WLN-ENGINE-*/WLN-L3-* DEFECT uses the shared producer
# (they use diagnostics._fingerprint, which is scheme-independent).
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
    """Ambiguous fingerprint migration that must orphan instead of carrying.

    Collapse: two findings DISTINCT under wlfp1 (different ``old_fp``) collapse to
    one ``new_fp`` under wlfp2. Fan-out: one legacy ``old_fp`` reconstructs for two
    current findings after a discriminator split. Both are reported LOUD and the
    ambiguous old fingerprint(s) are orphaned, but the rest of the migration proceeds.
    A whole-run abort would brick a real project permanently, so we never abort."""

    new_fp: str | None
    old_fps: tuple[str, ...]
    new_fps: tuple[str, ...] = ()

    @property
    def message(self) -> str:
        if self.new_fps:
            return (
                f"WLN-ENGINE-FINGERPRINT-FANOUT: pre-rekey fingerprint {self.old_fps[0]} maps to "
                f"{len(self.new_fps)} wlfp2 fingerprints ({', '.join(self.new_fps)}); "
                "verdict orphaned, not carried."
            )
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
    """Build the ``old_fp -> new_fp`` map.

    The map is carried only for 1:1 keys. The inverse can collide (wlfp2 dropped
    line_start): if >1 distinct old_fp shares a new_fp, all those old_fps are
    excluded. A later source-discriminator split can also fan one old_fp out to
    multiple new_fps; that old_fp is excluded too because choosing a carried verdict
    target would be arbitrary.
    """
    new_to_olds: dict[str, set[str]] = {}
    old_to_news: dict[str, set[str]] = {}
    for r in remaps:
        new_to_olds.setdefault(r.new_fp, set()).add(r.old_fp)
        old_to_news.setdefault(r.old_fp, set()).add(r.new_fp)
    old_to_new: dict[str, str] = {old: next(iter(news)) for old, news in old_to_news.items() if len(news) == 1}
    collapse_collisions = tuple(
        RekeyCollision(new_fp=nf, old_fps=tuple(sorted(olds)))
        for nf, olds in sorted(new_to_olds.items())
        if len(olds) > 1
    )
    fanout_collisions = tuple(
        RekeyCollision(new_fp=None, old_fps=(old,), new_fps=tuple(sorted(news)))
        for old, news in sorted(old_to_news.items())
        if len(news) > 1
    )
    collisions = collapse_collisions + fanout_collisions
    for c in collisions:
        for of in c.old_fps:
            old_to_new.pop(of, None)
    return RemapResult(old_to_new=old_to_new, collisions=collisions)


# --- S4: pre-flight snapshot (the SOLE provenance source on resume) ---------------


def snapshot_dir(root: Path) -> Path:
    return paths.weft_state_dir(root) / SNAPSHOT_DIR_NAME


def _has_path_or_symlink(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _read_project_store_bytes(root: Path, path: Path) -> bytes | None:
    """Read an optional project-local store without following symlinks.

    Missing, non-regular, symlinked, or escaping paths are not snapshot/probe inputs.
    """
    if path.is_symlink():
        return None
    try:
        safe = safe_project_file(root, path, label=path.name)
    except WardlineError:
        return None
    return read_bytes_no_follow(safe)


def _read_required_snapshot_bytes(root: Path, path: Path) -> bytes:
    """Read a snapshot store that must exist and must be a regular in-project file."""
    try:
        if path.is_symlink():
            raise WardlineError(f"{path.name}: refusing to read through a symlink")
        safe = safe_project_file(root, path, label=path.name)
    except WardlineError as exc:
        raise WardlineError(f"non-regular rekey snapshot {path.name} under {path.parent}: {exc}") from exc
    data = read_bytes_no_follow(safe)
    if data is None:
        raise WardlineError(f"non-regular rekey snapshot {path.name} under {path.parent}")
    return data


def _refuse_preexisting_snapshot_without_journal(root: Path) -> None:
    """Fresh rekey runs must create their own snapshot provenance.

    A snapshot without a journal is not resumable state; trusting it would let an
    untrusted checkout pre-plant old fingerprints that a fresh run would carry into
    live stores.
    """
    sdir = snapshot_dir(root)
    if sdir.is_symlink():
        raise WardlineError(f"pre-existing rekey snapshot at {sdir} is a symlink; refusing to trust it")
    if not sdir.exists():
        return
    if not sdir.is_dir():
        raise WardlineError(f"pre-existing rekey snapshot at {sdir} is not a directory; refusing to trust it")
    try:
        entries = tuple(sdir.iterdir())
    except OSError as exc:
        raise WardlineError(f"could not inspect pre-existing rekey snapshot at {sdir}: {exc}") from exc
    if entries:
        raise WardlineError(
            f"pre-existing rekey snapshot at {sdir} has no migration journal; "
            "refusing to trust stale or caller-planted provenance."
        )


def _read_live_store_payloads(root: Path) -> dict[str, bytes]:
    state = paths.weft_state_dir(root)
    payloads: dict[str, bytes] = {}
    for name, _key, _ver in _STORES:
        live = state / name
        # Read the live store WITHOUT following a symlink: an untrusted checkout could
        # plant `.weft/wardline/<store>.yaml` as a symlink to a user-readable file outside
        # the repo, and a naive read would copy that target into the in-project snapshot
        # (arbitrary file disclosure). A symlinked/non-regular/missing store is simply not
        # snapshot-eligible.
        data = _read_project_store_bytes(root, live)
        if data is None:
            continue
        payloads[name] = data
    return payloads


def _publish_snapshot_payloads(root: Path, payloads: dict[str, bytes]) -> tuple[str, ...]:
    sdir = snapshot_dir(root)
    present: list[str] = []
    for name, _key, _ver in _STORES:
        data = payloads.get(name)
        if data is None:
            continue
        present.append(name)
        dest = safe_project_file(root, sdir / name, label=name)
        if dest.exists():
            continue  # never clobber the pre-migration snapshot
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return tuple(present)


def snapshot_stores(root: Path) -> tuple[str, ...]:
    """Copy each EXISTING YAML store into ``.rekey_snapshot/`` byte-identical. The
    snapshot is the immutable provenance source the carry legs read — resume NEVER
    re-reads the (already-rewritten) live store. Idempotent: an existing snapshot is
    the pre-migration truth and is NEVER clobbered (a second invocation keeps it)."""
    return _publish_snapshot_payloads(root, _read_live_store_payloads(root))


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
    data = read_bytes_no_follow(path)
    if data is None:
        return {}
    return _load_old_store_bytes(data, path.name)


def _load_old_store_bytes(
    data: bytes,
    name: str,
    *,
    preserve_falsey_types: bool = False,
) -> dict[str, Any]:
    yaml = require_yaml("reading the rekey snapshot")
    try:
        decoded = yaml.safe_load(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigError(f"malformed snapshot {name}: not valid UTF-8") from exc
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        raise ConfigError(f"malformed snapshot {name}: {exc}") from exc
    loaded = decoded if preserve_falsey_types else decoded or {}
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ConfigError(f"snapshot {name} is not a mapping")
    return loaded


def _carry_store(snapshot_path: Path, list_key: str, version: int, old_to_new: dict[str, str]) -> CarryResult:
    loaded = _read_old_store(snapshot_path)
    return _carry_loaded_store(loaded, list_key, version, old_to_new, store_name=snapshot_path.name)


def _carry_store_bytes(
    data: bytes, snapshot_name: str, list_key: str, version: int, old_to_new: dict[str, str]
) -> CarryResult:
    loaded = _load_old_store_bytes(data, snapshot_name)
    return _carry_loaded_store(loaded, list_key, version, old_to_new, store_name=snapshot_name)


def _carry_loaded_store(
    loaded: dict[str, Any],
    list_key: str,
    version: int,
    old_to_new: dict[str, str],
    *,
    store_name: str = "snapshot store",
) -> CarryResult:
    """Remap one store: swap each entry's ``fingerprint`` old->new while byte-preserving
    every OTHER field (rationale/reason/expires/rule_id/path/message/...), drop entries
    whose old_fp is not in the remap (orphans), and re-stamp the wlfp2 scheme header.
    Deterministic order: (rule_id, path, new fingerprint)."""
    raw_entries = loaded.get(list_key) or []
    # A snapshot store ALREADY at the live scheme needs no remap: its fingerprints are
    # wlfp2 keys, and pushing them through the wlfp1->wlfp2 map would orphan every one
    # (the mixed-scheme leg of A7, weft-dda1a6d8dd). Identity-carry it untouched.
    scheme = _require_rekey_store_scheme(loaded.get("fingerprint_scheme"), store_name=store_name)
    already_current = scheme == FINGERPRINT_SCHEME
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


def _validate_judged_source_for_carry(loaded: dict[str, Any], *, store_name: str) -> None:
    _require_rekey_store_scheme(loaded.get("fingerprint_scheme"), store_name=store_name)
    validate_judged_document(
        loaded,
        store_name=store_name,
        require_current_scheme=False,
        allow_empty=False,
    )


def _carry_judged_loaded_store(
    loaded: dict[str, Any],
    old_to_new: dict[str, str],
    *,
    store_name: str,
) -> CarryResult:
    source_version = loaded.get("version")
    _validate_judged_source_for_carry(loaded, store_name=store_name)
    result = _carry_loaded_store(
        loaded,
        "findings",
        JUDGED_VERSION,
        old_to_new,
        store_name=store_name,
    )
    if source_version == 1:
        for entry in result.document["findings"]:
            entry["judge_transport"] = JudgeTransport.OPENROUTER.value
    # The source contract alone is insufficient: a resumed journal can contain a
    # malformed or colliding target fingerprint. Validate the exact v2 document we
    # would publish after remapping and legacy transport injection.
    validate_judged_document(
        result.document,
        store_name=store_name,
        require_current_scheme=True,
        allow_empty=False,
    )
    return result


def carry_judged_forward(snapshot_path: Path, old_to_new: dict[str, str]) -> CarryResult:
    data = read_bytes_no_follow(snapshot_path)
    return _carry_judged_loaded_store(
        {} if data is None else _load_old_store_bytes(data, snapshot_path.name, preserve_falsey_types=True),
        old_to_new,
        store_name=snapshot_path.name,
    )


def carry_waivers_forward(snapshot_path: Path, old_to_new: dict[str, str]) -> CarryResult:
    return _carry_store(snapshot_path, "waivers", WAIVERS_VERSION, old_to_new)


# --- S6: journal — remap + per-leg done-flags ONLY (snapshot is the content source) -

JOURNAL_SCHEMA_VERSION = 1
# Legs in apply order: YAML first (gate-critical — baseline restores the local gate),
# Filigree last (reconciliation debt, no remap endpoint).
LEG_NAMES: tuple[str, ...] = ("baseline", "judged", "waivers", "filigree")
_FINGERPRINT_HEX = frozenset("0123456789abcdef")
# Maps a YAML leg to (snapshot filename, live-store path fn, list key, store version).
_YAML_LEGS: dict[str, tuple[str, Any, str, int]] = {
    "baseline": ("baseline.yaml", paths.baseline_path, "entries", BASELINE_VERSION),
    "judged": ("judged.yaml", paths.judged_path, "findings", JUDGED_VERSION),
    "waivers": ("waivers.yaml", paths.waivers_path, "waivers", WAIVERS_VERSION),
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
        "collisions": [
            {
                "new_fp": c.new_fp,
                "old_fps": list(c.old_fps),
                **({"new_fps": list(c.new_fps)} if c.new_fps else {}),
            }
            for c in journal.collisions
        ],
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


def _journal_string_list(raw: object, *, path: Path, field_name: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(value, str) for value in raw):
        raise ConfigError(f"malformed migration journal {path.name}: {field_name} must be a list of strings")
    return list(raw)


def _load_journal_legs(raw: object, *, path: Path) -> list[Leg]:
    # Backward compatibility: journals written before per-leg progress was
    # persisted omitted ``legs`` (or wrote an empty list). Resume them from the
    # canonical first leg rather than rejecting a recoverable old journal.
    if raw is None or raw == []:
        return [Leg(name) for name in LEG_NAMES]
    if not isinstance(raw, list):
        raise ConfigError(f"malformed migration journal {path.name}: legs must be a list")

    names: list[str] = []
    legs: list[Leg] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ConfigError(f"malformed migration journal {path.name}: legs[{index}] must be a named mapping")
        name = item["name"]
        names.append(name)
        done = item.get("done", False)
        debt = item.get("debt")
        if not isinstance(done, bool):
            raise ConfigError(f"malformed migration journal {path.name}: legs[{index}].done must be a bool")
        if debt is not None and not isinstance(debt, str):
            raise ConfigError(f"malformed migration journal {path.name}: legs[{index}].debt must be a string or null")
        legs.append(
            Leg(
                name=name,
                done=done,
                carried=_journal_string_list(item.get("carried", []), path=path, field_name=f"legs[{index}].carried"),
                orphaned=_journal_string_list(
                    item.get("orphaned", []), path=path, field_name=f"legs[{index}].orphaned"
                ),
                debt=debt,
            )
        )

    if tuple(names) != LEG_NAMES:
        raise ConfigError(f"{path.name}: journal legs must be exactly {LEG_NAMES!r} in order; got {tuple(names)!r}")
    return legs


def _load_journal_collisions(raw: object, *, path: Path) -> list[RekeyCollision]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError(f"malformed migration journal {path.name}: collisions must be a list")
    collisions: list[RekeyCollision] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"malformed migration journal {path.name}: collisions[{index}] must be a mapping")
        new_fp = item.get("new_fp")
        if new_fp is not None and not isinstance(new_fp, str):
            raise ConfigError(
                f"malformed migration journal {path.name}: collisions[{index}].new_fp must be a string or null"
            )
        collisions.append(
            RekeyCollision(
                new_fp=new_fp,
                old_fps=tuple(
                    _journal_string_list(item.get("old_fps", []), path=path, field_name=f"collisions[{index}].old_fps")
                ),
                new_fps=tuple(
                    _journal_string_list(item.get("new_fps", []), path=path, field_name=f"collisions[{index}].new_fps")
                ),
            )
        )
    return collisions


def _validate_journal_remap(raw: object, *, journal_name: str) -> dict[str, str]:
    """Return a valid one-to-one fingerprint remap or reject it without echoing input."""
    if not isinstance(raw, dict):
        raise ConfigError(f"malformed migration journal {journal_name}: remap must be a mapping")

    validated: dict[str, str] = {}
    target_entries: dict[str, int] = {}
    for index, (old_fp, new_fp) in enumerate(raw.items()):
        if not isinstance(old_fp, str) or len(old_fp) != 64 or not set(old_fp) <= _FINGERPRINT_HEX:
            raise ConfigError(
                f"malformed migration journal {journal_name}: remap source fingerprint at entry {index} "
                "must be a 64-char lowercase hex string"
            )
        if not isinstance(new_fp, str) or len(new_fp) != 64 or not set(new_fp) <= _FINGERPRINT_HEX:
            raise ConfigError(
                f"malformed migration journal {journal_name}: remap target fingerprint at entry {index} "
                "must be a 64-char lowercase hex string"
            )
        first_entry = target_entries.get(new_fp)
        if first_entry is not None:
            raise ConfigError(
                f"malformed migration journal {journal_name}: remap target collision between entries "
                f"{first_entry} and {index}; target fingerprints must be injective"
            )
        validated[old_fp] = new_fp
        target_entries[new_fp] = index
    return validated


def load_journal(path: Path) -> Journal:
    yaml = require_yaml("loading the rekey journal")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"malformed migration journal {path.name}: {exc}") from exc
    if not isinstance(loaded, dict) or "remap" not in loaded:
        raise ConfigError(f"malformed migration journal {path.name}")
    schema_version = loaded.get("schema_version", JOURNAL_SCHEMA_VERSION)
    if type(schema_version) is not int or schema_version != JOURNAL_SCHEMA_VERSION:
        raise ConfigError(
            f"{path.name}: unsupported migration journal schema_version {schema_version!r}; "
            f"expected {JOURNAL_SCHEMA_VERSION}"
        )
    remap = _validate_journal_remap(loaded["remap"], journal_name=path.name)
    legs = _load_journal_legs(loaded.get("legs"), path=path)
    collisions = _load_journal_collisions(loaded.get("collisions"), path=path)
    scheme_from = loaded.get("fingerprint_scheme_from", FINGERPRINT_SCHEME_V0)
    scheme_to = loaded.get("fingerprint_scheme_to", FINGERPRINT_SCHEME)
    if not isinstance(scheme_from, str) or not isinstance(scheme_to, str):
        raise ConfigError(f"malformed migration journal {path.name}: fingerprint schemes must be strings")
    if scheme_from != FINGERPRINT_SCHEME_V0 or scheme_to != FINGERPRINT_SCHEME:
        raise ConfigError(
            f"{path.name}: unsupported migration journal schemes from={scheme_from!r}, to={scheme_to!r}; "
            f"this build only resumes {FINGERPRINT_SCHEME_V0!r} -> {FINGERPRINT_SCHEME!r}"
        )
    snapshot_prescheme = loaded.get("snapshot_prescheme", False)
    if not isinstance(snapshot_prescheme, bool):
        raise ConfigError(f"malformed migration journal {path.name}: snapshot_prescheme must be a bool")
    return Journal(
        remap=remap,
        collisions=collisions,
        legs=legs,
        schema_version=schema_version,
        fingerprint_scheme_from=scheme_from,
        fingerprint_scheme_to=scheme_to,
        snapshot_prescheme=snapshot_prescheme,
    )


# --- S7: per-leg-atomic, idempotent application (crash-safe; snapshot is the source) -


def _write_store_doc(root: Path, live_path: Path, document: dict[str, Any]) -> None:
    yaml = require_yaml("writing a rekeyed store")
    safe = safe_project_file(root, live_path, label=live_path.name)
    safe.parent.mkdir(parents=True, exist_ok=True)
    safe.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False, allow_unicode=True), encoding="utf-8"
    )


def _validate_store_payload(data: bytes, store_name: str) -> dict[str, Any]:
    loaded = _load_old_store_bytes(
        data,
        store_name,
        preserve_falsey_types=store_name == "judged.yaml",
    )
    if store_name == "judged.yaml":
        _validate_judged_source_for_carry(loaded, store_name=store_name)
    else:
        _require_rekey_store_scheme(loaded.get("fingerprint_scheme"), store_name=store_name)
    return loaded


def _preflight_store_payloads(payloads: dict[str, bytes], journal: Journal) -> None:
    for store_name, data in payloads.items():
        loaded = _validate_store_payload(data, store_name)
        if store_name == "judged.yaml":
            _carry_judged_loaded_store(loaded, journal.remap, store_name=store_name)


def _preflight_pending_snapshot_payloads(root: Path, journal: Journal) -> dict[str, bytes | None]:
    """Read and validate every pending YAML snapshot before any migration write.

    Return the validated bytes so application consumes the exact preflighted
    payloads. This closes both incremental validation and a preflight/use race:
    a later snapshot cannot become unsupported after an earlier leg mutates its
    live store and journal.
    """
    sdir = snapshot_dir(root)
    payloads: dict[str, bytes | None] = {}
    for leg in journal.legs:
        if leg.done or leg.name == "filigree":
            continue
        snap_name, _live_path_fn, _list_key, _version = _YAML_LEGS[leg.name]
        snap = sdir / snap_name
        if not _has_path_or_symlink(snap):
            payloads[leg.name] = None
            continue
        data = _read_required_snapshot_bytes(root, snap)
        loaded = _validate_store_payload(data, snap_name)
        if leg.name == "judged":
            _carry_judged_loaded_store(loaded, journal.remap, store_name=snap_name)
        payloads[leg.name] = data
    return payloads


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
    _validate_journal_remap(journal.remap, journal_name=jpath.name)
    snapshot_payloads = _preflight_pending_snapshot_payloads(root, journal)
    for leg in journal.legs:
        if leg.done:
            continue
        if leg.name == "filigree":
            _apply_filigree_leg(leg, findings, filigree)
            write_journal(jpath, journal, root=root)
            continue
        snap_name, live_path_fn, list_key, version = _YAML_LEGS[leg.name]
        snapshot_data = snapshot_payloads[leg.name]
        if snapshot_data is None:
            # The store never existed pre-migration — nothing to carry, create nothing.
            leg.done = True
            write_journal(jpath, journal, root=root)
            continue
        if leg.name == "judged":
            result = _carry_judged_loaded_store(
                _load_old_store_bytes(snapshot_data, snap_name, preserve_falsey_types=True),
                journal.remap,
                store_name=snap_name,
            )
        else:
            result = _carry_store_bytes(snapshot_data, snap_name, list_key, version, journal.remap)
        _write_store_doc(root, live_path_fn(root), result.document)
        leg.carried = list(result.carried)
        leg.orphaned = list(result.orphaned)
        leg.done = True
        write_journal(jpath, journal, root=root)  # persist the flag AFTER the store write
    return journal


# --- S8: Filigree leg — LAST, reconciliation debt, soft-fail, never aborts ----------


def _apply_filigree_leg(leg: Leg, findings: Sequence[Finding] | None, filigree: Any) -> None:
    """Re-emit the current scan's findings under their NEW (wlfp2) fingerprints;
    Filigree's ``mark_unseen`` sweep closes the now-absent old_fp associations (there
    is no remap endpoint, so this is reconciliation debt, honestly).

    The emit carries the FULL finding set (all kinds), exactly like a normal scan emit —
    NOT the DEFECT-only join population. Filigree's sweep is kind-blind and scoped per
    (file, scan_source): a DEFECT-only re-emit that names a file would sweep that file's
    still-live FACT fingerprints as unseen (false "fixed"), and filtering out the
    FACT-kind incomplete-analysis markers (WLN-ENGINE-SOURCE-ROOT-MISSING, the
    out-of-root-symlink WLN-ENGINE-FILE-SKIPPED) would let the sweep run on a scan the
    normal emit path refuses to sweep ("missing findings are not proof of a fix").
    Emitting all kinds keeps the sweep — the leg's whole mechanism — while the emitter's
    incomplete-analysis guard is computed over the unfiltered set. ``carried`` still
    records only the join population: that is what the stores re-keyed on.

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
    scanned = sorted({f.location.path for f in findings})
    try:
        result = filigree.emit(list(findings), scanned_paths=scanned)
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


def _store_fingerprints_from_payloads(payloads: dict[str, bytes]) -> dict[str, tuple[str | None, set[str]]]:
    out: dict[str, tuple[str | None, set[str]]] = {}
    for name, key, _ver in _STORES:
        data = payloads.get(name)
        if data is None:
            continue
        loaded = _load_old_store_bytes(data, name)
        scheme = _require_rekey_store_scheme(loaded.get("fingerprint_scheme"), store_name=name)
        fps = {
            e["fingerprint"]
            for e in (loaded.get(key) or [])
            if isinstance(e, dict) and isinstance(e.get("fingerprint"), str)
        }
        if fps:
            out[name] = (scheme, fps)
    return out


def _store_fingerprints(root: Path) -> dict[str, tuple[str | None, set[str]]]:
    """Per live store: its ``fingerprint_scheme`` header (None when pre-scheme) and the
    fingerprints it records, read RAW (a pre-migration store would SCHEME_MISMATCH the
    enforcing loaders). The scheme is load-bearing: a store ALREADY at the live scheme
    holds wlfp2 fingerprints, and judging it against the wlfp1-reconstructed remap keys
    misreads every healthy entry as orphaned (A7, weft-dda1a6d8dd). Read-only."""
    return _store_fingerprints_from_payloads(_read_live_store_payloads(root))


def _payloads_have_prescheme_store(payloads: dict[str, bytes]) -> bool:
    for name, key, _ver in _STORES:
        data = payloads.get(name)
        if data is None:
            continue
        loaded = _load_old_store_bytes(data, name)
        if loaded.get(key) and not loaded.get("fingerprint_scheme"):
            return True
    return False


def _dir_has_prescheme_store(dir_path: Path, *, root: Path | None = None) -> bool:
    """True iff a store in ``dir_path`` holds entries but carries NO ``fingerprint_scheme``
    header — i.e. it predates P1's scheme stamp. Such a store MAY also predate the
    taint-resolution-drift fix (705acfe), in which case its fingerprints fold resolved-taint
    values that v0 reconstruction cannot reproduce — so its verdicts orphan from a
    fingerprint-FORMULA change, not source churn. The header alone can't distinguish the two
    eras, so callers surface the possibility rather than mislabel every orphan a source move."""
    for name, key, _ver in _STORES:
        p = dir_path / name
        data = _read_project_store_bytes(root, p) if root is not None else read_bytes_no_follow(p)
        if data is None:
            continue
        loaded = _load_old_store_bytes(data, p.name)
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
        prescheme=_dir_has_prescheme_store(paths.weft_state_dir(root), root=root),
        current_scheme_stores=tuple(current_scheme_stores),
        stale=tuple(sorted(stale)),
        no_op=not migration_pending,
    )


# --- Orchestrators (scan-free: the CLI runs the scan and passes findings) ----------


def run_rekey(root: Path, findings: Sequence[Finding], *, filigree: Any = None) -> Journal:
    """Fresh migration: validate then publish one exact live-store byte snapshot,
    plan the remap from the single scan, write the journal, then apply the legs."""
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
    live_payloads = _read_live_store_payloads(root)
    journal = new_journal(compute_old_new_fingerprints(findings))
    _preflight_store_payloads(live_payloads, journal)
    populated_schemes = [scheme for scheme, _fps in _store_fingerprints_from_payloads(live_payloads).values()]
    if populated_schemes and all(s == FINGERPRINT_SCHEME for s in populated_schemes):
        raise WardlineError(
            f"every store is already at the {FINGERPRINT_SCHEME} fingerprint scheme — "
            "no fingerprint migration is pending; a rekey would only orphan healthy "
            "verdicts. Nothing to do (run `wardline rekey --probe` for the per-store view)."
        )
    _refuse_preexisting_snapshot_without_journal(root)
    _publish_snapshot_payloads(root, live_payloads)  # exact preflighted bytes; no second live read
    # Detect from the immutable snapshot (byte-identical to the pre-migration live stores)
    # so the caution persists onto the journal for --resume display too.
    journal.snapshot_prescheme = _payloads_have_prescheme_store(live_payloads)
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
    snap_payloads = [
        (name, _read_required_snapshot_bytes(root, sdir / name))
        for name, _k, _v in _STORES
        if _has_path_or_symlink(sdir / name)
    ]
    jpath = paths.migration_journal_path(root)
    if not snap_payloads and not jpath.is_file():
        raise WardlineError(f"no rekey snapshot under {sdir} — nothing to roll back")
    state = paths.weft_state_dir(root)
    restored: list[str] = []
    for name, data in snap_payloads:
        live = safe_project_file(root, state / name, label=name)
        live.parent.mkdir(parents=True, exist_ok=True)
        live.write_bytes(data)
        restored.append(name)
    # Remove the journal, then the snapshot files + dir (best-effort cleanup).
    jpath.unlink(missing_ok=True)
    for name, _k, _v in _STORES:
        (sdir / name).unlink(missing_ok=True)
    if not sdir.is_symlink() and sdir.is_dir() and not any(sdir.iterdir()):
        sdir.rmdir()
    return RollbackResult(restored=tuple(restored))
