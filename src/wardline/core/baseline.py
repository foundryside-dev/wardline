# src/wardline/core/baseline.py
"""The git-committable finding baseline (SP3).

A ``.weft/wardline/baseline.yaml`` is a snapshot of accepted findings keyed on the
full ``Finding.fingerprint`` (strict match — see spec §2 dial 1). The committed
file carries ``rule_id``/``path``/``message`` per entry for human auditability in
a git diff; only ``fingerprint`` is loaded into the match set. No governance.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wardline.core.errors import ConfigError, WardlineError
from wardline.core.finding import (
    FINGERPRINT_SCHEME,
    Finding,
    Kind,
    Severity,
    require_fingerprint_scheme,
)
from wardline.core.optional_deps import require_yaml
from wardline.core.paths import baseline_path as baseline_file
from wardline.core.safe_paths import read_bytes_no_follow, safe_project_path, safe_write_text, write_text_no_follow

BASELINE_VERSION: int = 1
"""Bumped on a format change; validated on load (mirrors STDLIB_TAINT_VERSION)."""

# CRITICAL sorts first so high-severity entries sit at the top of the git diff.
_SEVERITY_SORT: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.ERROR: 1,
    Severity.WARN: 2,
    Severity.INFO: 3,
    Severity.NONE: 4,
}
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class Baseline:
    fingerprints: frozenset[str]

    def contains(self, fingerprint: str) -> bool:
        return fingerprint in self.fingerprints


# Length-bound on the human diagnostic surfaced by the repo-binding probe — keep
# it short and free of any path outside the store name (trust-boundary discipline).
_STORE_MESSAGE_CAP = 200


@dataclass(frozen=True, slots=True)
class BaselineStoreStatus:
    """READ-ONLY verdict of can-I-read-my-own-store, for the doctor repo-binding probe.

    The load-bearing, non-tautological signal is ``schema_version`` — a fact READ
    FROM INSIDE the store, not derived from the path. ``binding_ok`` is true IFF
    this build can read the store at a schema it serves (``present and readable``).
    ``schema_version`` reports the on-disk version STRICTLY as read from the file
    (never the served constant): null when the store is unreadable OR carries no
    version field. ``binding_ok`` is true IFF this build read a servable version
    from inside the store; the on-disk version of an UNREADABLE store rides in
    ``message`` as the human diagnostic.
    """

    present: bool
    readable: bool
    schema_version: int | None
    baseline_finding_count: int | None
    binding_ok: bool
    message: str


def _read_store_text_no_follow(root: Path, path: Path) -> tuple[bool, str | None]:
    """Return ``(present, text)`` for a repo-owned store without following symlinks."""
    candidate = path if path.is_absolute() else Path(os.path.abspath(os.fspath(path)))
    try:
        safe = safe_project_path(root, candidate, label=path.name)
        mode = safe.stat(follow_symlinks=False).st_mode
    except FileNotFoundError:
        return False, None
    except (OSError, WardlineError):
        return True, None
    if not stat.S_ISREG(mode):
        return True, None
    raw = read_bytes_no_follow(safe)
    if raw is None:
        return True, None
    try:
        return True, raw.decode("utf-8")
    except UnicodeDecodeError:
        return True, None


def inspect_baseline_store(root: Path) -> BaselineStoreStatus:
    """Probe the baseline store for ``root`` WITHOUT writing/migrating/creating it.

    This is the wardline analog of the 2026-06-26 stale-binary incident: a server
    can start cleanly yet be unable to read its repo-scoped store, so its findings
    silently go dark. Reusing the same ``require_yaml`` + ``_build_baseline``
    validation the loader runs, three outcomes:

    * ABSENT — ``baseline.yaml`` does not exist (opt-in feature not set up): not the
      incident, ``binding_ok`` false but no error is implied.
    * PRESENT + READABLE — parses and ``version == BASELINE_VERSION``: ``binding_ok``
      true, ``schema_version`` is the on-disk version, count is the entry total.
    * PRESENT + UNREADABLE — version mismatch / malformed / not-a-mapping (the
      stale-binary incident): ``binding_ok`` false, ``schema_version`` null, the
      on-disk version (when available) named in ``message``.
    """
    path = baseline_file(root)
    present, text = _read_store_text_no_follow(root, path)
    if not present:
        return BaselineStoreStatus(
            present=False,
            readable=False,
            schema_version=None,
            baseline_finding_count=None,
            binding_ok=False,
            message=(
                f"no baseline store at {path.name} — baseline gating is opt-in; "
                "run `wardline baseline create` to enable it"
            ),
        )
    if text is None:
        return BaselineStoreStatus(
            present=True,
            readable=False,
            schema_version=None,
            baseline_finding_count=None,
            binding_ok=False,
            message=f"baseline store {path.name} is unreadable — regenerate the baseline",
        )
    yaml = require_yaml("reading baseline.yaml")
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        # Keep the message generic + content-free: a raw YAMLError can echo a file snippet.
        return BaselineStoreStatus(
            present=True,
            readable=False,
            schema_version=None,
            baseline_finding_count=None,
            binding_ok=False,
            message=f"baseline store {path.name} is not valid YAML — regenerate the baseline",
        )
    on_disk_version = raw.get("version") if isinstance(raw, dict) else None
    try:
        baseline = _build_baseline(raw, path.name)
    except ConfigError:
        if isinstance(on_disk_version, int) and on_disk_version != BASELINE_VERSION:
            message = (
                f"baseline store schema v{on_disk_version} not served by this build "
                f"(serves v{BASELINE_VERSION}) — rebuild wardline or regenerate the baseline"
            )
        else:
            # Content-free: do NOT interpolate the raw exception. A crafted store can
            # smuggle arbitrary content (a fingerprint_scheme value, a non-int version
            # repr) into ConfigError text, which would echo back out through the doctor
            # seam — name only path.name + the served version (both non-leaky).
            message = (
                f"baseline store {path.name} is unreadable (invalid scheme/version or "
                f"structure) — this build serves v{BASELINE_VERSION}; regenerate the baseline"
            )
        return BaselineStoreStatus(
            present=True,
            readable=False,
            schema_version=None,
            baseline_finding_count=None,
            binding_ok=False,
            message=message[:_STORE_MESSAGE_CAP],
        )
    # Readable: report the version STRICTLY as READ FROM the file (the non-tautological
    # fact) — never the served constant. A degenerate empty `{}` store parses without a
    # version field, so schema_version stays null and binding_ok is false: wardline can
    # open it but has no servable-version fact to assert. A real baseline (even with zero
    # findings) always carries `version`, so this only ever affects a crafted/empty store.
    schema_version = on_disk_version if isinstance(on_disk_version, int) else None
    count = len(baseline.fingerprints)
    binding_ok = schema_version is not None
    message = (
        f"baseline store readable: schema v{schema_version}, {count} finding(s)"
        if binding_ok
        else f"baseline store {path.name} carries no schema version — regenerate the baseline"
    )
    return BaselineStoreStatus(
        present=True,
        readable=True,
        schema_version=schema_version,
        baseline_finding_count=count,
        binding_ok=binding_ok,
        message=message,
    )


def _is_baselineable_finding(finding: Finding) -> bool:
    # A DEFECT is baselineable regardless of rule maturity: preview rules gate
    # exactly like stable ones (wardline-4ada23bb09), so a preview finding that
    # gates must be suppressible too — otherwise a preview FP could break the
    # build with no escape hatch. ``maturity`` is informational only.
    return finding.kind is Kind.DEFECT


def build_baseline_document(findings: Iterable[Finding]) -> dict[str, Any]:
    """Pure: the YAML-shaped dict for the given findings (deduped, severity-sorted)."""
    unique: dict[str, Finding] = {}
    for f in findings:
        if not _is_baselineable_finding(f):
            continue
        unique.setdefault(f.fingerprint, f)
    ordered = sorted(
        unique.values(),
        key=lambda f: (_SEVERITY_SORT[f.severity], f.rule_id, f.location.path, f.fingerprint),
    )
    return {
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "version": BASELINE_VERSION,
        "entries": [
            {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "path": f.location.path, "message": f.message}
            for f in ordered
        ],
    }


def write_baseline(path: Path, findings: Iterable[Finding], root: Path | None = None) -> None:
    yaml = require_yaml("writing baseline.yaml")
    text = yaml.safe_dump(
        build_baseline_document(findings), sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    if root is not None:
        safe_write_text(root, path, text, label=path.name)
    else:
        write_text_no_follow(path, text, label=path.name)


# NOTE: ``collect_and_write_baseline`` / ``generate_baseline`` (the scan-running
# orchestration) live in :mod:`wardline.core.baseline_ops`, NOT here. They call
# ``run.run_scan``; keeping them in this module made ``baseline`` (a policy-tier
# dependency of suppression/finding_identity) import the orchestrator and closed a
# real import cycle. This module stays pure baseline IO/derive.


def load_baseline(path: Path) -> Baseline:
    if not path.exists():
        return Baseline(frozenset())
    yaml = require_yaml("loading baseline.yaml")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    return _build_baseline(raw, path.name)


def _build_baseline(raw: Any, name: str = "baseline.yaml") -> Baseline:
    if not isinstance(raw, dict):
        raise ConfigError(f"{name}: must be a mapping at top level")
    if not raw:
        return Baseline(frozenset())
    # Loader order is load-bearing: empty-guard (above) → scheme → version.
    require_fingerprint_scheme(raw, store_name=name)
    if raw.get("version") != BASELINE_VERSION:
        raise ConfigError(f"{name}: version mismatch — expected {BASELINE_VERSION}, got {raw.get('version')!r}")
    entries = raw.get("entries")
    if entries is None:
        return Baseline(frozenset())
    if not isinstance(entries, list):
        raise ConfigError(f"{name}: 'entries' must be a list")
    fingerprints: set[str] = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"{name} entries[{idx}] must be a mapping")
        fp = entry.get("fingerprint")
        if not isinstance(fp, str) or len(fp) != 64 or not set(fp) <= _HEX:
            raise ConfigError(f"{name} entries[{idx}].fingerprint must be a 64-char lowercase hex string")
        if fp in fingerprints:
            raise ConfigError(f"{name} entries[{idx}]: duplicate fingerprint {fp!r}")
        fingerprints.add(fp)
    return Baseline(frozenset(fingerprints))
