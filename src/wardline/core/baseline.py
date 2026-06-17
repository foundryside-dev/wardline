# src/wardline/core/baseline.py
"""The git-committable finding baseline (SP3).

A ``.weft/wardline/baseline.yaml`` is a snapshot of accepted findings keyed on the
full ``Finding.fingerprint`` (strict match — see spec §2 dial 1). The committed
file carries ``rule_id``/``path``/``message`` per entry for human auditability in
a git diff; only ``fingerprint`` is loaded into the match set. No governance.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wardline.core.errors import ConfigError
from wardline.core.finding import (
    FINGERPRINT_SCHEME,
    Finding,
    Kind,
    Maturity,
    Severity,
    SuppressionState,
    require_fingerprint_scheme,
)
from wardline.core.optional_deps import require_yaml
from wardline.core.paths import baseline_path as baseline_file
from wardline.core.safe_paths import safe_write_text, write_text_no_follow

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


def _is_baselineable_finding(finding: Finding) -> bool:
    return finding.kind is Kind.DEFECT and finding.maturity is not Maturity.PREVIEW


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


def collect_and_write_baseline(
    root: Path,
    *,
    overwrite: bool,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    confine_to_root: bool = True,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
) -> list[Finding]:
    """Derive the baselineable findings for ``root`` and write them to
    ``.weft/wardline/baseline.yaml``. Returns the findings that were baselined.

    Captures current stable DEFECTs, EXCLUDING preview findings that never gate
    and any with an active waiver (else the baseline swallows them and their
    expiry never resurfaces — spec §8).
    Honors ``config_path`` exactly as ``scan`` does, so the baseline is built
    from the same waiver set the scans will consume.

    Raises ``FileExistsError`` (with the baseline path as its message) if a
    baseline already exists and ``overwrite`` is False; the existence check
    runs *before* config load so a stale-but-present baseline is reported as
    such even when the config is broken.
    """
    # Lazy import to avoid an import cycle (run imports baseline loading helpers).
    from wardline.core.run import run_scan

    baseline_path = baseline_file(root)
    if baseline_path.exists() and not overwrite:
        raise FileExistsError(str(baseline_path))
    result = run_scan(
        root,
        config_path=config_path,
        cache_dir=cache_dir,
        confine_to_root=confine_to_root,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    to_baseline = [
        f
        for f in result.findings
        if _is_baselineable_finding(f) and f.suppressed is not SuppressionState.WAIVED
    ]
    # baseline_path is root-PREFIXED (weft_state_dir(root)/baseline.yaml). Pass it to the
    # root-confined writer as an ABSOLUTE path: a relative `root` (e.g. `wardline baseline
    # create pkg`) makes baseline_path `pkg/.weft/.../baseline.yaml`, which safe_write_text
    # would resolve under `pkg` AGAIN (`pkg/pkg/.weft/...`) — writing a baseline the next
    # scan of `pkg` never loads. .resolve() is idempotent for the absolute store_dir-override
    # form. run_scan still gets the original `root`, so finding paths are unchanged.
    write_baseline(baseline_path.resolve(), to_baseline, root=root)
    return to_baseline


def generate_baseline(
    root: Path,
    *,
    overwrite: bool,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    confine_to_root: bool = True,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
) -> int:
    """Derive a baseline from current findings and write it. Returns the number
    of fingerprints baselined. Raises ``FileExistsError`` if a baseline already
    exists and ``overwrite`` is False (shared by the CLI and MCP baseline
    surfaces)."""
    return len(
        collect_and_write_baseline(
            root,
            overwrite=overwrite,
            config_path=config_path,
            cache_dir=cache_dir,
            confine_to_root=confine_to_root,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
    )


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
