# src/wardline/core/waivers.py
"""Finding waivers (SP3).

Waivers are machine-written state (via the MCP ``waiver_add`` tool) under
``.weft/wardline/waivers.yaml`` (the
member-owned subtree), a ``waivers:`` list each keyed on a finding's full
``fingerprint`` (copied from scan output), with a REQUIRED reason and an OPTIONAL
ISO expiry date. They are fingerprint-keyed entries an operator never hand-authors,
so they live in wardline's own state — NOT in the read-only operator ``weft.toml``.
An expired waiver stops suppressing (the finding resurfaces). No governance.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from wardline.core.errors import ConfigError
from wardline.core.finding import FINGERPRINT_SCHEME, require_fingerprint_scheme
from wardline.core.optional_deps import require_yaml
from wardline.core.paths import waivers_path
from wardline.core.safe_paths import safe_project_file

WAIVERS_VERSION: int = 1
"""Bumped on a format change; validated on load (mirrors BASELINE_VERSION)."""

_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class Waiver:
    fingerprint: str
    reason: str
    expires: date | None = None

    def is_active(self, today: date) -> bool:
        """Active through the expiry day; expired strictly after (today > expires)."""
        return self.expires is None or today <= self.expires


def _parse_expiry(raw: Any, idx: int) -> date | None:
    if raw is None:
        return None
    if isinstance(raw, datetime):  # datetime IS-A date — check it FIRST
        return raw.date()
    if isinstance(raw, date):
        return raw
    if isinstance(raw, str):
        try:
            return date.fromisoformat(raw)
        except ValueError as exc:
            raise ConfigError(f"waivers[{idx}].expires {raw!r} is not an ISO date (YYYY-MM-DD)") from exc
    raise ConfigError(f"waivers[{idx}].expires must be a date or ISO string, got {type(raw).__name__}")


def parse_waivers(raw: Sequence[Mapping[str, Any]]) -> tuple[Waiver, ...]:
    if not raw:
        return ()
    waivers: list[Waiver] = []
    seen: set[str] = set()
    for idx, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ConfigError(f"waivers[{idx}] must be a mapping")
        fp = item.get("fingerprint")
        if not isinstance(fp, str) or len(fp) != 64 or not set(fp) <= _HEX:
            raise ConfigError(f"waivers[{idx}].fingerprint must be a 64-char lowercase hex string")
        if fp in seen:
            raise ConfigError(f"waivers[{idx}]: duplicate fingerprint {fp!r}")
        seen.add(fp)
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ConfigError(f"waivers[{idx}].reason is required (non-empty string)")
        waivers.append(Waiver(fingerprint=fp, reason=reason, expires=_parse_expiry(item.get("expires"), idx)))
    return tuple(waivers)


def build_waivers_document(waivers: Iterable[Waiver]) -> dict[str, Any]:
    """Pure: the YAML-shaped dict (scheme header + version + waivers) for the
    given waivers, preserving caller order. ``add_waiver`` writes its own
    header inline (it preserves existing raw entries verbatim); this is the
    object→document path the rekey migration (P4) writes through."""
    entries: list[dict[str, Any]] = []
    for w in waivers:
        entry: dict[str, Any] = {"fingerprint": w.fingerprint, "reason": w.reason}
        if w.expires is not None:
            entry["expires"] = w.expires.isoformat()
        entries.append(entry)
    return {"fingerprint_scheme": FINGERPRINT_SCHEME, "version": WAIVERS_VERSION, "waivers": entries}


def load_project_waivers(root: Path) -> tuple[Waiver, ...]:
    """Read wardline's machine-written waivers from ``.weft/wardline/waivers.yaml``.

    Absent file → empty tuple. Validates via the same rules as :func:`parse_waivers`,
    so a malformed entry fails loud (a finding must not be silently suppressed by a
    bad waiver record).
    """
    path = waivers_path(root)
    if not path.is_file():
        return ()
    yaml = require_yaml("loading waivers")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path.name} is not a mapping")
    # Loader order is load-bearing: empty-guard → scheme → version → entries.
    if not loaded:
        return ()
    require_fingerprint_scheme(loaded, store_name=path.name)
    if loaded.get("version") != WAIVERS_VERSION:
        raise ConfigError(f"{path.name}: version mismatch — expected {WAIVERS_VERSION}, got {loaded.get('version')!r}")
    raw = loaded.get("waivers")
    if raw is not None and not isinstance(raw, list):
        raise ConfigError(f"malformed {path.name}: 'waivers' must be a list")
    return parse_waivers(raw or ())


def add_waiver(
    path: Path,
    *,
    fingerprint: str,
    reason: str,
    expires: date | None,
    root: Path | None = None,
) -> Waiver:
    """Append a waiver to the ``waivers:`` list in ``path`` — wardline's machine/CLI
    state file ``.weft/wardline/waivers.yaml`` (creating it if absent). Validates via
    the SAME rules as :func:`parse_waivers`, so a bad fingerprint or empty reason
    raises :class:`ConfigError` BEFORE any write.

    ``expires`` is stored as an ISO string (``YYYY-MM-DD``); both the in-line
    validation parse and a later ``parse_waivers`` round-trip accept it.
    """
    config_path = path
    if root is not None:
        config_path = safe_project_file(root, config_path, label=config_path.name)
    entry: dict[str, object] = {"fingerprint": fingerprint, "reason": reason}
    if expires is not None:
        entry["expires"] = expires.isoformat()
    # Validate by parsing the single entry — reuses the canonical rules. Raises
    # ConfigError on a bad fingerprint/reason/expiry BEFORE the file is touched.
    waiver = parse_waivers((entry,))[0]

    yaml = require_yaml("updating waivers")
    raw: dict[str, Any] = {}
    if config_path.exists():
        try:
            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"malformed {config_path.name}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError(f"{config_path.name} is not a mapping")
        # A non-empty existing store must already carry the current scheme — else
        # appending a current-scheme fingerprint to an old-scheme file would mint a
        # mixed, silently-orphaning store. (Empty/absent → fresh write below.)
        if loaded:
            require_fingerprint_scheme(loaded, store_name=config_path.name)
        raw = loaded
    existing = raw.get("waivers")
    if existing is not None and not isinstance(existing, list):
        raise ConfigError(f"malformed {config_path.name}: 'waivers' must be a list")
    waivers = list(existing or [])
    if any(isinstance(w, Mapping) and w.get("fingerprint") == fingerprint for w in waivers):
        raise ConfigError(f"waiver for {fingerprint} already exists")
    waivers.append(entry)
    # Re-stamp the scheme header (idempotent) and place it first for readability.
    document = {"fingerprint_scheme": FINGERPRINT_SCHEME, "version": WAIVERS_VERSION, "waivers": waivers}
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )
    return waiver


class WaiverSet:
    """Fingerprint → waiver lookup with expiry-aware matching."""

    def __init__(self, waivers: Iterable[Waiver]) -> None:
        self._by_fp: dict[str, Waiver] = {w.fingerprint: w for w in waivers}

    def match(self, fingerprint: str, today: date) -> Waiver | None:
        waiver = self._by_fp.get(fingerprint)
        if waiver is None or not waiver.is_active(today):
            return None
        return waiver
