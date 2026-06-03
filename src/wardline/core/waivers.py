# src/wardline/core/waivers.py
"""Human-authored finding waivers (SP3).

Waivers live inline in ``wardline.yaml`` under a ``waivers:`` list, each keyed on
a finding's full ``fingerprint`` (copied from scan output), with a REQUIRED reason
and an OPTIONAL ISO expiry date. An expired waiver stops suppressing (the finding
resurfaces). No governance.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from wardline.core.errors import ConfigError
from wardline.core.optional_deps import require_yaml
from wardline.core.safe_paths import safe_project_file

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


def add_waiver(
    config_path: Path,
    *,
    fingerprint: str,
    reason: str,
    expires: date | None,
    root: Path | None = None,
) -> Waiver:
    """Append a waiver to ``config_path``'s ``waivers:`` list (creating the file if
    absent). Validates via the SAME rules as :func:`parse_waivers`, so a bad
    fingerprint or empty reason raises :class:`ConfigError` BEFORE any write.

    ``expires`` is stored as an ISO string (``YYYY-MM-DD``) — the human-authored
    canonical form; both the in-line validation parse and a later
    ``load`` → ``parse_waivers`` round-trip accept it.
    """
    if root is not None:
        config_path = safe_project_file(root, config_path, label=config_path.name)
    entry: dict[str, object] = {"fingerprint": fingerprint, "reason": reason}
    if expires is not None:
        entry["expires"] = expires.isoformat()
    # Validate by parsing the single entry — reuses the canonical rules. Raises
    # ConfigError on a bad fingerprint/reason/expiry BEFORE the file is touched.
    waiver = parse_waivers((entry,))[0]

    yaml = require_yaml("updating wardline.yaml waivers")
    raw: dict[str, Any] = {}
    if config_path.exists():
        try:
            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"malformed {config_path.name}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError(f"{config_path.name} is not a mapping")
        raw = loaded
    existing = raw.get("waivers")
    if existing is not None and not isinstance(existing, list):
        raise ConfigError(f"malformed {config_path.name}: 'waivers' must be a list")
    waivers = list(existing or [])
    if any(isinstance(w, Mapping) and w.get("fingerprint") == fingerprint for w in waivers):
        raise ConfigError(f"waiver for {fingerprint} already exists")
    waivers.append(entry)
    raw["waivers"] = waivers
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        yaml.safe_dump(raw, sort_keys=False, default_flow_style=False, allow_unicode=True),
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
