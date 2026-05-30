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
from typing import Any

from wardline.core.errors import ConfigError

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
            raise ConfigError(f"waivers[{idx}].fingerprint must be a 64-char hex string")
        if fp in seen:
            raise ConfigError(f"waivers[{idx}]: duplicate fingerprint {fp!r}")
        seen.add(fp)
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ConfigError(f"waivers[{idx}].reason is required (non-empty string)")
        waivers.append(Waiver(fingerprint=fp, reason=reason, expires=_parse_expiry(item.get("expires"), idx)))
    return tuple(waivers)


class WaiverSet:
    """Fingerprint → waiver lookup with expiry-aware matching."""

    def __init__(self, waivers: Iterable[Waiver]) -> None:
        self._by_fp: dict[str, Waiver] = {w.fingerprint: w for w in waivers}

    def match(self, fingerprint: str, today: date) -> Waiver | None:
        waiver = self._by_fp.get(fingerprint)
        if waiver is None or not waiver.is_active(today):
            return None
        return waiver
