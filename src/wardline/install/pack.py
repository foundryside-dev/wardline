# src/wardline/install/pack.py
"""`wardline install` pack activation helper."""

from __future__ import annotations


def activate_pack(pack_name: str) -> str:
    """Return operator guidance for activating a trust-grammar pack.

    Packs import and execute code (see the ``_is_local_pack`` guard in
    ``core/config``), so they MUST be operator-authored — wardline never writes the
    shared, read-only ``weft.toml``. This emits the snippet for the operator to add
    by hand; runtime trust is still asserted separately via ``--trust-pack``.
    """
    return (
        f"To activate trust-grammar pack {pack_name!r}, add it to weft.toml under "
        f'[wardline]:\n\n    [wardline]\n    packs = ["{pack_name}"]\n\n'
        f"then pass --trust-pack {pack_name} at scan/judge time."
    )
