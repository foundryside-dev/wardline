"""FROZEN wlfp1 fingerprint formula — migration-only (`wardline rekey`, P4).

A byte-exact copy of ``compute_finding_fingerprint`` as it stood BEFORE P3
(commit ``966cd9f``) dropped ``line_start`` from the hash: the wlfp1 formula with
``str(line_start)`` IN the parts. The migration computes each finding's OLD
fingerprint with this and its NEW fingerprint with the live engine, from a single
scan, to carry baseline/judged/waiver verdicts across the wlfp1->wlfp2 value change.

This module is NEVER imported by the production scan path — it lives apart so the
identity oracle stays byte-green and so this formula can never be "fixed" again.
It is frozen: do not edit it to track the live engine. ``FINGERPRINT_SCHEME_V0`` is
the scheme label a wlfp1 store carries (P1 stamped it).
"""

from __future__ import annotations

import hashlib

FINGERPRINT_SCHEME_V0 = "wlfp1"


def compute_finding_fingerprint_v0(
    *,
    rule_id: str,
    path: str,
    line_start: int | None,
    qualname: str | None = None,
    taint_path: str | None = None,
) -> str:
    digest = hashlib.sha256()
    parts = (rule_id, path, str(line_start), qualname or "", taint_path or "")
    digest.update("\x00".join(parts).encode())
    return digest.hexdigest()
