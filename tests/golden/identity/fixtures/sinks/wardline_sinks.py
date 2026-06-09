"""Sink-family identity fixture for the parity oracle (weft-4a9d0f863c).

Mirrors the shape that exposed the fingerprint-instability bug: a ``@trusted``
"admin/export" surface where an operator-supplied string reaches a spread of
dangerous sinks. It exercises the call-site-anchored rules (PY-WL-106/108/116/
117/118 + PY-WL-101 + PY-WL-120) whose fingerprints fold a per-call discriminator,
so the corpus freezes a *resolution-invariant* join key across many rules — not
just the two boundary rules the original two fixtures covered.

Permanent demonstration fixtures — do NOT "fix" the planted flaws.
"""

from __future__ import annotations

import importlib
import pickle
import sqlite3
import subprocess
from collections.abc import Sequence

from wardline.decorators import external_boundary, trusted


@external_boundary
def read_admin_arg(argv: Sequence[str]) -> str:
    """An operator-supplied string crossing the admin boundary (untrusted)."""
    return argv[0] if argv else ""


@trusted(level="ASSURED")
def import_catalog_blob(argv: Sequence[str]) -> object:
    """Untrusted bytes reach a deserialization sink (PY-WL-106)."""
    blob = read_admin_arg(argv).encode()
    return pickle.loads(blob)  # noqa: S301


@trusted(level="ASSURED")
def run_export(argv: Sequence[str]) -> object:
    """Untrusted text reaches a shell/command sink (PY-WL-108)."""
    cmd = read_admin_arg(argv)
    return subprocess.run(cmd, shell=True, check=False)  # noqa: S602


@trusted(level="ASSURED")
def load_report_plugin(argv: Sequence[str]) -> object:
    """Untrusted text reaches a dynamic-import sink (PY-WL-115)."""
    name = read_admin_arg(argv)
    return importlib.import_module(name)


@trusted(level="ASSURED")
def open_catalog_file(argv: Sequence[str]) -> str:
    """Untrusted text reaches a filesystem-path sink (PY-WL-116)."""
    path = read_admin_arg(argv)
    with open(path, encoding="utf-8") as fh:  # noqa: PTH123
        return fh.read()


@trusted(level="ASSURED")
def _refine_a(x: object) -> object:
    return x


@trusted(level="ASSURED")
def _refine_b(x: object) -> object:
    return x


@trusted(level="ASSURED")
def fan_out_stored(argv: Sequence[str], db: object) -> tuple[object, object]:
    """Two trusted-callee call sites on ONE physical line — exercises the per-call
    discriminator for PY-WL-105 (untrusted->trusted-callee) and PY-WL-120 (stored
    arg) so the collision gate is non-vacuous for those rules, not only PY-WL-106/118."""
    stored = db.fetchone()  # type: ignore[attr-defined]
    return _refine_a(stored), _refine_b(stored)


@trusted(level="ASSURED")
def double_deserialize(argv: Sequence[str]) -> tuple[object, object]:
    """Two deserialization sinks (same rule, same name) on ONE physical line —
    distinct call nodes MUST get distinct fingerprints via the per-call column
    discriminator, so neither finding is silently dropped on the join key."""
    blob = read_admin_arg(argv).encode()
    return pickle.loads(blob), pickle.loads(blob)  # noqa: S301


@trusted(level="ASSURED")
def chained_queries(argv: Sequence[str]) -> object:
    """Two SQL sinks CHAINED on ONE physical line — both ``execute`` calls share a
    start column under CPython's whole-span anchor, so a start-column-only
    discriminator would collapse them. The full-span discriminator must keep the
    two distinct findings on distinct fingerprints (weft-4a9d0f863c collision gate)."""
    name = read_admin_arg(argv)
    conn = sqlite3.connect(":memory:")
    return conn.cursor().execute(f"SELECT {name}").execute(f"DELETE {name}")  # noqa: S608


@trusted(level="BOGUS")
@trusted(level="BOGUS")
def stacked_invalid_levels(p: object) -> object:
    """Two stacked identical invalid trust decorators on ONE def — PY-WL-114 emits one
    finding per decorator, anchored at the ENTITY line (not the decorator). The two findings
    share name, token, AND entity line, so the discriminator must carry each decorator's
    POSITION in the decorator_list (its ordinal) — a move-stable within-def index that keeps
    the two join keys distinct without using absolute lines or columns (wardline-377b896a87
    collision gate). Isolated trivial body — no sinks — so it perturbs no other finding."""
    return p


@trusted(level="ASSURED")
def lookup_member(argv: Sequence[str]) -> list[object]:
    """Untrusted text reaches a SQL execution sink (PY-WL-118); the returned
    cursor read is also stored/persisted data leaving a trusted producer
    (PY-WL-101 / PY-WL-120) — the exact shape whose resolved return tier drifted."""
    name = read_admin_arg(argv)
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM members WHERE name = '{name}'")  # noqa: S608
    return cur.fetchall()
