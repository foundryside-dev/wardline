"""P3 rekey driver — ENTITY-RELATIVE fingerprint stability.

A benign comment inserted ABOVE a finding-bearing entity shifts every line number
but must NOT change the finding's fingerprint, because the discriminator is
entity-relative (offset from the enclosing def), not absolute. RED before P3 (the
hash still folds absolute line_start); GREEN after.

NOTE: this is "entity-relative", NOT "move-stable" in the strong sense — a comment
inserted INSIDE the function above the sink still shifts the relative offset (an
accepted limitation, wardline-8654423823). This test only exercises comment-above-
entity, the reported churn case.

Scans the SAME relative path twice (write -> scan -> overwrite -> scan) so the
`path` component of the fingerprint is held constant; runs in a tmp dir so the
frozen identity corpus is untouched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("blake3", reason="run_scan identity path needs wardline[loomweave]")

from wardline.core.finding import Kind  # noqa: E402
from wardline.core.run import run_scan  # noqa: E402

# One finding per (rule_id, qualname) so the non-fingerprint match key is unambiguous:
# a command-injection sink (PY-WL-108, call-site family) and a broad handler (PY-WL-103,
# handler-anchored) in distinct trusted functions.
_SRC = """\
from collections.abc import Sequence

from wardline.decorators import external_boundary, trusted


@external_boundary
def source(argv: Sequence[str]) -> str:
    return argv[0] if argv else ""


@trusted(level="ASSURED")
def runner(argv: Sequence[str]) -> object:
    import subprocess

    cmd = source(argv)
    return subprocess.run(cmd, shell=True)


@trusted(level="ASSURED")
def swallower(argv: Sequence[str]) -> None:
    try:
        _work(source(argv))
    except Exception:
        return None
"""

_COMMENT_ABOVE = "# audit: reviewed upstream — a benign comment that shifts every line below\n"


def _scan_fps(proj: Path) -> dict[tuple[str, str], str]:
    """Map (rule_id, qualname) -> fingerprint for the DEFECTs in one scan."""
    out: dict[tuple[str, str], str] = {}
    for f in run_scan(proj).findings:
        if f.kind is not Kind.DEFECT or f.qualname is None:
            continue
        key = (f.rule_id, f.qualname)
        assert key not in out, f"fixture must emit ONE finding per (rule, qualname); got 2 for {key}"
        out[key] = f.fingerprint
    return out


def test_comment_above_entity_keeps_fingerprint(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    mod = proj / "m.py"

    mod.write_text(_SRC, encoding="utf-8")
    before = _scan_fps(proj)

    mod.write_text(_COMMENT_ABOVE + _SRC, encoding="utf-8")
    after = _scan_fps(proj)

    # Non-vacuity: the fixture really produces both move-prone families — a call-site
    # sink (PY-WL-112 here: subprocess shell=True) and a handler-anchored broad except.
    rules = {rule for rule, _ in before}
    _CALL_SITE = {
        "PY-WL-105",
        "PY-WL-106",
        "PY-WL-107",
        "PY-WL-108",
        "PY-WL-112",
        "PY-WL-115",
        "PY-WL-116",
        "PY-WL-117",
        "PY-WL-118",
        "PY-WL-120",
    }
    assert rules & _CALL_SITE, f"expected a call-site sink finding; got {sorted(rules)}"
    assert "PY-WL-103" in rules, f"expected a broad-handler finding; got {sorted(rules)}"

    assert before.keys() == after.keys(), "the same findings must surface before and after the benign comment"
    drifted = {k: (before[k], after[k]) for k in before if before[k] != after[k]}
    assert not drifted, f"benign comment above the entity churned the fingerprint for: {drifted}"
