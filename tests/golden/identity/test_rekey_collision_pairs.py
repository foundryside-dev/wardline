"""P3 rekey guard — multi-emit COLLISION-FREEDOM after the line_start drop.

When two findings share (rule_id, qualname) they are distinguished TODAY only by
absolute line_start. After P3 drops line_start from the hash, each multi-emit rule
must carry a source-derived entity-relative discriminator that keeps them distinct.
This is the `wardline-6102d4c833` regression net: GREEN today (line_start), and it
MUST STAY GREEN after S4 — if a multi-emit rule loses its discriminator it goes RED
here instead of silently collapsing in baseline.setdefault.

Runs in a tmp dir (non-corpus). The planted pairs are the worst cases:
- two same-COLUMN, different-LINE, SAME-LENGTH sink calls (so rel_line is the SOLE
  distinguisher — equal-length text keeps col/end_col identical, else the gate is
  vacuous);
- two broad `except` handlers (PY-WL-103);
- two silent handlers (PY-WL-104).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

pytest.importorskip("blake3", reason="run_scan identity path needs wardline[loomweave]")

from wardline.core.finding import Kind  # noqa: E402
from wardline.core.run import run_scan  # noqa: E402

_SRC = """\
from collections.abc import Sequence

from wardline.decorators import external_boundary, trusted


@external_boundary
def source(argv: Sequence[str]) -> str:
    return argv[0] if argv else ""


@trusted(level="ASSURED")
def two_sinks(argv: Sequence[str]) -> None:
    import subprocess

    aa = source(argv)
    bb = source(argv)
    subprocess.run(aa, shell=True)
    subprocess.run(bb, shell=True)


@trusted(level="ASSURED")
def two_broad(argv: Sequence[str]) -> None:
    try:
        _alpha(source(argv))
    except Exception:
        _log(1)
    try:
        _beta(source(argv))
    except Exception:
        _log(2)


@trusted(level="ASSURED")
def two_silent(argv: Sequence[str]) -> None:
    try:
        _gamma(source(argv))
    except Exception:
        pass
    try:
        _delta(source(argv))
    except Exception:
        pass
"""


def test_multiemit_pairs_stay_distinct(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text(_SRC, encoding="utf-8")

    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for f in run_scan(proj).findings:
        if f.kind is not Kind.DEFECT or f.qualname is None:
            continue
        groups[(f.rule_id, f.qualname)].append(f.fingerprint)

    multi = {k: v for k, v in groups.items() if len(v) > 1}
    # Non-vacuity: the three planted multi-emit groups must actually be present.
    assert ("PY-WL-112", "m.two_sinks") in multi, f"expected 2 sink findings in two_sinks; groups={dict(groups)}"
    assert ("PY-WL-103", "m.two_broad") in multi, f"expected 2 broad findings in two_broad; groups={dict(groups)}"
    assert ("PY-WL-104", "m.two_silent") in multi, f"expected 2 silent findings in two_silent; groups={dict(groups)}"

    collided = {k: v for k, v in multi.items() if len(set(v)) != len(v)}
    assert not collided, f"distinct findings in one (rule, qualname) share a fingerprint: {collided}"
