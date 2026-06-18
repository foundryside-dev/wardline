"""Live `warpline reverify | wardline scan --affected -` round-trip oracle.

Deselected by default (marker ``warpline_e2e``); run with:
    WARDLINE_WARPLINE_BIN=<path> .venv/bin/pytest -m warpline_e2e -v

This is the ONLY oracle that exercises the real producer→consumer delta seam: a
live ``warpline`` binary computes a ``warpline.reverify_worklist.v1`` over a small
sample tree, and wardline consumes it through the same stdin path an agent would
(`warpline reverify | wardline scan --affected -`). The hermetic golden
(`test_warpline_delta_scope.py`) vendors the worklist shape and runs on every PR;
this one proves the live wire — that a real warpline emits something wardline's
parser accepts and scopes against, end to end.

Auto-skips cleanly when no ``warpline`` binary is resolvable (same shape as the
loomweave / legis oracles), so default CI is never affected. The scheduled /
``workflow_dispatch`` ``live-oracles`` matrix runs it FAIL-CLOSED
(`WARDLINE_LIVE_ORACLE_REQUIRED=1` turns the skip into a failure via the conftest
hook), so a missing binary in the required run fails instead of passing green.

The warpline invocation is kept tolerant on purpose: warpline owns its own CLI
surface, so this oracle resolves the binary, runs ``reverify`` over the sample
tree, and skips with a specific reason if the producer cannot emit a worklist —
it asserts on wardline's side of the seam (exit code + scope block + analyzed ⊆
discovery), never on warpline's internal output shape beyond "is parseable JSON".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from shutil import which

import pytest

pytestmark = pytest.mark.warpline_e2e

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _wardline_cli() -> str:
    """The wardline console script next to the running interpreter (installed by the
    project's ``[project.scripts]`` entry point), falling back to PATH."""
    candidate = Path(sys.executable).parent / "wardline"
    if candidate.is_file():
        return str(candidate)
    on_path = which("wardline")
    if on_path is not None:
        return on_path
    pytest.skip("wardline console script not found next to the interpreter or on PATH")


def _resolve_warpline() -> str | None:
    """Pick an explicit binary first, then PATH, then local builds — mirrors the
    loomweave oracle's resolution so a valid build is never skipped for a missing
    PATH entry."""
    candidates: list[str | None] = [
        os.environ.get("WARDLINE_WARPLINE_BIN"),
        which("warpline"),
        str(Path.home() / "warpline" / "target" / "release" / "warpline"),
        str(Path.home() / "warpline" / "target" / "debug" / "warpline"),
    ]
    for cand in candidates:
        if cand and Path(cand).is_file():
            return cand
    return None


def _run_reverify(warpline_bin: str, proj: Path) -> str:
    """Run ``warpline reverify`` over the sample tree and return its JSON stdout.

    Drives the real producer CLI (`warpline reverify --repo <r> --changed-entity-key-id
    <int> --json`; ``--changed-entity-key-id`` is a loomweave entity key id). Skips with
    a specific reason if the producer cannot emit a parseable worklist — the contract this
    oracle pins is wardline's consumption of whatever warpline emits, not warpline's
    internal worklist completeness (a NO_SNAPSHOT worklist with null locators is a valid
    producer output and exercises the consumer's empty-scope → full-fallback path)."""
    argv = [
        warpline_bin,
        "reverify",
        "--repo",
        str(proj),
        "--changed-entity-key-id",
        "1",
        "--json",
    ]
    try:
        proc = subprocess.run(  # noqa: S603 — test-local, operator-supplied binary
            argv,
            cwd=str(proj),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except OSError as exc:  # binary not executable / spawn failure
        pytest.skip(f"warpline reverify could not be spawned: {exc}")
    if proc.returncode != 0:
        pytest.skip(f"warpline reverify rc={proc.returncode}: {proc.stderr.strip()[-300:]}")
    out = proc.stdout.strip()
    if not out:
        pytest.skip("warpline reverify produced empty stdout")
    try:
        json.loads(out)
    except json.JSONDecodeError as exc:
        pytest.skip(f"warpline reverify stdout is not JSON: {exc}")
    return out


def test_warpline_reverify_into_wardline_affected_round_trip(tmp_path: Path) -> None:
    warpline_bin = _resolve_warpline()
    if warpline_bin is None:
        pytest.skip(
            "no warpline binary found; set WARDLINE_WARPLINE_BIN to a warpline build "
            "(or put `warpline` on PATH) to run the live delta-scope oracle"
        )

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")

    # Producer half: warpline computes the reverify worklist over the sample tree.
    worklist = _run_reverify(warpline_bin, proj)

    # Consumer half: pipe the worklist into `wardline scan --affected -` exactly as an
    # agent would. agent-summary carries the `scope` block as a top-level key; write it
    # to an explicit path so we read the block back regardless of stdout chatter.
    summary_path = proj / "summary.json"
    scan = subprocess.run(  # noqa: S603 — test-local invocation of our own CLI
        [
            _wardline_cli(),
            "scan",
            str(proj),
            "--affected",
            "-",
            "--format",
            "agent-summary",
            "--output",
            str(summary_path),
        ],
        input=worklist,
        capture_output=True,
        text=True,
        timeout=120,
    )

    # Exit code: a clean tree gates green (0); a finding-driven non-green is also an
    # acceptable outcome (1). A wardline-internal error (2) is a real failure of the seam.
    assert scan.returncode in (0, 1), (
        f"wardline scan --affected - errored (rc={scan.returncode}):\n{scan.stderr.strip()[-1000:]}"
    )

    assert summary_path.is_file(), f"no agent-summary written; stderr:\n{scan.stderr[-1000:]}"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    # The scope block is the load-bearing proof the delta seam fired end to end.
    scope = summary.get("scope")
    assert scope is not None, f"agent-summary carried no scope block: {summary!r}"
    assert scope["mode"] in {"delta", "full-fallback"}, scope["mode"]

    # Analyzed set is a subset of discovery (equal only in full-fallback). This is the
    # core invariant the oracle pins on the live wire: a producer-supplied scope never
    # widens analysis beyond what discovery found.
    files_discovered = scope["files_discovered"]
    files_analyzed = scope["files_analyzed"]
    assert isinstance(files_discovered, int) and isinstance(files_analyzed, int)
    assert files_analyzed <= files_discovered
    if scope["mode"] == "full-fallback":
        assert files_analyzed == files_discovered
