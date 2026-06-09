"""WP6 live e2e: the real ``wardline scan --lang rust`` CLI over the ``.rs`` corpus.

Deselected by default (marker ``rust_e2e``); run with:
    .venv/bin/pytest -m rust_e2e -v

Unlike the loomweave/legis/filigree e2es this needs no external server — only the
``wardline[rust]`` extra (tree-sitter). It shells out through the SAME interpreter
running the suite (``sys.executable``), so it exercises *this* worktree's wardline, not
whatever ``wardline`` console script happens to be on PATH (the editable-main hazard).
This is the only check that drives discovery → analyze → JSONL → gate → process exit
code as one real subprocess.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

pytestmark = pytest.mark.rust_e2e

_CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "rust"
# Run the CLI in-interpreter via -c so the worktree's wardline is imported (no PATH lookup).
_RUN_CLI = "from wardline.cli.entrypoint import main; main()"


def _scan(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _RUN_CLI, "scan", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_live_scan_rust_corpus_trips_gate_and_emits_findings(tmp_path) -> None:
    # The dense corpus file alone (clean file excluded so only true positives are present).
    work = tmp_path / "proj"
    work.mkdir()
    (work / "command_sink.rs").write_text((_CORPUS / "command_sink.rs").read_text(), encoding="utf-8")
    out = tmp_path / "findings.jsonl"

    proc = _scan([str(work), "--lang", "rust", "--fail-on", "ERROR", "--output", str(out)])

    assert proc.returncode == 1, proc.stderr  # gate tripped on the RS-WL-108 ERRORs
    assert "preview" in (proc.stdout + proc.stderr).lower()
    rule_ids = [json.loads(line)["rule_id"] for line in out.read_text().splitlines() if line.strip()]
    assert rule_ids.count("RS-WL-108") == 6
    assert rule_ids.count("RS-WL-112") == 3


def test_live_scan_rust_clean_corpus_exits_zero(tmp_path) -> None:
    work = tmp_path / "proj"
    work.mkdir()
    (work / "clean_commands.rs").write_text((_CORPUS / "clean_commands.rs").read_text(), encoding="utf-8")
    out = tmp_path / "findings.jsonl"

    proc = _scan([str(work), "--lang", "rust", "--fail-on", "ERROR", "--output", str(out)])
    assert proc.returncode == 0, proc.stderr
