"""`wardline scan` (Python) inert-gate visibility — Part A of wardline-bd9d1e65cb.

The Python counterpart of the Rust empty-trust-surface warning
(``test_scan_rust.py::test_scan_lang_rust_warns_on_empty_trust_surface``): a Python
scan over a codebase that declares NO wardline trust boundaries enforces nothing, so a
clean/green result there proves nothing. The CLI must say so loudly on stderr — that is
the false-green an armed ``--fail-on ERROR`` gate hides (the elspeth failure mode).
"""

from __future__ import annotations

from click.testing import CliRunner

from wardline.cli.scan import scan

# Six unannotated functions over a framework source/sink shape — no wardline trust
# markers anywhere, so the taint gate has nothing to enforce.
_INERT_APP = """\
from fastapi import Request
import subprocess

def a(r): return r.query_params.get("x")
def b(r): return a(r)
def c(r): subprocess.run(b(r), shell=True)
def d(r): return r.headers.get("h")
def e(r): return d(r)
def f(r): subprocess.run(e(r), shell=True)
"""

# Same shape but with a declared wardline boundary: the gate now has something to enforce.
_ANNOTATED_APP = """\
import subprocess
from wardline.decorators import external_boundary, trusted

@external_boundary
def read_raw(p):
    return p

@trusted(level="ASSURED")
def runs(p):
    subprocess.run(read_raw(p), shell=True)
"""


def test_armed_gate_warns_when_no_trust_boundaries(tmp_path) -> None:
    # An armed gate (--fail-on) that PASSES green while recognizing zero boundaries is the
    # false-assurance case — warn loudly.
    (tmp_path / "app.py").write_text(_INERT_APP, encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--fail-on", "ERROR", "--output", str(out)])
    assert result.exit_code == 0
    assert "INERT" in result.output
    assert "0 trust boundaries recognized" in result.output


def test_bare_scan_stays_quiet_even_when_inert(tmp_path) -> None:
    # No gate armed: `gate: NOT_EVALUATED` already says nothing was enforced, and the loud
    # banner would just be fatigue. The structured resolution.inert field still carries it.
    (tmp_path / "app.py").write_text(_INERT_APP, encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0
    assert "INERT" not in result.output


def test_armed_gate_quiet_when_boundaries_declared(tmp_path) -> None:
    # A declared boundary means the gate is enforcing — no inert warning even when armed.
    (tmp_path / "app.py").write_text(_ANNOTATED_APP, encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(scan, [str(tmp_path), "--fail-on", "ERROR", "--output", str(out)])
    assert "INERT" not in result.output
