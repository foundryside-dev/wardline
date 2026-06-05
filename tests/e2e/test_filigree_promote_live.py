"""WS-A2 live oracle (opt-in): scan->emit->file_finding against a real Filigree with
the /api/loom/findings/promote route. Skips cleanly until that route exists.

Run: WARDLINE_FILIGREE_URL=http://localhost:PORT/api/loom/scan-results \
     uv run pytest -m filigree_e2e
"""

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.filigree_e2e

_URL = os.environ.get("WARDLINE_FILIGREE_URL")

_SRC = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _promote_route_live(url: str) -> bool:
    import urllib.error
    import urllib.request

    from wardline.core.filigree_issue import promote_url_from_loom

    req = urllib.request.Request(
        promote_url_from_loom(url),
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)  # noqa: S310
        return True
    except urllib.error.HTTPError as exc:
        return exc.code != 404  # route exists if it answers anything but 404-not-routed
    except OSError:
        return False


@pytest.mark.skipif(not _URL, reason="set WARDLINE_FILIGREE_URL to run the live promote oracle")
def test_scan_emit_then_file_finding(tmp_path):
    if not _promote_route_live(_URL):
        pytest.skip("Filigree promote route /api/loom/findings/promote not available (ask #1 not shipped)")
    from wardline.core.filigree_emit import FiligreeEmitter
    from wardline.core.filigree_issue import FiligreeIssueFiler
    from wardline.core.run import run_scan

    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    result = run_scan(tmp_path)
    finding = next(f for f in result.findings if f.rule_id == "PY-WL-101")
    emit = FiligreeEmitter(_URL).emit(result.findings)
    assert emit.reachable
    res = FiligreeIssueFiler(_URL).file(finding.fingerprint, priority="P2")
    assert res.reachable and res.issue_id and not res.not_found
    # Idempotent: re-filing returns the same issue, created=False.
    again = FiligreeIssueFiler(_URL).file(finding.fingerprint)
    assert again.issue_id == res.issue_id and again.created is False


# --- WS-A2 close-on-fixed lifecycle (ask #3 + #3b) ---------------------------
#
# Asserts the headline DoD of wardline-7a56cd1b83: file finding -> issue opens;
# fix the code + re-scan -> issue CLOSES (without any clean-stale call); regress
# -> issue REOPENS. The close is driven purely by Wardline's normal emit, which
# already POSTs mark_unseen=True plus the full scanned_paths set (clean files
# included) so Filigree can reconcile a file whose last finding disappeared.
#
# Per-run unique token in the function name keeps each run's PY-WL-101
# fingerprint distinct (so reruns don't collide in the live Filigree DB) while
# staying stable within a run across the tainted -> clean -> tainted re-scans.


def _tainted_src(token: str) -> str:
    return (
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        f"@trusted\ndef leaky_{token}(p):\n    return read_raw(p)\n"
    )


def _clean_src(token: str) -> str:
    # Same function, taint flow removed -> no PY-WL-101. svc.py is still scanned,
    # so it rides out in scanned_paths and the prior finding is swept to unseen.
    return (
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        f"@trusted\ndef leaky_{token}(p):\n    return 'constant'\n"
    )


def _issue_status_category(loom_url: str, issue_id: str) -> str | None:
    """GET the issue's status_category from the live Filigree (None if absent)."""
    import json
    import urllib.parse
    import urllib.request

    from wardline.core.filigree_issue import api_base_url_from_loom

    base = api_base_url_from_loom(loom_url)
    url = f"{base}/issue/{urllib.parse.quote(issue_id, safe='')}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        payload = json.loads(resp.read().decode("utf-8"))
    return payload.get("status_category") if isinstance(payload, dict) else None


def _open_tainted_issue(tmp_path: Path) -> tuple[Path, str, str]:
    """Scan a tainted svc.py, emit, and file the finding -> an OPEN tracked issue.

    Returns (svc_path, token, issue_id). The caller drives the close.
    """
    import uuid

    from wardline.core.filigree_emit import FiligreeEmitter
    from wardline.core.filigree_issue import FiligreeIssueFiler
    from wardline.core.run import run_scan

    # Unique filename per run: the path Filigree stores is relative to the scan
    # root (just the filename), and scan_source is always "wardline", so a shared
    # name would let one test's emit sweep another test's finding to unseen and
    # close its issue. A per-run name isolates each test's (file, scan_source).
    token = uuid.uuid4().hex[:8]
    svc = tmp_path / f"svc_{token}.py"
    svc.write_text(_tainted_src(token), encoding="utf-8")
    result = run_scan(tmp_path)
    finding = next(f for f in result.findings if f.rule_id == "PY-WL-101")
    assert FiligreeEmitter(_URL).emit(result.findings, scanned_paths=result.scanned_paths).reachable
    filed = FiligreeIssueFiler(_URL).file(finding.fingerprint, priority="P2")
    assert filed.reachable and filed.issue_id and not filed.not_found
    assert _issue_status_category(_URL, filed.issue_id) != "done"  # opened, not closed
    return svc, token, filed.issue_id


@pytest.mark.skipif(not _URL, reason="set WARDLINE_FILIGREE_URL to run the live close-on-fixed oracle")
def test_close_on_fixed_then_reopen(tmp_path):
    """file -> open; fix + re-scan -> CLOSE; regress -> REOPEN (no clean-stale)."""
    if not _promote_route_live(_URL):
        pytest.skip("Filigree promote route /api/loom/findings/promote not available (ask #1 not shipped)")
    from wardline.core.filigree_emit import FiligreeEmitter
    from wardline.core.run import run_scan

    svc, _token, issue_id = _open_tainted_issue(tmp_path)

    # Fix the code: re-scan is clean -> finding absent from the batch but svc.py
    # rides out in scanned_paths -> Filigree sweeps it to unseen and closes the issue.
    svc.write_text(_clean_src(_token), encoding="utf-8")
    r2 = run_scan(tmp_path)
    assert not any(f.rule_id == "PY-WL-101" for f in r2.findings)
    assert FiligreeEmitter(_URL).emit(r2.findings, scanned_paths=r2.scanned_paths).reachable
    assert _issue_status_category(_URL, issue_id) == "done", "close-on-fixed did not close the issue"

    # Regress: the finding returns -> Filigree reopens the cascade-closed issue.
    svc.write_text(_tainted_src(_token), encoding="utf-8")
    r3 = run_scan(tmp_path)
    assert any(f.rule_id == "PY-WL-101" for f in r3.findings)
    assert FiligreeEmitter(_URL).emit(r3.findings, scanned_paths=r3.scanned_paths).reachable
    assert _issue_status_category(_URL, issue_id) != "done", "reopen-on-regress did not reopen the issue"


@pytest.mark.skipif(not _URL, reason="set WARDLINE_FILIGREE_URL to run the live close-on-fixed oracle")
def test_close_on_fixed_via_cli(tmp_path):
    """The real `wardline scan --filigree-url` command closes the issue on fix."""
    if not _promote_route_live(_URL):
        pytest.skip("Filigree promote route /api/loom/findings/promote not available (ask #1 not shipped)")
    from click.testing import CliRunner

    from wardline.cli.scan import scan

    svc, token, issue_id = _open_tainted_issue(tmp_path)
    svc.write_text(_clean_src(token), encoding="utf-8")
    result = CliRunner().invoke(scan, [str(tmp_path), "--filigree-url", _URL])
    assert result.exit_code == 0, result.output
    assert _issue_status_category(_URL, issue_id) == "done", "CLI scan did not close the issue on fix"


@pytest.mark.skipif(not _URL, reason="set WARDLINE_FILIGREE_URL to run the live close-on-fixed oracle")
def test_close_on_fixed_via_mcp(tmp_path):
    """The MCP `scan` tool closes the issue on fix (same emit path as the CLI)."""
    if not _promote_route_live(_URL):
        pytest.skip("Filigree promote route /api/loom/findings/promote not available (ask #1 not shipped)")
    from wardline.core.filigree_emit import FiligreeEmitter
    from wardline.mcp.server import _scan

    svc, token, issue_id = _open_tainted_issue(tmp_path)
    svc.write_text(_clean_src(token), encoding="utf-8")
    _scan({}, tmp_path, filigree=FiligreeEmitter(_URL))
    assert _issue_status_category(_URL, issue_id) == "done", "MCP scan did not close the issue on fix"
