"""WS-A2 live oracle (opt-in): scan->emit->file_finding against a real Filigree with
the /api/loom/findings/promote route. Skips cleanly until that route exists.

Run: WARDLINE_FILIGREE_URL=http://localhost:PORT/api/loom/scan-results \
     uv run pytest -m filigree_e2e
"""

import os

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
