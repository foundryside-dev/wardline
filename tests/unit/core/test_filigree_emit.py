from __future__ import annotations

import json

import pytest

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import (
    EmitResult,
    FiligreeEmitter,
    Response,
    build_scan_results_body,
)
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState


def _f(**kw: object) -> Finding:
    base: dict[str, object] = dict(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/m.py", line_start=5, line_end=6),
        fingerprint="a" * 64,
    )
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


# --- body builder ------------------------------------------------------------


def test_body_envelope() -> None:
    body = build_scan_results_body([_f()])
    assert body["scan_source"] == "wardline"
    assert isinstance(body["findings"], list) and len(body["findings"]) == 1


def test_finding_uses_path_not_file_path() -> None:
    wire = build_scan_results_body([_f()])["findings"][0]
    assert wire["path"] == "src/m.py"
    assert "file_path" not in wire


def test_fingerprint_is_top_level_and_severity_lowercased() -> None:
    wire = build_scan_results_body([_f()])["findings"][0]
    assert wire["fingerprint"] == "a" * 64
    assert wire["severity"] == "high"  # ERROR -> high
    assert wire["language"] == "python"
    assert wire["line_start"] == 5 and wire["line_end"] == 6


def test_metadata_namespaced_and_carries_suppression() -> None:
    wire = build_scan_results_body([_f(suppressed=SuppressionState.WAIVED, suppression_reason="fp")])["findings"][0]
    assert set(wire["metadata"]) == {"wardline"}
    assert wire["metadata"]["wardline"]["suppressed"] == "waived"
    assert wire["metadata"]["wardline"]["suppression_reason"] == "fp"


def test_suggestion_capped_at_10k_and_omitted_when_none() -> None:
    none_wire = build_scan_results_body([_f()])["findings"][0]
    assert "suggestion" not in none_wire
    long = "x" * 20000
    capped = build_scan_results_body([_f(suggestion=long)])["findings"][0]["suggestion"]
    assert len(capped) == 10000  # exact boundary, not just <=
    exact = build_scan_results_body([_f(suggestion="y" * 10000)])["findings"][0]["suggestion"]
    assert exact == "y" * 10000  # at-limit passes through untouched


def test_all_kinds_emitted() -> None:
    findings = [_f(kind=k, severity=Severity.NONE if k is not Kind.DEFECT else Severity.ERROR) for k in Kind]
    body = build_scan_results_body(findings)
    assert len(body["findings"]) == len(list(Kind))
    fact = next(w for w, f in zip(body["findings"], findings, strict=True) if f.kind is Kind.FACT)
    assert fact["severity"] == "info"


# --- emitter -----------------------------------------------------------------


class _FakeTransport:
    def __init__(self, response: Response | None = None, exc: Exception | None = None) -> None:
        self._response, self._exc = response, exc
        self.calls: list[tuple[str, bytes]] = []

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> Response:
        self.calls.append((url, body))
        if self._exc is not None:
            raise self._exc
        assert self._response is not None
        return self._response


def _ok_body() -> str:
    return json.dumps(
        {
            "succeeded": ["id1"],
            "failed": [],
            "stats": {"findings_created": 1, "findings_updated": 0},
            "warnings": ["severity coerced"],
        }
    )


def test_success_surfaces_stats_and_warnings() -> None:
    t = _FakeTransport(response=Response(status=200, body=_ok_body()))
    res = FiligreeEmitter("http://x/api/loom/scan-results", transport=t).emit([_f()])
    assert res.reachable is True
    assert res.created == 1
    assert res.warnings == ("severity coerced",)
    assert t.calls[0][0] == "http://x/api/loom/scan-results"
    assert json.loads(t.calls[0][1])["scan_source"] == "wardline"


def test_http_400_raises_filigree_emit_error() -> None:
    t = _FakeTransport(response=Response(status=400, body='{"error":"bad path key"}'))
    with pytest.raises(FiligreeEmitError) as exc:
        FiligreeEmitter("http://x", transport=t).emit([_f()])
    assert '{"error":"bad path key"}' in str(exc.value)  # verbatim response body echoed


def test_http_5xx_is_sibling_degraded_not_loud() -> None:
    # A server outage (503) is the sibling's fault, not a Wardline payload bug:
    # warn + continue (reachable=False), never exit-2. (Charter: non-load-bearing.)
    t = _FakeTransport(response=Response(status=503, body="upstream down"))
    res = FiligreeEmitter("http://x", transport=t).emit([_f()])
    assert res.reachable is False


def test_2xx_with_unparseable_body_warns_not_crashes() -> None:
    # POST accepted (2xx) but the body is not a JSON object -> surface a warning,
    # reachable=True, zeroed stats; must NOT raise.
    t = _FakeTransport(response=Response(status=200, body="<html>maintenance</html>"))
    res = FiligreeEmitter("http://x", transport=t).emit([_f()])
    assert res.reachable is True
    assert res.created == 0 and res.updated == 0
    assert res.warnings and "non-JSON-object" in res.warnings[0]


def test_2xx_with_nonnumeric_stats_does_not_crash() -> None:
    body = json.dumps({"stats": {"findings_created": None, "findings_updated": "x"}, "warnings": []})
    res = FiligreeEmitter("http://x", transport=_FakeTransport(Response(200, body))).emit([_f()])
    assert res.reachable is True and res.created == 0 and res.updated == 0


def test_failed_list_surfaced_in_result() -> None:
    body = json.dumps({"stats": {"findings_created": 1}, "failed": ["id9"], "warnings": []})
    res = FiligreeEmitter("http://x", transport=_FakeTransport(Response(200, body))).emit([_f()])
    assert res.failed == 1


def test_connection_error_is_sibling_absent() -> None:
    t = _FakeTransport(exc=ConnectionRefusedError("no server"))
    res = FiligreeEmitter("http://x", transport=t).emit([_f()])
    assert res.reachable is False  # warns + continues; no raise
    assert isinstance(res, EmitResult)


def test_urllib_transport_converts_httperror_to_response(monkeypatch) -> None:
    # LYNCHPIN: the absent-vs-loud split depends on UrllibTransport catching HTTPError
    # (a URLError subclass) and returning a Response with its status — NOT re-raising it
    # (which emit() would then misclassify as sibling-absent). Pin it directly.
    import io
    import urllib.error
    import urllib.request

    from wardline.core.filigree_emit import UrllibTransport

    def _raise_http_error(req, timeout=None):  # noqa: ARG001
        raise urllib.error.HTTPError(
            url="http://x/api/loom/scan-results",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"path required"}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise_http_error)
    resp = UrllibTransport().post("http://x/api/loom/scan-results", b"{}", {"Content-Type": "application/json"})
    assert resp.status == 400
    assert "path required" in resp.body


def test_urllib_transport_rejects_non_http_scheme() -> None:
    from wardline.core.filigree_emit import UrllibTransport

    with pytest.raises(FiligreeEmitError):
        UrllibTransport().post("file:///etc/passwd", b"{}", {})


def test_judged_finding_carries_suppression_metadata() -> None:
    wire = build_scan_results_body([_f(suppressed=SuppressionState.JUDGED, suppression_reason="over-taint floor")])[
        "findings"
    ][0]
    assert wire["metadata"]["wardline"]["suppressed"] == "judged"
    assert wire["metadata"]["wardline"]["suppression_reason"] == "over-taint floor"
