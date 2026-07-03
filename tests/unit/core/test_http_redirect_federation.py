"""Federation-facing consequences of WeftHttp's redirect refusal (real sockets).

The transport pin lives in test_http.py; these tests pin the downstream contract the
fix restores: ``FiligreeEmitter.verify_token``'s documented 3xx-inconclusive branch
(filigree_emit.py — "Report INCONCLUSIVE ... so doctor --repair never pins a local
token into .env on an unverified probe") was UNREACHABLE while urllib followed
301/302/303: a 302→200 chain surfaced as a bare 200 and returned
``ProbeResult(accepted=True)`` for a probe whose POST never exercised auth — and the
bearer token rode the redirect cross-origin. With redirects refused at the transport,
the 302 surfaces and the branch is live.
"""

from __future__ import annotations

import contextlib
import http.server
import threading
from collections.abc import Iterator

import pytest

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import FiligreeEmitter
from wardline.core.filigree_issue import FiligreeIssueFiler
from wardline.core.judge import UrllibTransport as JudgeUrllibTransport


class _ScriptedHandler(http.server.BaseHTTPRequestHandler):
    """Serves one scripted (status, headers, body) reply and records every request."""

    def _reply(self) -> None:
        server = self.server
        server.requests.append((self.command, self.path, dict(self.headers)))  # type: ignore[attr-defined]
        status, extra_headers, payload = server.script  # type: ignore[attr-defined]
        self.send_response(status)
        for key, value in extra_headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # keep pytest output clean


@contextlib.contextmanager
def _live_server(script: tuple[int, dict[str, str], bytes]) -> Iterator[http.server.HTTPServer]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _ScriptedHandler)
    server.script = script  # type: ignore[attr-defined]
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_verify_token_reports_inconclusive_on_redirect_not_accepted() -> None:
    # a Filigree URL behind a redirecting proxy: the probe POST answers 302 pointing at
    # a target that would 200 anything. Pre-fix this chain yielded accepted=True (and
    # doctor --repair would pin the token on an unverified probe); post-fix the 302
    # surfaces as the documented inconclusive outcome and the token never leaves the
    # origin actually dialed.
    with _live_server((200, {}, b"{}")) as target:
        target_url = f"http://127.0.0.1:{target.server_address[1]}/anything"
        with _live_server((302, {"Location": target_url}, b"moved")) as redirector:
            url = f"http://127.0.0.1:{redirector.server_address[1]}/api/weft/wardline/scan-results"
            probe = FiligreeEmitter(url, token="SECRET-TOKEN").verify_token()
    assert probe.accepted is False
    assert probe.reachable is False  # inconclusive: the probe never exercised auth
    assert probe.status == 302
    # the bearer never crossed origins: the redirect target saw no request at all
    assert target.requests == []  # type: ignore[attr-defined]
    (request,) = redirector.requests  # type: ignore[attr-defined]
    assert request[2].get("Authorization") == "Bearer SECRET-TOKEN"


def test_issue_filer_promote_redirect_never_forges_success() -> None:
    # wardline-f68c483d92: FiligreeIssueFiler was the one federation transport left on
    # raw urlopen after the WeftHttp sweep — a 302 from the promote URL re-sent the
    # bearer cross-origin, rewrote the POST into a body-less GET, and parsed the
    # redirect target's 200 body as a clean promote (forged issue_id). Post-fix the
    # 302 surfaces unfollowed and the promote is a loud reject, never a success.
    forged = b'{"issue_id": "FORGED-123", "created": true}'
    with _live_server((200, {}, forged)) as target:
        target_url = f"http://127.0.0.1:{target.server_address[1]}/anything"
        with _live_server((302, {"Location": target_url}, b"moved")) as redirector:
            url = f"http://127.0.0.1:{redirector.server_address[1]}"
            filer = FiligreeIssueFiler(url, token="SECRET-TOKEN")
            with pytest.raises(FiligreeEmitError, match=r"rejected promote \(302\)"):
                filer.file("f" * 16)
    # the bearer never crossed origins and the forged body was never parsed
    assert target.requests == []  # type: ignore[attr-defined]
    (request,) = redirector.requests  # type: ignore[attr-defined]
    assert request[0] == "POST"
    assert request[2].get("Authorization") == "Bearer SECRET-TOKEN"


def test_issue_filer_association_redirect_is_soft_skip_never_attached() -> None:
    # The association leg fail-softs every non-2xx: a redirect must surface as a
    # skipped (not attached) result with the 302 named — never as attached=True via
    # the redirect target's 200.
    with _live_server((200, {}, b"{}")) as target:
        target_url = f"http://127.0.0.1:{target.server_address[1]}/anything"
        with _live_server((302, {"Location": target_url}, b"moved")) as redirector:
            url = f"http://127.0.0.1:{redirector.server_address[1]}"
            result = FiligreeIssueFiler(url, token="SECRET-TOKEN").attach_entity_association(
                issue_id="wardline-abc123",
                entity_id="loomweave:eid:" + "a" * 32,
                content_hash="b" * 32,
            )
    assert result.attached is False
    assert result.reason is not None and "302" in result.reason
    assert target.requests == []  # type: ignore[attr-defined]


def test_judge_transport_redirect_surfaces_status_key_never_crosses_origin() -> None:
    # Same class, judge side: the transport carries the operator's OpenRouter API key
    # as Authorization: Bearer. A 302 must surface as a status (call_judge's 3xx/4xx
    # band -> loud JudgeTransportError), with the key never re-sent to the target.
    with _live_server((200, {}, b'{"choices": []}')) as target:
        target_url = f"http://127.0.0.1:{target.server_address[1]}/anything"
        with _live_server((302, {"Location": target_url}, b"moved")) as redirector:
            url = f"http://127.0.0.1:{redirector.server_address[1]}/api/v1/chat/completions"
            response = JudgeUrllibTransport().post(url, b"{}", {"Authorization": "Bearer sk-or-KEY"})
    assert response.status == 302
    assert target.requests == []  # type: ignore[attr-defined]
    (request,) = redirector.requests  # type: ignore[attr-defined]
    assert request[2].get("Authorization") == "Bearer sk-or-KEY"


def test_emit_reports_redirect_as_failure_never_clean() -> None:
    # the false-green telemetry pin: pre-fix a 302→200 chain parsed as a CLEAN reachable
    # emit (created=0, failures=(), no signal) while the findings body was dropped at
    # the redirect. Post-fix the surfaced 302 is a status-bearing failure — a signal.
    emitter_kwargs = {"token": "SECRET-TOKEN", "protocol_errors_loud": False}
    with _live_server((200, {}, b"{}")) as target:
        target_url = f"http://127.0.0.1:{target.server_address[1]}/anything"
        with _live_server((302, {"Location": target_url}, b"moved")) as redirector:
            url = f"http://127.0.0.1:{redirector.server_address[1]}/api/weft/wardline/scan-results"
            result = FiligreeEmitter(url, **emitter_kwargs).emit([])
    # never a clean emit: the redirect surfaces as a failure/warning-bearing outcome
    assert not (result.reachable and not result.failures and not result.warnings)
    assert target.requests == []  # type: ignore[attr-defined]
