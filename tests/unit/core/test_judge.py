from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime

import pytest

from wardline.core.errors import (
    JudgeConfigurationError,
    JudgeContractError,
    JudgeTransportError,
)
from wardline.core.judge import (
    _STATIC_POLICY_BLOCK,
    JUDGE_POLICY_HASH,
    JudgeRequest,
    JudgeResponse,
    JudgeVerdict,
    Response,
    UrllibTransport,
    build_messages,
    call_judge,
)


def _req(**kw: object) -> JudgeRequest:
    base: dict[str, object] = dict(
        rule_id="PY-WL-101", message="m", severity="ERROR",
        file_path="src/m.py", line=5, qualname="m.f", fingerprint="a" * 64,
        taint_summary="actual_return=MIXED_RAW", surrounding_code="def f(): ...",
    )
    base.update(kw)
    return JudgeRequest(**base)  # type: ignore[arg-type]


def _url() -> str:
    return "https://openrouter.ai/api/v1/chat/completions"


# --- Task 1: dataclasses + verdict -------------------------------------------


def test_verdict_values() -> None:
    assert JudgeVerdict.TRUE_POSITIVE.value == "TRUE_POSITIVE"
    assert JudgeVerdict.FALSE_POSITIVE.value == "FALSE_POSITIVE"


def test_request_is_frozen() -> None:
    req = _req()
    with pytest.raises(AttributeError):
        req.rule_id = "x"  # type: ignore[misc]


def test_response_holds_audit_fields() -> None:
    resp = JudgeResponse(
        verdict=JudgeVerdict.FALSE_POSITIVE, rationale="over-taint floor",
        confidence=0.9, model_id="anthropic/claude-opus-4-8",
        recorded_at=datetime.now(UTC), prompt_tokens_total=100,
        prompt_tokens_cached=None, policy_hash="sha256:abc",
    )
    assert resp.verdict is JudgeVerdict.FALSE_POSITIVE
    assert resp.prompt_tokens_cached is None  # None != 0


# --- Task 2: policy block + message builder ----------------------------------


def test_policy_block_teaches_wardline_model() -> None:
    block = _STATIC_POLICY_BLOCK
    assert "wardline-triage-judge" in block
    assert "TaintState" in block and "MIXED_RAW" in block
    assert "PY-WL-101" in block and "PY-WL-104" in block
    assert "FALSE_POSITIVE" in block and "TRUE_POSITIVE" in block
    assert "over-taint" in block.lower()
    assert "ELSPETH" not in block and "Three-Tier" not in block


def test_policy_hash_is_sha256_of_block() -> None:
    import hashlib
    expect = "sha256:" + hashlib.sha256(_STATIC_POLICY_BLOCK.encode("utf-8")).hexdigest()
    assert expect == JUDGE_POLICY_HASH


def test_build_messages_caches_static_block_and_wraps_untrusted_data() -> None:
    req = JudgeRequest(
        rule_id="PY-WL-101", message="untrusted reaches trusted", severity="ERROR",
        file_path="src/m.py", line=5, qualname="m.f", fingerprint="a" * 64,
        taint_summary="actual_return=MIXED_RAW, declared_return=GUARDED",
        surrounding_code="def f():\n    return user_input",
    )
    messages = build_messages(req, policy_block=_STATIC_POLICY_BLOCK)
    assert messages[0]["role"] == "system"
    assert messages[0]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert messages[0]["content"][0]["text"] == _STATIC_POLICY_BLOCK
    user_texts = [b["text"] for b in messages[1]["content"]]
    assert any("UNTRUSTED DATA BOUNDARY" in t for t in user_texts)
    payload = next(json.loads(t) for t in user_texts if t.lstrip().startswith("{"))
    assert payload["finding"]["rule_id"] == "PY-WL-101"
    assert payload["surrounding_code"]["text"] == "def f():\n    return user_input"


def test_build_messages_truncates_long_excerpt() -> None:
    req = JudgeRequest(
        rule_id="PY-WL-103", message="m", severity="WARN", file_path="src/m.py",
        line=1, qualname=None, fingerprint="b" * 64, taint_summary="tier=UNKNOWN_RAW",
        surrounding_code="x" * 50_000,
    )
    messages = build_messages(req, policy_block=_STATIC_POLICY_BLOCK)
    payload = next(
        json.loads(b["text"]) for b in messages[1]["content"] if b["text"].lstrip().startswith("{")
    )
    assert payload["surrounding_code"]["truncated"] is True
    assert len(payload["surrounding_code"]["text"]) <= 12_000


# --- Task 3: transport -------------------------------------------------------


def test_urllib_transport_converts_httperror_to_response(monkeypatch) -> None:
    def _raise(req, timeout=None):  # noqa: ARG001
        raise urllib.error.HTTPError(
            url=_url(), code=401, msg="Unauthorized", hdrs=None,
            fp=io.BytesIO(b'{"error":"bad key"}'),
        )
    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    resp = UrllibTransport().post(_url(), b"{}", {"Content-Type": "application/json"})
    assert resp.status == 401 and "bad key" in resp.body


def test_urllib_transport_rejects_non_http_scheme() -> None:
    with pytest.raises(JudgeConfigurationError):
        UrllibTransport().post("file:///etc/passwd", b"{}", {})


# --- Task 4: call_judge ------------------------------------------------------


class _FakeTransport:
    def __init__(self, response: Response | None = None, exc: Exception | None = None) -> None:
        self._response, self._exc = response, exc
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []

    def post(self, url, body, headers):  # type: ignore[no-untyped-def]
        self.calls.append((url, body, dict(headers)))
        if self._exc is not None:
            raise self._exc
        assert self._response is not None
        return self._response


def _completion(content: str, *, cached: int | None = 7, total: int = 120,
                model: str = "anthropic/claude-opus-4-8", finish: str = "stop") -> str:
    usage: dict[str, object] = {"prompt_tokens": total}
    if cached is not None:
        usage["prompt_tokens_details"] = {"cached_tokens": cached}
    return json.dumps({
        "model": model,
        "choices": [{"finish_reason": finish, "message": {"content": content}}],
        "usage": usage,
    })


def _good_verdict() -> str:
    return json.dumps({"verdict": "FALSE_POSITIVE", "rationale": "constructor over-taint floor", "confidence": 0.88})


def test_call_judge_happy_path(monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "sk-or-test")
    t = _FakeTransport(Response(200, _completion(_good_verdict())))
    resp = call_judge(_req(), transport=t)
    assert resp.verdict is JudgeVerdict.FALSE_POSITIVE
    assert resp.confidence == 0.88
    assert resp.model_id == "anthropic/claude-opus-4-8"
    assert resp.prompt_tokens_total == 120 and resp.prompt_tokens_cached == 7
    assert resp.policy_hash == JUDGE_POLICY_HASH
    url, body, headers = t.calls[0]
    assert headers["Authorization"] == "Bearer sk-or-test"
    sent = json.loads(body)
    assert sent["temperature"] == 0
    assert sent["messages"][0]["content"][0]["cache_control"] == {"type": "ephemeral"}


def test_call_judge_missing_key_is_configuration_error(monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_OPENROUTER_API_KEY", raising=False)
    with pytest.raises(JudgeConfigurationError):
        call_judge(_req(), transport=_FakeTransport(Response(200, _completion(_good_verdict()))))


def test_call_judge_cached_none_preserved(monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "k")
    t = _FakeTransport(Response(200, _completion(_good_verdict(), cached=None)))
    assert call_judge(_req(), transport=t).prompt_tokens_cached is None


def test_call_judge_5xx_is_transport_error(monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "k")
    with pytest.raises(JudgeTransportError):
        call_judge(_req(), transport=_FakeTransport(Response(503, "upstream down")))


def test_call_judge_4xx_is_transport_error(monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "k")
    with pytest.raises(JudgeTransportError):
        call_judge(_req(), transport=_FakeTransport(Response(401, '{"error":"bad key"}')))


def test_call_judge_connection_error_is_transport_error(monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "k")
    with pytest.raises(JudgeTransportError):
        call_judge(_req(), transport=_FakeTransport(exc=ConnectionRefusedError("no")))


@pytest.mark.parametrize("content", [
    "not json at all",
    json.dumps({"verdict": "MAYBE", "rationale": "x", "confidence": 0.5}),
    json.dumps({"verdict": "TRUE_POSITIVE", "confidence": 0.5}),
    json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "x", "confidence": 2}),
    json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "x", "confidence": 0.5, "extra": 1}),
])
def test_call_judge_malformed_2xx_crashes(monkeypatch, content: str) -> None:
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "k")
    with pytest.raises(JudgeContractError):
        call_judge(_req(), transport=_FakeTransport(Response(200, _completion(content))))


def test_call_judge_truncated_output_crashes(monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "k")
    t = _FakeTransport(Response(200, _completion(_good_verdict(), finish="length")))
    with pytest.raises(JudgeContractError):
        call_judge(_req(), transport=t)
