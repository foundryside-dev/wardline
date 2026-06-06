# tests/unit/loomweave/test_hmac.py
import hashlib
import hmac as _hmac

from wardline.loomweave._hmac import canonical_message, sign_request
from wardline.loomweave.client import LoomweaveClient, Response

# --- Fixed inputs shared by the canonical-message and sign_request oracles. ---
_SECRET = "s3cr3t"
_METHOD = "POST"
_PAQ = "/api/wardline/resolve"
_BODY = b'{"qualnames":[]}'
_TIMESTAMP = "1700000000"
_NONCE = "0123456789abcdef0123456789abcdef"
# sha256_hex(_BODY), written out so a body change is caught here, not silently.
_BODY_SHA256 = "f9006c5afab431fab2f25f75b7006191d7f26ed3610e62fe46467657f3e1ae88"


def test_canonical_message_is_the_pinned_five_field_string():
    # The exact wire message Loomweave's verifier signs:
    # METHOD \n PATH_AND_QUERY \n sha256_hex(body) \n TIMESTAMP \n NONCE
    # (loomweave-cli/src/http_read/auth.rs:220-234, fn canonical_hmac_message).
    # Written as an explicit literal so a future field reorder (e.g. swapping the
    # body-hash and timestamp lines, or dropping the nonce) fails this assertion.
    expected = (
        "POST\n"
        "/api/wardline/resolve\n"
        "f9006c5afab431fab2f25f75b7006191d7f26ed3610e62fe46467657f3e1ae88\n"
        "1700000000\n"
        "0123456789abcdef0123456789abcdef"
    )
    assert canonical_message(_METHOD, _PAQ, _BODY, _TIMESTAMP, _NONCE) == expected
    assert not expected.endswith("\n")


def test_empty_body_hashes_the_empty_string():
    # bodyless GET: sha256(b"") = e3b0c4…b855, on the third line.
    msg = canonical_message("GET", "/api/wardline/taint-facts?qualname=x", b"", "1700000000", "deadbeef")
    assert msg == (
        "GET\n"
        "/api/wardline/taint-facts?qualname=x\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "1700000000\n"
        "deadbeef"
    )


def test_hmac_primitive_matches_loomweave_known_answer():
    # Loomweave's HMAC-SHA256 known-answer test (auth.rs:298): proves Wardline's
    # primitive (stdlib hmac+sha256, lowercase hex) is byte-identical to the verifier's.
    digest = _hmac.new(b"key", b"The quick brown fox jumps over the lazy dog", hashlib.sha256).hexdigest()
    assert digest == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"


def test_sign_request_matches_pinned_signature():
    # Pinned lowercase-hex HMAC-SHA256 over the fixed inputs above. Computed once
    # and frozen as a literal — if the canonical message or the primitive drifts,
    # this value no longer reproduces.
    assert sign_request(_SECRET, _METHOD, _PAQ, _BODY, _TIMESTAMP, _NONCE) == (
        "e2db9d3044d75258515b3b145d318a02d5500b3d01bb2799085ec79e84deb436"
    )


def test_sign_request_is_bare_lowercase_hex():
    sig = sign_request(_SECRET, _METHOD, _PAQ, _BODY, _TIMESTAMP, _NONCE)
    # The client builds the header value as f"loomweave:{sig}"; assert sig is bare hex.
    assert ":" not in sig
    assert all(c in "0123456789abcdef" for c in sig)


class _FakeTransport:
    """Records request headers; always answers a default 200 (mirrors test_client)."""

    def __init__(self):
        self.calls = []  # list of (method, url, body, headers)

    def request(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        return Response(status=200, body="{}")


def test_send_emits_all_three_auth_headers_with_a_fresh_unique_nonce():
    t = _FakeTransport()
    client = LoomweaveClient(
        "http://loomweave.example",
        secret=_SECRET,
        project="proj",
        transport=t,
    )
    # Two signed calls so we can assert the nonce is fresh (differs) per request.
    client.resolve(["a.b"])
    client.resolve(["c.d"])

    for _method, _url, sent_body, headers in t.calls:
        assert "X-Weft-Component" in headers
        assert "X-Weft-Timestamp" in headers
        assert "X-Weft-Nonce" in headers
        nonce = headers["X-Weft-Nonce"]
        assert nonce  # non-empty
        assert all(c in "0123456789abcdef" for c in nonce)  # hex
        # The component signs over the captured timestamp AND nonce.
        expected = sign_request(
            _SECRET, _method, "/api/wardline/resolve", sent_body, headers["X-Weft-Timestamp"], nonce
        )
        assert headers["X-Weft-Component"] == f"loomweave:{expected}"

    # Freshness: the two requests carry different nonces.
    assert t.calls[0][3]["X-Weft-Nonce"] != t.calls[1][3]["X-Weft-Nonce"]
