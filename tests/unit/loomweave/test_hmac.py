# tests/unit/loomweave/test_hmac.py
import hashlib
import hmac as _hmac

from wardline.loomweave._hmac import canonical_message, sign_request


def test_canonical_message_is_three_lines_no_trailing_newline():
    msg = canonical_message("POST", "/api/wardline/resolve", b'{"a":1}')
    body_hash = hashlib.sha256(b'{"a":1}').hexdigest()
    assert msg == f"POST\n/api/wardline/resolve\n{body_hash}"
    assert not msg.endswith("\n")


def test_empty_body_hashes_the_empty_string():
    # bodyless GET: sha256(b"") = e3b0c4…b855
    msg = canonical_message("GET", "/api/wardline/taint-facts?qualname=x", b"")
    assert msg.endswith("\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


def test_sign_request_matches_a_reference_hmac():
    secret, method, paq, body = "s3cr3t", "POST", "/api/wardline/resolve", b'{"qualnames":[]}'
    expected = _hmac.new(
        secret.encode("utf-8"),
        canonical_message(method, paq, body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert sign_request(secret, method, paq, body) == expected
    assert all(c in "0123456789abcdef" for c in sign_request(secret, method, paq, body))


def test_header_value_format():
    sig = sign_request("s", "GET", "/x", b"")
    # The client builds the header value as f"loomweave:{sig}"; assert sig is bare hex.
    assert ":" not in sig
