# src/wardline/loomweave/_hmac.py
"""Loomweave's HMAC-SHA256 request signature, reproduced byte-exactly (stdlib only).

Pinned from Loomweave's verifier `canonical_hmac_message`
(loomweave-cli/src/http_read/auth.rs:220-234). The signed message is five fields
joined by '\\n', no trailing newline:

    <METHOD>\\n<PATH_AND_QUERY>\\n<sha256_hex(body)>\\n<TIMESTAMP>\\n<NONCE>

then lowercase-hex HMAC-SHA256 over that message. The verifier hard-requires the
`x-weft-component`, `x-weft-timestamp`, AND `x-weft-nonce` request headers; a
missing/empty nonce 401s before the signature is even checked. The nonce is fed
into a replay cache (max length 128) under a 300s freshness window, so every
request must carry a fresh, unique, high-entropy nonce. The header is
`X-Weft-Component: loomweave:<hmac>`. Note: the BODY hash here is SHA-256; the
freshness hash (loomweave/facts.py) is blake3 — they are unrelated.
"""

from __future__ import annotations

import hashlib
import hmac


def canonical_message(method: str, path_and_query: str, body: bytes, timestamp: str, nonce: str) -> str:
    """The exact string Loomweave signs: five fields joined by '\n', no trailing newline.

    ``method`` is signed verbatim; pass the uppercase HTTP verb (e.g. ``"POST"``)
    so the signature matches Loomweave's server-side uppercase method string.
    ``timestamp`` and ``nonce`` are required — the verifier rejects a request that
    omits either (auth.rs:137-162)."""
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method}\n{path_and_query}\n{body_hash}\n{timestamp}\n{nonce}"


def sign_request(secret: str, method: str, path_and_query: str, body: bytes, timestamp: str, nonce: str) -> str:
    """Return the lowercase-hex HMAC-SHA256 signature (bare hex, no 'loomweave:' prefix)."""
    return hmac.new(
        secret.encode("utf-8"),
        canonical_message(method, path_and_query, body, timestamp, nonce).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
