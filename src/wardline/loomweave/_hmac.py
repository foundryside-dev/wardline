# src/wardline/loomweave/_hmac.py
"""Loomweave's HMAC-SHA256 request signature, reproduced byte-exactly (stdlib only).

Pinned from Loomweave's `canonical_hmac_message` / `component_hmac_hex`
(loomweave-cli/src/http_read.rs) and `contracts.md` §Authentication:

    <METHOD>\\n<PATH_AND_QUERY>\\n<sha256_hex(body)>      # no trailing newline

then lowercase-hex HMAC-SHA256 over that message. The header is
`X-Weft-Component: loomweave:<hmac>`. Note: the BODY hash here is SHA-256; the
freshness hash (loomweave/facts.py) is blake3 — they are unrelated.
"""

from __future__ import annotations

import hashlib
import hmac


def canonical_message(method: str, path_and_query: str, body: bytes, timestamp: str | None = None) -> str:
    """The exact string Loomweave signs: parts joined by '\n', no trailing newline.

    ``method`` is signed verbatim; pass the uppercase HTTP verb (e.g. ``"POST"``)
    so the signature matches Loomweave's server-side uppercase method string."""
    body_hash = hashlib.sha256(body).hexdigest()
    if timestamp is not None:
        return f"{method}\n{path_and_query}\n{timestamp}\n{body_hash}"
    return f"{method}\n{path_and_query}\n{body_hash}"


def sign_request(secret: str, method: str, path_and_query: str, body: bytes, timestamp: str | None = None) -> str:
    """Return the lowercase-hex HMAC-SHA256 signature (bare hex, no 'loomweave:' prefix)."""
    return hmac.new(
        secret.encode("utf-8"),
        canonical_message(method, path_and_query, body, timestamp).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
