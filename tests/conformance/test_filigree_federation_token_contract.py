"""WEFT_FEDERATION_TOKEN bearer-token auth contract — filigree producer ↔ wardline consumer.

Filigree is the AUTHORITY for the inbound federation bearer-token gate
(``/api/weft/*`` + the classic federation-write aliases + the dashboard ``/mcp``
transport). Wardline is a CONSUMER: it resolves a federation token (env var or the
auto-minted ``.weft/filigree/federation_token`` file) and presents it as
``Authorization: Bearer <token>``, then reads back the auth-status ladder in
``FiligreeEmitter.verify_token`` (401/403 → rejected; 400/2xx → accepted).

Unlike the SEI and qualname seams, filigree publishes NO machine-readable contract
fixture — the contract lives in filigree SOURCE CONSTANTS
(``federation_token.py``) + middleware LOGIC (``dashboard_auth.py``) + ADR-018. So
this seam follows the ``UPSTREAM_BLOB_SHA`` branch of the kit: wardline AUTHORS the
vendored contract restatement (``fixtures/filigree_federation_token_contract.json``)
and pins it.

Drift alarm (two layers):
    1. Layer-1 byte-pin (DEFAULT suite, this file): ``UPSTREAM_BLOB_SHA`` pins the
       git-blob hash of the wardline-authored contract file. ANY byte change reds
       the default PR suite — a re-vendor is deliberate and bumps the constant in
       the same commit.
    2. Layer-2 substantive recheck (opt-in, ``-m filigree_token_drift``): re-reads
       the SIBLING filigree source (``federation_token.py`` / ``dashboard_auth.py``)
       and asserts the contract VALUES still match. It is SUBSTANTIVE, not
       byte-exact (filigree ships no fixture to byte-compare) — the same sanctioned
       shape as the Python qualname axis's substantive Layer-2. Skips clean when the
       sibling checkout is absent (CI).

A live ``filigree_e2e`` token round-trip (``test_live_token_round_trip``, bottom)
exercises the seam end-to-end against a real filigree: a wrong token →
``accepted=False`` (401), a good token → ``accepted=True`` — so the marker is bound
to a test that actually drives the token contract, not merely the promote flow.

RE-VENDOR PROCEDURE (release-gate; run ``pytest -m filigree_token_drift -v`` before
every release, or on a deliberate filigree contract bump):
    1. Reconcile the contract VALUES in
       ``fixtures/filigree_federation_token_contract.json`` against the sibling
       filigree source (env-var names + read order in ``federation_token.py``; the
       Bearer/status semantics in ``dashboard_auth.py`` + ADR-018). NEVER let the
       vendored copy drift silently — Layer-2 is the alarm.
    2. Recompute the blob hash (``git hash-object`` of the fixture, equivalently
       ``hashlib.sha1(b"blob %d\\0" % len(data) + data)``) and update
       ``UPSTREAM_BLOB_SHA`` in the SAME commit; refresh the ``_provenance`` block.
    3. Re-run conformance and CONFORM the consumer
       (``wardline.core.filigree_emit`` / ``wardline.install.doctor``) until green;
       never weaken the assertions.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from wardline.core.filigree_emit import FiligreeEmitter, Response

CONTRACT_PATH = Path(__file__).parent / "fixtures" / "filigree_federation_token_contract.json"

# The git blob hash of the wardline-AUTHORED vendored contract restatement. Named
# ``UPSTREAM_BLOB_SHA`` to match the kit's canonical Layer-1 pin constant (the same
# name the SEI consumer seam uses when it vendors an upstream authority's contract):
# "upstream" here is filigree's contract (the authority), restated into bytes wardline
# owns because filigree publishes no fixture to vendor verbatim. The Layer-1 byte-pin
# below runs in the DEFAULT PR suite, so ANY byte change without a matching re-pin reds
# the suite — the fail-closed protection that lets the Layer-2 substantive recheck skip
# clean when the sibling filigree checkout is absent. Re-vendors bump this in the SAME
# commit as the bytes.
UPSTREAM_BLOB_SHA = "a7825e9f17ab3db9b5bb94c56e8cbf03c783d96f"


def _contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _filigree_repo() -> Path | None:
    """The sibling filigree checkout root. Env takes EXCLUSIVE precedence
    (first-configured, not first-existing): when ``WARDLINE_FILIGREE_REPO`` is set,
    resolve the sibling ONLY from it and skip clean if the federation-token source is
    absent under that root — the local-dev ``../filigree`` convenience checkout is
    consulted ONLY when the env var is unset. This shares ONE resolution contract with
    the other ``_drift`` rechecks (see test_loomweave_qualname_parity.py:150): an
    operator who points the release-gate env var at a specific checkout that lacks the
    file gets a clean skip, never a silent compare against the local convenience
    sibling. None when absent (CI runners lack the sibling — Layer-2 skips clean)."""
    marker = ("src", "filigree", "federation_token.py")
    if env := os.environ.get("WARDLINE_FILIGREE_REPO"):
        root = Path(env)
        return root if root.joinpath(*marker).is_file() else None
    root = Path(__file__).resolve().parents[3] / "filigree"
    return root if root.joinpath(*marker).is_file() else None


# --------------------------------------------------------------------------- #
# Layer-1 byte-pin + structural self-tests — DEFAULT suite (no marker).
# --------------------------------------------------------------------------- #


def test_vendored_contract_matches_blob_pin() -> None:
    """Layer-1 (default suite): the wardline-authored contract byte-pins to its git
    blob hash. ANY edit without a matching re-pin reds the default PR suite."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = CONTRACT_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored federation-token contract changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, update UPSTREAM_BLOB_SHA in the same commit and re-run "
        "conformance (see the RE-VENDOR PROCEDURE at the top of this module); if not, revert the edit."
    )


def test_contract_shape_is_well_formed() -> None:
    contract = _contract()
    assert contract["contract"] == "weft/filigree-federation-bearer-token"
    for key in ("env", "token_file", "header", "status_ladder", "consumer_verdict", "_provenance"):
        assert key in contract, f"vendored contract is missing the '{key}' section"
    env = contract["env"]
    assert env["canonical_env_var"] == "WEFT_FEDERATION_TOKEN"
    assert env["read_order"][0] == env["canonical_env_var"]
    assert env["read_order"] == [env["canonical_env_var"], *env["deprecated_aliases"]]
    assert contract["header"]["scheme"] == "Bearer"
    # The accepted/rejected status partitions must be disjoint and non-empty.
    accepted = set(contract["consumer_verdict"]["accepted_statuses"])
    rejected = set(contract["consumer_verdict"]["rejected_statuses"])
    assert accepted and rejected and not (accepted & rejected)


# --------------------------------------------------------------------------- #
# Consumer-binding — wardline's FiligreeEmitter / doctor MUST conform to the
# vendored contract values. Default suite (no live filigree needed).
# --------------------------------------------------------------------------- #


class _FakeTransport:
    """Records the last POST and returns a canned status."""

    def __init__(self, status: int) -> None:
        self._status = status
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> Response:
        self.calls.append((url, body, dict(headers)))
        return Response(status=self._status, body="")


def test_consumer_sends_contract_bearer_header() -> None:
    """The consumer presents exactly the vendored header form ``Bearer <token>``."""
    contract = _contract()
    t = _FakeTransport(status=400)
    FiligreeEmitter("http://127.0.0.1:8749/api/weft/scan-results", transport=t, token="tok").verify_token()
    _, _, headers = t.calls[0]
    assert headers[contract["header"]["name"]] == f"{contract['header']['scheme']} tok"


def test_consumer_verdict_matches_contract_status_ladder() -> None:
    """``verify_token`` partitions statuses EXACTLY as the vendored contract dictates:
    rejected_statuses → accepted=False; accepted_statuses → accepted=True."""
    contract = _contract()
    url = "http://127.0.0.1:8749/api/weft/scan-results"
    for status in contract["consumer_verdict"]["rejected_statuses"]:
        probe = FiligreeEmitter(url, transport=_FakeTransport(status), token="t").verify_token()
        assert probe.reachable is True and probe.accepted is False, f"status {status} must be REJECTED"
        assert probe.status == status
    for status in contract["consumer_verdict"]["accepted_statuses"]:
        probe = FiligreeEmitter(url, transport=_FakeTransport(status), token="t").verify_token()
        assert probe.accepted is True, f"status {status} must be ACCEPTED (auth passed before body validation)"


def test_consumer_env_var_name_matches_contract() -> None:
    """Wardline's env-var reader (doctor .env pin path) uses the SAME canonical
    ``WEFT_FEDERATION_TOKEN`` name the contract declares — bind both ends."""
    contract = _contract()
    from wardline.install import doctor

    source = Path(doctor.__file__).read_text(encoding="utf-8")
    assert contract["env"]["canonical_env_var"] in source, (
        "wardline.install.doctor does not reference the canonical env var the contract declares"
    )
    # And the token-file relpath the consumer probes matches the contract.
    assert contract["token_file"]["project_store_relpath"] == ".weft/filigree/federation_token"
    assert all(part in source for part in (".weft", "filigree", "federation_token"))


# --------------------------------------------------------------------------- #
# Layer-2 substantive drift recheck (opt-in, -m filigree_token_drift).
# --------------------------------------------------------------------------- #


@pytest.mark.filigree_token_drift
def test_vendored_contract_matches_sibling_filigree_source() -> None:
    """Layer-2 (opt-in, ``-m filigree_token_drift``): the SUBSTANTIVE contract values
    must still match the sibling filigree source. Filigree ships no fixture to
    byte-compare, so this parses the live source CONSTANTS and asserts agreement
    (the same sanctioned shape as the Python qualname axis's substantive Layer-2).
    Absent sibling checkout (CI) skips clean; drift FAILS."""
    repo = _filigree_repo()
    if repo is None:
        pytest.skip("no sibling filigree checkout (set WARDLINE_FILIGREE_REPO to enable the drift recheck)")
    contract = _contract()
    token_src = (repo / "src" / "filigree" / "federation_token.py").read_text(encoding="utf-8")
    auth_src = (repo / "src" / "filigree" / "dashboard_auth.py").read_text(encoding="utf-8")

    env = contract["env"]
    # Canonical env var + deprecated aliases + read order are filigree CONSTANTS.
    assert f'WEFT_FEDERATION_ENV_VAR = "{env["canonical_env_var"]}"' in token_src, (
        "filigree's canonical federation env var drifted from the vendored contract"
    )
    for alias in env["deprecated_aliases"]:
        assert alias in token_src, f"filigree dropped/renamed deprecated alias {alias!r} the contract still lists"
    assert f'FEDERATION_TOKEN_FILENAME = "{contract["token_file"]["filename"]}"' in token_src, (
        "filigree's persisted token filename drifted from the vendored contract"
    )
    # The Bearer scheme + case-insensitive match live in dashboard_auth.py.
    assert '!= "bearer"' in auth_src, "filigree's case-insensitive Bearer scheme check drifted"
    assert "401" in auth_src and "WWW-Authenticate" in auth_src, (
        "filigree's 401 + WWW-Authenticate: Bearer envelope drifted from the contract"
    )


# --------------------------------------------------------------------------- #
# Live token round-trip (opt-in, -m filigree_e2e) — binds the marker to a test
# that actually drives the token contract end-to-end against a real filigree.
# --------------------------------------------------------------------------- #

_URL = os.environ.get("WARDLINE_FILIGREE_URL")
_GOOD_TOKEN = os.environ.get("WARDLINE_FILIGREE_TOKEN")


@pytest.mark.filigree_e2e
@pytest.mark.skipif(
    not (_URL and _GOOD_TOKEN),
    reason="set WARDLINE_FILIGREE_URL + WARDLINE_FILIGREE_TOKEN (a real federation token) to run the live round-trip",
)
def test_live_token_round_trip() -> None:
    """Live filigree, real bearer gate: a WRONG token is rejected (401 → accepted=False);
    the GOOD token is accepted (400/2xx → accepted=True). Exercises the exact ladder
    the vendored contract pins, end-to-end, via the consumer's verify_token()."""
    assert _URL is not None and _GOOD_TOKEN is not None  # narrowed by skipif

    bad = FiligreeEmitter(_URL, token="definitely-not-the-token").verify_token()
    assert bad.reachable is True, "live filigree must be reachable to run this oracle"
    if bad.accepted:
        # The contract's tier-3 graceful-degrade: with NO federation token configured
        # the daemon does not install the auth middleware, so even a wrong token reaches
        # body validation (400 authed-bad-body). Such a daemon cannot exercise the REJECT
        # path — skip rather than fail (the oracle needs an auth-ENFORCING filigree).
        pytest.skip(
            f"live filigree at {_URL} is not enforcing federation auth (a wrong token was accepted, "
            f"status={bad.status}) — set WEFT_FEDERATION_TOKEN on the daemon to run the reject-path oracle"
        )
    assert bad.accepted is False and bad.status in (401, 403), (
        f"a wrong token must be rejected per the contract ladder, got status={bad.status}"
    )

    good = FiligreeEmitter(_URL, token=_GOOD_TOKEN).verify_token()
    assert good.reachable is True
    assert good.accepted is True, (
        f"the good token must pass the bearer gate (400 authed-bad-body or 2xx), got status={good.status}"
    )
