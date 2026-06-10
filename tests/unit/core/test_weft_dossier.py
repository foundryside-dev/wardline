"""T4.3 — build_weft_dossier orchestrator: resolve SEI + wire live providers.

Detects Loomweave capabilities once, resolves the qualname to its opaque SEI binding
via the Track-3 SeiResolver, wires the Loomweave linkage + Filigree work providers, and
calls the source-agnostic core assembler. Degrades honestly when a source is absent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wardline.filigree.dossier_client import Response
from wardline.loomweave.client import LinkageResult, ResolveResult
from wardline.loomweave.identity import ContentStatus, IdentityStatus
from wardline.weft_dossier import build_weft_dossier

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "def mid(p):\n    return read_raw(p)\n"
    "@trusted\ndef leaky(p):\n    return mid(p)\n"
)


def _proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


class _FakeLoomweave:
    """A Loomweave that serves SEI + linkages over HTTP."""

    def __init__(self, *, sei="loomweave:eid:abc", content_hash="ch", linkages_http=True, sei_supported=True):
        self._sei = sei
        self._content_hash = content_hash
        self._linkages_http = linkages_http
        self._sei_supported = sei_supported

    def capabilities(self):
        return {
            "linkages": {"http": self._linkages_http},
            "sei": {"supported": self._sei_supported, "version": 1},
        }

    def resolve(self, qualnames, *, plugin=None):
        self.plugin_hints = [*getattr(self, "plugin_hints", []), plugin]
        return ResolveResult(resolved={q: f"python:function:{q}" for q in qualnames}, unresolved=[])

    def resolve_identity(self, locator):
        return {"sei": self._sei, "current_locator": locator, "content_hash": self._content_hash, "alive": True}

    def resolve_sei(self, sei):
        return {
            "alive": True,
            "current_locator": "python:function:svc.leaky",
            "content_hash": self._content_hash,
            "sei": sei,
        }

    def get_callers(self, entity_id, *, limit=50):
        return LinkageResult(neighbours=("python:function:svc.caller",), total=1, truncated=False)

    def get_callees(self, entity_id, *, limit=50):
        return LinkageResult(neighbours=("python:function:svc.mid",), total=1, truncated=False)


class _FakeFiligreeTransport:
    def __init__(self, body):
        self._body = body

    def get(self, url, headers):
        return Response(status=200, body=self._body)


def test_full_wiring_keys_on_sei_and_fills_all_sections(tmp_path: Path) -> None:
    fili_body = json.dumps({"associations": [{"issue_id": "wardline-7", "content_hash_at_attach": "ch"}]})
    d = build_weft_dossier(
        "svc.leaky",
        root=_proj(tmp_path),
        loomweave_client=_FakeLoomweave(),
        filigree_url="http://filigree.example",
        filigree_transport=_FakeFiligreeTransport(fili_body),
    )
    # identity keyed on the opaque SEI, alive
    assert d.identity.sei == "loomweave:eid:abc"
    assert d.identity.keyed_on_sei is True
    assert d.identity.identity_status is IdentityStatus.ALIVE
    # self trust posture (real) still computed
    assert d.trust.gate_verdict == "defect"
    # linkages from live Loomweave
    assert d.linkages.available is True
    assert d.linkages.callees == ["python:function:svc.mid"]
    assert d.linkages.content_status is ContentStatus.FRESH
    # work from live Filigree, FRESH (attach hash matches the binding content hash)
    assert d.work.available is True
    assert d.work.tickets[0].issue_id == "wardline-7"
    assert d.work.content_status is ContentStatus.FRESH
    # whole envelope token-bounded
    assert d.estimated_tokens() <= 2000


def test_loomweave_without_http_linkages_degrades_linkages_only(tmp_path: Path) -> None:
    d = build_weft_dossier(
        "svc.leaky",
        root=_proj(tmp_path),
        loomweave_client=_FakeLoomweave(linkages_http=False),
    )
    # SEI still resolved (identity present); linkages honestly unavailable
    assert d.identity.sei == "loomweave:eid:abc"
    assert d.linkages.available is False
    assert "http linkages" in (d.linkages.reason or "").lower()


def test_no_loomweave_no_filigree_is_self_only(tmp_path: Path) -> None:
    d = build_weft_dossier("svc.leaky", root=_proj(tmp_path))
    assert d.identity.sei is None
    assert d.identity.identity_status is IdentityStatus.UNAVAILABLE
    assert d.linkages.available is False
    assert d.work.available is False
    assert d.trust.gate_verdict == "defect"  # self posture still real


def test_pre_sei_loomweave_degrades_identity_but_keeps_self(tmp_path: Path) -> None:
    d = build_weft_dossier(
        "svc.leaky",
        root=_proj(tmp_path),
        loomweave_client=_FakeLoomweave(sei_supported=False),
    )
    assert d.identity.sei is None  # no SEI capability → no opaque key
    assert d.identity.identity_status is IdentityStatus.UNAVAILABLE
    assert d.trust.gate_verdict == "defect"


def test_loomweave_capabilities_outage_degrades_to_self_only(tmp_path: Path) -> None:
    # capabilities() returns None (outage during the probe) → no SEI, no linkages,
    # but the call still succeeds with a real self posture (fail-closed, honest).
    class _DeadLoomweave(_FakeLoomweave):
        def capabilities(self):
            return None

        def resolve_identity(self, locator):
            return None

    d = build_weft_dossier("svc.leaky", root=_proj(tmp_path), loomweave_client=_DeadLoomweave())
    assert d.identity.identity_status is IdentityStatus.UNAVAILABLE
    assert d.linkages.available is False
    assert d.trust.gate_verdict == "defect"


def test_weft_dossier_with_sei_entity(tmp_path: Path) -> None:
    fili_body = json.dumps({"associations": [{"issue_id": "wardline-7", "content_hash_at_attach": "ch"}]})
    d = build_weft_dossier(
        "sei:loomweave:eid:abc",
        root=_proj(tmp_path),
        loomweave_client=_FakeLoomweave(),
        filigree_url="http://filigree.example",
        filigree_transport=_FakeFiligreeTransport(fili_body),
    )
    # identity keyed on the resolved SEI
    assert d.identity.sei == "sei:loomweave:eid:abc"
    assert d.identity.keyed_on_sei is True
    assert d.identity.identity_status is IdentityStatus.ALIVE
    # self trust posture (real) still computed for resolved svc.leaky
    assert d.trust.gate_verdict == "defect"
    # linkages resolved via locator
    assert d.linkages.available is True
    assert d.linkages.callees == ["python:function:svc.mid"]


def test_weft_dossier_with_sei_entity_unsupported_or_missing_loomweave(tmp_path: Path) -> None:
    from wardline.core.errors import DossierError

    proj = _proj(tmp_path)

    # Missing loomweave_client
    with pytest.raises(DossierError, match="no Loomweave URL configured"):
        build_weft_dossier("sei:loomweave:eid:abc", root=proj)

    # Unsupported SEI
    with pytest.raises(DossierError, match="Loomweave instance does not support SEI"):
        build_weft_dossier("sei:loomweave:eid:abc", root=proj, loomweave_client=_FakeLoomweave(sei_supported=False))
