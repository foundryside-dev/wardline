"""T4.3 — ClarionLinkageProvider + resolve_entity_binding.

The live Clarion source for the dossier's linkages section. Reads callers/callees
over HTTP, carries the SEI identity axis from the resolved binding, and marks the
content axis FRESH (read live from the current index). Fail-soft: a pre-linkage
Clarion, an unknown entity, or an outage yields an honest unavailable section.
"""

from __future__ import annotations

from wardline.clarion.client import LinkageResult
from wardline.clarion.dossier_sources import ClarionLinkageProvider, resolve_entity_binding
from wardline.clarion.identity import ContentStatus, EntityBinding, IdentityStatus


class _FakeClient:
    def __init__(self, callers=None, callees=None, resolved=None):
        self._callers = callers
        self._callees = callees
        self._resolved = resolved or {}
        self.caller_calls = []

    def get_callers(self, entity_id, *, limit=50):
        self.caller_calls.append((entity_id, limit))
        return self._callers

    def get_callees(self, entity_id, *, limit=50):
        return self._callees

    def resolve(self, qualnames):
        from wardline.clarion.client import ResolveResult

        resolved = {q: self._resolved[q] for q in qualnames if q in self._resolved}
        return ResolveResult(resolved=resolved, unresolved=[q for q in qualnames if q not in resolved])


_ALIVE = EntityBinding(
    locator="python:function:svc.leaky",
    sei="clarion:eid:abc",
    identity=IdentityStatus.ALIVE,
    content_hash="h1",
)


def test_linkages_compose_callers_and_callees_fresh_live() -> None:
    client = _FakeClient(
        callers=LinkageResult(neighbours=("python:function:svc.a",), total=1, truncated=False),
        callees=LinkageResult(neighbours=("python:function:svc.mid",), total=1, truncated=False),
    )
    sec = ClarionLinkageProvider(client, linkages_http=True).linkages(_ALIVE)
    assert sec.available is True
    assert sec.callers == ["python:function:svc.a"]
    assert sec.callees == ["python:function:svc.mid"]
    assert sec.scc_peers == []  # SCC not served over HTTP yet — honest empty
    # identity axis comes from the resolved binding; content axis is FRESH (live read)
    assert sec.identity_status is IdentityStatus.ALIVE
    assert sec.content_status is ContentStatus.FRESH
    # queried on the binding's locator
    assert client.caller_calls[0][0] == "python:function:svc.leaky"


def test_linkages_unavailable_when_clarion_lacks_http_route() -> None:
    sec = ClarionLinkageProvider(_FakeClient(), linkages_http=False).linkages(_ALIVE)
    assert sec.available is False
    assert "http linkages" in (sec.reason or "").lower()


def test_linkages_unavailable_when_both_sides_soft_fail() -> None:
    # entity unknown to Clarion / outage on both sides → honest unavailable, no crash
    sec = ClarionLinkageProvider(_FakeClient(callers=None, callees=None), linkages_http=True).linkages(_ALIVE)
    assert sec.available is False
    assert sec.reason is not None


def test_linkages_truncation_is_surfaced() -> None:
    client = _FakeClient(
        callers=LinkageResult(neighbours=("a",), total=99, truncated=True),
        callees=LinkageResult(neighbours=(), total=0, truncated=False),
    )
    sec = ClarionLinkageProvider(client, linkages_http=True).linkages(_ALIVE)
    assert sec.available is True
    assert sec.reason is not None and "truncat" in sec.reason.lower()


def test_orphaned_identity_axis_is_carried_into_linkages() -> None:
    orphaned = EntityBinding(locator="python:function:old", sei="clarion:eid:x", identity=IdentityStatus.ORPHANED)
    client = _FakeClient(
        callers=LinkageResult(neighbours=(), total=0, truncated=False),
        callees=LinkageResult(neighbours=(), total=0, truncated=False),
    )
    sec = ClarionLinkageProvider(client, linkages_http=True).linkages(orphaned)
    # the two axes stay independent: identity ORPHANED, content FRESH (live read)
    assert sec.identity_status is IdentityStatus.ORPHANED
    assert sec.content_status is ContentStatus.FRESH


def test_resolve_entity_binding_resolves_qualname_then_locator() -> None:
    client = _FakeClient(resolved={"svc.leaky": "python:function:svc.leaky"})

    class _Resolver:
        def resolve_locator(self, locator):
            assert locator == "python:function:svc.leaky"
            return EntityBinding(locator=locator, sei="clarion:eid:abc", identity=IdentityStatus.ALIVE)

    binding = resolve_entity_binding(client, _Resolver(), "svc.leaky")
    assert binding is not None
    assert binding.sei == "clarion:eid:abc"


def test_resolve_entity_binding_none_when_qualname_unresolvable() -> None:
    client = _FakeClient(resolved={})  # qualname not known to Clarion

    class _Resolver:
        def resolve_locator(self, locator):  # pragma: no cover - must not be called
            raise AssertionError("should not resolve a locator we could not obtain")

    assert resolve_entity_binding(client, _Resolver(), "svc.unknown") is None
