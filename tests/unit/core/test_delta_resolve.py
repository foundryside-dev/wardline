"""Phase 2 — entity→file resolution + caller-closure (``core.delta_resolve``).

Covers every case the warpline-delta-scan plan names for resolution: the SEI
(loomweave) path, the ``python:method:`` locator bug fix, ``:setter``/``:deleter`` and
nested-class canonicalization, method-vs-class-level locators, the qualname fallback,
partial resolution, the SEI-drift → locator fallback (recorded ``stale_sei``),
``build_qualname_index`` skipping a ``SyntaxError`` file, and the reverse-edge caller
closure pulling a caller's file into the analyzed set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wardline.core.delta_resolve import (
    build_qualname_index,
    canonical_qualname,
    resolve_affected_scope,
)
from wardline.core.delta_scope import AffectedEntity, AffectedScope
from wardline.core.sei_resolution import locator_to_qualname
from wardline.loomweave.identity import SeiCapability, SeiResolver

_CAPS_PRESENT = {"sei": {"supported": True, "version": 1}}


class FakeClient:
    """LoomweaveClient stand-in at the surface the resolver uses (mirrors the SEI oracle
    / SeiResolver test doubles). ``resolve_sei`` returns a fixed body per SEI."""

    def __init__(self, *, caps: Any = None, resolve_sei: dict[str, Any] | None = None) -> None:
        self._caps = caps
        self._resolve_sei = resolve_sei
        self.sei_calls: list[str] = []

    def capabilities(self) -> Any:
        return self._caps

    def resolve_identity(self, locator: str) -> dict[str, Any] | None:
        return None

    def resolve_sei(self, sei: str) -> dict[str, Any] | None:
        self.sei_calls.append(sei)
        return self._resolve_sei


def _resolver(client: FakeClient) -> SeiResolver:
    return SeiResolver(client, SeiCapability.from_capabilities(client.capabilities()))


def _write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _scope(*entities: AffectedEntity, source_kind: str = "entity_list") -> AffectedScope:
    return AffectedScope(frozenset(entities), source_kind, len(entities))


# --- canonicalization helper -------------------------------------------------


def test_canonical_qualname_strips_property_suffixes() -> None:
    assert canonical_qualname("pkg.mod.Cls.prop:setter") == "pkg.mod.Cls.prop"
    assert canonical_qualname("pkg.mod.Cls.prop:deleter") == "pkg.mod.Cls.prop"
    assert canonical_qualname("pkg.mod.func") == "pkg.mod.func"


def test_locator_to_qualname_handles_method_prefix() -> None:
    # The Phase 2 bug fix: python:method: must resolve, not hit the python: catch-all.
    assert locator_to_qualname("python:method:pkg.mod.Cls.m") == "pkg.mod.Cls.m"
    assert locator_to_qualname("python:function:pkg.mod.f") == "pkg.mod.f"
    assert locator_to_qualname("python:class:pkg.mod.Cls") == "pkg.mod.Cls"


# --- build_qualname_index ----------------------------------------------------


def test_build_qualname_index_maps_qualname_to_file(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.py", "def alpha():\n    return 1\n")
    b = _write(tmp_path, "b.py", "class Box:\n    def beta(self):\n        return 2\n")
    index = build_qualname_index([a, b], tmp_path)
    assert index.by_qualname["a.alpha"] == "a.py"
    assert index.by_qualname["b.Box.beta"] == "b.py"


def test_build_qualname_index_skips_syntax_error_file(tmp_path: Path) -> None:
    ok = _write(tmp_path, "ok.py", "def good():\n    return 1\n")
    bad = _write(tmp_path, "bad.py", "def broken(:\n    pass\n")  # invalid syntax
    index = build_qualname_index([ok, bad], tmp_path)  # must not raise
    assert index.by_qualname["ok.good"] == "ok.py"
    assert all(path != "bad.py" for path in index.by_qualname.values())


def test_build_qualname_index_canonicalizes_property_accessor(tmp_path: Path) -> None:
    src = (
        "class Cfg:\n"
        "    @property\n"
        "    def value(self):\n"
        "        return self._v\n"
        "    @value.setter\n"
        "    def value(self, v):\n"
        "        self._v = v\n"
    )
    f = _write(tmp_path, "cfg.py", src)
    index = build_qualname_index([f], tmp_path)
    # The setter entity's raw qualname carries ':setter'; the key is canonical.
    assert index.by_qualname["cfg.Cfg.value"] == "cfg.py"


# --- resolve via SEI ---------------------------------------------------------


def test_resolve_via_sei_authoritative(tmp_path: Path) -> None:
    f = _write(tmp_path, "svc.py", "def handler():\n    return 1\n")
    index = build_qualname_index([f], tmp_path)
    client = FakeClient(
        caps=_CAPS_PRESENT,
        resolve_sei={"alive": True, "current_locator": "python:function:svc.handler"},
    )
    scope = _scope(AffectedEntity(sei="loomweave:eid:abc", locator=None))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=_resolver(client))
    assert resolved.files == frozenset({"svc.py"})
    assert "svc.handler" in resolved.affected_qualnames
    assert len(resolved.resolved) == 1
    assert resolved.loomweave_used is True
    assert client.sei_calls == ["loomweave:eid:abc"]


def test_resolve_via_sei_method_locator(tmp_path: Path) -> None:
    src = "class Svc:\n    def handle(self):\n        return 1\n"
    f = _write(tmp_path, "svc.py", src)
    index = build_qualname_index([f], tmp_path)
    client = FakeClient(
        caps=_CAPS_PRESENT,
        # SEI resolves to a python:method: locator — exercises the prefix bug fix.
        resolve_sei={"alive": True, "current_locator": "python:method:svc.Svc.handle"},
    )
    scope = _scope(AffectedEntity(sei="loomweave:eid:m", locator=None))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=_resolver(client))
    assert resolved.files == frozenset({"svc.py"})
    assert "svc.Svc.handle" in resolved.affected_qualnames


# --- qualname fallback -------------------------------------------------------


def test_resolve_qualname_fallback_no_resolver(tmp_path: Path) -> None:
    f = _write(tmp_path, "svc.py", "def handler():\n    return 1\n")
    index = build_qualname_index([f], tmp_path)
    scope = _scope(AffectedEntity(sei=None, locator="python:function:svc.handler"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)
    assert resolved.files == frozenset({"svc.py"})
    assert len(resolved.fell_back) == 1
    assert resolved.loomweave_used is False


def test_resolve_qualname_fallback_resolver_unsupported(tmp_path: Path) -> None:
    f = _write(tmp_path, "svc.py", "def handler():\n    return 1\n")
    index = build_qualname_index([f], tmp_path)
    client = FakeClient(caps=None)  # pre-SEI loomweave → unsupported
    scope = _scope(AffectedEntity(sei="loomweave:eid:x", locator="python:function:svc.handler"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=_resolver(client))
    assert resolved.files == frozenset({"svc.py"})
    assert len(resolved.fell_back) == 1
    assert resolved.loomweave_used is False


def test_resolve_method_locator_via_fallback(tmp_path: Path) -> None:
    src = "class Svc:\n    def handle(self):\n        return 1\n"
    f = _write(tmp_path, "svc.py", src)
    index = build_qualname_index([f], tmp_path)
    scope = _scope(AffectedEntity(sei=None, locator="python:method:svc.Svc.handle"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)
    assert resolved.files == frozenset({"svc.py"})
    assert "svc.Svc.handle" in resolved.affected_qualnames


def test_resolve_property_setter_via_base_locator(tmp_path: Path) -> None:
    src = (
        "class Cfg:\n"
        "    @property\n"
        "    def value(self):\n"
        "        return self._v\n"
        "    @value.setter\n"
        "    def value(self, v):\n"
        "        self._v = v\n"
    )
    f = _write(tmp_path, "cfg.py", src)
    index = build_qualname_index([f], tmp_path)
    # Locator names the base property — must match the (canonical) setter entity's key.
    scope = _scope(AffectedEntity(sei=None, locator="python:function:cfg.Cfg.value"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)
    assert resolved.files == frozenset({"cfg.py"})
    assert "cfg.Cfg.value" in resolved.affected_qualnames


def test_resolve_class_level_locator_scopes_methods(tmp_path: Path) -> None:
    src = "class Svc:\n    def a(self):\n        return 1\n    def b(self):\n        return 2\n"
    f = _write(tmp_path, "svc.py", src)
    index = build_qualname_index([f], tmp_path)
    scope = _scope(AffectedEntity(sei=None, locator="python:class:svc.Svc"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)
    assert resolved.files == frozenset({"svc.py"})
    # The class qualname itself is the affected key; the filter's prefix rule scopes in
    # both methods (covered in the finding-filter tests).
    assert "svc.Svc" in resolved.affected_qualnames


def test_resolve_nested_class_qualname(tmp_path: Path) -> None:
    src = "class Outer:\n    class Inner:\n        def deep(self):\n            return 1\n"
    f = _write(tmp_path, "nest.py", src)
    index = build_qualname_index([f], tmp_path)
    scope = _scope(AffectedEntity(sei=None, locator="python:method:nest.Outer.Inner.deep"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)
    assert resolved.files == frozenset({"nest.py"})
    assert "nest.Outer.Inner.deep" in resolved.affected_qualnames


# --- partial resolution / unresolved -----------------------------------------


def test_partial_resolution_is_not_full_fallback(tmp_path: Path) -> None:
    f = _write(tmp_path, "svc.py", "def handler():\n    return 1\n")
    index = build_qualname_index([f], tmp_path)
    good = AffectedEntity(sei=None, locator="python:function:svc.handler")
    bogus = AffectedEntity(sei=None, locator="python:function:nope.missing")
    resolved = resolve_affected_scope(_scope(good, bogus), index=index, sei_resolver=None)
    assert len(resolved.files) == 1
    assert resolved.files == frozenset({"svc.py"})
    assert len(resolved.unresolved) == 1
    assert resolved.unresolved[0] is bogus


# --- SEI drift ---------------------------------------------------------------


def test_sei_drift_falls_through_to_locator(tmp_path: Path) -> None:
    f = _write(tmp_path, "svc.py", "def renamed():\n    return 1\n")
    index = build_qualname_index([f], tmp_path)
    client = FakeClient(
        caps=_CAPS_PRESENT,
        # SEI resolves to a qualname that no longer exists in the index (a rename since
        # loomweave's last index) → drift; recovery is via the supplied locator.
        resolve_sei={"alive": True, "current_locator": "python:function:svc.old_name"},
    )
    entity = AffectedEntity(sei="loomweave:eid:drift", locator="python:function:svc.renamed")
    resolved = resolve_affected_scope(_scope(entity), index=index, sei_resolver=_resolver(client))
    assert resolved.files == frozenset({"svc.py"})
    assert len(resolved.stale_sei) == 1
    assert resolved.stale_sei[0] is entity
    assert len(resolved.fell_back) == 0
    assert len(resolved.resolved) == 0


def test_sei_drift_no_locator_is_unresolved(tmp_path: Path) -> None:
    f = _write(tmp_path, "svc.py", "def renamed():\n    return 1\n")
    index = build_qualname_index([f], tmp_path)
    client = FakeClient(
        caps=_CAPS_PRESENT,
        resolve_sei={"alive": True, "current_locator": "python:function:svc.old_name"},
    )
    entity = AffectedEntity(sei="loomweave:eid:drift", locator=None)
    resolved = resolve_affected_scope(_scope(entity), index=index, sei_resolver=_resolver(client))
    assert resolved.files == frozenset()
    assert len(resolved.unresolved) == 1
    assert len(resolved.stale_sei) == 0


# --- caller closure ----------------------------------------------------------


def test_caller_closure_pulls_callers_file(tmp_path: Path) -> None:
    # b.py defines the changed callee; a.py's sink calls it. A worklist naming b.py's
    # entity must pull a.py into the analyzed set via the reverse-edge closure.
    _write(tmp_path, "b.py", "def source():\n    return input()\n")
    a = _write(
        tmp_path,
        "a.py",
        "from b import source\n\ndef sink():\n    return source()\n",
    )
    b = tmp_path / "b.py"
    index = build_qualname_index([a, b], tmp_path)
    # The structural pass resolved a.sink -> b.source.
    assert "b.source" in index.project_edges["a.sink"]
    scope = _scope(AffectedEntity(sei=None, locator="python:function:b.source"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)
    assert "b.py" in resolved.files  # base
    assert "a.py" in resolved.files  # caller closure
    # The filter set stays the BASE set (only files expanded).
    assert resolved.affected_qualnames == frozenset({"b.source"})


def test_caller_closure_does_not_expand_from_unrelated_entities_in_same_file(tmp_path: Path) -> None:
    # b.py defines the affected callee and an unrelated helper. Only callers of
    # b.source should expand the analyzed files; callers of b.unrelated must not
    # be swept in just because they share the base file.
    b = _write(
        tmp_path,
        "b.py",
        "def source():\n    return input()\n\ndef unrelated():\n    return 'noise'\n",
    )
    a = _write(
        tmp_path,
        "a.py",
        "from b import source\n\ndef sink():\n    return source()\n",
    )
    noise = _write(
        tmp_path,
        "noise.py",
        "from b import unrelated\n\ndef caller():\n    return unrelated()\n",
    )
    index = build_qualname_index([a, b, noise], tmp_path)

    scope = _scope(AffectedEntity(sei=None, locator="python:function:b.source"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)

    assert resolved.files == frozenset({"a.py", "b.py"})


def test_caller_closure_self_method(tmp_path: Path) -> None:
    src = (
        "class Svc:\n    def sink(self):\n        return self.source()\n    def source(self):\n        return input()\n"
    )
    f = _write(tmp_path, "svc.py", src)
    index = build_qualname_index([f], tmp_path)
    assert "svc.Svc.source" in index.project_edges["svc.Svc.sink"]
    scope = _scope(AffectedEntity(sei=None, locator="python:method:svc.Svc.source"))
    resolved = resolve_affected_scope(scope, index=index, sei_resolver=None)
    assert resolved.files == frozenset({"svc.py"})
