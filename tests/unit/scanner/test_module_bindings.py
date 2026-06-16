"""Module-level binding channel (wardline-13cfdd7b31 / wardline-66b2c91470).

Module-scope simple bindings — ``runner = subprocess.run`` (callable alias),
``client = httpx.Client()`` (constructed instance) — are collected per module
onto ``AnalysisContext.module_bindings`` and layered UNDER each function's own
bindings by the sink machinery (:func:`resolved_sink_calls`), closing the
documented v1 module-level false negatives: a module-level callable alias used
in a function now fires PY-WL-112/108, a module-level constructed client fires
PY-WL-117.
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from wardline.core.config import WardlineConfig
from wardline.scanner.analyzer import WardlineAnalyzer

if TYPE_CHECKING:
    from pathlib import Path

_HEADER = (
    "import os, pickle, subprocess\n"
    "import httpx\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _scan(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return findings, analyzer.last_context


def _hits(findings, rule_id: str) -> list[tuple[str, str | None]]:
    return [(f.rule_id, f.qualname) for f in findings if f.rule_id == rule_id]


def test_context_module_bindings_collects_module_scope_bindings(tmp_path) -> None:
    _, ctx = _scan(
        tmp_path,
        """
        runner = subprocess.run
        client = httpx.Client()

        @trusted(level='ASSURED')
        def f(p):
            return 1
        """,
    )
    bindings = ctx.module_bindings["m"]
    assert bindings.callable_aliases["runner"] == "subprocess.run"
    assert bindings.instance_classes["client"] == "httpx.Client"


def test_112_module_level_callable_alias_fires(tmp_path) -> None:
    # The exact wardline-13cfdd7b31 repro: module-scope ``runner = subprocess.run``
    # used inside a trusted function with shell=True.
    findings, _ = _scan(
        tmp_path,
        """
        runner = subprocess.run

        @trusted(level='ASSURED')
        def f(p):
            runner(read_raw(p), shell=True)
        """,
    )
    assert _hits(findings, "PY-WL-112") == [("PY-WL-112", "m.f")]


def test_117_module_level_client_construction_fires(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        client = httpx.Client()

        @trusted(level='ASSURED')
        def f(p):
            client.get(read_raw(p))
        """,
    )
    assert _hits(findings, "PY-WL-117") == [("PY-WL-117", "m.f")]


def test_108_module_level_callable_alias_fires(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        sh = os.system

        @trusted(level='ASSURED')
        def f(p):
            sh(read_raw(p))
        """,
    )
    assert _hits(findings, "PY-WL-108") == [("PY-WL-108", "m.f")]


def test_106_module_level_callable_alias_fires(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        loader = pickle.loads

        @trusted(level='ASSURED')
        def f(p):
            return loader(read_raw(p))
        """,
    )
    assert _hits(findings, "PY-WL-106") == [("PY-WL-106", "m.f")]


def test_function_local_rebind_shadows_module_binding(tmp_path) -> None:
    # A function-local rebind to an unresolvable/non-sink value must shadow the
    # module-level binding — no false positive on the local ``client``.
    findings, _ = _scan(
        tmp_path,
        """
        client = httpx.Client()

        @trusted(level='ASSURED')
        def f(p):
            client = object()
            client.get(read_raw(p))
        """,
    )
    assert _hits(findings, "PY-WL-117") == []


def test_module_binding_clean_argument_does_not_fire(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        client = httpx.Client()

        @trusted(level='ASSURED')
        def f():
            client.get('https://example.com')
        """,
    )
    assert _hits(findings, "PY-WL-117") == []
