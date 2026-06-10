"""Module-global taint channel (wardline-66b2c91470).

Read direction: a module-level variable assigned from a raw source at import
time (``RAW = read_raw(...)`` where ``read_raw`` is an ``@external_boundary``
function, or a call matching ``config.untrusted_sources``) carries its taint
into every function that reads it — the L2 walk seeds the global like an
implicit parameter, so a local reassignment shadows it flow-sensitively.

Write direction: a function assigning raw to a declared ``global g`` marks the
module global, and OTHER functions reading ``g`` inherit (one merge hop —
see the analyzer's documented approximation).
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from wardline.core.config import WardlineConfig
from wardline.core.taints import RAW_ZONE
from wardline.scanner.analyzer import WardlineAnalyzer

if TYPE_CHECKING:
    from pathlib import Path

_HEADER = (
    "import os\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _scan(tmp_path: Path, src: str, config: WardlineConfig | None = None, header: str = _HEADER):
    p = tmp_path / "m.py"
    p.write_text(header + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], config or WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return findings, analyzer.last_context


def _hits(findings, rule_id: str) -> list[tuple[str, str | None]]:
    return [(f.rule_id, f.qualname) for f in findings if f.rule_id == rule_id]


def test_module_level_raw_assignment_taints_reader(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        RAW = read_raw('seed')

        @trusted(level='ASSURED')
        def f():
            os.system(RAW)
        """,
    )
    assert _hits(findings, "PY-WL-108") == [("PY-WL-108", "m.f")]


def test_module_level_raw_via_config_untrusted_sources(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        RAW = fetchlib.fetch()

        @trusted(level='ASSURED')
        def f():
            os.system(RAW)
        """,
        config=WardlineConfig(untrusted_sources=("fetchlib.fetch",)),
        header=("import os\nimport fetchlib\nfrom wardline.decorators import external_boundary, trusted\n"),
    )
    assert _hits(findings, "PY-WL-108") == [("PY-WL-108", "m.f")]


def test_local_reassignment_shadows_module_global(tmp_path) -> None:
    # Flow-sensitive shadowing: the function overwrites the global name with a
    # literal BEFORE the sink — no finding.
    findings, _ = _scan(
        tmp_path,
        """
        RAW = read_raw('seed')

        @trusted(level='ASSURED')
        def f():
            RAW = 'ls -la'
            os.system(RAW)
        """,
    )
    assert _hits(findings, "PY-WL-108") == []


def test_clean_module_global_stays_clean(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        CMD = 'ls -la'

        @trusted(level='ASSURED')
        def f():
            os.system(CMD)
        """,
    )
    assert _hits(findings, "PY-WL-108") == []


def test_module_level_rebind_to_safe_clears_seed(tmp_path) -> None:
    # Last-binding-wins at module scope (same discipline as collect_sink_bindings).
    findings, _ = _scan(
        tmp_path,
        """
        RAW = read_raw('seed')
        RAW = 'ls -la'

        @trusted(level='ASSURED')
        def f():
            os.system(RAW)
        """,
    )
    assert _hits(findings, "PY-WL-108") == []


def test_global_write_propagates_to_other_readers(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        G = 'init'

        def poison(p):
            global G
            G = read_raw(p)

        @trusted(level='ASSURED')
        def use():
            os.system(G)
        """,
    )
    assert _hits(findings, "PY-WL-108") == [("PY-WL-108", "m.use")]


def test_global_clean_write_does_not_poison(tmp_path) -> None:
    findings, _ = _scan(
        tmp_path,
        """
        def set_default():
            global G
            G = 'ls -la'

        @trusted(level='ASSURED')
        def use():
            os.system(G)
        """,
    )
    assert _hits(findings, "PY-WL-108") == []


def test_raw_module_global_propagates_to_return_taint(tmp_path) -> None:
    _, ctx = _scan(
        tmp_path,
        """
        RAW = read_raw('seed')

        @trusted(level='ASSURED')
        def f():
            return RAW
        """,
    )
    assert ctx.function_return_taints["m.f"] in RAW_ZONE
