"""PY-WL-121 — untrusted data reaches an XML parsing sink (XXE / billion-laughs, CWE-611)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_xml import UntrustedToXML

_HEADER = (
    "from wardline.decorators import external_boundary, trusted\n@external_boundary\ndef read_raw(p):\n    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, list(findings)


def test_121_stdlib_etree_fromstring_fires_warn(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import xml.etree.ElementTree as ET
        @trusted(level='ASSURED')
        def f(p):
            return ET.fromstring(read_raw(p))
        """,
    )
    findings = UntrustedToXML().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-121", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    # stdlib etree is entity-safe since 3.7.1 — billion-laughs DoS only -> WARN
    assert findings[0].severity == Severity.WARN


def test_121_stdlib_etree_parse_and_iterparse_fire(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import xml.etree.ElementTree as ET
        @trusted(level='ASSURED')
        def f(p):
            ET.parse(read_raw(p))
            ET.iterparse(read_raw(p))
            return 1
        """,
    )
    sinks = sorted(x.properties["sink"] for x in UntrustedToXML().check(ctx))
    assert sinks == ["xml.etree.ElementTree.iterparse", "xml.etree.ElementTree.parse"]


def test_121_minidom_and_sax_fire_warn(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import xml.dom.minidom
        import xml.sax
        @trusted(level='ASSURED')
        def f(p, h):
            xml.dom.minidom.parseString(read_raw(p))
            xml.sax.parseString(read_raw(p), h)
            return 1
        """,
    )
    findings = UntrustedToXML().check(ctx)
    assert sorted(x.properties["sink"] for x in findings) == [
        "xml.dom.minidom.parseString",
        "xml.sax.parseString",
    ]
    # All pyexpat-based stdlib parsers share the same default-on risk class (DoS).
    assert {x.severity for x in findings} == {Severity.WARN}


def test_121_lxml_fires_error(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        from lxml import etree
        @trusted(level='ASSURED')
        def f(p):
            return etree.fromstring(read_raw(p))
        """,
    )
    findings = UntrustedToXML().check(ctx)
    assert [x.properties["sink"] for x in findings] == ["lxml.etree.fromstring"]
    # lxml resolves external entities by default — genuine XXE -> ERROR
    assert findings[0].severity == Severity.ERROR


def test_121_keyword_spelling_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import xml.etree.ElementTree as ET
        @trusted(level='ASSURED')
        def f(p):
            return ET.fromstring(text=read_raw(p))
        """,
    )
    assert [x.rule_id for x in UntrustedToXML().check(ctx)] == ["PY-WL-121"]


def test_121_literal_xml_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import xml.etree.ElementTree as ET
        @trusted(level='ASSURED')
        def f():
            return ET.fromstring('<root/>')
        """,
    )
    assert UntrustedToXML().check(ctx) == []


def test_121_taint_in_non_dangerous_slot_is_clean(tmp_path) -> None:
    # The parser keyword is not the XML document slot — taint there is not XXE.
    ctx, _ = _analyze(
        tmp_path,
        """
        import xml.etree.ElementTree as ET
        @trusted(level='ASSURED')
        def f(p):
            return ET.fromstring('<root/>', parser=read_raw(p))
        """,
    )
    assert UntrustedToXML().check(ctx) == []


def test_121_defusedxml_is_not_a_sink(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import defusedxml.ElementTree
        @trusted(level='ASSURED')
        def f(p):
            return defusedxml.ElementTree.fromstring(read_raw(p))
        """,
    )
    assert UntrustedToXML().check(ctx) == []


def test_121_undecorated_is_suppressed(tmp_path) -> None:
    # Freedom zone -> modulate -> NONE -> no finding (opt-in preserved).
    ctx, _ = _analyze(
        tmp_path,
        """
        import xml.etree.ElementTree as ET
        def f(p):
            return ET.fromstring(read_raw(p))
        """,
    )
    assert UntrustedToXML().check(ctx) == []


def test_121_registered_end_to_end(tmp_path) -> None:
    _, findings = _analyze(
        tmp_path,
        """
        from lxml import etree
        @trusted(level='ASSURED')
        def f(p):
            return etree.parse(read_raw(p))
        """,
    )
    assert "PY-WL-121" in {f.rule_id for f in findings}
