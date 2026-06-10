# src/wardline/scanner/rules/untrusted_to_xml.py
"""PY-WL-121 — untrusted data reaches an XML parsing sink (XXE family, CWE-611).

Charter: a tainted document/stream reaching an XML parser inside a trusted-tier
function. Tier-modulated; fires only where trust is declared. Only the DOCUMENT
slot (position 0 / its keyword spelling) is dangerous — taint in a ``parser=``
or handler slot is not XXE.

Severity is PER-SINK, calibrated to each parser's *default* posture (verified on
the project interpreter, 2026-06-10 scrub):

* ``lxml.etree.*`` — **ERROR**: resolves external entities by default
  (``resolve_entities=True``), so tainted XML is genuine XXE (local file
  disclosure / SSRF).
* stdlib ``xml.etree.ElementTree`` / ``xml.dom.minidom`` / ``xml.sax`` —
  **WARN**: external general entities have been disabled by default since
  CPython 3.7.1 (``ET.fromstring`` raises on an external-entity payload), so
  the default-on residual risk is the billion-laughs internal-entity-expansion
  DoS shared by every pyexpat-based parser. NOT the ERROR class the gap report
  originally claimed — the "stdlib resolves external entities by default"
  premise was disproven by the verifier; all three stdlib families share the
  same DoS-only default risk, hence the same WARN.

``defusedxml`` is the blessed remediation and is deliberately not a sink.

The 121…126 preview family's binding- and arg-slot-aware check machinery used to
live here as ``SpecSinkCheckMixin``; it graduated into the consolidated
:class:`TaintedSinkRule` base (``SINK_SPECS`` / ``SINK_SEVERITIES``, review
2026-06-10), so this module is now an attribute-only rule like its siblings.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import ArgSpec, TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

# Only the DOCUMENT slot is dangerous; ``parser=``/handler slots are not XXE.
_SINK_SPECS: dict[str, ArgSpec | None] = {
    "xml.etree.ElementTree.fromstring": ArgSpec(positions=(0,), keywords=("text",)),
    "xml.etree.ElementTree.parse": ArgSpec(positions=(0,), keywords=("source",)),
    "xml.etree.ElementTree.XML": ArgSpec(positions=(0,), keywords=("text",)),
    "xml.etree.ElementTree.iterparse": ArgSpec(positions=(0,), keywords=("source",)),
    "xml.dom.minidom.parse": ArgSpec(positions=(0,), keywords=("file",)),
    "xml.dom.minidom.parseString": ArgSpec(positions=(0,), keywords=("string",)),
    "xml.sax.parse": ArgSpec(positions=(0,), keywords=("source",)),
    "xml.sax.parseString": ArgSpec(positions=(0,), keywords=("string",)),
    "lxml.etree.fromstring": ArgSpec(positions=(0,), keywords=("text",)),
    "lxml.etree.parse": ArgSpec(positions=(0,), keywords=("source",)),
    "lxml.etree.XML": ArgSpec(positions=(0,), keywords=("text",)),
}

# Per-sink calibration (see module docstring): stdlib = billion-laughs DoS only
# since 3.7.1 → WARN; lxml = entity-resolving by default → the ERROR base.
_STDLIB_SEVERITIES: dict[str, Severity] = {fqn: Severity.WARN for fqn in _SINK_SPECS if fqn.startswith("xml.")}

METADATA = RuleMetadata(
    rule_id="PY-WL-121",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches an XML parsing sink (XXE/billion-laughs: lxml.etree at ERROR, "
        "stdlib etree/minidom/sax at WARN) in a trusted-tier function."
    ),
    examples_violation=(
        "from lxml import etree\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    return etree.fromstring(read_raw(p))",
        "import xml.etree.ElementTree as ET\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    return ET.fromstring(read_raw(p))",
    ),
    examples_clean=(
        "import xml.etree.ElementTree as ET\n@trusted(level='ASSURED')\ndef f():\n    ET.fromstring('<r/>')",
    ),
    maturity=Maturity.PREVIEW,
)


class UntrustedToXML(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = frozenset(_SINK_SPECS)
    SINK_SPECS = _SINK_SPECS
    SINK_SEVERITIES = _STDLIB_SEVERITIES
    sink_label = "XML-parsing"
