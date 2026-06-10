# src/wardline/scanner/rules/untrusted_to_template.py
"""PY-WL-122 — untrusted data compiled into a server-side template (SSTI, CWE-1336).

Charter: a tainted string reaching a template COMPILATION sink
(``jinja2.Template``, ``jinja2.Environment.from_string`` — including the
construct-then-method form — and ``mako.template.Template``) inside a
trusted-tier function. Tier-modulated; fires only where trust is declared.

Only the template SOURCE slot is dangerous: tainted data passed as a render
variable (``Template('{{ x }}').render(x=raw)``) is the safe idiom and must not
fire — autoescaping/render-time substitution is exactly the mitigation. Loading
a template BY NAME (``env.get_template(raw)``) is not SSTI either.

Severity: ERROR. SSTI in Jinja2/Mako is RCE-adjacent (``{{ ''.__class__ ... }}``
sandbox escapes are a documented exploitation primitive), the same blast-radius
class as the PY-WL-118/108 ERROR family.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import ArgSpec, TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

# Only the template-source slot; render context / loader names are not SSTI.
_SINK_SPECS: dict[str, ArgSpec | None] = {
    "jinja2.Template": ArgSpec(positions=(0,), keywords=("source",)),
    "jinja2.Environment.from_string": ArgSpec(positions=(0,), keywords=("source",)),
    "mako.template.Template": ArgSpec(positions=(0,), keywords=("text",)),
}

METADATA = RuleMetadata(
    rule_id="PY-WL-122",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data is compiled into a server-side template "
        "(jinja2.Template/Environment.from_string, mako Template) in a trusted-tier function (SSTI)."
    ),
    examples_violation=(
        "import jinja2\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    return jinja2.Template(read_raw(p)).render()",
        "import jinja2\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n"
        "    env = jinja2.Environment()\n    return env.from_string(read_raw(p))",
    ),
    examples_clean=(
        # Tainted data as a RENDER variable is the safe idiom — only a tainted SOURCE is SSTI.
        "import jinja2\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n"
        "    jinja2.Template('Hello {{ name }}').render(name=read_raw(p))",
    ),
    maturity=Maturity.PREVIEW,
)


class UntrustedToTemplate(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = frozenset(_SINK_SPECS)
    SINK_SPECS = _SINK_SPECS
    sink_label = "template-compilation"
