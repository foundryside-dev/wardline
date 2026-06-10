"""PY-WL-122 — untrusted data compiled into a server-side template (SSTI, CWE-1336)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_template import UntrustedToTemplate

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


def test_122_jinja2_template_fires_error(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import jinja2
        @trusted(level='ASSURED')
        def f(p):
            return jinja2.Template(read_raw(p)).render()
        """,
    )
    findings = UntrustedToTemplate().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-122", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR  # SSTI is RCE-adjacent


def test_122_environment_from_string_construct_then_method(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import jinja2
        @trusted(level='ASSURED')
        def f(p):
            env = jinja2.Environment()
            return env.from_string(read_raw(p))
        """,
    )
    findings = UntrustedToTemplate().check(ctx)
    assert [x.properties["sink"] for x in findings] == ["jinja2.Environment.from_string"]


def test_122_chained_environment_from_string(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import jinja2
        @trusted(level='ASSURED')
        def f(p):
            return jinja2.Environment().from_string(read_raw(p))
        """,
    )
    assert [x.rule_id for x in UntrustedToTemplate().check(ctx)] == ["PY-WL-122"]


def test_122_mako_template_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import mako.template
        @trusted(level='ASSURED')
        def f(p):
            return mako.template.Template(read_raw(p))
        """,
    )
    assert [x.properties["sink"] for x in UntrustedToTemplate().check(ctx)] == ["mako.template.Template"]


def test_122_literal_template_with_tainted_render_context_is_clean(tmp_path) -> None:
    # Tainted data as a RENDER variable is the safe idiom — only the template
    # SOURCE being tainted is SSTI.
    ctx, _ = _analyze(
        tmp_path,
        """
        import jinja2
        @trusted(level='ASSURED')
        def f(p):
            return jinja2.Template('Hello {{ name }}').render(name=read_raw(p))
        """,
    )
    assert UntrustedToTemplate().check(ctx) == []


def test_122_get_template_by_name_is_not_a_sink(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import jinja2
        @trusted(level='ASSURED')
        def f(p):
            env = jinja2.Environment()
            return env.get_template(read_raw(p))
        """,
    )
    assert UntrustedToTemplate().check(ctx) == []


def test_122_undecorated_is_suppressed(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        import jinja2
        def f(p):
            return jinja2.Template(read_raw(p))
        """,
    )
    assert UntrustedToTemplate().check(ctx) == []


def test_122_registered_end_to_end(tmp_path) -> None:
    _, findings = _analyze(
        tmp_path,
        """
        import jinja2
        @trusted(level='ASSURED')
        def f(p):
            return jinja2.Template(read_raw(p))
        """,
    )
    assert "PY-WL-122" in {f.rule_id for f in findings}
